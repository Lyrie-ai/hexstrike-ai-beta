"""Descriptor-relative workspace operations that reject symlink traversal and linked files."""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-+/=]+"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(?i)(set-cookie\s*:\s*[^=;\s]+=)[^;\r\n]+"), r"\1[REDACTED_COOKIE_VALUE]"),
    (
        re.compile(
            r"(?i)(\b(?:session_id|sessionid|phpsessid|jsessionid|auth_token|access_token|refresh_token|id_token)\s*=\s*)[^;\s'\"&]+"
        ),
        r"\1[REDACTED_COOKIE_VALUE]",
    ),
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|password|passwd|token|auth_token)\s*([=:])\s*['\"]?([^\s'\",;]{4,})['\"]?"
        ),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
]


def redact_secrets(text: str, extra_secrets: Optional[List[str]] = None) -> str:
    if not text:
        return ""
    # Strip terminal control sequences before text reaches logs or operator displays.
    redacted = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    redacted = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", redacted)
    redacted = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", redacted)
    if extra_secrets:
        for secret in extra_secrets:
            if secret and len(secret) >= 3:
                redacted = redacted.replace(secret, "[REDACTED_SECRET]")
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def redact_http_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Remove authentication material before headers become evidence."""
    sensitive = {"cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key", "api-key", "x-auth-token"}
    return {key: "[REDACTED_HEADER_VALUE]" if key.lower() in sensitive else value
            for key, value in headers.items()}


class WorkspaceSecurityError(PermissionError):
    """Raised when a workspace operation attempts path escape or violates confinement."""


class ConfinedWorkspace:
    """
    Confined workspace manager for a specific directory root.
    Uses descriptor-relative (`dir_fd`) traversal and operations on POSIX platforms so
    parent-symlink swap races cannot escape the workspace during create, modify, read,
    delete, or list operations.
    """

    def __init__(
        self,
        base_dir: Optional[str | Path] = None,
        max_file_size: int = 100 * 1024 * 1024,
        max_workspace_bytes: int = 500 * 1024 * 1024,
    ) -> None:
        if base_dir is None:
            default_root = Path(tempfile.gettempdir()) / "hexstrike_workspace"
        else:
            default_root = Path(base_dir)
        default_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(default_root, 0o700)
        except OSError:
            pass
        self.base_dir: Path = default_root.resolve()
        self.max_file_size = max_file_size
        self.max_workspace_bytes = max_workspace_bytes

    def _parse_relative_parts(self, user_path: str, allow_root: bool = False) -> List[str]:
        if not isinstance(user_path, str):
            raise WorkspaceSecurityError("Path must be a string")

        raw = user_path.strip()
        if not raw:
            if allow_root:
                return []
            raise WorkspaceSecurityError("Path must not be empty")

        if "\x00" in raw:
            raise WorkspaceSecurityError("Null bytes are forbidden in workspace paths")

        decoded = raw
        for _ in range(3):
            unquoted = urllib.parse.unquote(decoded)
            if unquoted == decoded:
                break
            decoded = unquoted

        for candidate in (raw, decoded):
            if re.match(r"^[a-zA-Z]:", candidate):
                raise WorkspaceSecurityError(f"Drive-qualified path forbidden: {user_path}")
            if candidate.startswith("\\\\") or candidate.startswith("//"):
                raise WorkspaceSecurityError(f"UNC path forbidden: {user_path}")
            if candidate.startswith("/") or candidate.startswith("\\"):
                raise WorkspaceSecurityError(f"Absolute path forbidden: {user_path}")
            if ":" in candidate and os.name == "nt":
                raise WorkspaceSecurityError(f"Alternate data stream forbidden: {user_path}")

            normalized = candidate.replace("\\", "/")
            parts = [p for p in normalized.split("/") if p and p != "."]
            if any(p == ".." for p in parts):
                raise WorkspaceSecurityError(f"Path traversal ('..') forbidden: {user_path}")

        normalized_rel = decoded.replace("\\", "/")
        parts = [p for p in normalized_rel.split("/") if p and p != "."]
        if not parts and not allow_root:
            raise WorkspaceSecurityError("Path resolves to workspace root")
        for part in parts:
            if part in (".", "..") or "/" in part or "\\" in part:
                raise WorkspaceSecurityError(f"Invalid path component: {part}")
        return parts

    def _open_root_dir_fd(self) -> int:
        base_st = os.lstat(self.base_dir)
        if stat.S_ISLNK(base_st.st_mode) or not stat.S_ISDIR(base_st.st_mode):
            raise WorkspaceSecurityError("Workspace root is not a real directory")
        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(self.base_dir), dir_flags)
        try:
            fd_st = os.fstat(fd)
            if fd_st.st_dev != base_st.st_dev or fd_st.st_ino != base_st.st_ino:
                raise WorkspaceSecurityError("Workspace root changed during open")
            return fd
        except Exception:
            os.close(fd)
            raise

    def _walk_parent_dir_fd(
        self, parts: List[str], create_parents: bool = False
    ) -> Tuple[int, str, List[Tuple[Path, int, int]]]:
        """
        Traverse `parts[:-1]` step-by-step using `dir_fd` + `O_NOFOLLOW | O_DIRECTORY`.
        Returns `(parent_dir_fd, leaf_name, ancestor_records)` where caller owns `parent_dir_fd`.
        """
        cur_fd = self._open_root_dir_fd()
        cur_path = self.base_dir
        root_st = os.fstat(cur_fd)
        ancestors: List[Tuple[Path, int, int]] = [(cur_path, root_st.st_dev, root_st.st_ino)]

        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            for part in parts[:-1]:
                cur_path = cur_path / part
                if create_parents:
                    try:
                        os.mkdir(part, 0o700, dir_fd=cur_fd)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        if exc.errno != errno.EEXIST:
                            raise WorkspaceSecurityError(f"Cannot create parent directory '{part}': {exc}") from exc
                try:
                    next_fd = os.open(part, dir_flags, dir_fd=cur_fd)
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise WorkspaceSecurityError(f"Symlink or non-directory ancestor forbidden: {part}") from exc
                    raise
                os.close(cur_fd)
                cur_fd = next_fd
                st = os.fstat(cur_fd)
                if not stat.S_ISDIR(st.st_mode):
                    raise WorkspaceSecurityError(f"Ancestor is not a directory: {part}")
                ancestors.append((cur_path, st.st_dev, st.st_ino))
            return cur_fd, parts[-1], ancestors
        except Exception:
            os.close(cur_fd)
            raise

    @staticmethod
    def _verify_ancestors_unchanged(ancestors: List[Tuple[Path, int, int]]) -> None:
        """
        Verify that every ancestor path in the workspace still resolves to the exact
        same `(st_dev, st_ino)` directory opened during traversal.
        """
        for anc_path, exp_dev, exp_ino in ancestors:
            try:
                st = os.lstat(anc_path)
            except OSError as exc:
                raise WorkspaceSecurityError("Ancestor directory disappeared during operation") from exc
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise WorkspaceSecurityError("Parent directory symlink race detected")
            if st.st_dev != exp_dev or st.st_ino != exp_ino:
                raise WorkspaceSecurityError("Parent directory swap race detected")

    def _current_usage_bytes(self) -> int:
        total = 0
        for root, _, files in os.walk(self.base_dir, followlinks=False):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    if not fpath.is_symlink():
                        total += fpath.stat().st_size
                except OSError:
                    pass
        return total

    def _safe_cleanup_created_leaf_in_parent_fd(
        self, parent_fd: int, leaf: str, expected_dev: int, expected_ino: int
    ) -> None:
        """
        Clean up a newly created empty file strictly inside the pinned `parent_fd`
        only if `os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)` still matches
        `(expected_dev, expected_ino)`. Never uses a pathname.
        """
        try:
            cur_st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (
                stat.S_ISREG(cur_st.st_mode)
                and cur_st.st_dev == expected_dev
                and cur_st.st_ino == expected_ino
                and cur_st.st_size == 0
                and cur_st.st_nlink == 1
            ):
                os.unlink(leaf, dir_fd=parent_fd)
        except OSError:
            pass

    def _safe_write_bytes(
        self, user_path: str, data: bytes, require_existing: bool = False, append: bool = False, exclusive: bool = False, expected_sha256: Optional[str] = None
    ) -> str:
        if len(data) > self.max_file_size:
            raise ValueError(f"File size {len(data)} exceeds limit {self.max_file_size} bytes")
        if self._current_usage_bytes() + len(data) > self.max_workspace_bytes:
            raise ValueError("Workspace quota exceeded")

        parts = self._parse_relative_parts(user_path, allow_root=False)
        rel_str = "/".join(parts)

        parent_fd, leaf, ancestors = self._walk_parent_dir_fd(parts, create_parents=not require_existing)
        try:
            existed_before = False
            try:
                pre_st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                existed_before = True
                if stat.S_ISLNK(pre_st.st_mode):
                    raise WorkspaceSecurityError(f"Symlink target forbidden: {user_path}")
                if not stat.S_ISREG(pre_st.st_mode):
                    raise WorkspaceSecurityError(f"Target is not a regular file: {user_path}")
                if pre_st.st_nlink > 1:
                    raise WorkspaceSecurityError(f"Hardlinked file forbidden: {user_path}")
            except FileNotFoundError:
                if require_existing:
                    raise FileNotFoundError("File does not exist")

            # Never pass O_TRUNC to os.open so a raced hardlink is never truncated before fstat check
            flags = (os.O_RDWR if expected_sha256 else os.O_WRONLY) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            if not require_existing:
                flags |= os.O_CREAT
                if exclusive:
                    flags |= os.O_EXCL
            if append:
                flags |= os.O_APPEND

            try:
                fd = os.open(leaf, flags, 0o600, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise WorkspaceSecurityError("Symlink race detected during open") from exc
                raise

            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise WorkspaceSecurityError("Target is not a regular file")
                if st.st_nlink > 1:
                    raise WorkspaceSecurityError("Hardlink race detected on open file descriptor")

                try:
                    self._verify_ancestors_unchanged(ancestors)
                    pinned_leaf_st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                    if pinned_leaf_st.st_dev != st.st_dev or pinned_leaf_st.st_ino != st.st_ino:
                        raise WorkspaceSecurityError("Parent directory swap race detected during open")
                except WorkspaceSecurityError:
                    if not existed_before:
                        self._safe_cleanup_created_leaf_in_parent_fd(
                            parent_fd, leaf, st.st_dev, st.st_ino
                        )
                    raise

                if expected_sha256:
                    digest = hashlib.sha256()
                    while chunk := os.read(fd, 65536):
                        digest.update(chunk)
                    if digest.hexdigest() != expected_sha256:
                        raise ValueError("File changed since it was read; patch was not applied")
                if not append:
                    os.ftruncate(fd, 0)
                    os.lseek(fd, 0, os.SEEK_SET)
                remaining = memoryview(data)
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise OSError("Workspace write made no progress")
                    remaining = remaining[written:]
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)

        return rel_str

    def create_file(self, filename: str, content: str | bytes, binary: bool = False, exclusive: bool = False) -> Dict[str, Any]:
        try:
            raw_bytes = content if isinstance(content, bytes) else content.encode("utf-8")
            rel_path = self._safe_write_bytes(filename, raw_bytes, require_existing=False, append=False, exclusive=exclusive)
            return {
                "success": True,
                "path": rel_path,
                "size": len(raw_bytes),
                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            }
        except WorkspaceSecurityError as exc:
            return {"success": False, "error": str(exc), "code": "PATH_CONFINEMENT_VIOLATION"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def modify_file(self, filename: str, content: str | bytes, append: bool = False, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
        try:
            raw_bytes = content if isinstance(content, bytes) else content.encode("utf-8")
            rel_path = self._safe_write_bytes(filename, raw_bytes, require_existing=True, append=append, expected_sha256=expected_sha256)
            return {"success": True, "path": rel_path}
        except WorkspaceSecurityError as exc:
            return {"success": False, "error": str(exc), "code": "PATH_CONFINEMENT_VIOLATION"}
        except FileNotFoundError:
            return {"success": False, "error": "File does not exist"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def read_file(
        self,
        filename: str,
        max_bytes: int = 1024 * 1024,
        binary: bool = False,
        offset: int = 0,
        compute_full_sha256: bool = True,
    ) -> Dict[str, Any]:
        try:
            parts = self._parse_relative_parts(filename, allow_root=False)
            rel_str = "/".join(parts)
            parent_fd, leaf, ancestors = self._walk_parent_dir_fd(parts, create_parents=False)
            try:
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
                try:
                    fd = os.open(leaf, flags, dir_fd=parent_fd)
                except FileNotFoundError:
                    return {"success": False, "error": "File does not exist", "code": "ARTIFACT_MISSING"}
                except OSError as exc:
                    if exc.errno == errno.ELOOP:
                        raise WorkspaceSecurityError("Symlink target forbidden") from exc
                    raise
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode):
                        raise WorkspaceSecurityError("Target is not a regular file")
                    if st.st_nlink > 1:
                        raise WorkspaceSecurityError("Hardlink target forbidden")
                    self._verify_ancestors_unchanged(ancestors)
                    total_bytes = int(st.st_size)

                    file_sha256 = ""
                    if compute_full_sha256:
                        os.lseek(fd, 0, os.SEEK_SET)
                        full_hasher = hashlib.sha256()
                        while True:
                            blk = os.read(fd, 262144)
                            if not blk:
                                break
                            full_hasher.update(blk)
                        file_sha256 = full_hasher.hexdigest()

                    safe_offset = max(0, min(int(offset), total_bytes))
                    os.lseek(fd, safe_offset, os.SEEK_SET)
                    limit = max(0, int(max_bytes or self.max_file_size))
                    chunks: List[bytes] = []
                    remaining = limit
                    while remaining > 0:
                        blk = os.read(fd, min(remaining, 262144))
                        if not blk:
                            break
                        chunks.append(blk)
                        remaining -= len(blk)
                    data = b"".join(chunks)
                finally:
                    os.close(fd)
            finally:
                os.close(parent_fd)

            chunk_sha256 = hashlib.sha256(data).hexdigest()
            if not file_sha256:
                file_sha256 = chunk_sha256
            has_more = (safe_offset + len(data)) < total_bytes
            return {
                "success": True,
                "path": rel_str,
                "raw_bytes": data if binary else None,
                "content": "" if binary else data.decode("utf-8", errors="replace"),
                "size": len(data),
                "total_bytes": total_bytes,
                "source_stat": {"size": st.st_size, "mtime_ns": st.st_mtime_ns, "mode": stat.S_IMODE(st.st_mode)},
                "offset": safe_offset,
                "has_more": has_more,
                "next_offset": (safe_offset + len(data)) if has_more else None,
                "sha256": file_sha256,
                "chunk_sha256": chunk_sha256,
            }
        except WorkspaceSecurityError as exc:
            return {"success": False, "error": str(exc), "code": "PATH_CONFINEMENT_VIOLATION"}
        except FileNotFoundError:
            return {"success": False, "error": "File does not exist", "code": "ARTIFACT_MISSING"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _unlink_tree_dir_fd(self, dir_fd: int) -> None:
        dup_fd = os.dup(dir_fd)
        with os.scandir(dup_fd) as it:
            for entry in it:
                name = entry.name
                if name in (".", ".."):
                    continue
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                    sub_fd = os.open(
                        name,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=dir_fd,
                    )
                    try:
                        self._unlink_tree_dir_fd(sub_fd)
                    finally:
                        os.close(sub_fd)
                    os.rmdir(name, dir_fd=dir_fd)
                else:
                    os.unlink(name, dir_fd=dir_fd)

    def delete_file(self, filename: str) -> Dict[str, Any]:
        try:
            parts = self._parse_relative_parts(filename, allow_root=False)
            parent_fd, leaf, ancestors = self._walk_parent_dir_fd(parts, create_parents=False)
            try:
                try:
                    st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    return {"success": False, "error": "File does not exist"}

                if stat.S_ISLNK(st.st_mode):
                    raise WorkspaceSecurityError("Deleting symlinks is forbidden")
                if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
                    raise WorkspaceSecurityError("Deleting hardlinked file is forbidden")

                self._verify_ancestors_unchanged(ancestors)

                if stat.S_ISDIR(st.st_mode):
                    sub_fd = os.open(
                        leaf,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent_fd,
                    )
                    try:
                        self._unlink_tree_dir_fd(sub_fd)
                    finally:
                        os.close(sub_fd)
                    os.rmdir(leaf, dir_fd=parent_fd)
                else:
                    os.unlink(leaf, dir_fd=parent_fd)
                return {"success": True}
            finally:
                os.close(parent_fd)
        except WorkspaceSecurityError as exc:
            return {"success": False, "error": str(exc), "code": "PATH_CONFINEMENT_VIOLATION"}
        except FileNotFoundError:
            return {"success": False, "error": "File does not exist"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def list_files(self, directory: str = ".") -> Dict[str, Any]:
        try:
            parts = self._parse_relative_parts(directory, allow_root=True)
            if not parts:
                dir_fd = self._open_root_dir_fd()
                rel_prefix = ""
            else:
                parent_fd, leaf, ancestors = self._walk_parent_dir_fd(parts, create_parents=False)
                try:
                    self._verify_ancestors_unchanged(ancestors)
                    dir_fd = os.open(
                        leaf,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=parent_fd,
                    )
                except FileNotFoundError:
                    return {"success": False, "error": "Directory does not exist"}
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise WorkspaceSecurityError("Symlink or non-directory target forbidden") from exc
                    raise
                finally:
                    os.close(parent_fd)
                rel_prefix = "/".join(parts)

            files = []
            try:
                dup_fd = os.dup(dir_fd)
                with os.scandir(dup_fd) as it:
                    entries = sorted(list(it), key=lambda e: e.name)
                    for entry in entries:
                        st = os.stat(entry.name, dir_fd=dir_fd, follow_symlinks=False)
                        if stat.S_ISLNK(st.st_mode):
                            continue
                        is_dir = stat.S_ISDIR(st.st_mode)
                        rel_item = f"{rel_prefix}/{entry.name}".lstrip("/")
                        files.append(
                            {
                                "name": entry.name,
                                "path": rel_item,
                                "type": "directory" if is_dir else "file",
                                "size": st.st_size if stat.S_ISREG(st.st_mode) else 0,
                                "modified": st.st_mtime,
                            }
                        )
            finally:
                os.close(dir_fd)

            return {"success": True, "files": files}
        except WorkspaceSecurityError as exc:
            return {"success": False, "error": str(exc), "code": "PATH_CONFINEMENT_VIOLATION"}
        except FileNotFoundError:
            return {"success": False, "error": "Directory does not exist"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def save_artifact(
        self,
        engagement_id: str,
        artifact_id: str,
        content: bytes | str,
        extension: str = "txt",
    ) -> Dict[str, Any]:
        safe_eng = re.sub(r"[^A-Za-z0-9_\-]", "_", engagement_id) or "default"
        safe_art = re.sub(r"[^A-Za-z0-9_\-]", "_", artifact_id)
        safe_ext = re.sub(r"[^A-Za-z0-9]", "", extension) or "bin"
        rel_name = f"engagements/{safe_eng}/artifacts/{safe_art}.{safe_ext}"
        return self.create_file(rel_name, content, binary=isinstance(content, bytes))
