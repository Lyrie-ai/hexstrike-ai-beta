"""Coordinated state snapshots and replacement for idle controllers."""

from __future__ import annotations


import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from uuid import uuid4
from hexstrike.persistence import database_connection

from hexstrike import __version__


def _write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}-{uuid4().hex}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def _recover_restore(root: Path, journal: Path) -> None:
    stage = root.parent / json.loads(journal.read_text())["staging_directory"]
    if stage.parent != root.parent or not stage.name.startswith(f".{root.name}-restore-") or stage.is_symlink():
        raise ValueError("Invalid restore journal; manual recovery required")
    previous = stage / "previous"
    if not root.exists() and previous.is_dir() and not previous.is_symlink():
        previous.rename(root)
    if not root.is_dir():
        raise ValueError("Interrupted restore requires manual recovery")
    if stage.exists():
        shutil.rmtree(stage)
    journal.unlink()


@contextmanager
def state_access(root: Path, *, exclusive: bool = False):
    """Keep maintenance mutually exclusive with controller operations."""
    root = Path(root).expanduser()
    if root.is_symlink():
        raise ValueError("State directory must not be a symbolic link")
    root = root.resolve()
    root.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(root.parent / f".{root.name}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("State is busy; stop active operations before maintenance") from None
        journal = root.parent / f".{root.name}.restore.json"
        if journal.exists():
            if not exclusive:
                raise ValueError("Interrupted restore detected; run rollback --state to recover before starting the controller")
            _recover_restore(root, journal)
        yield
    finally:
        os.close(fd)


def state_operation(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        with state_access(self.base_root):
            info = self.base_root.stat()
            if (info.st_dev, info.st_ino) != self._state_identity:
                raise ValueError("State was restored; restart this controller before continuing")
            return method(self, *args, **kwargs)
    return guarded


def _copy_tree(source: Path, destination: Path) -> None:
    """Copy regular files using directory descriptors; never follow links."""
    def copy_dir(src_fd: int, dst: Path):
        dst.mkdir(mode=0o700)
        for name in os.listdir(src_fd):
            info = os.stat(name, dir_fd=src_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=src_fd)
                try:
                    copy_dir(child, dst / name)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=src_fd)
                with os.fdopen(fd, "rb") as src:
                    if not stat.S_ISREG(os.fstat(src.fileno()).st_mode) or os.fstat(src.fileno()).st_nlink != 1:
                        raise ValueError("Snapshot source must be a regular file with a single link")
                    out_fd = os.open(dst / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    with os.fdopen(out_fd, "wb") as out:
                        shutil.copyfileobj(src, out)
                        out.flush()
                        os.fsync(out.fileno())
            else:
                raise ValueError("Snapshots cannot contain symbolic links or special files")

    fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        copy_dir(fd, destination)
    finally:
        os.close(fd)


def _hashes(root: Path) -> dict[str, str]:
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.relative_to(root) != Path("backup_manifest.json"):
            with path.open("rb") as stream:
                result[str(path.relative_to(root))] = hashlib.file_digest(stream, "sha256").hexdigest()
    return result


def _require_idle(root: Path) -> None:
    db = root / "hexstrike.db"
    if not db.exists():
        return
    if db.is_symlink():
        raise ValueError("Database must not be a symbolic link")
    with database_connection(f"{db.as_uri()}?mode=ro", uri=True) as conn:
        active = conn.execute("SELECT count(*) FROM jobs WHERE state IN ('queued', 'running', 'cancelling')").fetchone()[0]
    if active:
        raise ValueError("Stop active jobs before backing up or restoring state")
    from hexstrike.execution.runner import is_pid_alive
    for category in ("environments", "browser_sessions"):
        for owner_file in (root / category).glob("*/*/owner.json"):
            owner = json.loads(owner_file.read_text())
            if is_pid_alive(owner["pid"], owner["created"]):
                raise ValueError("Stop detached execution and browser sessions before maintenance")


def backup_state_dir(state_root: Path, output_dir: Path | None = None) -> dict:
    with state_access(state_root, exclusive=True):
        root = state_root.resolve()
        _require_idle(root)
        parent = (output_dir or root.parent / f"{root.name}.backups").expanduser().resolve()
        if parent == root or root in parent.parents:
            raise ValueError("Backup destination must be outside the state directory")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        stage = Path(tempfile.mkdtemp(prefix=".snapshot-", dir=parent))
        snapshot = parent / f"backup_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}_{uuid4().hex}"
        try:
            # The maintenance lock prevents controller writers across both databases
            # and the workspace. SQLite's backup API also includes committed WAL data.
            for name in ("hexstrike.db", "hexstrike_memory.db", "http_auth.db"):
                source = root / name
                if source.is_symlink():
                    raise ValueError("Database must not be a symbolic link")
                if source.exists():
                    with database_connection(f"{source.as_uri()}?mode=ro", uri=True) as src:
                        with database_connection(stage / name) as dst:
                            src.backup(dst)
                    (stage / name).chmod(0o600)
            for name in ("workspace", "custom_adapters", "environments", "browser_sessions"):
                if (root / name).exists() or (root / name).is_symlink():
                    _copy_tree(root / name, stage / name)
            config = root / "research.json"
            if config.exists() or config.is_symlink():
                from hexstrike.workspace.confined_fs import ConfinedWorkspace
                read = ConfinedWorkspace(root).read_file("research.json", binary=True, max_bytes=1024 * 1024)
                if not read["success"] or read["has_more"]:
                    raise ValueError("Research configuration is unsafe or too large to back up")
                target = stage / "research.json"
                target.write_bytes(read["raw_bytes"])
                target.chmod(0o600)
            meta = {
                "format": 1, "version": __version__, "created_at": datetime.now(timezone.utc).isoformat(),
                "source_state_dir": str(root), "backup_dir": str(snapshot),
                "copied_items": sorted(p.name for p in stage.iterdir()), "sha256": _hashes(stage),
            }
            _write_json(stage / "backup_manifest.json", meta)
            stage.rename(snapshot)
            _write_json(parent / "latest_backup.json", meta)
            return {"success": True, **meta}
        finally:
            if stage.exists():
                shutil.rmtree(stage)


def restore_state_dir(state_root: Path, backup_dir: Path | None = None) -> dict:
    with state_access(state_root, exclusive=True):
        root = state_root.resolve()
        _require_idle(root)
        parent = root.parent / f"{root.name}.backups"
        if backup_dir is None:
            pointer = parent / "latest_backup.json"
            if not pointer.exists():
                return {"success": False, "error": "No state backup found"}
            backup_dir = Path(json.loads(pointer.read_text())["backup_dir"])
        backup_dir = Path(backup_dir).expanduser()
        if not backup_dir.is_dir():
            return {"success": False, "error": "Backup directory does not exist"}
        stage_parent = Path(tempfile.mkdtemp(prefix=f".{root.name}-restore-", dir=root.parent))
        stage = stage_parent / "state"
        previous = stage_parent / "previous"
        journal = root.parent / f".{root.name}.restore.json"
        try:
            _copy_tree(backup_dir, stage)
            meta = json.loads((stage / "backup_manifest.json").read_text())
            if meta.get("format") != 1 or meta.get("version") != __version__:
                raise ValueError("Snapshot format or application version is incompatible")
            if meta.get("sha256") != _hashes(stage):
                raise ValueError("Snapshot integrity check failed")
            allowed = {"hexstrike.db", "hexstrike_memory.db", "http_auth.db", "workspace", "custom_adapters", "environments", "browser_sessions", "research.json", "backup_manifest.json"}
            if any(p.name not in allowed for p in stage.iterdir()):
                raise ValueError("Snapshot contains unexpected state entries")
            for name in ("hexstrike.db", "hexstrike_memory.db", "http_auth.db"):
                if (stage / name).exists():
                    with database_connection(stage / name) as conn:
                        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                            raise ValueError("Snapshot database is corrupt")
            (stage / "backup_manifest.json").unlink()
            _write_json(journal, {"staging_directory": stage_parent.name})
            if root.exists():
                root.rename(previous)
            try:
                stage.rename(root)
            except BaseException:
                if previous.exists():
                    previous.rename(root)
                raise
            return {"success": True, "restored_state_dir": str(root), "from_backup": str(backup_dir), "restored_items": meta["copied_items"]}
        finally:
            # If recovery itself failed, preserve the previous state for the operator.
            if previous.exists() and not root.exists():
                pass
            else:
                shutil.rmtree(stage_parent)
                journal.unlink(missing_ok=True)
