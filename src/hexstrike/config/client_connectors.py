"""Client-specific MCP configuration rendering with preservation of unrelated settings."""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import tomllib
import tempfile
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from hexstrike.transports.telemetry import controller_url


SUPPORTED_CLIENTS = (
    "claude-code",
    "claude-desktop",
    "codex",
    "cursor",
    "vscode",
    "vscode-portable",
    "gemini-cli",
    "antigravity",
)


def default_client_config_path(client: str, workspace_root: Optional[Path] = None) -> Path:
    home = Path.home()
    ws = workspace_root or Path.cwd()
    sys_name = platform.system().lower()

    if client == "claude-code":
        return home / ".claude.json"
    if client == "claude-desktop":
        if sys_name == "darwin":
            return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        if sys_name == "windows":
            appdata = Path(os.environ.get("APPDATA", str(home)))
            return appdata / "Claude" / "claude_desktop_config.json"
        return home / ".config" / "Claude" / "claude_desktop_config.json"
    if client == "codex":
        return home / ".codex" / "config.toml"
    if client == "cursor":
        return ws / ".cursor" / "mcp.json"
    if client == "vscode":
        return ws / ".vscode" / "mcp.json"
    if client == "vscode-portable":
        return ws / ".mcp.json"
    if client == "gemini-cli":
        return ws / ".gemini" / "settings.json"
    if client == "antigravity":
        return home / ".gemini" / "antigravity" / "mcp_config.json"
    raise ValueError(f"Unsupported client '{client}'. Supported: {SUPPORTED_CLIENTS}")


def build_server_entry(
    client: str,
    python_executable: Optional[str] = None,
    mcp_script_path: Optional[str] = None,
    worker_target: str = "local",
    state_dir: Optional[str] = None,
    topology: str = "local",
    ssh_controller_host: Optional[str] = None,
    remote_http_url: Optional[str] = None,
    remote_python: str = "python3",
    remote_state_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build a client MCP server configuration entry supporting three explicit operating topologies:
      1. `local` (default): Local MCP controller process; optional `--worker <host>` dispatches
         tool subprocesses over SSH while controller state/TUI remain local.
      2. `ssh-controller`: Server-hosted MCP controller invoked over SSH stdio (`ssh -T <host> ...`)
         sharing `remote_state_dir` directly with a server-side `hexstrike tui --state-dir <remote_state_dir>`.
      3. `remote-http`: Server-hosted MCP controller over authenticated Streamable HTTP/SSE
         sharing `remote_state_dir` with the server-side TUI.
    """
    effective_topology = topology
    if ssh_controller_host:
        effective_topology = "ssh-controller"
    elif remote_http_url:
        effective_topology = "remote-http"

    if effective_topology == "remote-http":
        if not remote_http_url:
            raise ValueError("remote_http_url is required when topology='remote-http'")
        controller_url(remote_http_url)
        if client == "codex":
            return {"url": remote_http_url, "bearer_token_env_var": "HEXSTRIKE_API_TOKEN"}
        if client in ("claude-desktop", "antigravity"):
            raise ValueError(f"Use local or SSH stdio for {client}; HTTP credential configuration is not supported by this connector")
        variable = "${env:HEXSTRIKE_API_TOKEN}" if client in ("cursor", "vscode") else "${HEXSTRIKE_API_TOKEN}"
        entry: Dict[str, Any] = {
            "httpUrl" if client == "gemini-cli" else "url": remote_http_url,
            "headers": {"Authorization": f"Bearer {variable}"},
        }
        if client in ("vscode", "vscode-portable", "claude-code"):
            entry["type"] = "http"
        return entry

    if effective_topology == "ssh-controller":
        if not ssh_controller_host:
            raise ValueError("ssh_controller_host is required when topology='ssh-controller'")
        if not re.fullmatch(r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9_][A-Za-z0-9_.:-]*", ssh_controller_host):
            raise ValueError("SSH controller must be a host or user@host, without options or shell syntax")
        remote_args = [remote_python, "-m", "hexstrike.transports.mcp_stdio", "--transport", "stdio"]
        if remote_state_dir:
            remote_args.extend(["--state-dir", remote_state_dir])
        if worker_target and worker_target != "local":
            remote_args.extend(["--worker", worker_target])
        if any("\x00" in arg or "\n" in arg for arg in remote_args):
            raise ValueError("Remote command arguments must not contain NUL or newline characters")
        ssh_args = ["-T", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", ssh_controller_host]
        ssh_args.extend(shlex.quote(arg) for arg in remote_args)
        if client == "vscode":
            return {
                "type": "stdio",
                "command": "ssh",
                "args": ssh_args,
            }
        return {
            "command": "ssh",
            "args": ssh_args,
        }

    py_exe = python_executable or sys.executable
    if mcp_script_path:
        args = [str(Path(mcp_script_path).resolve()), "--transport", "stdio"]
    else:
        args = ["-m", "hexstrike.transports.mcp_stdio", "--transport", "stdio"]

    if worker_target and worker_target != "local":
        args.extend(["--worker", worker_target])
    if state_dir:
        args.extend(["--state-dir", str(Path(state_dir).resolve())])

    if client == "vscode":
        return {
            "type": "stdio",
            "command": py_exe,
            "args": args,
        }
    return {
        "command": py_exe,
        "args": args,
    }


def _render_codex_toml_entry(server_name: str, entry: Dict[str, Any]) -> str:
    if "url" in entry:
        url_escaped = json.dumps(entry["url"])
        return (
            f"\n[mcp_servers.{server_name}]\n"
            f"url = {url_escaped}\n"
            f"bearer_token_env_var = {json.dumps(entry['bearer_token_env_var'])}\n"
        )
    cmd_escaped = json.dumps(entry["command"])
    args_escaped = json.dumps(entry["args"])
    return (
        f"\n[mcp_servers.{server_name}]\n"
        f"command = {cmd_escaped}\n"
        f"args = {args_escaped}\n"
    )


def _write_config(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class ClientConfigManager:
    """Safely connects, disconnects, previews, and rolls back client MCP configs."""

    def __init__(self, server_name: str = "hexstrike-ai") -> None:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", server_name):
            raise ValueError("Server name must contain only letters, numbers, underscores, and hyphens")
        self.server_name = server_name

    def connect(
        self,
        client: str,
        config_path: Optional[str | Path] = None,
        python_executable: Optional[str] = None,
        mcp_script_path: Optional[str] = None,
        worker_target: str = "local",
        state_dir: Optional[str] = None,
        topology: str = "local",
        ssh_controller_host: Optional[str] = None,
        remote_http_url: Optional[str] = None,
        remote_python: str = "python3",
        remote_state_dir: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        if client not in SUPPORTED_CLIENTS:
            raise ValueError(f"Unsupported client '{client}'. Choose from {SUPPORTED_CLIENTS}")

        target_path = Path(config_path) if config_path else default_client_config_path(client)
        entry = build_server_entry(
            client=client,
            python_executable=python_executable,
            mcp_script_path=mcp_script_path,
            worker_target=worker_target,
            state_dir=state_dir,
            topology=topology,
            ssh_controller_host=ssh_controller_host,
            remote_http_url=remote_http_url,
            remote_python=remote_python,
            remote_state_dir=remote_state_dir,
        )

        effective_topology = (
            "ssh-controller"
            if ssh_controller_host or topology == "ssh-controller"
            else ("remote-http" if remote_http_url or topology == "remote-http" else "local")
        )
        state_option = f" --state-dir {shlex.quote(remote_state_dir)}" if remote_state_dir else ""
        if effective_topology == "ssh-controller":
            tui_guidance = f"Run on {ssh_controller_host}: hexstrike{state_option} tui"
            controller_host = ssh_controller_host
        elif effective_topology == "remote-http":
            tui_guidance = (
                f"Run on server: hexstrike{state_option} tui "
                f"(or locally: hexstrike tui --remote-url {shlex.quote(controller_url(remote_http_url))})"
            )
            controller_host = remote_http_url
        else:
            st_hint = str(Path(state_dir).resolve()) if state_dir else "<default-state-dir>"
            tui_guidance = f"Run locally: hexstrike --state-dir {shlex.quote(st_hint)} tui"
            controller_host = "local"

        backup_path: Optional[Path] = None
        if client == "codex" or target_path.suffix == ".toml":
            existing_text = target_path.read_text(encoding="utf-8") if target_path.exists() else ""
            if existing_text.strip():
                tomllib.loads(existing_text)
            cleaned = self._strip_codex_section(existing_text, self.server_name)
            new_text = cleaned.rstrip() + _render_codex_toml_entry(self.server_name, entry)
            tomllib.loads(new_text)
            if not dry_run:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                if target_path.exists():
                    backup_path = target_path.with_suffix(target_path.suffix + ".hexstrike.bak")
                    shutil.copy2(target_path, backup_path)
                _write_config(target_path, new_text)
            return {
                "success": True,
                "client": client,
                "topology": effective_topology,
                "controller_host": controller_host,
                "tui_guidance": tui_guidance,
                "config_path": str(target_path),
                "backup_path": str(backup_path) if backup_path else None,
                "dry_run": dry_run,
                "entry": entry,
            }

        # JSON-based client configs
        top_key = "servers" if client == "vscode" else "mcpServers"
        doc: Dict[str, Any] = {}
        if target_path.exists():
            raw = target_path.read_text(encoding="utf-8").strip()
            if raw:
                doc = json.loads(raw)
                if not isinstance(doc, dict):
                    raise ValueError(f"Existing config at {target_path} is not a JSON object")

        if top_key not in doc or not isinstance(doc[top_key], dict):
            doc[top_key] = {}

        doc[top_key][self.server_name] = entry
        serialized = json.dumps(doc, indent=2) + "\n"

        if not dry_run:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if target_path.exists():
                backup_path = target_path.with_suffix(target_path.suffix + ".hexstrike.bak")
                shutil.copy2(target_path, backup_path)
            _write_config(target_path, serialized)

        return {
            "success": True,
            "client": client,
            "topology": effective_topology,
            "controller_host": controller_host,
            "tui_guidance": tui_guidance,
            "config_path": str(target_path),
            "backup_path": str(backup_path) if backup_path else None,
            "top_level_key": top_key,
            "dry_run": dry_run,
            "entry": entry,
        }

    def disconnect(
        self,
        client: str,
        config_path: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        target_path = Path(config_path) if config_path else default_client_config_path(client)
        if not target_path.exists():
            return {"success": True, "removed": False, "config_path": str(target_path)}

        if client == "codex" or target_path.suffix == ".toml":
            text = target_path.read_text(encoding="utf-8")
            updated = self._strip_codex_section(text, self.server_name)
            removed = updated != text
            _write_config(target_path, updated)
            return {"success": True, "removed": removed, "config_path": str(target_path)}

        top_key = "servers" if client == "vscode" else "mcpServers"
        doc = json.loads(target_path.read_text(encoding="utf-8"))
        removed = False
        if isinstance(doc, dict) and isinstance(doc.get(top_key), dict):
            if self.server_name in doc[top_key]:
                doc[top_key].pop(self.server_name, None)
                removed = True
                _write_config(target_path, json.dumps(doc, indent=2) + "\n")
        return {"success": True, "removed": removed, "config_path": str(target_path)}

    def disconnect_all(self, workspace_root: Optional[Path] = None) -> Dict[str, Any]:
        removed_clients: List[str] = []
        checked: List[str] = []
        failed: List[str] = []
        for client in SUPPORTED_CLIENTS:
            cfg_path = default_client_config_path(client, workspace_root=workspace_root)
            checked.append(client)
            if cfg_path.exists():
                try:
                    res = self.disconnect(client, config_path=cfg_path)
                    if res.get("removed"):
                        removed_clients.append(client)
                except (OSError, ValueError):
                    failed.append(client)
        return {"success": not failed, "checked_clients": checked, "removed_clients": removed_clients, "failed_clients": failed}

    def rollback(self, client: str, config_path: Optional[str | Path] = None) -> Dict[str, Any]:
        target_path = Path(config_path) if config_path else default_client_config_path(client)
        backup_path = target_path.with_suffix(target_path.suffix + ".hexstrike.bak")
        if not backup_path.exists():
            return {"success": False, "error": f"No backup found at {backup_path}"}
        shutil.copy2(backup_path, target_path)
        return {"success": True, "restored": str(target_path), "from_backup": str(backup_path)}

    @staticmethod
    def _strip_codex_section(toml_text: str, server_name: str) -> str:
        header = f"[mcp_servers.{server_name}]"
        lines = toml_text.splitlines()
        out: List[str] = []
        skipping = False
        for ln in lines:
            stripped = ln.strip()
            if stripped == header or stripped.startswith(f"[mcp_servers.{server_name}."):
                skipping = True
                continue
            if skipping and stripped.startswith("[") and stripped.endswith("]"):
                skipping = False
            if not skipping:
                out.append(ln)
        return "\n".join(out) + ("\n" if out else "")
