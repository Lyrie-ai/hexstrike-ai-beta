"""Command-line entrypoints for controller operation, monitoring, and maintenance."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from hexstrike import __version__
from hexstrike.adapters.catalog import CustomAdapterManifest
from hexstrike.application.services import HexStrikeRuntime, resolve_default_state_dir
from hexstrike.application.state import backup_state_dir, restore_state_dir, state_access
from hexstrike.browser.inspector import find_chromium_executable
from hexstrike.config.client_connectors import SUPPORTED_CLIENTS, ClientConfigManager
from hexstrike.execution.runner import SshWorkerBridge
from hexstrike.reporting.formatter import sanitize_terminal_text
from hexstrike.transports.telemetry import TelemetryClient, TelemetryError
from hexstrike.workspace.confined_fs import redact_secrets


CRIMSON_BANNER_ASCII = (
    "██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗\n"
    "██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝\n"
    "███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  \n"
    "██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  \n"
    "██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗\n"
    "╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝"
)


def _get_console() -> Console:
    no_color = bool(os.environ.get("NO_COLOR"))
    return Console(no_color=no_color, highlight=not no_color)


def _cmd_status(rt: HexStrikeRuntime, args: argparse.Namespace) -> int:
    data = rt.system_status(engagement_id=args.engagement)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    console = _get_console()
    console.print(f"[bold red]{CRIMSON_BANNER_ASCII}[/bold red]")
    eng = data["engagement"]
    caps = data["capabilities"]
    console.print(
        Panel(
            f"[bold white]Version:[/bold white] {data['version']}  |  "
            f"[bold white]Engagement:[/bold white] {eng['engagement_id']} ({eng['name']})\n"
            f"[bold white]Worker Target:[/bold white] [bold red]{eng['worker_target']}[/bold red]  |  "
            f"[bold white]Autonomous Mode:[/bold white] {'ENABLED' if eng['autonomous_mode'] else 'DISABLED'}\n"
            f"[bold white]Registered Capabilities:[/bold white] {caps['registered_capabilities']} "
            f"(Local Ready: {caps['available_local']}, Missing: {caps['missing_local']}, Incompatible: {caps['incompatible_local']})\n"
            f"[bold white]Active Jobs:[/bold white] {data['jobs']['running_count']}  |  "
            f"[bold white]Recorded Findings:[/bold white] {data['findings_count']}",
            title="[bold red]HexStrike Operational Status[/bold red]",
            border_style="red",
        )
    )
    return 0


def _cmd_doctor(rt: HexStrikeRuntime, args: argparse.Namespace) -> int:
    status = rt.system_status()
    caps = rt.capabilities_search(limit=100)["capabilities"]
    remote_probe: Optional[Dict[str, Any]] = None
    if args.remote_worker:
        bridge = SshWorkerBridge(ssh_target=args.remote_worker, runner=rt.runner)
        remote_probe = bridge.probe_worker()

    report = {
        "system": status["platform"],
        "version": status["version"],
        "workspace_root": status["workspace_root"],
        "capabilities_summary": status["capabilities"],
        "capabilities": caps,
        "remote_worker": remote_probe,
    }

    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    console = _get_console()
    tbl = Table(title="HexStrike Capability & Binary Diagnostics", border_style="red")
    tbl.add_column("Capability ID", style="bold white")
    tbl.add_column("Category", style="red")
    tbl.add_column("Binary", style="cyan")
    tbl.add_column("Local Status")
    for c in caps:
        st = c["status"]
        color = "green" if st == "enabled" else ("yellow" if st == "incompatible" else "dim")
        tbl.add_row(c["capability_id"], c["category"], str(c["binary_name"] or "builtin"), f"[{color}]{st}[/{color}]")
    console.print(tbl)

    if remote_probe is not None:
        console.print(
            Panel(
                json.dumps(remote_probe, indent=2),
                title=f"[bold red]Remote Worker Probe ({args.remote_worker})[/bold red]",
                border_style="red",
            )
        )
    return 0


def _cmd_watch(rt: Optional[HexStrikeRuntime], args: argparse.Namespace) -> int:
    console = _get_console()
    console.print(f"[bold red]{CRIMSON_BANNER_ASCII}[/bold red]")
    remote_url = getattr(args, "remote_url", None)
    api_token = getattr(args, "api_token", None) or os.environ.get("HEXSTRIKE_API_TOKEN")
    if remote_url:
        console.print(
            f"[bold red]Watching remote controller telemetry at {remote_url} for engagement '{args.engagement}'...[/bold red]"
        )
    else:
        console.print(
            f"[bold red]Watching live AI-client execution stream for engagement '{args.engagement}'...[/bold red]"
        )
    remote = TelemetryClient(remote_url, api_token) if remote_url else None
    last_seq = 0
    start = time.monotonic()
    try:
        while True:
            if remote_url:
                try:
                    snap = remote.snapshot(args.engagement, last_seq)
                except TelemetryError as exc:
                    console.print(f"Disconnected: {exc}", markup=False)
                    if args.once or (args.max_seconds and time.monotonic() - start >= args.max_seconds):
                        return 1
                    time.sleep(1.0)
                    continue
                events = snap.get("events", [])
            else:
                assert rt is not None
                events = rt.store.get_events(since_seq=last_seq, engagement_id=args.engagement, limit=100)
            for ev in events:
                last_seq = max(last_seq, int(ev["seq"]))
                ts = str(ev.get("created_at", ""))[11:19]
                lvl = str(ev.get("level", "INFO")).upper()
                msg = sanitize_terminal_text(str(ev.get("message", "")))
                console.print(f"[bold red][{ts}][/bold red] [{lvl}] {msg}")
            if args.once or (args.max_seconds and (time.monotonic() - start) >= args.max_seconds):
                break
            time.sleep(0.4)
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_tools(rt: HexStrikeRuntime, args: argparse.Namespace) -> int:
    sub = args.tools_action
    if sub == "discover":
        res = (rt.registry.discover_installed(query=args.query or "", offset=args.offset, limit=100)
               if args.installed else rt.capabilities_search(query=args.query or "", category=args.category, limit=100))
        print(json.dumps(res, indent=2))
        return 0
    if sub == "describe":
        res = rt.capabilities_describe([args.capability_id], probe_version=True)
        print(json.dumps(res, indent=2))
        return 0
    if sub == "scaffold":
        cid = args.capability_id
        bin_name = cid.split(".")[-1]
        scaffold = {
            "capability_id": cid,
            "name": f"Custom {bin_name} Adapter",
            "category": cid.split(".")[0],
            "binary_name": bin_name,
            "description": f"Declarative custom adapter for {bin_name}",
            "arg_template": ["{target}"],
            "parameters": {
                "target": {"type": "string", "description": "Target host or URL"},
            },
            "required": ["target"],
            "risk_level": "medium",
            "requires_network": True,
            "version": "1.0.0",
        }
        if args.output:
            Path(args.output).write_text(json.dumps(scaffold, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"success": True, "written_to": args.output}))
        else:
            print(json.dumps(scaffold, indent=2))
        return 0
    if sub == "validate":
        raw = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        manifest = CustomAdapterManifest.from_dict(raw)
        print(json.dumps({"success": True, "validated": manifest.to_dict()}, indent=2))
        return 0
    if sub == "install-adapter":
        raw = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        manifest = CustomAdapterManifest.from_dict(raw)
        adapter = rt.registry.register_custom_adapter(manifest)
        print(json.dumps({"success": True, "capability_id": adapter.descriptor.capability_id}, indent=2))
        return 0
    if sub == "enable":
        ok = rt.registry.enable_capability(args.capability_id)
        print(json.dumps({"success": ok, "capability_id": args.capability_id, "status": "enabled"}))
        return 0 if ok else 1
    if sub == "disable":
        ok = rt.registry.disable_capability(args.capability_id)
        print(json.dumps({"success": ok, "capability_id": args.capability_id, "status": "disabled"}))
        return 0 if ok else 1
    if sub == "quarantine":
        ok = rt.registry.quarantine_capability(args.capability_id)
        print(json.dumps({"success": ok, "capability_id": args.capability_id, "status": "quarantined"}))
        return 0 if ok else 1
    if sub == "remove":
        ok = rt.registry.remove_custom_capability(args.capability_id)
        print(json.dumps({"success": ok, "capability_id": args.capability_id, "removed": ok}))
        return 0 if ok else 1
    return 1


def _inspect_optional_components() -> Dict[str, Any]:
    components: Dict[str, Any] = {}
    for mod_name, extra_name in (
        ("mcp", "mcp"),
        ("textual", "tui"),
        ("playwright", "browser"),
        ("graphiti_core", "memory"),
    ):
        try:
            __import__(mod_name)
            components[extra_name] = {"installed": True, "module": mod_name}
        except ImportError:
            components[extra_name] = {"installed": False, "module": mod_name}
    chrome_bin = find_chromium_executable()
    components["chromium_binary"] = {
        "installed": chrome_bin is not None,
        "executable_path": chrome_bin,
    }
    return components


def _cmd_connect(args: argparse.Namespace) -> int:
    mgr = ClientConfigManager()
    res = mgr.connect(
        client=args.client,
        config_path=args.config_path,
        python_executable=args.python,
        mcp_script_path=args.mcp_script,
        worker_target=args.worker,
        state_dir=args.state_dir,
        topology=getattr(args, "topology", "local"),
        ssh_controller_host=getattr(args, "ssh_controller", None),
        remote_http_url=getattr(args, "remote_http_url", None),
        remote_python=getattr(args, "remote_python", "python3"),
        remote_state_dir=getattr(args, "remote_state_dir", None),
        dry_run=args.dry_run,
    )
    print(json.dumps(res, indent=2))
    return 0


def _cmd_disconnect(args: argparse.Namespace) -> int:
    mgr = ClientConfigManager()
    res = mgr.disconnect(client=args.client, config_path=args.config_path)
    print(json.dumps(res, indent=2))
    return 0


def _cmd_rollback(args: argparse.Namespace) -> int:
    if getattr(args, "state", False) or not getattr(args, "client", None):
        state_root = Path(args.state_dir).expanduser() if args.state_dir else resolve_default_state_dir()
        b_path = Path(args.backup_path) if getattr(args, "backup_path", None) else None
        res = restore_state_dir(state_root, backup_dir=b_path)
        print(json.dumps(res, indent=2))
        return 0 if res.get("success") else 1

    mgr = ClientConfigManager()
    res = mgr.rollback(client=args.client, config_path=args.config_path)
    print(json.dumps(res, indent=2))
    return 0 if res.get("success") else 1


def _cmd_backup(rt: HexStrikeRuntime, args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir) if getattr(args, "output_dir", None) else None
    res = backup_state_dir(rt.base_root, output_dir=out_dir)
    print(json.dumps(res, indent=2))
    return 0 if res.get("success") else 1


def _install_step(argv: List[str], timeout: int = 300) -> Dict[str, Any]:
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {"success": proc.returncode == 0, "returncode": proc.returncode,
                "error": redact_secrets(proc.stderr[-1000:]) if proc.returncode else None}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Installer timed out"}
    except OSError:
        return {"success": False, "error": "Installer could not be started"}


def _cmd_upgrade(rt: HexStrikeRuntime, args: argparse.Namespace) -> int:
    if not args.package_source:
        raise ValueError("Upgrade requires --package-source identifying the intended package")
    backup_res = backup_state_dir(rt.base_root)
    with state_access(rt.base_root, exclusive=True):
        result = _install_step([sys.executable, "-m", "pip", "install", "--upgrade", args.package_source])
        if result["success"]:
            result = _install_step([sys.executable, "-I", "-c",
                "from importlib.metadata import version; import hexstrike.cli.main; "
                "import hexstrike.transports.mcp_stdio; print(version('hexstrike-ai'))"])
    out = {"success": result["success"], "installation": result,
           "pre_upgrade_backup": backup_res["backup_dir"], "package_rollback_performed": False,
           "restart_required": True}
    if not result["success"]:
        out["error"] = "Upgrade failed. State snapshot retained; reinstall the previous package before restoring its state."
    print(json.dumps(out, indent=2))
    return 0 if out["success"] else 1


def _cmd_setup(rt: HexStrikeRuntime, args: argparse.Namespace) -> int:
    install_actions: Dict[str, Any] = {}
    if getattr(args, "install_extras", False):
        source = getattr(args, "package_source", None)
        if source is None:
            checkout = Path(__file__).resolve().parents[3]
            source = str(checkout) if (checkout / "pyproject.toml").exists() else None
        requirement = f"{source}[all]" if source else f"hexstrike-ai[all]=={__version__}"
        install_actions["pip_extras"] = _install_step([sys.executable, "-m", "pip", "install", requirement])
        if install_actions["pip_extras"]["success"]:
            install_actions["verify_extras"] = _install_step([sys.executable, "-I", "-c", "import mcp, textual, playwright, graphiti_core"])
    if getattr(args, "install_chromium", False) and all(a["success"] for a in install_actions.values()):
        install_actions["playwright_chromium"] = _install_step([sys.executable, "-m", "playwright", "install", "chromium"])
        if install_actions["playwright_chromium"]["success"]:
            install_actions["verify_chromium"] = _install_step([sys.executable, "-I", "-c",
                "from pathlib import Path; from playwright.sync_api import sync_playwright; "
                "p=sync_playwright().start(); assert Path(p.chromium.executable_path).is_file(); p.stop()"])
    if any(not action["success"] for action in install_actions.values()):
        print(json.dumps({"success": False, "install_actions": install_actions}))
        return 1

    if args.worker and args.worker != "local":
        rt.engagement_manage(action="configure", engagement_id="default", worker_target=args.worker)
    status = rt.system_status()
    out: Dict[str, Any] = {
        "success": True,
        "version": status["version"],
        "state_dir": str(rt.base_root),
        "workspace_dir": status["workspace_root"],
        "worker_target": status["engagement"]["worker_target"],
        "optional_components": _inspect_optional_components(),
        "capabilities": status["capabilities"],
    }
    if install_actions:
        out["install_actions"] = install_actions
    if args.client:
        mgr = ClientConfigManager()
        out["client_connection"] = mgr.connect(
            client=args.client,
            config_path=args.config_path,
            worker_target=args.worker or "local",
            state_dir=str(rt.base_root),
            topology=getattr(args, "topology", "local"),
            ssh_controller_host=getattr(args, "ssh_controller", None),
            remote_http_url=getattr(args, "remote_http_url", None),
            remote_state_dir=getattr(args, "remote_state_dir", str(rt.base_root)),
            dry_run=args.dry_run,
        )
    print(json.dumps(out, indent=2))
    return 0


def _cmd_uninstall(rt: HexStrikeRuntime, args: argparse.Namespace) -> int:
    rt.job_cancel(cancel_all=True)
    from hexstrike.application.state import _require_idle
    deadline = time.monotonic() + 10
    while True:
        try:
            _require_idle(rt.base_root)
            break
        except ValueError:
            if time.monotonic() >= deadline:
                raise ValueError("Some jobs or detached sessions have not stopped; state was retained")
            time.sleep(.1)
    archive_path: Optional[str] = None
    if getattr(args, "archive_to", None) and rt.base_root.exists():
        b_res = backup_state_dir(rt.base_root, output_dir=Path(args.archive_to))
        archive_path = b_res.get("backup_dir")

    disconnected_clients: List[str] = []
    if getattr(args, "disconnect_clients", False):
        mgr = ClientConfigManager()
        disc_res = mgr.disconnect_all()
        disconnected_clients = disc_res.get("removed_clients", [])
        if not disc_res["success"]:
            print(json.dumps({"success": False, "client_disconnection": disc_res, "archived_to": archive_path}))
            return 1

    purged_state = False
    if args.purge_data and rt.base_root.exists():
        with state_access(rt.base_root, exclusive=True):
            shutil.rmtree(rt.base_root)
        purged_state = True

    removed_package = False
    if getattr(args, "remove_package", False):
        result = _install_step([sys.executable, "-m", "pip", "uninstall", "-y", "hexstrike-ai"], timeout=120)
        removed_package = result["success"]
        if not removed_package:
            print(json.dumps({"success": False, "installation": result, "purged_engagement_data": purged_state, "archived_to": archive_path}))
            return 1

    print(
        json.dumps(
            {
                "success": True,
                "state_dir": str(rt.base_root),
                "archived_to": archive_path,
                "disconnected_clients": disconnected_clients,
                "purged_engagement_data": purged_state,
                "retained_evidence": not purged_state,
                "removed_package": removed_package,
            },
            indent=2,
        )
    )
    return 0


def _main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hexstrike", description="HexStrike AI MCP CLI & Live Telemetry Monitor")
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("HEXSTRIKE_STATE_DIR") or os.environ.get("HEXSTRIKE_HOME"),
        help="Persistent state directory (defaults to user state directory)",
    )
    sub = parser.add_subparsers(dest="command")

    p_secret = sub.add_parser("credential", help="Store an origin-bound HTTP credential; read JSON from stdin")
    p_secret.add_argument("name")
    p_execution_secret = sub.add_parser("execution-secret", help="Read an execution environment secret from stdin")
    p_execution_secret.add_argument("name")

    # tui
    p_tui = sub.add_parser("tui", help="Launch the terminal operations monitor")
    p_tui.add_argument("--engagement", default="default")
    p_tui.add_argument("--remote-url", default=None, help="Optional remote HTTP controller URL to poll")
    p_tui.add_argument("--api-token", default=None, help="Bearer token for remote HTTP controller")

    # watch
    p_watch = sub.add_parser("watch", help="Stream live AI-client tool execution & findings in terminal")
    p_watch.add_argument("--engagement", default="default")
    p_watch.add_argument("--remote-url", default=None, help="Optional remote HTTP controller URL to poll")
    p_watch.add_argument("--api-token", default=None, help="Bearer token for remote HTTP controller")
    p_watch.add_argument("--once", action="store_true", help="Print existing events and exit")
    p_watch.add_argument("--max-seconds", type=float, default=None)

    # status
    p_status = sub.add_parser("status", help="Show system, engagement, worker, and job status")
    p_status.add_argument("--engagement", default="default")
    p_status.add_argument("--json", action="store_true")

    # doctor
    p_doc = sub.add_parser("doctor", help="Run local and optional remote worker diagnostics")
    p_doc.add_argument("--remote-worker", default=None, help="Optional SSH worker target")
    p_doc.add_argument("--json", action="store_true")

    # setup, backup, upgrade & uninstall
    p_setup = sub.add_parser("setup", help="Guided setup for controller topology, worker, extras, and AI client")
    p_setup.add_argument("--worker", default="local")
    p_setup.add_argument("--topology", choices=["local", "ssh-controller", "remote-http"], default="local")
    p_setup.add_argument("--ssh-controller", default=None, help="SSH host running the server-hosted MCP controller")
    p_setup.add_argument("--remote-http-url", default=None, help="Authenticated remote MCP HTTP endpoint")
    p_setup.add_argument("--remote-state-dir", help="Override the remote account’s default state directory")
    p_setup.add_argument("--client", choices=SUPPORTED_CLIENTS, default=None)
    p_setup.add_argument("--config-path", default=None)
    p_setup.add_argument("--package-source", default=None, help="Local checkout or package for optional extras")
    p_setup.add_argument("--install-extras", action="store_true", help="Install optional Python extras")
    p_setup.add_argument("--install-chromium", action="store_true", help="Install Playwright Chromium binary")
    p_setup.add_argument("--dry-run", action="store_true")

    p_backup = sub.add_parser("backup", help="Create a transactional backup of state DBs and workspace artifacts")
    p_backup.add_argument("--output-dir", default=None)

    p_upg = sub.add_parser("upgrade", help="Backup state, optionally upgrade package, and verify schema")
    p_upg.add_argument("--package-source", default=None, help="Optional wheel/sdist or package spec to upgrade")
    p_upg.add_argument("--dry-run", action="store_true")

    p_uninst = sub.add_parser("uninstall", help="Stop active jobs, disconnect clients, and retain or purge state/package")
    p_uninst.add_argument("--purge-data", action="store_true", help="Delete state DB and engagement artifacts")
    p_uninst.add_argument("--archive-to", default=None, help="Backup state/evidence to directory before cleanup")
    p_uninst.add_argument("--disconnect-clients", action="store_true", help="Remove HexStrike from AI client configs")
    p_uninst.add_argument("--remove-package", action="store_true", help="Uninstall hexstrike-ai Python package via pip")

    # tools
    p_tools = sub.add_parser("tools", help="Discover, describe, scaffold, validate, or toggle tool adapters")
    t_sub = p_tools.add_subparsers(dest="tools_action", required=True)
    p_td = t_sub.add_parser("discover")
    p_td.add_argument("--query", default="")
    p_td.add_argument("--installed", action="store_true", help="Inventory installed PATH executables, including those without adapters")
    p_td.add_argument("--offset", type=int, default=0)
    p_td.add_argument("--category", default=None)

    p_tdesc = t_sub.add_parser("describe")
    p_tdesc.add_argument("capability_id")

    p_tscaf = t_sub.add_parser("scaffold")
    p_tscaf.add_argument("capability_id")
    p_tscaf.add_argument("--output", default=None)

    p_tval = t_sub.add_parser("validate")
    p_tval.add_argument("manifest")

    p_tinst = t_sub.add_parser("install-adapter")
    p_tinst.add_argument("manifest")

    p_ten = t_sub.add_parser("enable")
    p_ten.add_argument("capability_id")

    p_tdis = t_sub.add_parser("disable")
    p_tdis.add_argument("capability_id")

    p_tquar = t_sub.add_parser("quarantine")
    p_tquar.add_argument("capability_id")

    p_trem = t_sub.add_parser("remove")
    p_trem.add_argument("capability_id")

    # connect / disconnect / rollback
    p_conn = sub.add_parser("connect", help="Configure an AI client to connect to HexStrike MCP")
    p_conn.add_argument("client", choices=SUPPORTED_CLIENTS)
    p_conn.add_argument("--config-path", default=None)
    p_conn.add_argument("--python", default=None)
    p_conn.add_argument("--mcp-script", default=None)
    p_conn.add_argument("--worker", default="local")
    p_conn.add_argument("--topology", choices=["local", "ssh-controller", "remote-http"], default="local")
    p_conn.add_argument("--ssh-controller", default=None, help="SSH host running server-side controller + TUI")
    p_conn.add_argument("--remote-http-url", default=None, help="URL of remote authenticated HTTP MCP server")
    p_conn.add_argument("--remote-python", default="python3")
    p_conn.add_argument("--remote-state-dir", help="Override the remote account’s default state directory")
    p_conn.add_argument("--dry-run", action="store_true")

    p_disc = sub.add_parser("disconnect", help="Remove HexStrike MCP entry from an AI client config")
    p_disc.add_argument("client", choices=SUPPORTED_CLIENTS)
    p_disc.add_argument("--config-path", default=None)

    p_roll = sub.add_parser("rollback", help="Restore backed-up AI client config or application state snapshot")
    p_roll.add_argument("client", nargs="?", choices=SUPPORTED_CLIENTS, default=None)
    p_roll.add_argument("--config-path", default=None)
    p_roll.add_argument("--state", action="store_true", help="Rollback HexStrike state directory from backup")
    p_roll.add_argument("--backup-path", default=None, help="Explicit state backup directory to restore")

    p_server = sub.add_parser("server", help="Start or reopen the server dashboard using saved settings")
    p_server.add_argument("--configure", action="store_true", help="Configure remote access and authentication interactively")
    p_server.add_argument("--url", help="Public MCP URL, ending in /mcp")
    p_server.add_argument("--host", help="Listening address (default: loopback)")
    p_server.add_argument("--port", type=int)
    p_server.add_argument("--tls-cert")
    p_server.add_argument("--tls-key")
    p_server.add_argument("--tailscale", action="store_true", help="Set up HTTPS through an already connected Tailscale installation")
    server_action = p_server.add_mutually_exclusive_group()
    server_action.add_argument("--headless", action="store_true", help="Run in the foreground for a service manager")
    server_action.add_argument("--no-ui", action="store_true", help="Start in the background")
    server_action.add_argument("--restart", action="store_true", help="Restart an idle background server after an update")
    server_action.add_argument("--stop", action="store_true", help="Stop a background server started by this command")
    server_action.add_argument("--connection", action="store_true", help="Print client configuration including the auth token")
    p_server.add_argument("--client", choices=["cursor", "claude", "codex", "vscode"], default="cursor")

    # mcp
    p_mcp = sub.add_parser("mcp", help="Start the HexStrike MCP server")
    p_mcp.add_argument("--transport", choices=["stdio", "streamable-http", "sse"], default="stdio")
    p_mcp.add_argument("--worker", default=os.environ.get("HEXSTRIKE_WORKER", "local"))

    p_mcp.add_argument("--host", default="127.0.0.1")
    p_mcp.add_argument("--port", type=int, default=8000)
    p_mcp.add_argument("--allow-external-bind", action="store_true")
    p_mcp.add_argument("--allowed-host", action="append", default=[])
    p_mcp.add_argument("--tls-cert")
    p_mcp.add_argument("--tls-key")

    args = parser.parse_args(argv)
    cmd = args.command or "status"

    if cmd == "server":
        from hexstrike.cli.server import run_server
        return run_server(args)
    if cmd == "connect":
        return _cmd_connect(args)
    if cmd == "disconnect":
        return _cmd_disconnect(args)
    if cmd == "rollback":
        return _cmd_rollback(args)
    if cmd == "mcp":
        from hexstrike.transports.mcp_stdio import main as mcp_main

        mcp_argv = ["--transport", args.transport, "--worker", args.worker, "--host", args.host, "--port", str(args.port)]
        if args.allow_external_bind:
            mcp_argv.append("--allow-external-bind")
        for host in args.allowed_host:
            mcp_argv.extend(["--allowed-host", host])
        if args.tls_cert:
            mcp_argv.extend(["--tls-cert", args.tls_cert])
        if args.tls_key:
            mcp_argv.extend(["--tls-key", args.tls_key])
        if args.state_dir:
            mcp_argv.extend(["--state-dir", args.state_dir])
        return mcp_main(mcp_argv)

    if cmd == "watch" and getattr(args, "remote_url", None):
        return _cmd_watch(None, args)

    if cmd in ("setup", "upgrade") and args.dry_run:
        print(json.dumps({"success": True, "dry_run": True, "command": cmd, "package_source": getattr(args, "package_source", None)}))
        return 0
    rt = None if cmd == "tui" and args.remote_url else HexStrikeRuntime(state_dir=args.state_dir)
    if cmd == "tui":
        try:
            from hexstrike.tui.dashboard import HexStrikeMonitorApp
        except ImportError as exc:
            raise SystemExit(
                f"Textual is required for 'hexstrike tui' ({exc}). Install via: pip install 'hexstrike-ai[tui]'"
            ) from exc
        app = HexStrikeMonitorApp(
            runtime=None if getattr(args, "remote_url", None) else rt,
            engagement_id=args.engagement,
            remote_url=getattr(args, "remote_url", None),
            api_token=getattr(args, "api_token", None),
        )
        app.run()
        return 0
    if cmd == "execution-secret":
        from hexstrike.http.client import AuthenticationStore
        AuthenticationStore(rt.base_root).put_execution(args.name, sys.stdin.read(65537))
        print(json.dumps({"stored": args.name}))
        return 0
    if cmd == "credential":
        from hexstrike.http.client import AuthenticationStore
        AuthenticationStore(rt.base_root).put(args.name, json.load(sys.stdin))
        print(json.dumps({"stored": args.name}))
        return 0
    if cmd == "watch":
        return _cmd_watch(rt, args)
    if cmd == "doctor":
        return _cmd_doctor(rt, args)
    if cmd == "setup":
        return _cmd_setup(rt, args)
    if cmd == "backup":
        return _cmd_backup(rt, args)
    if cmd == "upgrade":
        return _cmd_upgrade(rt, args)
    if cmd == "uninstall":
        return _cmd_uninstall(rt, args)
    if cmd == "tools":
        with state_access(rt.base_root):
            return _cmd_tools(rt, args)

    if not hasattr(args, "engagement"):
        args.engagement = "default"
    if not hasattr(args, "json"):
        args.json = False
    return _cmd_status(rt, args)


def main(argv: Optional[List[str]] = None) -> int:
    try:
        return _main(argv)
    except subprocess.TimeoutExpired:
        print(json.dumps({"success": False, "error": "A setup command timed out; check its service or network connection"}))
        return 1
    except (ValueError, OSError) as exc:
        print(json.dumps({"success": False, "error": redact_secrets(str(exc))}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
