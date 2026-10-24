"""Saved server settings, authenticated startup, and local connection handoff."""
from __future__ import annotations

import fcntl
import getpass
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

import psutil

from hexstrike.application.services import resolve_default_state_dir
from hexstrike.application.state import _write_json
from hexstrike.transports.telemetry import TelemetryClient, TelemetryError, controller_url


def server_addresses() -> list[str]:
    """Find active interface addresses, preferring the SSH or routed address."""
    addresses = set()
    stats = psutil.net_if_stats()
    for interface, entries in psutil.net_if_addrs().items():
        if interface not in stats or not stats[interface].isup:
            continue
        for entry in entries:
            if entry.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            address = ipaddress.ip_address(entry.address.split('%', 1)[0])
            if not (address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified):
                addresses.add(str(address))
    ordered = sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))
    ssh = os.environ.get('SSH_CONNECTION', '').split()
    preferred = ssh[2] if len(ssh) == 4 else None
    if preferred not in addresses:
        # UDP connect selects a route without sending data to the documentation address.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect(('192.0.2.1', 9))
                preferred = probe.getsockname()[0]
        except OSError:
            preferred = None
    if preferred in addresses:
        ordered.remove(preferred)
        ordered.insert(0, preferred)
    return ordered


def listener_address(host: str) -> str:
    if host not in ('0.0.0.0', '::'):
        return host
    version = 4 if host == '0.0.0.0' else 6
    return next((address for address in server_addresses() if ipaddress.ip_address(address).version == version),
                '127.0.0.1' if version == 4 else '::1')


def endpoint_url(host: str, port: int, tls: bool = False) -> str:
    authority = f'[{host}]' if ':' in host else host
    return f"{'https' if tls else 'http'}://{authority}:{port}/mcp"


def load_settings(root: Path) -> dict:
    path = root / "server.json"
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("server.json must be a regular file")
        if info.st_mode & 0o077:
            raise ValueError("server.json contains credentials; restrict its permissions to 0600")
        settings = json.load(stream)
    validate_settings(settings)
    return settings


def validate_settings(settings: dict) -> None:
    if not isinstance(settings, dict) or not {"url", "host", "port", "token"} <= settings.keys():
        raise ValueError("Server settings require url, host, port, and token")
    if not isinstance(settings["url"], str) or not isinstance(settings["host"], str):
        raise ValueError("Server URL and listening host must be strings")
    url = settings["url"]
    if url != controller_url(url) + "/mcp":
        raise ValueError("The connection URL must end in /mcp without a query or credentials")
    token = settings["token"]
    if not isinstance(token, str) or len(token) < 16 or len(token) > 4096 or not token.isascii() or any(c.isspace() for c in token):
        raise ValueError("Use an ASCII authentication token of at least 16 characters, without spaces")
    port = settings["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    host = settings["host"]
    if host != "localhost":
        ipaddress.ip_address(host)
    cert, key = settings.get("tls_cert"), settings.get("tls_key")
    if bool(cert) != bool(key):
        raise ValueError("Both a TLS certificate and its private key are required")
    if cert and not url.startswith("https://"):
        raise ValueError("A TLS listener requires an HTTPS connection URL")
    if settings.get('address_mode') not in (None, 'auto', 'local', 'manual'):
        raise ValueError("Unknown server address mode")
    for file in (cert, key):
        if file and not Path(file).is_file():
            raise ValueError("A configured TLS certificate or private key does not exist")


def configure(root: Path, args) -> dict:
    if root.is_symlink():
        raise ValueError("Server state must not be a symbolic link")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(root / "server-config.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        return _configure_locked(root, args)
    finally:
        os.close(fd)


def _configure_locked(root: Path, args) -> dict:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing = (root / "server.json").exists()
    changes = any(getattr(args, name, None) for name in ("url", "host", "port", "tls_cert", "tls_key", "configure", "tailscale", "auto", "local"))
    if existing and changes and _running_process(root)[0] is not None:
        raise ValueError("Stop the server before changing its connection settings")
    settings = load_settings(root) if existing else {
        "url": "http://127.0.0.1:8000/mcp", "host": "127.0.0.1", "port": 8000,
        "token": os.environ.get("HEXSTRIKE_API_TOKEN") or secrets.token_urlsafe(32),
        "address_mode": "auto",
    }
    if any(getattr(args, name, None) for name in ('auto', 'local')) and any(
            getattr(args, name, None) for name in ('url', 'host', 'tls_cert', 'tls_key', 'configure', 'tailscale')):
        raise ValueError("Use --auto or --local separately from explicit connection settings")
    if any(getattr(args, name, None) for name in ('url', 'host', 'tls_cert', 'tls_key', 'configure', 'tailscale')):
        settings['address_mode'] = 'manual'
    if getattr(args, 'auto', False) or getattr(args, 'local', False):
        settings['address_mode'] = 'local' if getattr(args, 'local', False) else 'auto'
        settings.pop('tls_cert', None)
        settings.pop('tls_key', None)
        settings['host'] = '127.0.0.1'
        settings['url'] = endpoint_url(settings['host'], settings['port'])
    previous_host, previous_port = settings['host'], settings['port']
    previous_url = urlsplit(settings['url'])
    direct_url = previous_url.hostname in (previous_host, '127.0.0.1' if previous_host == '0.0.0.0' else '::1' if previous_host == '::' else previous_host) and (previous_url.port or (443 if previous_url.scheme == 'https' else 80)) == previous_port
    for name in ("url", "host", "port", "tls_cert", "tls_key"):
        value = getattr(args, name, None)
        if value is not None:
            settings[name] = value
    if settings.get('address_mode') == 'auto' and _running_process(root)[0] is None:
        addresses = server_addresses()
        preferred = addresses[0] if addresses else '127.0.0.1'
        settings['host'] = ('0.0.0.0' if ipaddress.ip_address(preferred).version == 4 else '::') if addresses else '127.0.0.1'
        settings['url'] = endpoint_url(preferred, settings['port'])
    elif not getattr(args, 'url', None) and direct_url:
        settings['url'] = endpoint_url(listener_address(settings['host']), settings['port'], bool(settings.get('tls_cert')))
    if getattr(args, "configure", False):
        if not sys.stdin.isatty():
            raise ValueError("Interactive configuration needs a terminal; use --url and transport options for unattended setup")
        print("MCP setup: 1 This machine only, 2 Existing HTTPS proxy, 3 TLS certificate files, 4 Tailscale HTTPS (optional)")
        choice = input("Connection [1]: ").strip() or "1"
        if choice == "1":
            settings.update(url="http://127.0.0.1:8000/mcp", host="127.0.0.1", port=8000)
            settings.pop("tls_cert", None)
            settings.pop("tls_key", None)
        elif choice == "2":
            settings.update(url=input("Public HTTPS URL (ending /mcp): ").strip(), host="127.0.0.1", port=8000)
            if not settings["url"].startswith("https://"):
                raise ValueError("An HTTPS proxy requires an https:// URL")
            settings.pop("tls_cert", None)
            settings.pop("tls_key", None)
        elif choice == "3":
            settings.update(url=input("Public HTTPS URL (ending /mcp): ").strip(), host="0.0.0.0", port=8443,
                            tls_cert=str(Path(input("Certificate file: ").strip()).expanduser()),
                            tls_key=str(Path(input("Private key file: ").strip()).expanduser()))
        elif choice == "4":
            args.tailscale = True
            settings.update(host="127.0.0.1", port=8000)
            settings.pop("tls_cert", None)
            settings.pop("tls_key", None)
        else:
            raise ValueError("Choose a connection method from 1 to 4")
        token = getpass.getpass("Auth token (Enter to keep the generated/current token): ").strip()
        if token:
            settings["token"] = token
    if getattr(args, "tailscale", False):
        if not shutil.which("tailscale"):
            raise ValueError("Tailscale is not installed. Install it and sign in, or choose an existing HTTPS proxy/TLS files")
        result = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise ValueError("Tailscale is unavailable; sign in with tailscale up first")
        status = json.loads(result.stdout)
        dns = status.get("Self", {}).get("DNSName", "").rstrip(".")
        if status.get("BackendState") != "Running" or not dns:
            raise ValueError("Sign in to Tailscale and enable MagicDNS before using Tailscale HTTPS")
        settings.update(url=f"https://{dns}/mcp", host="127.0.0.1")
        settings.pop("tls_cert", None)
        settings.pop("tls_key", None)
        validate_settings(settings)
        target = f"http://127.0.0.1:{settings['port']}"
        probe = subprocess.run(["tailscale", "serve", "status", "--json"], capture_output=True, text=True, timeout=15)
        if probe.returncode:
            raise ValueError("Could not inspect existing Tailscale Serve configuration")
        served = json.loads(probe.stdout) or {}
        listener = served.get("TCP", {}).get("443")
        handlers = served.get("Web", {}).get(f"{dns}:443", {}).get("Handlers", {})
        if listener and not (listener == {"HTTPS": True} and handlers == {"/": {"Proxy": target}}):
            raise ValueError("Tailscale port 443 already serves another application; its configuration was left unchanged")
        result = subprocess.run(["tailscale", "serve", "--bg", "--https=443", target], text=True, timeout=60)
        if result.returncode:
            raise ValueError("Tailscale Serve could not start; check HTTPS enablement and the account's Serve permissions")
    validate_settings(settings)
    if not existing or settings != load_settings(root):
        _write_json(root / "server.json", settings)
    return settings


def connection_text(settings: dict, client: str = "cursor", reveal: bool = False) -> str:
    token = settings["token"] if reveal else "<reveal-token-in-server-ui>"
    url = settings["url"]
    if client == "claude":
        return "claude mcp add --transport http hexstrike " + shlex.quote(url) + " --header " + shlex.quote("Authorization: Bearer " + token)
    if client == "codex":
        return '[mcp_servers.hexstrike]\nurl = ' + json.dumps(url) + '\nhttp_headers = { Authorization = ' + json.dumps("Bearer " + token) + ' }\n'
    entry = {"url": url, "headers": {"Authorization": "Bearer " + token}}
    if client == "vscode":
        entry["type"] = "http"
    return json.dumps({"servers" if client == "vscode" else "mcpServers": {"hexstrike": entry}}, indent=2)


def _server_argv(root: Path, settings: dict) -> list[str]:
    args = ["--state-dir", str(root), "--transport", "streamable-http", "--host", settings["host"], "--port", str(settings["port"])]
    hostname = urlsplit(settings["url"]).hostname
    args += ["--allowed-host", hostname]
    host = settings['host']
    if host not in ('localhost', '127.0.0.1', '::1'):
        args += ['--allow-external-bind']
    if host in ('0.0.0.0', '::'):
        version = 4 if host == '0.0.0.0' else 6
        for address in server_addresses():
            if ipaddress.ip_address(address).version == version:
                args += ['--allowed-host', address]
    if settings.get("tls_cert"):
        args += ["--tls-cert", settings["tls_cert"], "--tls-key", settings["tls_key"]]
    return args


def _process_identity(pid: int):
    """Use Linux boot-relative process identity, unaffected by wall-clock corrections."""
    try:
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return {'boot_id': boot, 'start_ticks': fields[19]}
    except (OSError, IndexError):
        return None


def _running_process(root: Path):
    try:
        record = json.loads((root / "server-process.json").read_text())
        proc = psutil.Process(record["pid"])
        identity = record.get('identity')
        same_process = _process_identity(proc.pid) == identity if identity else proc.create_time() == record["created"]
        if same_process and "--headless" in proc.cmdline() and str(root) in proc.cmdline():
            return proc, record
    except (OSError, ValueError, KeyError, psutil.Error):
        pass
    return None, None


def run_headless(root: Path, settings: dict) -> int:
    from hexstrike.transports.mcp_stdio import main
    fd = os.open(root / "server.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("HexStrike is already running for this state directory") from None
        _write_json(root / "server-process.json", {"pid": os.getpid(), "created": psutil.Process().create_time(),
                                                   "identity": _process_identity(os.getpid()),
                                                   "managed": bool(os.environ.get("HEXSTRIKE_SERVICE_MANAGED"))})
        os.environ["HEXSTRIKE_API_TOKEN"] = settings["token"]
        return main(_server_argv(root, settings))
    finally:
        os.close(fd)


def monitor_connection(settings: dict) -> tuple[str, tuple[str, int] | None]:
    host = settings["host"]
    host = "127.0.0.1" if host == "0.0.0.0" else "::1" if host == "::" else host
    port = settings["port"]
    if settings.get("tls_cert"):
        hostname = urlsplit(settings["url"]).hostname
        authority = f"[{hostname}]" if ":" in hostname else hostname
        return f"https://{authority}:{port}/mcp", (host, port)
    authority = f"[{host}]" if ":" in host else host
    return f"http://{authority}:{port}/mcp", None


def ensure_running(root: Path, settings: dict) -> None:
    monitor_url, address = monitor_connection(settings)
    client = TelemetryClient(monitor_url, settings["token"], timeout=2, connect_address=address)
    try:
        client.snapshot("default")
        return
    except TelemetryError:
        pass
    proc, _ = _running_process(root)
    child = None
    if proc is None:
        log = root / "server.log"
        if log.exists() and log.stat().st_size > 5 * 1024 * 1024:
            log.replace(root / "server.log.1")
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "ab") as stream:
            env = dict(os.environ)
            env.pop("HEXSTRIKE_API_TOKEN", None)
            child = subprocess.Popen([sys.executable, "-m", "hexstrike.cli.main", "--state-dir", str(root), "server", "--headless"],
                                     stdin=subprocess.DEVNULL, stdout=stream, stderr=stream,
                                     start_new_session=True, close_fds=True, env=env)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if child and child.poll() is not None:
            raise ValueError(f"Server could not start; inspect {root / 'server.log'}")
        try:
            client.snapshot("default")
            return
        except TelemetryError:
            time.sleep(.25)
    raise ValueError(f"Local server is not reachable; check listener/TLS settings and {root / 'server.log'}")


def run_server(args) -> int:
    root = Path(args.state_dir).expanduser().resolve() if args.state_dir else resolve_default_state_dir().resolve()
    if args.stop or args.restart:
        proc, record = _running_process(root)
        if record and record.get("managed"):
            raise ValueError("This server is managed by a service; stop it with your service manager")
        if proc:
            if args.restart:
                from hexstrike.application.state import _require_idle
                _require_idle(root)
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=15)
            except psutil.TimeoutExpired:
                raise ValueError("Server is still draining; inspect its log before forcing shutdown") from None
        if args.stop:
            print("Server stopped" if proc else "No managed HexStrike process is running")
            return 0
    settings = configure(root, args)
    if args.headless:
        return run_headless(root, settings)
    if args.connection:
        print(connection_text(settings, args.client, reveal=True))
        return 0
    ensure_running(root, settings)
    if args.no_ui or not sys.stdin.isatty():
        print(f"HexStrike server ready.\nMCP URL: {settings['url']}\nOpen the dashboard: hexstrike server\nConnection settings: hexstrike server --connection")
        return 0
    from hexstrike.tui.dashboard import HexStrikeMonitorApp
    monitor_url, address = monitor_connection(settings)
    HexStrikeMonitorApp(remote_url=monitor_url, api_token=settings["token"],
                        connection_url=settings["url"], connect_address=address).run()
    return 0
