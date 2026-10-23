"""Local development checks: no real client config, SSH, package install, or secrets.

Only temporary files and loopback HTTP with a synthetic bearer marker are used.
"""
import asyncio
import io
import json
import shlex
import sqlite3
import socket
import subprocess
import sys
import time
import threading
import tomllib
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import pytest

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.cli.main import backup_state_dir, restore_state_dir, main as cli_main
from hexstrike.config.client_connectors import ClientConfigManager, build_server_entry
from hexstrike.tui.dashboard import HexStrikeMonitorApp
from hexstrike.application.state import state_access
from hexstrike.transports.telemetry import TelemetryClient, TelemetryError


def test_core_startup_defers_graph_sdk_until_memory_is_used(tmp_path):
    script = """
import sys
from hexstrike.application.services import HexStrikeRuntime
rt = HexStrikeRuntime(state_dir=sys.argv[1])
assert rt.system_status()['status'] == 'ready'
assert 'graphiti_core' not in sys.modules
result = rt.job_start(capability_id='api.jwt_analyzer', operation='analyze',
    arguments={'token': 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ.'})
assert result['success'], result
memory = rt.memory_query(engagement_id='default')
assert memory['episodes'], memory
if memory['graphiti_active']:
    assert 'graphiti_core' in sys.modules
"""
    result = subprocess.run(
        [sys.executable, '-c', script, str(tmp_path / 'state')],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_backup_does_not_follow_workspace_symlink_outside_state(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    outside = tmp_path / "private-outside"
    outside.mkdir()
    (outside / "synthetic-secret").write_text("LOCAL_FIXTURE_SECRET")
    (rt.workspace.base_dir / "outside-link").symlink_to(outside, target_is_directory=True)
    try:
        result = backup_state_dir(rt.base_root)
    except (OSError, ValueError):
        return
    copied = Path(result["backup_dir"]) / "workspace" / "outside-link" / "synthetic-secret"
    assert not copied.exists(), "Backup followed a workspace symlink and copied an external file"


def test_restore_removes_adapter_added_after_snapshot(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    adapters = rt.base_root / "custom_adapters"
    adapters.mkdir(exist_ok=True)
    (adapters / "original.json").write_text('{"original": true}')
    backup = backup_state_dir(rt.base_root)
    new = adapters / "post-backup.json"
    new.write_text('{"added_after_snapshot": true}')
    result = restore_state_dir(rt.base_root, Path(backup["backup_dir"]))
    assert result["success"], result
    assert not new.exists(), "Rollback retained post-snapshot adapter configuration"
    assert (adapters / "original.json").exists()


def test_backups_in_same_second_do_not_mutate_previous_snapshot(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    item = rt.workspace.base_dir / "evidence.txt"
    item.write_text("original")

    class FixedClock:
        @staticmethod
        def now(*args, **kwargs):
            return datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)

    with patch("hexstrike.application.state.datetime", FixedClock):
        first = backup_state_dir(rt.base_root)
        item.write_text("replacement")
        second = backup_state_dir(rt.base_root)
    assert (Path(first["backup_dir"]) / "workspace" / "evidence.txt").read_text() == "original", (
        "Second backup overwrote first snapshot", first["backup_dir"], second["backup_dir"])


def test_setup_reports_failed_dependency_install(tmp_path, capsys):
    failure = subprocess.CompletedProcess(["fixture-install"], 1, "", "synthetic install failure")
    with patch("hexstrike.cli.main.subprocess.run", return_value=failure):
        code = cli_main(["--state-dir", str(tmp_path), "setup", "--install-extras", "--install-chromium"])
    result = json.loads(capsys.readouterr().out)
    assert code != 0 and result["success"] is False, (code, result)


def test_codex_http_config_preserves_authentication_configuration(tmp_path):
    config = tmp_path / "codex.toml"
    result = ClientConfigManager().connect(client="codex", config_path=config,
        topology="remote-http", remote_http_url="https://fixture.invalid/mcp")
    assert result["entry"]["bearer_token_env_var"] == "HEXSTRIKE_API_TOKEN"
    server = tomllib.loads(config.read_text())["mcp_servers"]["hexstrike-ai"]
    assert any(k in server for k in ("bearer_token_env_var", "http_headers", "env_http_headers", "headers")), (
        "Rendered configuration discarded authentication", server)


def test_codex_reconnect_removes_stale_subtables_and_preserves_other_servers(tmp_path):
    config = tmp_path / "config.toml"
    config.write_text('[mcp_servers.hexstrike-ai]\nurl = "https://old.invalid/mcp"\n'
                      '[mcp_servers.hexstrike-ai.http_headers]\nX-Old = "old"\n'
                      '[mcp_servers.other]\ncommand = "other"\n')
    manager = ClientConfigManager()
    manager.connect("codex", config_path=config, topology="remote-http", remote_http_url="https://new.invalid/mcp")
    parsed = tomllib.loads(config.read_text())["mcp_servers"]
    assert parsed["other"] == {"command": "other"}
    assert parsed["hexstrike-ai"] == {"url": "https://new.invalid/mcp", "bearer_token_env_var": "HEXSTRIKE_API_TOKEN"}
    manager.disconnect("codex", config_path=config)
    assert tomllib.loads(config.read_text())["mcp_servers"] == {"other": {"command": "other"}}


def test_failed_config_replacement_preserves_existing_content(tmp_path):
    config = tmp_path / "config.toml"
    original = '[mcp_servers.other]\ncommand = "other"\n'
    config.write_text(original)
    with patch("hexstrike.config.client_connectors.os.replace", side_effect=OSError("replace failed")):
        with pytest.raises(OSError):
            ClientConfigManager().connect("codex", config_path=config)
    assert config.read_text() == original


def test_ssh_controller_preserves_remote_state_path_as_one_argument():
    path = "/srv/HexStrike State"
    entry = build_server_entry("cursor", topology="ssh-controller", ssh_controller_host="fixture-host", remote_state_dir=path)
    remote = entry["args"][entry["args"].index("fixture-host") + 1:]
    # SSH joins remote-command arguments for the remote shell; no SSH is executed.
    parsed = shlex.split(" ".join(remote))
    assert parsed[parsed.index("--state-dir") + 1:] == [path], parsed


def test_remote_monitor_stop_action_does_not_dereference_local_runtime():
    app = HexStrikeMonitorApp(remote_url="https://fixture.invalid")
    assert app.runtime is None
    # Current implementation fails before any network request.
    app.action_stop_all_jobs()


def test_remote_monitor_decodes_normal_telemetry_response():
    app = HexStrikeMonitorApp(remote_url="https://fixture.invalid")
    payload = {"success": True, "status": {}, "jobs": [], "findings": [], "events": []}
    with patch.object(app._remote._opener, "open", return_value=io.BytesIO(json.dumps(payload).encode())):
        assert app._fetch_remote_telemetry() == payload


def test_remote_monitor_does_not_forward_token_to_redirect_origin():
    received = []

    class Destination(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.headers.get("Authorization"))
            body = b'{"success": true, "status": {}, "jobs": [], "findings": [], "events": []}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{destination.server_port}/different-origin")
            self.end_headers()

        def log_message(self, *args):
            pass

    source = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (source, destination)]
    for t in threads:
        t.start()
    try:
        app = HexStrikeMonitorApp(remote_url=f"http://127.0.0.1:{source.server_port}", api_token="SYNTHETIC_BEARER")
        try:
            app._fetch_remote_telemetry()
        except (urllib.error.URLError, PermissionError, ValueError):
            pass
        assert all(v is None for v in received), "Bearer token was forwarded to another origin"
    finally:
        for s in (source, destination):
            s.shutdown()
            s.server_close()
        for t in threads:
            t.join(2)


def test_graph_count_is_not_silently_limited_to_candidate_window(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    for i in range(205):
        rt.memory.record_episode("default", "observation", f"subject-{i}", f"fact-{i}")
    with sqlite3.connect(rt.memory.graphiti_adapter.db_path) as db:
        expected = db.execute("SELECT count(*) FROM graphiti_entity_nodes WHERE group_id = 'default'").fetchone()[0]
    assert expected > 200
    try:
        rows, _, _ = asyncio.run(rt.memory.graphiti_adapter.driver.execute_query(
            "MATCH (n:Entity) WHERE n.group_id = 'default' RETURN count(*) AS total"))
    except (ValueError, NotImplementedError):
        return
    assert rows == [{"total": expected}], ("COUNT silently truncated candidate set", expected, rows)

    rows, _, _ = asyncio.run(rt.memory.graphiti_adapter.driver.execute_query(
        "MATCH (n:Entity) WHERE n.name = 'subject-0' RETURN n.name AS name LIMIT 1"))
    assert rows == [{"name": "subject-0"}]


def test_restore_rejects_tampering_without_changing_live_state(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    item = rt.workspace.base_dir / "evidence.txt"
    item.write_text("original")
    snapshot = Path(backup_state_dir(rt.base_root)["backup_dir"])
    (snapshot / "workspace" / "evidence.txt").write_text("tampered")
    item.write_text("current")
    with pytest.raises(ValueError, match="integrity"):
        restore_state_dir(rt.base_root, snapshot)
    assert item.read_text() == "current"


def test_restore_rejects_links_without_changing_live_state(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    snapshot = Path(backup_state_dir(rt.base_root)["backup_dir"])
    (snapshot / "workspace" / "link").symlink_to(tmp_path)
    with pytest.raises(ValueError, match="links"):
        restore_state_dir(rt.base_root, snapshot)
    assert rt.system_status()["status"] == "ready"


def test_failed_restore_reinstates_previous_directory(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    backup = backup_state_dir(rt.base_root)
    item = rt.workspace.base_dir / "current.txt"
    item.write_text("current")
    rename = Path.rename

    def fail_install(path, target):
        if path.name == "state" and "-restore-" in path.parent.name:
            raise OSError("simulated rename failure")
        return rename(path, target)

    with patch.object(Path, "rename", fail_install), pytest.raises(OSError):
        restore_state_dir(rt.base_root, Path(backup["backup_dir"]))
    assert item.read_text() == "current"


def test_snapshot_lock_blocks_writers_and_controller_startup(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    with state_access(rt.base_root, exclusive=True):
        with pytest.raises(ValueError, match="busy"):
            rt.engagement_manage(action="configure", name="unexpected")
        with pytest.raises(ValueError, match="busy"):
            HexStrikeRuntime(state_dir=rt.base_root)
    with state_access(rt.base_root):
        with pytest.raises(ValueError, match="busy"):
            backup_state_dir(rt.base_root)


def test_restore_invalidates_existing_controller(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    backup = backup_state_dir(rt.base_root)
    restore_state_dir(rt.base_root, Path(backup["backup_dir"]))
    with pytest.raises(ValueError, match="restart"):
        rt.system_status()
    assert HexStrikeRuntime(state_dir=rt.base_root).system_status()["status"] == "ready"


def test_interrupted_restore_does_not_create_empty_state(tmp_path):
    root = tmp_path / "state"
    HexStrikeRuntime(state_dir=root)
    snapshot = Path(backup_state_dir(root)["backup_dir"])
    stage = tmp_path / ".state-restore-fixture"
    stage.mkdir()
    root.rename(stage / "previous")
    (tmp_path / ".state.restore.json").write_text(json.dumps({"staging_directory": stage.name}))
    with pytest.raises(ValueError, match="Interrupted restore"):
        HexStrikeRuntime(state_dir=root)
    assert not root.exists()
    assert restore_state_dir(root, snapshot)["success"]
    assert HexStrikeRuntime(state_dir=root).system_status()["status"] == "ready"


def test_backup_rejects_hardlinked_external_file(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    outside = tmp_path / "outside.txt"
    outside.write_text("synthetic outside file")
    (rt.workspace.base_dir / "link.txt").hardlink_to(outside)
    with pytest.raises(ValueError, match="single link"):
        backup_state_dir(rt.base_root)
    assert outside.read_text() == "synthetic outside file"


def test_failed_backup_keeps_previous_snapshot_pointer(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    first = backup_state_dir(rt.base_root)
    pointer = Path(first["backup_dir"]).parent / "latest_backup.json"
    saved = pointer.read_bytes()
    with patch("hexstrike.application.state._copy_tree", side_effect=OSError("copy failed")):
        with pytest.raises(OSError):
            backup_state_dir(rt.base_root)
    assert pointer.read_bytes() == saved
    assert Path(first["backup_dir"]).exists()


def test_setup_dry_run_does_not_create_state_or_run_installer(tmp_path, capsys):
    state = tmp_path / "absent"
    with patch("hexstrike.cli.main.subprocess.run") as run:
        assert cli_main(["--state-dir", str(state), "setup", "--install-extras", "--dry-run"]) == 0
    assert not state.exists()
    run.assert_not_called()
    assert json.loads(capsys.readouterr().out)["dry_run"]


def test_uninstall_reports_package_failure(tmp_path, capsys):
    failure = subprocess.CompletedProcess([], 1, "", "package removal failed")
    with patch("hexstrike.cli.main.subprocess.run", return_value=failure):
        assert cli_main(["--state-dir", str(tmp_path), "uninstall", "--remove-package"]) == 1
    assert json.loads(capsys.readouterr().out)["success"] is False


@pytest.mark.parametrize("body", [b"not-json", b"[]", b'{"success":true}', b"x" * 1048577])
def test_monitor_rejects_invalid_or_oversized_responses(body):
    client = TelemetryClient("https://fixture.invalid", "synthetic-token")
    with patch.object(client._opener, "open", return_value=io.BytesIO(body)):
        with pytest.raises(TelemetryError):
            client.snapshot("default")


@pytest.mark.parametrize("path", ["/srv/HexStrike State", "/srv/it's a test", "/srv/$(literal);value"])
def test_ssh_command_preserves_quoted_paths(path):
    entry = build_server_entry("cursor", topology="ssh-controller", ssh_controller_host="fixture-host", remote_state_dir=path)
    remote = entry["args"][entry["args"].index("fixture-host") + 1:]
    assert shlex.split(" ".join(remote))[-1] == path


@pytest.mark.parametrize("transport", ["streamable-http", "sse"])
def test_real_http_mcp_job_is_visible_and_cancellable_in_remote_tui(tmp_path, transport):
    import httpx2 as httpx
    import psutil
    import uvicorn
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from mcp.client.sse import sse_client
    from textual.widgets import DataTable, Static
    from hexstrike.adapters.catalog import CustomAdapterManifest
    from hexstrike.transports.mcp_stdio import create_hexstrike_mcp_server

    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.registry.register_custom_adapter(CustomAdapterManifest(
        capability_id="fixture.wait", name="Wait fixture", category="fixture",
        binary_name="sleep", description="Local cancellation fixture", arg_template=["20"],
        parameters={}, required=[], requires_network=False,
    ))
    mcp = create_hexstrike_mcp_server(rt, api_token="synthetic-token")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    application = mcp.streamable_http_app() if transport == "streamable-http" else mcp.sse_app()
    server = uvicorn.Server(uvicorn.Config(application, log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started

    def payload(result):
        data = getattr(result, "structured_content", None)
        if not isinstance(data, dict):
            data = json.loads(result.content[0].text)
        return data.get("result", data)

    async def exercise():
        url = f"http://127.0.0.1:{port}/" + ("mcp" if transport == "streamable-http" else "sse")
        async with httpx.AsyncClient(headers={"Authorization": "Bearer synthetic-token"}) as http:
            connection = (streamable_http_client(url, http_client=http) if transport == "streamable-http"
                          else sse_client(url, headers={"Authorization": "Bearer synthetic-token"}))
            async with connection as (reader, writer):
                async with ClientSession(reader, writer) as session:
                    await session.initialize()
                    telemetry = (await http.get(f"http://127.0.0.1:{port}/api/v6/telemetry")).json()
                    assert telemetry['clients'], telemetry
                    client = telemetry['clients'][0]
                    assert client['peer'] == '127.0.0.1'
                    assert client['name'] and client['session_id'].startswith('client_')
                    assert client['transport'] == ('SSE' if transport == 'sse' else 'Streamable HTTP')
                    assert telemetry['server']['addresses']
                    inventory = (await http.get(f"http://127.0.0.1:{port}/api/v6/inventory?limit=2")).json()
                    assert len(inventory['executables']) == 2 and inventory['next_offset'] == 2
                    assert inventory['total'] > 2
                    result = payload(await session.call_tool("job_start", {
                        "capability_id": "fixture.wait", "operation": "run", "arguments": {}, "wait": False,
                    }))
                    assert result["success"], result
                    job_id = result["job"]["job_id"]
                    app = HexStrikeMonitorApp(remote_url=url, api_token="synthetic-token", poll_interval=0.05)
                    async with app.run_test(size=(120, 40)) as pilot:
                        for _ in range(60):
                            await pilot.pause(0.05)
                            table = app.query_one("#jobs-table", DataTable)
                            rows = [table.get_row_at(i) for i in range(table.row_count)]
                            job = rt.store.get_job(job_id)
                            if job.pid and any(r[0] == job_id and r[3] == "RUNNING" for r in rows):
                                break
                        else:
                            pytest.fail(f"Remote UI did not display running job: {rows}")
                        assert app.query_one("#tools-table", DataTable).row_count > 0
                        pid = job.pid
                        assert psutil.pid_exists(pid)
                        with pytest.raises(ValueError, match="busy"):
                            backup_state_dir(rt.base_root)
                        if transport == "sse":
                            stop_control = app.query_one("#action-stop")
                            await pilot.click(stop_control)
                        else:
                            await pilot.press("s")
                        for _ in range(60):
                            await pilot.pause(0.05)
                            rows = [table.get_row_at(i) for i in range(table.row_count)]
                            if any(r[0] == job_id and r[3] == "CANCELLED" for r in rows) and not psutil.pid_exists(pid):
                                break
                        else:
                            pytest.fail("Remote cancellation did not stop the child and update the UI")
                        assert "DISCONNECTED" not in str(app.query_one("#status-strip", Static).content)
                        app._remote.token = "invalid-fixture-token"
                        for _ in range(60):
                            await pilot.pause(.05)
                            if "DISCONNECTED" in str(app.query_one("#status-strip", Static).content):
                                break
                        else:
                            pytest.fail("Monitor did not display authentication loss")
                        assert table.row_count > 0
                        app._remote.token = "synthetic-token"
                        for _ in range(60):
                            await pilot.pause(.05)
                            if "DISCONNECTED" not in str(app.query_one("#status-strip", Static).content):
                                break
                        else:
                            pytest.fail("Monitor did not recover after authentication was restored")
            await asyncio.sleep(.1)
            telemetry = (await http.get(f"http://127.0.0.1:{port}/api/v6/telemetry")).json()
            assert telemetry['clients'][0]['state'] == 'closed', telemetry['clients']
            assert telemetry['clients'][0]['active_requests'] == 0

    try:
        asyncio.run(exercise())
    finally:
        rt.job_cancel(cancel_all=True)
        rt._executor.shutdown(wait=True)
        server.should_exit = True
        thread.join(5)
        sock.close()


def test_monitor_ignores_response_after_widgets_are_unmounted():
    app = HexStrikeMonitorApp(remote_url="https://fixture.invalid")
    app._render_snapshot({"status": {}, "jobs": [], "findings": [], "events": []})


def test_monitor_inventory_requires_auth_and_clients_are_principal_scoped(tmp_path):
    from starlette.testclient import TestClient
    from hexstrike.domain.models import Principal
    from hexstrike.transports.monitoring import MonitorState
    from hexstrike.transports.mcp_stdio import create_hexstrike_mcp_server
    rt = HexStrikeRuntime(state_dir=tmp_path)
    application = create_hexstrike_mcp_server(rt, api_token='fixture-token').streamable_http_app()
    with TestClient(application, base_url='http://localhost') as client:
        assert client.get('/api/v6/inventory').status_code == 401
        assert client.get('/api/v6/telemetry').status_code == 401
        response = client.get('/api/v6/inventory?limit=1', headers={'Authorization': 'Bearer fixture-token'})
        assert response.status_code == 200 and len(response.json()['executables']) == 1

    monitor = MonitorState(rt)
    async def exchange(owner, method='POST', status=200):
        payload = json.dumps({'method': 'initialize', 'params': {'clientInfo': {'name': 'fixture-client', 'version': '1'}}}).encode()
        async def receive():
            return {'type': 'http.request', 'body': payload, 'more_body': False}
        async def send(message):
            pass
        async def inner(scope, read, write):
            assert (await read())['body'] == payload
            await write({'type': 'http.response.start', 'status': status, 'headers': [(b'mcp-session-id', b'private-session-id')]})
            await write({'type': 'http.response.body', 'body': b'{}'})
        await monitor.observe(inner, {'path': '/mcp', 'type': 'http', 'method': method,
            'client': ('127.0.0.1', 1234), 'headers': []}, receive, send, Principal(owner, owner))
    asyncio.run(exchange('alice'))
    assert monitor.clients('bob') == []
    rows = monitor.clients('alice')
    assert len(rows) == 1 and rows[0]['name'] == 'fixture-client'
    assert 'private-session-id' not in json.dumps(rows)
    assert rows[0]['state'] == 'idle / last seen'
    asyncio.run(exchange('alice', 'DELETE'))
    assert monitor.clients('alice')[0]['state'] == 'closed'
    with patch('hexstrike.transports.monitoring.time.time', return_value=time.time()+301):
        assert monitor.clients('alice') == []
