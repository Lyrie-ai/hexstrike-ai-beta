"""Behavioral regression checks using isolated local fixtures."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

import jwt
import pytest

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.browser.inspector import find_chromium_executable
from hexstrike.domain.models import JobState, Principal
from hexstrike.execution.runner import ExecutionResult, is_pid_alive
from hexstrike.policy.engine import PolicyViolationError
from hexstrike.transports.mcp_stdio import create_hexstrike_mcp_server
from hexstrike.workspace.confined_fs import ConfinedWorkspace


SECRET = "review-fixture-only-not-a-real-secret-123456789"
JWT_SAMPLE = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."


def _bearer(subject: str) -> str:
    return jwt.encode(
        {
            "sub": subject,
            "iss": "https://auth.hexstrike.local",
            "aud": "hexstrike-api",
            "exp": int(time.time()) + 60,
        },
        SECRET,
        algorithm="HS256",
    )


async def _mcp_http_request(
    app: Any,
    payload: dict[str, Any],
    subject: str = "alice",
    session: bytes | None = None,
) -> tuple[int, dict[bytes, bytes], dict[str, Any]]:
    received = False
    messages: list[dict[str, Any]] = []
    body = json.dumps(payload).encode()

    async def receive() -> dict[str, Any]:
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.Event().wait()
        return {}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    headers = [
        (b"host", b"127.0.0.1:8000"),
        (b"content-type", b"application/json"),
        (b"accept", b"application/json, text/event-stream"),
        (b"mcp-protocol-version", b"2025-11-25"),
        (b"authorization", ("Bearer " + _bearer(subject)).encode()),
    ]
    if session:
        headers.append((b"mcp-session-id", session))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "server": ("127.0.0.1", 8000),
        "client": ("127.0.0.1", 12345),
        "headers": headers,
    }
    await asyncio.wait_for(app(scope, receive, send), timeout=5)
    start = next(m for m in messages if m["type"] == "http.response.start")
    raw = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), json.loads(raw) if raw else {}


def _tool_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": args}}


@pytest.mark.parametrize("legacy_ceiling", ["passive", "high"])
def test_legacy_risk_ceiling_does_not_block_execution(tmp_path, legacy_ceiling):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.engagement_manage(action="update", max_risk_level=legacy_ceiling)
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(capability_id="execution.sandbox", operation="backends")
    assert result["success"], result
    assert result["job"]["state"] == "completed"
    manifest = {
        "capability_id": "custom.risk_fixture", "name": "Local output fixture", "category": "local",
        "binary_name": "python3", "description": "Print a known fixture string",
        "arg_template": ["-c", "print('risk-metadata-only')"], "parameters": {}, "required": [],
        "risk_level": "critical", "requires_network": False,
    }
    installed = rt.job_start(capability_id="tools.adapters", operation="install",
                             arguments={"manifest": json.dumps(manifest)})
    assert installed["success"], installed
    try:
        executed = rt.job_start(capability_id="custom.risk_fixture", operation="run")
        assert executed["success"], executed
        assert executed["job"]["structured_output"]["lines"] == ["risk-metadata-only"]
    finally:
        rt.job_start(capability_id="tools.adapters", operation="remove",
                     arguments={"capability_id": "custom.risk_fixture"})


def test_http_cli_accepts_default_https_authority_and_rejects_foreign_hosts(tmp_path, monkeypatch):
    from starlette.testclient import TestClient
    from hexstrike.transports.mcp_stdio import main

    captured = {}
    monkeypatch.setenv("HEXSTRIKE_API_TOKEN", SECRET)
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: captured.update(app=app))
    main(["--transport", "streamable-http", "--state-dir", str(tmp_path),
          "--allowed-host", "assessment.example.org"])
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "https-regression", "version": "1"}}}
    with TestClient(captured["app"], base_url="https://assessment.example.org") as client:
        for authority in ("assessment.example.org", "assessment.example.org:443", "assessment.example.org:8443"):
            headers = {"Authorization": "Bearer " + SECRET, "Accept": "application/json, text/event-stream",
                       "Host": authority, "Origin": "https://" + authority}
            response = client.post("/mcp", headers=headers, json=request)
            assert response.status_code == 200, response.text
            assert "serverInfo" in response.text
        for header, value in (("Host", "assessment.example.org.attacker.invalid"),
                              ("Origin", "https://attacker.invalid")):
            headers = {"Authorization": "Bearer " + SECRET, "Accept": "application/json, text/event-stream",
                       "Host": "assessment.example.org"}
            headers[header] = value
            assert client.post("/mcp", headers=headers, json=request).status_code == 403


def test_status_does_not_disclose_other_users_engagement(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.engagement_manage(
        action="create",
        engagement_id="private-alice",
        name="PRIVATE_REVIEW_MARKER",
        principal=Principal("alice", "Alice"),
    )
    app = create_hexstrike_mcp_server(rt, jwt_secret=SECRET).streamable_http_app(
        stateless_http=True, json_response=True
    )

    async def check() -> None:
        async with app.router.lifespan_context(app):
            status, _, result = await _mcp_http_request(
                app,
                _tool_call("system_status", {"engagement_id": "private-alice"}),
                "bob",
            )
            assert "PRIVATE_REVIEW_MARKER" not in json.dumps(result), (status, result)

            # Legitimate control: Alice CAN view her own engagement status
            status_alice, _, result_alice = await _mcp_http_request(
                app,
                _tool_call("system_status", {"engagement_id": "private-alice"}),
                "alice",
            )
            assert status_alice == 200
            assert "PRIVATE_REVIEW_MARKER" in json.dumps(result_alice)

    asyncio.run(check())


def test_stateful_mcp_session_cannot_reuse_initial_users_identity(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    app = create_hexstrike_mcp_server(rt, jwt_secret=SECRET).streamable_http_app(json_response=True)

    async def check() -> None:
        async with app.router.lifespan_context(app):
            status, headers, init = await _mcp_http_request(
                app,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "review", "version": "1"},
                    },
                },
            )
            assert status == 200, init
            session = headers[b"mcp-session-id"]
            await _mcp_http_request(app, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session=session)
            status, _, result = await _mcp_http_request(
                app,
                _tool_call("engagement_manage", {"action": "create", "engagement_id": "created-by-bob"}),
                "bob",
                session,
            )
            eng = rt.store.get_engagement("created-by-bob")
            assert eng is None or eng.owner_principal_id == "bob", (status, result, eng.owner_principal_id)

    asyncio.run(check())


def test_failed_parent_race_does_not_create_external_file(tmp_path: Path) -> None:
    ws = ConfinedWorkspace(tmp_path / "workspace")
    parent = ws.base_dir / "parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    real_open = os.open

    def race(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(path).name == "newfile":
            parent.rename(ws.base_dir / "parked")
            parent.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    with patch("hexstrike.workspace.confined_fs.os.open", side_effect=race):
        result = ws.create_file("parent/newfile", "fixture")
    assert result["success"] is False
    assert not (outside / "newfile").exists(), result


def test_delete_parent_race_does_not_delete_external_file(tmp_path: Path) -> None:
    ws = ConfinedWorkspace(tmp_path / "workspace")
    parent = ws.base_dir / "parent"
    parent.mkdir()
    (parent / "sentinel").write_text("inside")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("outside")
    real_unlink = Path.unlink

    def race(path: Path, *args: Any, **kwargs: Any) -> None:
        if path == parent / "sentinel":
            parent.rename(ws.base_dir / "parked")
            parent.symlink_to(outside, target_is_directory=True)
        return real_unlink(path, *args, **kwargs)

    with patch.object(Path, "unlink", race):
        result = ws.delete_file("parent/sentinel")
    assert sentinel.exists(), result


def test_cancel_all_does_not_signal_another_users_process(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    alice = Principal("alice", "Alice")
    rt.engagement_manage(action="create", engagement_id="alice-private", principal=alice)
    res = rt.job_start(
        capability_id="api.jwt_analyzer",
        operation="analyze",
        arguments={"token": JWT_SAMPLE},
        engagement_id="alice-private",
        principal=alice,
    )
    job = rt.store.get_job(res["job"]["job_id"])
    job.state = JobState.RUNNING
    rt.store.save_job(job)
    rt.runner._active_processes[job.job_id] = object()  # type: ignore[assignment]
    calls: list[str] = []
    with patch.object(rt.runner, "cancel", side_effect=lambda jid, **kw: calls.append(jid) or True):
        rt.job_cancel(cancel_all=True, principal=Principal("bob", "Bob"))
    rt.runner._active_processes.clear()
    assert calls == [], calls


def test_completed_job_cancel_does_not_signal_stale_pid_or_change_result(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(
        capability_id="api.jwt_analyzer",
        operation="analyze",
        arguments={"token": JWT_SAMPLE},
    )
    jid = result["job"]["job_id"]
    assert result["job"]["state"] == "completed"
    with patch.object(rt.runner, "cancel", return_value=False) as cancel:
        cancel_res = rt.job_cancel(job_id=jid)
    assert cancel.call_count == 0, "Terminal job dispatched cancellation (potential stale PID use)"
    assert cancel_res["already_finished"] is True
    assert rt.store.get_job(jid).state.value == "completed"

    # Also verify PID reuse guard: if expected_create_time differs from current process create_time, is_pid_alive is False
    assert is_pid_alive(os.getpid(), expected_create_time=1.0) is False


def test_revoked_engagement_queued_job_does_not_start(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path, max_workers=1)
    gate, executed = threading.Event(), []
    rt._executor.submit(gate.wait)
    adapter = rt.registry.get_adapter("web.http_inspect")

    def direct(*args: Any, **kwargs: Any) -> ExecutionResult:
        executed.append(True)
        return ExecutionResult(success=True, return_code=0, stdout="{}", stderr="", execution_time=0.01)

    try:
        with patch.object(adapter, "execute_direct", side_effect=direct):
            rt.job_start(
                capability_id="web.http_inspect",
                operation="probe",
                arguments={"url": "http://127.0.0.1/"},
                wait=False,
            )
            rt.engagement_manage(action="revoke")
            gate.set()
            rt._executor.shutdown(wait=True)
    finally:
        gate.set()
        rt._executor.shutdown(wait=True)
    assert executed == [], "Queued adapter executed after engagement revocation"


def test_remote_builtin_dispatches_to_selected_worker_and_executes_protocol(tmp_path: Path) -> None:
    calls = []

    class WorkerFixture:
        def execute_argv(self, argv: list[str], **kwargs: Any) -> ExecutionResult:
            calls.append(argv)
            import subprocess as _sp

            run_argv = list(argv)
            run_argv[0] = sys.executable
            cp = _sp.run(run_argv, capture_output=True, text=True, timeout=10)
            return ExecutionResult(
                success=(cp.returncode == 0),
                return_code=cp.returncode,
                stdout=cp.stdout,
                stderr=cp.stderr,
                execution_time=0.05,
                worker_target="fixture-worker",
                argv=list(argv),
            )

    class _FastServer(HTTPServer):
        def server_bind(self) -> None:
            import socket as _s

            _s.socket.bind(self.socket, self.server_address)
            self.server_address = self.socket.getsockname()[:2]
            self.server_name = "127.0.0.1"
            self.server_port = self.server_address[1]

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args: Any) -> None:
            pass

    srv = _FastServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        rt = HexStrikeRuntime(state_dir=tmp_path)
        rt.engagement_manage(action="configure", worker_target="fixture-worker")
        with patch.object(rt, "_get_ssh_bridge", return_value=WorkerFixture()):
            result = rt.job_start(
                capability_id="web.http_inspect",
                operation="probe",
                arguments={"url": f"http://127.0.0.1:{srv.server_port}/"},
            )
        assert calls, result["job"].get("error_message")
        assert result["success"] is True, result["job"].get("error_message")
        assert result["job"]["structured_output"].get("executed_on_remote_worker") is True
    finally:
        srv.shutdown()
        srv.server_close()


def test_functional_graphiti_persistence_search_restart_isolation_and_deletion(tmp_path: Path) -> None:
    # 1. Ingest episodes and relationships in runtime 1
    rt1 = HexStrikeRuntime(state_dir=tmp_path)
    assert rt1.memory.graphiti_adapter.graphiti_available is True

    rt1.memory.record_episode(
        engagement_id="eng_one",
        entity_type="validated_finding",
        subject="10.20.30.40:8443",
        content="Jenkins unauthenticated script console exposed on port 8443",
        relations=[("10.20.30.40", "exposes_service", "jenkins_script_console")],
    )
    rt1.memory.record_episode(
        engagement_id="eng_two",
        entity_type="validated_finding",
        subject="172.16.0.9:6379",
        content="Redis instance without requirepass authentication",
        relations=[("172.16.0.9", "exposes_service", "redis_unauthenticated")],
    )

    # 2. Restart a brand-new runtime against the same state_dir and query Graphiti directly
    rt2 = HexStrikeRuntime(state_dir=tmp_path)
    res_one = rt2.memory_query(query="Jenkins", engagement_id="eng_one")
    assert len(res_one["graphiti_facts"]) >= 1
    assert any("jenkins" in f["fact"].lower() for f in res_one["graphiti_facts"])
    assert "redis" not in json.dumps(res_one).lower()

    # 3. Verify Graphiti driver.execute_query returns persisted records (not empty placeholder)
    records, _, _ = asyncio.run(
        rt2.memory.graphiti_adapter.driver.execute_query("MATCH (n) RETURN n", group_id="eng_one")
    )
    assert len(records) >= 1

    # 4. Delete eng_one memories and verify Graphiti facts for eng_one are purged while eng_two remains intact
    rt2.memory.delete_engagement_memories("eng_one")
    res_one_after = rt2.memory_query(query="Jenkins", engagement_id="eng_one")
    assert res_one_after["graphiti_facts"] == []
    assert res_one_after["episodes"] == []

    res_two_after = rt2.memory_query(query="Redis", engagement_id="eng_two")
    assert len(res_two_after["graphiti_facts"]) >= 1


def test_playwright_har_screenshot_and_explicit_failure_reporting(tmp_path: Path) -> None:
    class _FastServer(HTTPServer):
        def server_bind(self) -> None:
            import socket as _s

            _s.socket.bind(self.socket, self.server_address)
            self.server_address = self.socket.getsockname()[:2]
            self.server_name = "127.0.0.1"
            self.server_port = self.server_address[1]

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"<html><head><title>Browser Artifact Test</title></head><body><h1>Hello</h1></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    srv = _FastServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        rt = HexStrikeRuntime(state_dir=tmp_path)
        url = f"http://127.0.0.1:{srv.server_port}/"

        # 1. When execute_js=True is requested but Chromium is missing, job MUST fail with actionable error (not silent static fallback)
        with patch("hexstrike.browser.inspector.find_chromium_executable", return_value=None):
            failed_js = rt.registry.get_adapter("browser.inspect").execute_direct(
                operation="inspect", arguments={"url": url, "execute_js": True},
            )
            assert failed_js.success is False
            assert "Chromium" in failed_js.stderr

        # 2. When Chromium is available, verify HAR and screenshot artifacts are persisted as Evidence
        if find_chromium_executable():
            ok_pw = rt.job_start(
                capability_id="browser.inspect",
                operation="inspect",
                arguments={
                    "url": url,
                    "execute_js": True,
                    "capture_har": True,
                    "capture_screenshot": True,
                },
            )
            assert ok_pw["success"] is True
            out = ok_pw["job"]["structured_output"]
            assert out["har_captured"] is True
            assert out["screenshot_captured"] is True
            ev_list = rt.store.list_evidence(job_id=ok_pw["job"]["job_id"])
            ev_kinds = {e.kind for e in ev_list}
            assert "har" in ev_kinds
            assert "screenshot" in ev_kinds
    finally:
        srv.shutdown()
        srv.server_close()


def test_option_value_pairs_and_workflow_capability_and_full_policy_controls(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)

    # 1. Full policy control through engagement_manage
    upd = rt.engagement_manage(
        action="update",
        engagement_id="default",
        max_risk_level="high",
        max_rate_per_minute=120,
        max_concurrency=4,
        max_timeout_seconds=600,
        allowed_protocols=["http", "https", "tcp"],
    )
    assert upd["success"] is True
    scope = upd["engagement"]["scope"]
    assert scope["max_risk_level"] == "high"
    assert scope["max_rate_per_minute"] == 120
    assert scope["max_concurrency"] == 4
    assert scope["max_timeout_seconds"] == 600

    # 2. Valid option-value pair in extra_flags (e.g. ["--top-ports", "25"]) is allowed
    plan = rt.action_prepare(
        capability_id="network.nmap",
        operation="scan",
        arguments={
            "target": "127.0.0.1",
            "extra_flags": ["--top-ports", "25", "--max-retries", "2"],
        },
    )
    assert plan["success"] is True
    assert "--top-ports" in plan["plan"]["argv_preview"]
    assert "25" in plan["plan"]["argv_preview"]

    # While an attempt to sneak a hostname as the value of --top-ports is rejected
    with pytest.raises(PolicyViolationError):
        rt.action_prepare(
            capability_id="network.nmap",
            operation="scan",
            arguments={
                "target": "127.0.0.1",
                "extra_flags": ["--top-ports", "evil.example.com"],
            },
        )
