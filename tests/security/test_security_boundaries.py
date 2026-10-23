"""Behavioral regression checks using isolated local fixtures."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from hexstrike.adapters.catalog import JwtAnalyzerAdapter
from hexstrike.application.services import HexStrikeRuntime
from hexstrike.browser.inspector import find_chromium_executable
from hexstrike.domain.models import Principal, ScopePolicy
from hexstrike.policy.engine import PolicyEngine, PolicyViolationError
from hexstrike.transports.http_server import create_http_app
from hexstrike.transports.mcp_stdio import create_hexstrike_mcp_server
from hexstrike.workflows.engine import WorkflowRunner
from hexstrike.workspace.confined_fs import ConfinedWorkspace


TOKEN = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."


def test_other_user_cannot_modify_owner_scope(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    alice = Principal("alice", "Alice", role="operator")
    bob = Principal("bob", "Bob", role="operator")
    rt.engagement_manage(
        action="create",
        engagement_id="lab",
        allowed_targets=["127.0.0.1"],
        allow_all_targets=False,
        principal=alice,
    )
    with pytest.raises(PolicyViolationError):
        rt.engagement_manage(
            action="update",
            engagement_id="lab",
            allowed_targets=[],
            allow_all_targets=True,
            principal=bob,
        )
    assert not rt.store.get_engagement("lab").scope.allow_all_targets

    # Legitimate control: Alice CAN broaden her own engagement scope via MCP
    updated = rt.engagement_manage(
        action="update",
        engagement_id="lab",
        allowed_targets=[],
        allow_all_targets=True,
        principal=alice,
    )
    assert updated["success"] is True
    assert rt.store.get_engagement("lab").scope.allow_all_targets is True


def test_other_principal_cannot_use_owner_plan_or_handles(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    owner, other = Principal("alice", "Alice"), Principal("bob", "Bob")
    rt.engagement_manage(action="create", engagement_id="private", principal=owner)
    plan = rt.action_prepare(
        "api.jwt_analyzer",
        "analyze",
        {"token": TOKEN},
        engagement_id="private",
        principal=owner,
    )
    with pytest.raises(PolicyViolationError):
        rt.job_start(plan_id=plan["plan"]["plan_id"], principal=other)

    # Unknown engagement ID is rejected rather than silently falling back to default
    with pytest.raises(PolicyViolationError) as exc_info:
        rt.action_prepare(
            "api.jwt_analyzer",
            "analyze",
            {"token": TOKEN},
            engagement_id="nonexistent_engagement",
            principal=owner,
        )
    assert exc_info.value.code == "ENGAGEMENT_NOT_FOUND"

    # Owner executes her own plan and reads evidence; other principal is denied
    owner_run = rt.job_start(plan_id=plan["plan"]["plan_id"], principal=owner)
    assert owner_run["success"] is True
    job_id = owner_run["job"]["job_id"]
    ev_id = owner_run["job"]["evidence_ids"][0]

    with pytest.raises(PolicyViolationError):
        rt.job_status(job_id=job_id, principal=other)
    with pytest.raises(PolicyViolationError):
        rt.evidence_read(evidence_id=ev_id, principal=other)
    with pytest.raises(PolicyViolationError):
        rt.memory_query(engagement_id="private", principal=other)


def test_persistent_engagement_revocation_blocks_subsequent_jobs(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    alice = Principal("alice", "Alice")
    rt.engagement_manage(action="create", engagement_id="temp_eng", principal=alice)
    plan = rt.action_prepare(
        "api.jwt_analyzer",
        "analyze",
        {"token": TOKEN},
        engagement_id="temp_eng",
        principal=alice,
    )
    rt.engagement_manage(action="revoke", engagement_id="temp_eng", principal=alice)

    with pytest.raises(PolicyViolationError) as exc_rev:
        rt.job_start(plan_id=plan["plan"]["plan_id"], principal=alice)
    assert exc_rev.value.code == "ENGAGEMENT_REVOKED"


def test_cidr_cannot_include_excluded_host() -> None:
    scope = ScopePolicy(
        allow_all_targets=False,
        allowed_targets=["192.0.2.0/24"],
        excluded_targets=["192.0.2.10"],
    )
    with pytest.raises(PolicyViolationError):
        PolicyEngine().evaluate_target("192.0.2.0/24", scope)

    # Legitimate control: A non-overlapping subnet inside 192.0.2.0/24 is permitted
    assert PolicyEngine().evaluate_target("192.0.2.128/25", scope).network is not None


def test_nmap_ports_must_match_engagement(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    eng = rt.store.get_engagement("default")
    eng.scope = ScopePolicy(
        allow_all_targets=False,
        allowed_targets=["127.0.0.1"],
        allowed_ports=[443],
    )
    rt.store.save_engagement(eng)
    with pytest.raises(PolicyViolationError):
        rt.action_prepare("network.nmap", "scan", {"target": "127.0.0.1", "ports": "22"})

    # Legitimate control: Port 443 is permitted
    ok_plan = rt.action_prepare("network.nmap", "scan", {"target": "127.0.0.1", "ports": "443"})
    assert ok_plan["success"] is True


def test_extra_flags_cannot_add_unvalidated_target(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.engagement_manage(action="update", allowed_targets=["127.0.0.1"], allow_all_targets=False)
    with pytest.raises(PolicyViolationError):
        rt.action_prepare(
            "network.nmap",
            "scan",
            {"target": "127.0.0.1", "extra_flags": ["192.0.2.99"]},
        )


def test_parent_symlink_race_does_not_write_outside_workspace(tmp_path: Path) -> None:
    ws = ConfinedWorkspace(tmp_path / "workspace")
    parent = ws.base_dir / "parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("original")
    real_open = os.open

    def race_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(path).name == "sentinel":
            parent.rename(ws.base_dir / "parked")
            parent.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, *args, **kwargs)

    with patch("hexstrike.workspace.confined_fs.os.open", side_effect=race_open):
        res = ws.create_file("parent/sentinel", "replacement")
    assert res["success"] is False
    assert sentinel.read_text() == "original"


def test_hardlink_race_does_not_truncate_external_file(tmp_path: Path) -> None:
    ws = ConfinedWorkspace(tmp_path / "workspace")
    outside = tmp_path / "sentinel"
    outside.write_text("original")
    target = ws.base_dir / "newfile"
    real_open = os.open

    def race_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if Path(path).name == "newfile":
            os.link(outside, target)
        return real_open(path, flags, *args, **kwargs)

    with patch("hexstrike.workspace.confined_fs.os.open", side_effect=race_open):
        result = ws.create_file("newfile", "replacement")
    assert result["success"] is False
    assert outside.read_text() == "original", result


def test_separate_runtime_cancel_stops_child(tmp_path: Path) -> None:
    marker = tmp_path / "child-survived"

    class HarmlessSleeper(JwtAnalyzerAdapter):
        descriptor = replace(
            JwtAnalyzerAdapter.descriptor,
            capability_id="review.sleeper",
            binary_name=sys.executable,
        )

        def build_argv(self, operation: str, arguments: Any, binary_path: Any = None) -> list[str]:
            return [
                sys.executable,
                "-c",
                "import pathlib,sys,time; time.sleep(0.8); pathlib.Path(sys.argv[1]).write_text('survived')",
                str(marker),
            ]

        def execute_direct(self, *args: Any, **kwargs: Any) -> None:
            return None

    first = HexStrikeRuntime(state_dir=tmp_path / "state")
    second = HexStrikeRuntime(state_dir=tmp_path / "state")
    first.registry.register_adapter(HarmlessSleeper())
    result = first.job_start(
        capability_id="review.sleeper",
        operation="analyze",
        arguments={"token": TOKEN},
        wait=False,
    )
    jid = result["job"]["job_id"]
    try:
        deadline = time.monotonic() + 3
        while jid not in first.runner._active_processes and time.monotonic() < deadline:
            time.sleep(0.01)
        assert jid in first.runner._active_processes, "Fixture did not start child"
        cancellation = second.job_cancel(job_id=jid)
        first._executor.shutdown(wait=True)
        assert cancellation["process_terminated"] is True
        assert not marker.exists(), cancellation
        assert second.store.get_job(jid).state.value == "cancelled"
    finally:
        first.runner.cancel_all()
        first._executor.shutdown(wait=True)
        second._executor.shutdown(wait=True)


def test_http_origin_and_host_require_exact_hostname(tmp_path: Path) -> None:
    app = create_http_app(runtime=HexStrikeRuntime(state_dir=tmp_path), api_token="fixture-token")
    client = app.test_client()

    # Prefix spoof on Origin must be rejected
    resp_origin = client.get(
        "/api/v6/status",
        headers={
            "Authorization": "Bearer fixture-token",
            "Origin": "http://localhost.attacker.invalid",
        },
    )
    assert resp_origin.status_code == 403

    # Spoofed Host header must be rejected
    resp_host = client.get(
        "/api/v6/status",
        headers={
            "Authorization": "Bearer fixture-token",
            "Host": "localhost.attacker.invalid:8888",
        },
    )
    assert resp_host.status_code == 403

    # Valid exact loopback Origin and Host succeed
    resp_ok = client.get(
        "/api/v6/status",
        headers={
            "Authorization": "Bearer fixture-token",
            "Origin": "http://localhost:8888",
            "Host": "127.0.0.1:8888",
        },
    )
    assert resp_ok.status_code == 200


def test_concurrent_idempotency_executes_once(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    barrier = threading.Barrier(2)
    executions = []
    original_lookup = rt.store.get_job_by_idempotency
    adapter = rt.registry.get_adapter("api.jwt_analyzer")
    original_execute = adapter.execute_direct

    def synchronized_lookup(*args: Any, **kwargs: Any) -> Any:
        result = original_lookup(*args, **kwargs)
        barrier.wait(timeout=3)
        return result

    def record_execution(*args: Any, **kwargs: Any) -> Any:
        executions.append(1)
        return original_execute(*args, **kwargs)

    with patch.object(rt.store, "get_job_by_idempotency", side_effect=synchronized_lookup), patch.object(
        adapter, "execute_direct", side_effect=record_execution
    ):
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    rt.job_start,
                    capability_id="api.jwt_analyzer",
                    operation="analyze",
                    arguments={"token": TOKEN},
                    idempotency_key="same-request",
                )
                for _ in range(2)
            ]
            for future in futures:
                future.result(timeout=5)
    assert len(executions) == 1, f"Same idempotency key executed {len(executions)} times"


def test_disabled_and_quarantined_capabilities_stay_persisted_after_restart(tmp_path: Path) -> None:
    first = HexStrikeRuntime(state_dir=tmp_path)
    assert first.registry.disable_capability("api.jwt_analyzer")
    assert first.registry.quarantine_capability("web.nuclei")

    second = HexStrikeRuntime(state_dir=tmp_path)
    assert second.registry.get_adapter("api.jwt_analyzer") is None
    assert second.registry.get_adapter("web.nuclei") is None

    # Quarantine cannot be bypassed by ordinary enable_capability(unquarantine=False)
    assert second.registry.enable_capability("web.nuclei", unquarantine=False) is False
    assert second.registry.get_adapter("web.nuclei") is None


def test_network_mcp_rejects_anonymous_and_accepts_authenticated_tool_calls(tmp_path: Path) -> None:
    async def check() -> None:
        server = create_hexstrike_mcp_server(
            HexStrikeRuntime(state_dir=tmp_path),
            api_token="mcp-secret-token",
        )
        app = server.streamable_http_app(stateless_http=True, json_response=True)
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "system_status", "arguments": {}},
            }
        ).encode()

        async def _send_req(headers: list[tuple[bytes, bytes]]) -> int:
            sent: list[dict[str, Any]] = []
            received = False

            async def receive() -> dict[str, Any]:
                nonlocal received
                if not received:
                    received = True
                    return {"type": "http.request", "body": body, "more_body": False}
                await asyncio.Event().wait()
                return {}

            async def send(message: dict[str, Any]) -> None:
                sent.append(message)

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
            return next(m["status"] for m in sent if m["type"] == "http.response.start")

        base_headers = [
            (b"host", b"127.0.0.1:8000"),
            (b"content-type", b"application/json"),
            (b"accept", b"application/json, text/event-stream"),
            (b"mcp-protocol-version", b"2025-11-25"),
        ]
        async with app.router.lifespan_context(app):
            # 1. Anonymous request rejected with 401
            status_anon = await _send_req(base_headers)
            assert status_anon in (401, 403)

            # 2. Authenticated request with spoofed Origin rejected with 403
            status_bad_origin = await _send_req(
                [
                    *base_headers,
                    (b"authorization", b"Bearer mcp-secret-token"),
                    (b"origin", b"http://localhost.attacker.invalid"),
                ]
            )
            assert status_bad_origin == 403

            # 3. Authenticated request with valid Host and Bearer token succeeds (200)
            status_authed = await _send_req(
                [*base_headers, (b"authorization", b"Bearer mcp-secret-token")]
            )
            assert status_authed == 200

    asyncio.run(check())


def test_browser_blocks_redirect_to_disallowed_port(tmp_path: Path) -> None:
    visits: list[str] = []

    class _FastServer(HTTPServer):
        def server_bind(self) -> None:
            import socket as _s

            _s.socket.bind(self.socket, self.server_address)
            self.server_address = self.socket.getsockname()[:2]
            self.server_name = "127.0.0.1"
            self.server_port = self.server_address[1]

    class Destination(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            visits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<title>Excluded destination</title>")

        def log_message(self, *args: Any) -> None:
            pass

    destination = _FastServer(("127.0.0.1", 0), Destination)

    class Redirect(Destination):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{destination.server_port}/excluded")
            self.end_headers()

    source = _FastServer(("127.0.0.1", 0), Redirect)
    for server in (destination, source):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        rt = HexStrikeRuntime(state_dir=tmp_path)
        eng = rt.store.get_engagement("default")
        eng.scope = ScopePolicy(
            allow_all_targets=False,
            allowed_targets=["127.0.0.1"],
            allowed_ports=[source.server_port],
        )
        rt.store.save_engagement(eng)
        res = rt.job_start(
            capability_id="browser.inspect",
            operation="inspect",
            arguments={"url": f"http://127.0.0.1:{source.server_port}/"},
        )
        assert res["success"] is False
        assert visits == [], "Browser fetched disallowed redirect destination"
    finally:
        for server in (source, destination):
            server.shutdown()
            server.server_close()


def test_playwright_js_execution_and_graphiti_and_workflow_runner(tmp_path: Path) -> None:
    class _FastServer(HTTPServer):
        def server_bind(self) -> None:
            import socket as _s

            _s.socket.bind(self.socket, self.server_address)
            self.server_address = self.socket.getsockname()[:2]
            self.server_name = "127.0.0.1"
            self.server_port = self.server_address[1]

    class _JsHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = (
                "<html><head><title>Initial</title>"
                "<script>document.title = 'JS_DYNAMIC_TITLE_VERIFIED';</script>"
                "</head><body><form method='POST' action='/submit'><input name='q'/></form></body></html>"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    srv = _FastServer(("127.0.0.1", 0), _JsHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        rt = HexStrikeRuntime(state_dir=tmp_path)
        url = f"http://127.0.0.1:{srv.server_port}/"

        # 1. Verify LocalGraphitiAdapter is active
        assert rt.memory.graphiti_adapter.graphiti_available is True

        # 2. Verify held-out lesson safety check rejects unsafe recommendations
        unsafe_lesson = rt.memory.propose_lesson(
            source_engagement_id="default",
            capability_id="network.nmap",
            title="Unsafe escalation",
            recommendation="Use --no-sandbox and rm -rf /tmp to speed up scans",
        )
        evaluated_unsafe = rt.memory.run_held_out_evaluation(unsafe_lesson.lesson_id)
        assert evaluated_unsafe.eval_score == 0.0
        with pytest.raises(ValueError):
            rt.memory.promote_lesson(unsafe_lesson.lesson_id, reviewed_by="reviewer")

        # 3. Verify WorkflowRunner executes multi-step WSTG DAG
        wf = WorkflowRunner(rt)
        wf_res = wf.execute_workflow("web_baseline", target=url)
        assert wf_res["success"] is True
        assert "http_headers" in wf_res["completed_steps"]
        assert "browser_dom" in wf_res["completed_steps"]

        # 4. If Chromium is installed locally, verify Playwright JS execution updates document.title
        if find_chromium_executable():
            pw_res = rt.job_start(
                capability_id="browser.inspect",
                operation="inspect",
                arguments={"url": url, "execute_js": True},
            )
            assert pw_res["success"] is True
            out = pw_res["job"]["structured_output"]
            assert out["engine_used"] == "playwright_chromium"
            assert out["js_executed"] is True
            assert out["title"] == "JS_DYNAMIC_TITLE_VERIFIED"
    finally:
        srv.shutdown()
        srv.server_close()
