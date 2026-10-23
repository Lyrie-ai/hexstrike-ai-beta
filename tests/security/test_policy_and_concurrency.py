"""Behavioral regression checks using isolated local fixtures."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import shlex
import sys
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Generator, List, Tuple
from unittest.mock import patch

import psutil
import pytest

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.browser.inspector import sanitize_har_structure
from hexstrike.execution.runner import ExecutionResult, SshWorkerBridge

JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."


def test_database_descriptors_close_without_garbage_collection(tmp_path):
    import gc
    from hexstrike.http.client import AuthenticationStore

    runtime = HexStrikeRuntime(state_dir=tmp_path)
    runtime.memory.record_episode("default", "observation", "descriptor-fixture", "retained evidence")
    credentials = AuthenticationStore(tmp_path)
    process = psutil.Process()
    def opened():
        return sum(str(tmp_path) in item.path for item in process.open_files())
    gc.collect()
    baseline = opened()
    enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(20):
            runtime.system_status()
            runtime.memory_query(query="descriptor-fixture")
            credentials.put_execution("fixture", "synthetic-value")
        assert opened() <= baseline + 3, "Database descriptors remained open after operations returned"
    finally:
        if enabled:
            gc.enable()
        gc.collect()


def start_jwt(rt: HexStrikeRuntime) -> dict[str, Any]:
    return rt.job_start(
        capability_id="api.jwt_analyzer",
        operation="analyze",
        arguments={"token": JWT},
        wait=False,
    )


def test_concurrency_limit_is_shared_by_runtimes(tmp_path: Path) -> None:
    one = HexStrikeRuntime(state_dir=tmp_path)
    one.engagement_manage(action="configure", max_concurrency=1)
    two = HexStrikeRuntime(state_dir=tmp_path)
    gate, both, first = threading.Event(), threading.Event(), threading.Event()
    entered: List[int] = []
    lock = threading.Lock()

    def work(*args: Any, **kwargs: Any) -> ExecutionResult:
        with lock:
            entered.append(1)
            first.set()
            if len(entered) == 2:
                both.set()
        gate.wait(5)
        return ExecutionResult(True, 0, "{}", "", 0.01)

    try:
        with ExitStack() as stack:
            for rt in (one, two):
                stack.enter_context(
                    patch.object(rt.registry.get_adapter("api.jwt_analyzer"), "execute_direct", side_effect=work)
                )
            start_jwt(one)
            assert first.wait(3)
            start_jwt(two)
            overlapped = both.wait(0.7)
            gate.set()
            for rt in (one, two):
                rt._executor.shutdown(wait=True)
    finally:
        gate.set()
        for rt in (one, two):
            rt._executor.shutdown(wait=True)
    assert not overlapped, "Two runtimes sharing an engagement exceeded its max_concurrency=1"


def test_lowering_concurrency_preserves_existing_reservations(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path, max_workers=3)
    rt.engagement_manage(action="configure", max_concurrency=2)
    gate, two, third = threading.Event(), threading.Event(), threading.Event()
    entered: List[int] = []
    lock = threading.Lock()

    def work(*args: Any, **kwargs: Any) -> ExecutionResult:
        with lock:
            entered.append(1)
            if len(entered) == 2:
                two.set()
            if len(entered) == 3:
                third.set()
        gate.wait(5)
        return ExecutionResult(True, 0, "{}", "", 0.01)

    try:
        with patch.object(rt.registry.get_adapter("api.jwt_analyzer"), "execute_direct", side_effect=work):
            start_jwt(rt)
            start_jwt(rt)
            assert two.wait(3)
            rt.engagement_manage(action="configure", max_concurrency=1)
            start_jwt(rt)
            admitted = third.wait(0.7)
            gate.set()
            rt._executor.shutdown(wait=True)
    finally:
        gate.set()
        rt._executor.shutdown(wait=True)
    assert not admitted, "Changing the limit admitted a third job while two old jobs still ran"


@pytest.fixture
def lab() -> Generator[Tuple[str, List[str]], None, None]:
    hits: List[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append(self.path)
            body = b"<html><title>Fixture</title><body>local lab</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_queued_job_observes_target_exclusion_added_before_execution(
    tmp_path: Path, lab: Tuple[str, List[str]]
) -> None:
    url, hits = lab
    rt = HexStrikeRuntime(state_dir=tmp_path, max_workers=2)
    rt.engagement_manage(action="configure", max_concurrency=1)
    gate, entered = threading.Event(), threading.Event()

    def work(*args: Any, **kwargs: Any) -> ExecutionResult:
        entered.set()
        gate.wait(5)
        return ExecutionResult(True, 0, "{}", "", 0.01)

    try:
        with patch.object(rt.registry.get_adapter("api.jwt_analyzer"), "execute_direct", side_effect=work):
            start_jwt(rt)
            assert entered.wait(3)
            queued = rt.job_start(
                capability_id="web.http_inspect",
                operation="probe",
                arguments={"url": url},
                wait=False,
            )
            assert rt.store.get_job(queued["job"]["job_id"]).state.value == "queued"
            rt.engagement_manage(action="configure", excluded_targets=["127.0.0.1"])
            gate.set()
            rt._executor.shutdown(wait=True)
    finally:
        gate.set()
        rt._executor.shutdown(wait=True)
    assert hits == [], "Queued request reached a target after the user excluded it"


def test_bridge_cancellation_stops_worker_child_with_local_transport(tmp_path: Path) -> None:
    # Only transport construction is replaced. Real bridge, runner, harness, and child run.
    bridge = SshWorkerBridge("fixture-no-ssh")
    marker = tmp_path / "owned-child.pid"
    child_script = (
        "import os,sys,time; from pathlib import Path; "
        "Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(15)"
    )
    cancel = threading.Event()
    results: List[Any] = []
    errors: List[Exception] = []

    def local_transport(remote_cmd: List[str]) -> List[str]:
        return [sys.executable, "-c", shlex.split(remote_cmd[2])[0], shlex.split(remote_cmd[3])[0]]

    def execute() -> None:
        try:
            results.append(
                bridge.execute_argv(
                    [sys.executable, "-c", child_script, str(marker)],
                    job_id="owned-round4-child",
                    timeout=5,
                    is_cancelled_fn=cancel.is_set,
                )
            )
        except Exception as exc:
            errors.append(exc)

    owned = None
    thread = threading.Thread(target=execute)
    try:
        with patch.object(bridge, "_build_ssh_argv", side_effect=local_transport):
            thread.start()
            deadline = time.monotonic() + 4
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            assert marker.exists(), (results, errors)
            owned = psutil.Process(int(marker.read_text()))
            owned.create_time()  # cache identity for safe fixture cleanup
            cancel.set()
            thread.join(5)
            assert not thread.is_alive(), "Bridge did not return after cancellation"
            assert not errors, errors
            time.sleep(0.1)
            survives = owned.is_running() and owned.status() != psutil.STATUS_ZOMBIE
            assert not survives, ("Bridge returned after cancellation but its worker child still ran", results)
    finally:
        cancel.set()
        if owned is not None:
            try:
                owned.kill()  # psutil checks creation identity; only the fixture child
                owned.wait(2)
            except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                pass
        thread.join(6)


def test_graph_query_returns_requested_value_or_rejects_unsupported_semantics(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.memory.record_episode("default", "observation", "fixture", "unrelated fixture fact")
    try:
        records, _, _ = asyncio.run(rt.memory.graphiti_adapter.driver.execute_query("RETURN 1 AS n"))
    except (ValueError, NotImplementedError):
        return  # a documented constrained driver may reject this operation
    assert records == [{"n": 1}], "Valid-looking Cypher returned unrelated stored edges instead of its result"


@pytest.mark.parametrize("where", ["url", "json_body"])
def test_har_sanitizer_removes_known_sensitive_fields_in_all_encodings(where: str) -> None:
    marker = "SYNTHETIC_SECRET_R4_9841"
    request: dict[str, Any] = {"url": "https://fixture.invalid/", "headers": [], "cookies": []}
    if where == "url":
        request.update(
            url="https://fixture.invalid/?sid=" + marker,
            queryString=[{"name": "sid", "value": marker}],
        )
    else:
        request["postData"] = {"mimeType": "application/json", "text": json.dumps({"password": marker})}
    data = {"log": {"entries": [{"request": request, "response": {}}]}}
    assert marker not in json.dumps(sanitize_har_structure(data)), "Known sensitive field survives in HAR"


def test_missing_artifact_is_not_silently_reported_as_complete_preview(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    job = rt.job_start(capability_id="api.jwt_analyzer", operation="analyze", arguments={"token": JWT})
    ev = rt.store.list_evidence(job_id=job["job"]["job_id"])[0]
    assert ev.artifact_id
    assert rt.workspace.delete_file(ev.artifact_id)["success"]
    result = rt.evidence_read(evidence_id=ev.evidence_id)
    assert result.get("error") or result.get("partial") or result.get("artifact_missing"), result


def test_user_artifact_budget_is_enforced_or_rejected(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.engagement_manage(action="configure", max_artifact_bytes=1)
    result = rt.job_start(capability_id="api.jwt_analyzer", operation="analyze", arguments={"token": JWT})
    assert not result["success"] or result.get("partial"), "User max_artifact_bytes=1 accepted but ignored"


def test_workflow_children_inherit_explicit_worker_selection(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    local_calls: List[bool] = []
    remote_calls: List[List[str]] = []

    def local(*args: Any, **kwargs: Any) -> ExecutionResult:
        local_calls.append(True)
        return ExecutionResult(True, 0, "{}", "", 0.01)

    class Worker:
        def execute_argv(self, argv: List[str], **kwargs: Any) -> ExecutionResult:
            remote_calls.append(argv)
            return ExecutionResult(True, 0, "{}", "", 0.01, worker_target="fixture-worker")

    # This tests dispatch inheritance only; does not claim to execute remote protocol.
    with patch.object(rt, "_get_ssh_bridge", return_value=Worker()), \
         patch.object(rt.registry.get_adapter("web.http_inspect"), "execute_direct", side_effect=local), \
         patch.object(rt.registry.get_adapter("browser.inspect"), "execute_direct", side_effect=local):
        result = rt.job_start(
            capability_id="workflow.wstg",
            operation="run",
            arguments={"target": "http://127.0.0.1/"},
            worker_target="fixture-worker",
        )
    assert result["success"], result
    assert not local_calls and len(remote_calls) == 2, (
        "Worker selection lost in child dispatch",
        local_calls,
        remote_calls,
    )


def test_screenshot_evidence_can_be_retrieved_without_byte_corruption(
    tmp_path: Path, lab: Tuple[str, List[str]]
) -> None:
    url, _ = lab
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(
        capability_id="browser.inspect",
        operation="inspect",
        arguments={"url": url, "capture_screenshot": True},
    )
    assert result["success"], result
    ev = next(e for e in rt.store.list_evidence(job_id=result["job"]["job_id"]) if e.kind == "screenshot")
    assert ev.artifact_id
    raw = (rt.workspace.base_dir / ev.artifact_id).read_bytes()
    assert raw.startswith(b"\x89PNG\r\n\x1a\n") and len(raw) < 32768
    assert hashlib.sha256(raw).hexdigest() == ev.sha256  # persistence positive control
    read_res = rt.evidence_read(evidence_id=ev.evidence_id, limit=32768)
    if read_res.get("encoding") == "base64":
        content = base64.b64decode(read_res["content"])
    elif isinstance(read_res.get("content"), bytes):
        content = read_res["content"]
    else:
        content = read_res.get("content", "").encode("utf-8")
    assert hashlib.sha256(content).hexdigest() == ev.sha256, "Screenshot handle returned corrupted/incomplete bytes"
