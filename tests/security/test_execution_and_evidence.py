"""Behavioral regression checks using isolated local fixtures."""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Generator
from unittest.mock import patch

import pytest
import psutil

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.domain.models import Finding, FindingState, Principal, ScopePolicy, Severity
from hexstrike.execution.remote_protocol import build_remote_builtin_argv
from hexstrike.execution.runner import REMOTE_WORKER_HARNESS
from hexstrike.policy.engine import PolicyEngine
from hexstrike.workspace.confined_fs import ConfinedWorkspace


JWT_SAMPLE = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."


def test_status_counts_findings_beyond_preview_limit(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    for index in range(27):
        rt.store.save_finding(Finding(
            finding_id=f"fixture-{index}", engagement_id="default", job_id="fixture-job",
            capability_id="fixture", title="Fixture finding", description="Local fixture",
            target="fixture", severity=Severity.INFO, state=FindingState.CANDIDATE,
        ))
    assert rt.system_status()["findings_count"] == 27
    rt.engagement_manage(action="create", engagement_id="empty", name="Empty fixture")
    assert rt.system_status(engagement_id="empty")["findings_count"] == 0


def test_actual_remote_harness_runs_harmless_child() -> None:
    payload = base64.b64encode(
        json.dumps({"argv": [sys.executable, "-c", "print('worker-ok')"], "timeout": 2}).encode()
    ).decode()
    with subprocess.Popen(
        [sys.executable, "-c", REMOTE_WORKER_HARNESS, payload],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as proc:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
        stdout, stderr = proc.communicate(timeout=2)
    assert proc.returncode == 0, stderr
    frames = [json.loads(line) for line in stdout.splitlines()]
    assert frames[-1]["success"] and "worker-ok" in frames[-1]["stdout"], frames


def test_restart_reconciles_job_whose_direct_executor_died(tmp_path: Path) -> None:
    script = r'''
import os, sys, threading
from pathlib import Path
from unittest.mock import patch
from hexstrike.application.services import HexStrikeRuntime
rt = HexStrikeRuntime(state_dir=sys.argv[1])
entered = threading.Event()
def block(*a, **kw):
    entered.set()
    threading.Event().wait(30)
with patch.object(rt.registry.get_adapter("api.jwt_analyzer"), "execute_direct", side_effect=block):
    res = rt.job_start(capability_id="api.jwt_analyzer", operation="analyze",
                       arguments={"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."}, wait=False)
    assert entered.wait(5)
    Path(sys.argv[1], "job-id").write_text(res["job"]["job_id"])
    os._exit(0)
'''
    child = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert child.returncode == 0, child.stderr
    rt = HexStrikeRuntime(state_dir=tmp_path)
    job = rt.store.get_job((tmp_path / "job-id").read_text())
    assert job is not None
    assert job.state.value in {"interrupted", "failed"}, (
        "Dead local direct executor remains advertised as active after restart",
        job.state.value,
    )


def test_real_fd_write_race_cleanup_cannot_delete_external_file(tmp_path: Path) -> None:
    ws = ConfinedWorkspace(tmp_path / "workspace")
    parent = ws.base_dir / "parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("external-original")
    verify = ws._verify_ancestors_unchanged

    def replace_parent(ancestors: Any) -> None:
        parent.rename(ws.base_dir / "parked")
        parent.symlink_to(outside, target_is_directory=True)
        return verify(ancestors)

    with patch.object(ws, "_verify_ancestors_unchanged", side_effect=replace_parent):
        result = ws.create_file("parent/sentinel", "new-content")
    assert result["success"] is False
    assert sentinel.exists(), result
    assert sentinel.read_text() == "external-original"


def test_promoted_private_lesson_is_not_shared_with_other_user(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    alice, bob = Principal("alice", "Alice"), Principal("bob", "Bob")
    rt.engagement_manage(action="create", engagement_id="alice", principal=alice)
    rt.engagement_manage(action="create", engagement_id="bob", principal=bob)
    lesson = rt.memory.propose_lesson(
        "alice",
        "network.nmap",
        "Alice internal service",
        "Use nmap service version scan for PRIVATE_ALICE_ASSET_MARKER.",
    )
    rt.memory.run_held_out_evaluation(lesson.lesson_id)
    rt.memory.promote_lesson(lesson.lesson_id, reviewed_by=alice)

    # Bob cannot see Alice's private promoted lesson
    result_bob = rt.memory_query(engagement_id="bob", principal=bob)
    assert "PRIVATE_ALICE_ASSET_MARKER" not in json.dumps(result_bob)

    # Positive control: Alice CAN see her own promoted lesson across her own engagements
    rt.engagement_manage(action="create", engagement_id="alice_second", principal=alice)
    result_alice = rt.memory_query(engagement_id="alice_second", principal=alice)
    assert "PRIVATE_ALICE_ASSET_MARKER" in json.dumps(result_alice)


def test_user_selected_concurrency_limit_is_enforced(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path, max_workers=2)
    rt.engagement_manage(action="configure", max_concurrency=1)
    gate, two_started = threading.Event(), threading.Event()
    started = []
    adapter = rt.registry.get_adapter("api.jwt_analyzer")
    assert adapter is not None
    original = adapter.execute_direct

    def blocking(*args: Any, **kwargs: Any) -> Any:
        started.append(1)
        if len(started) >= 2:
            two_started.set()
        gate.wait(timeout=4)
        return original(*args, **kwargs)

    try:
        with patch.object(adapter, "execute_direct", side_effect=blocking):
            for _ in range(2):
                rt.job_start(
                    capability_id="api.jwt_analyzer",
                    operation="analyze",
                    arguments={"token": JWT_SAMPLE},
                    wait=False,
                )
            overlapped = two_started.wait(timeout=1)
            gate.set()
            rt._executor.shutdown(wait=True)
    finally:
        gate.set()
        rt._executor.shutdown(wait=True)
    assert not overlapped, "Two jobs executed concurrently with max_concurrency=1"


def test_workflow_cancel_prevents_following_step(tmp_path: Path, acceptance_http_lab) -> None:
    url, hits, entered, gate = acceptance_http_lab
    rt = HexStrikeRuntime(state_dir=tmp_path)
    try:
        res = rt.job_start(capability_id="workflow.wstg", operation="run",
                           arguments={"target": url + "/slow"}, wait=False)
        assert entered.wait(5), "First workflow request did not reach the fixture"
        rt.job_cancel(job_id=res["job"]["job_id"])
        gate.set()
        rt._executor.shutdown(wait=True)
        children = [j for j in rt.store.list_jobs() if j.parent_job_id == res["job"]["job_id"]]
        assert len(children) == 1 and children[0].state.value == "cancelled"
        assert hits == ["/slow"], "A follow-on request ran after workflow cancellation"
    finally:
        gate.set()
        rt._executor.shutdown(wait=True)


def test_artifact_storage_failure_is_not_reported_as_full_success(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.workspace.max_workspace_bytes = 1
    result = rt.job_start(
        capability_id="api.jwt_analyzer",
        operation="analyze",
        arguments={"token": JWT_SAMPLE},
    )
    records = rt.store.list_evidence(job_id=result["job"]["job_id"])
    assert result["success"] is False or result.get("partial") is True, (
        result["job"]["state"],
        [(e.kind, e.artifact_id) for e in records],
    )


def test_graph_driver_rejects_unsupported_query_instead_of_returning_unrelated_edges(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    adapter = rt.memory.graphiti_adapter
    assert adapter.graphiti_available, "Graphiti extra is required for this acceptance test"
    rt.memory.record_episode("default", "observation", "fixture", "fixture content")
    with pytest.raises((ValueError, NotImplementedError)):
        asyncio.run(adapter.driver.execute_query("THIS IS NOT A SUPPORTED QUERY", group_id="default"))


@pytest.mark.parametrize("query,limit", [("absent-marker", 1), ("needle", 1), ("needle", 3)])
def test_memory_edges_follow_episode_filter_and_requested_limit(tmp_path, query, limit):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    for index in range(4):
        rt.memory.record_episode(
            "default", "observation", f"needle-{index}", "matching fixture",
            relations=[(f"needle-{index}", "tested_by", "fixture")],
        )
    rt.memory.record_episode(
        "default", "observation", "unrelated", "different fixture",
        relations=[("unrelated", "tested_by", "fixture")],
    )
    result = rt.memory_query(query=query, limit=limit)
    episode_ids = {episode["episode_id"] for episode in result["episodes"]}
    assert len(result["graph_edges"]) == len(episode_ids)
    assert len(result["graph_edges"]) <= limit
    assert all(edge["episode_id"] in episode_ids for edge in result["graph_edges"])


@pytest.fixture
def local_lab() -> Generator[str, None, None]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"<html><head><title>Static</title><script>document.title='Dynamic';</script></head><body>Fixture</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "session_id=REVIEW_HAR_COOKIE_VALUE_8842; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _run_remote_capability(capability: str, arguments: dict[str, Any], scope: ScopePolicy) -> subprocess.CompletedProcess[str]:
    argv = build_remote_builtin_argv(
        capability,
        "inspect" if capability == "browser.inspect" else "probe",
        arguments,
        scope,
        "fixture-job",
    )
    argv[0] = sys.executable
    return subprocess.run(argv, capture_output=True, text=True, timeout=15)


def test_remote_capability_honors_user_allowed_cidr(local_lab: str) -> None:
    scope = ScopePolicy(allow_all_targets=False, allowed_targets=["127.0.0.0/8"])
    PolicyEngine().evaluate_target(local_lab, scope)
    result = _run_remote_capability("web.http_inspect", {"url": local_lab}, scope)
    assert result.returncode == 0, result.stderr


def test_remote_browser_does_not_succeed_without_requested_features(local_lab: str) -> None:
    result = _run_remote_capability(
        "browser.inspect",
        {"url": local_lab, "execute_js": True, "capture_har": True, "capture_screenshot": True},
        ScopePolicy(),
    )
    if result.returncode != 0:
        assert result.stderr, "Failure must explain unfulfilled requirements"
        return
    payload = json.loads(result.stdout)
    assert payload.get("js_executed") is True and payload.get("har") and payload.get("screenshot_png_b64"), payload


def test_browser_har_does_not_expose_cookie_value(local_lab: str, tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(
        capability_id="browser.inspect",
        operation="inspect",
        arguments={"url": local_lab, "capture_har": True},
    )
    assert result["success"], result["job"].get("error_message")
    har_evidence = next(rt.store.get_evidence(eid) for eid in result["job"]["evidence_ids"] if rt.store.get_evidence(eid).kind == "har")
    har = json.loads(rt.workspace.read_file(har_evidence.artifact_id)["content"])
    assert "har" not in result["job"]["structured_output"]
    assert "REVIEW_HAR_COOKIE_VALUE_8842" not in json.dumps(har), "Cookie secret present in advertised redacted HAR"


def test_screenshot_result_contains_handle_not_inline_base64(local_lab: str, tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(
        capability_id="browser.inspect",
        operation="inspect",
        arguments={"url": local_lab, "capture_screenshot": True},
    )
    assert result["success"], result["job"].get("error_message")
    assert "screenshot_png_b64" not in result["job"]["structured_output"]
    screenshots = [e for e in rt.store.list_evidence(job_id=result["job"]["job_id"]) if e.kind == "screenshot"]
    assert screenshots and screenshots[0].artifact_id


@pytest.fixture
def acceptance_http_lab():
    gate, entered = threading.Event(), threading.Event()
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == '/slow':
                entered.set()
                gate.wait(10)
            self.send_response(302 if self.path == '/redirect' else 200)
            if self.path == '/redirect':
                self.send_header('Location', '/final')
            self.send_header('Set-Cookie', 'session=LOCAL_COOKIE_SECRET_8041; Path=/')
            self.send_header('X-Api-Key', 'LOCAL_HEADER_SECRET_8041')
            self.send_header('Content-Length', '2')
            self.end_headers()
            try:
                self.wfile.write(b'ok')
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', hits, entered, gate
    finally:
        gate.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize(('capability', 'operation'), [('web.http_inspect', 'probe'), ('browser.inspect', 'inspect')])
def test_acceptance_http_headers_are_redacted_before_persistence(tmp_path, acceptance_http_lab, capability, operation):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(capability_id=capability, operation=operation,
        arguments={'url': acceptance_http_lab[0]})
    assert result['success'], result
    for marker in ('LOCAL_COOKIE_SECRET_8041', 'LOCAL_HEADER_SECRET_8041'):
        assert marker not in json.dumps(result), 'Sensitive header reached the MCP job result'
        for ev in rt.store.list_evidence(job_id=result['job']['job_id']):
            assert marker not in json.dumps(rt.evidence_read(evidence_id=ev.evidence_id))
            assert marker not in (rt.workspace.base_dir / ev.artifact_id).read_text()


@pytest.mark.parametrize('capability', ['web.http_inspect', 'browser.inspect'])
def test_acceptance_remote_headers_are_redacted(acceptance_http_lab, capability):
    result = _run_remote_capability(capability, {'url': acceptance_http_lab[0]}, ScopePolicy())
    assert result.returncode == 0, result.stderr
    assert 'LOCAL_COOKIE_SECRET_8041' not in result.stdout
    assert 'LOCAL_HEADER_SECRET_8041' not in result.stdout


def test_acceptance_http_redirect_preference_is_honored(tmp_path, acceptance_http_lab):
    url, hits, _, _ = acceptance_http_lab
    rt = HexStrikeRuntime(state_dir=tmp_path)
    first = rt.job_start(capability_id='web.http_inspect', operation='probe',
        arguments={'url':url+'/redirect', 'follow_redirects':False})
    assert first['job']['structured_output']['status_code'] == 302
    assert '/final' not in hits
    second = rt.job_start(capability_id='web.http_inspect', operation='probe',
        arguments={'url':url+'/redirect', 'follow_redirects':True})
    assert second['job']['structured_output']['final_url'] == url+'/final'
    assert '/final' in hits


def test_acceptance_cancel_terminates_local_http_worker(tmp_path, acceptance_http_lab):
    url, _, entered, gate = acceptance_http_lab
    rt = HexStrikeRuntime(state_dir=tmp_path)
    try:
        result = rt.job_start(capability_id='web.http_inspect', operation='probe',
            arguments={'url':url+'/slow','timeout':30}, wait=False)
        assert entered.wait(5)
        cancelled = rt.job_cancel(job_id=result['job']['job_id'])
        assert cancelled['process_terminated'], cancelled
        job = rt.store.get_job(result['job']['job_id'])
        assert job.state.value == 'cancelled'
        assert not psutil.pid_exists(job.pid)
    finally:
        gate.set()
        rt._executor.shutdown(wait=True)


def test_acceptance_http_deadline_reports_timed_out(tmp_path, acceptance_http_lab):
    url, _, _, gate = acceptance_http_lab
    rt = HexStrikeRuntime(state_dir=tmp_path)
    try:
        result = rt.job_start(capability_id='web.http_inspect', operation='probe',
            arguments={'url':url+'/slow','timeout':30}, timeout_seconds=1)
        assert result['job']['state'] == 'timed_out', result
    finally:
        gate.set()
        rt._executor.shutdown(wait=True)


@pytest.mark.parametrize(('capability', 'output'), [
    ('web.gobuster', 'admin (Status: 200) [Size: 244]\napi (Status: 200) [Size: 244]\n'),
    ('web.ffuf', '{"url":"http://127.0.0.1/admin","status":200,"length":244}\n{"url":"http://127.0.0.1/api","status":200,"length":244}\n'),
])
def test_acceptance_directory_discovery_retains_native_results(capability, output):
    from hexstrike.adapters.catalog import parse_structured_cli_output
    structured, findings = parse_structured_cli_output(capability, output, 'http://127.0.0.1', 'fixture', 'job-fixture', 'WSTG-CONF-04')
    assert {x['path'] for x in structured['discovered_endpoints']} == {'/admin','/api'}
    assert len(findings) == 2


def test_acceptance_custom_install_remove_updates_existing_controller(tmp_path):
    from hexstrike.adapters.catalog import CustomAdapterManifest
    observer = HexStrikeRuntime(state_dir=tmp_path)
    administrator = HexStrikeRuntime(state_dir=tmp_path)
    manifest = CustomAdapterManifest.from_dict({
        'capability_id':'custom.fixture', 'name':'Fixture', 'category':'custom',
        'binary_name':'echo', 'description':'Local fixture output',
        'arg_template':['fixture-output'], 'parameters':{}, 'required':[],
        'requires_network':False,
    })
    administrator.registry.register_custom_adapter(manifest)
    assert observer.capabilities_search(query='custom.fixture')['count'] == 1
    result = observer.job_start(capability_id='custom.fixture', operation='run', arguments={})
    assert result['success'], result
    administrator.registry.remove_custom_capability('custom.fixture')
    assert observer.registry.get_adapter('custom.fixture') is None
    assert observer.capabilities_search(query='custom.fixture')['count'] == 0


def test_acceptance_new_binary_is_detected_after_initial_missing_probe(tmp_path):
    from hexstrike.registry.catalog_registry import CapabilityRegistry
    registry = CapabilityRegistry(search_paths=[str(tmp_path)])
    assert registry.get_binary_identity('fixture-probe').status.value == 'missing'
    executable = tmp_path/'fixture-probe'
    executable.write_text('#!/bin/sh\nprintf fixture\n')
    executable.chmod(0o700)
    assert registry.get_binary_identity('fixture-probe').status.value == 'enabled'


@pytest.mark.parametrize('output,expected', [
    ("[INFO] testing if GET parameter 'id' is dynamic\n[WARNING] GET parameter 'id' does not seem to be injectable", 0),
    ("[WARNING] heuristic test shows GET parameter 'id' might not be injectable", 0),
    ("[INFO] GET parameter 'id' appears to be injectable\n[WARNING] false positive or unexploitable injection point detected", 0),
    ("sqlmap identified the following injection point(s):\n---\nParameter: id (GET)\n    Type: boolean-based blind\n    Title: AND boolean-based blind\n    Payload: id=1 AND 1=1\n---", 1),
])
def test_sqlmap_requires_reported_injection_point(output, expected):
    from hexstrike.adapters.catalog import parse_structured_cli_output
    result, findings = parse_structured_cli_output('web.sqlmap', output, 'http://127.0.0.1/item?id=1', 'fixture', 'job', '')
    assert len(findings) == expected
    assert bool(result['injectable_indicators']) == bool(expected)


def test_workflow_deadline_stops_child_and_prevents_next_step(tmp_path, acceptance_http_lab):
    import time
    url, hits, _, gate = acceptance_http_lab
    rt = HexStrikeRuntime(state_dir=tmp_path)
    start = time.monotonic()
    try:
        result = rt.job_start(capability_id='workflow.wstg', arguments={'target':url+'/slow'}, timeout_seconds=1)
    finally:
        gate.set()
    assert result['job']['state'] == 'timed_out', result
    assert time.monotonic()-start < 4
    children = [j for j in rt.store.list_jobs() if j.parent_job_id == result['job']['job_id']]
    assert len(children) == 1
    assert children[0].state.value == 'timed_out'
    assert hits == ['/slow']


@pytest.fixture
def malformed_http_lab():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/loop':
                self.send_response(302); self.send_header('Location','/loop'); self.end_headers(); return
            body = b'short' if self.path == '/short' else b'X'*100000
            self.send_response(200); self.send_header('Content-Length','1000' if self.path == '/short' else str(len(body)))
            self.end_headers()
            try: self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError): pass
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try: yield f'http://127.0.0.1:{server.server_port}'
    finally: server.shutdown();server.server_close();thread.join(2)


@pytest.mark.parametrize('path', ['/short','/loop'])
def test_http_transport_failure_is_not_success(tmp_path, malformed_http_lab, path):
    rt=HexStrikeRuntime(state_dir=tmp_path)
    result=rt.job_start(capability_id='web.http_inspect',operation='probe',arguments={'url':malformed_http_lab+path,'follow_redirects':True})
    assert result['job']['state'] == 'failed',result
    assert result['job']['error_message']


def test_http_bounded_body_reports_truncation(tmp_path, malformed_http_lab):
    rt=HexStrikeRuntime(state_dir=tmp_path)
    result=rt.job_start(capability_id='web.http_inspect',operation='probe',arguments={'url':malformed_http_lab+'/large'})
    assert result['success']
    data=result['job']['structured_output']
    assert data['body_length'] == 65536
    assert data['body_truncated'] is True
    assert data['declared_body_length'] == 100000


def test_feroxbuster_json_response_retains_endpoint():
    from hexstrike.adapters.catalog import parse_structured_cli_output
    output=json.dumps({'type':'response','url':'http://127.0.0.1/admin','status':200,'content_length':66})
    result,findings=parse_structured_cli_output('web.feroxbuster',output,'http://127.0.0.1','fixture','job','')
    assert result['discovered_endpoints'][0]['path'] == '/admin'
    assert result['discovered_endpoints'][0]['status'] == 200
    assert len(findings)==1


@pytest.mark.parametrize('path', ['/short','/loop'])
def test_remote_http_transport_failure_is_not_success(malformed_http_lab, path):
    result=_run_remote_capability('web.http_inspect',{'url':malformed_http_lab+path,'follow_redirects':True},ScopePolicy())
    assert result.returncode != 0


def test_remote_http_bounded_body_reports_truncation(malformed_http_lab):
    result=_run_remote_capability('web.http_inspect',{'url':malformed_http_lab+'/large'},ScopePolicy())
    assert result.returncode == 0,result.stderr
    data=json.loads(result.stdout)
    assert data['body_length'] == 65536
    assert data['body_truncated'] is True


def test_http_multiple_query_parameters_remain_one_target(tmp_path, acceptance_http_lab):
    url,hits,_,_=acceptance_http_lab
    rt=HexStrikeRuntime(state_dir=tmp_path)
    result=rt.job_start(capability_id='web.http_inspect',operation='probe',arguments={'url':url+'/?first=1&second=2'})
    assert result['success'],result
    assert hits == ['/?first=1&second=2']
    with pytest.raises(PermissionError):
        rt.action_prepare(capability_id='web.http_inspect',operation='probe',arguments={'url':'127.0.0.1&echo'})


def test_controller_crash_recovery_terminates_orphan_worker(tmp_path, acceptance_http_lab):
    url,_,_,gate=acceptance_http_lab
    script='''
import os,sys,time,json
from pathlib import Path
from hexstrike.application.services import HexStrikeRuntime
rt=HexStrikeRuntime(state_dir=sys.argv[1])
r=rt.job_start(capability_id='web.http_inspect',operation='probe',arguments={'url':sys.argv[2]+'/slow','timeout':20},wait=False)
for _ in range(200):
 job=rt.store.get_job(r['job']['job_id'])
 if job.pid:
  Path(sys.argv[1],'crash-job.json').write_text(json.dumps(job.to_dict()))
  os._exit(0)
 time.sleep(.02)
os._exit(1)
'''
    worker=None
    try:
        result=subprocess.run([sys.executable,'-c',script,str(tmp_path),url],capture_output=True,text=True,timeout=10)
        assert result.returncode==0,result.stderr
        data=json.loads((tmp_path/'crash-job.json').read_text())
        worker=psutil.Process(data['pid']);worker.create_time()
        rt=HexStrikeRuntime(state_dir=tmp_path)
        assert rt.store.get_job(data['job_id']).state.value=='interrupted'
        assert not worker.is_running() or worker.status()==psutil.STATUS_ZOMBIE
        assert not rt.store.list_jobs(state='running')
    finally:
        gate.set()
        if worker is not None:
            try: worker.kill();worker.wait(2)
            except (psutil.NoSuchProcess,psutil.TimeoutExpired): pass


def test_oversized_tool_line_retains_bounded_evidence_prefix():
    from hexstrike.execution.runner import SafeSubprocessRunner
    budget=32768
    result=SafeSubprocessRunner(max_output_bytes=budget).run(
        [sys.executable,'-c',"print('PREFIX-' + 'X'*1000000)"],timeout=5)
    assert result.success and result.truncated
    assert result.stdout.startswith('PREFIX-')
    assert 0 < len(result.stdout.encode()) <= budget


def test_job_marks_truncated_tool_output_as_partial(tmp_path):
    from hexstrike.adapters.catalog import CustomAdapterManifest
    rt=HexStrikeRuntime(state_dir=tmp_path)
    rt.runner.max_output_bytes=32768
    rt.registry.register_custom_adapter(CustomAdapterManifest.from_dict({
        'capability_id':'custom.large_output','name':'Large output fixture','category':'custom',
        'binary_name':'echo','description':'Bounded output test','arg_template':['PREFIX-'+'X'*100000],
        'parameters':{},'required':[],'requires_network':False,
    }))
    result=rt.job_start(capability_id='custom.large_output',arguments={})
    assert result['success'] and result.get('partial'),result
    assert result['job']['structured_output']['_output_truncated'] is True
    assert result['job']['evidence_ids']


def test_offline_adapter_rejects_file_outside_workspace(tmp_path):
    outside = tmp_path / 'outside.txt'
    outside.write_text('harmless-confidential-fixture')
    rt = HexStrikeRuntime(state_dir=tmp_path / 'state')
    with pytest.raises(Exception, match='[Ww]orkspace|[Aa]bsolute|[Cc]onfinement'):
        rt.action_prepare('binary.strings', arguments={'target': str(outside)})


def test_burst_output_is_complete_with_slow_telemetry(tmp_path):
    import time
    from hexstrike.adapters.catalog import CustomAdapterManifest

    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.registry.register_custom_adapter(CustomAdapterManifest.from_dict({
        'capability_id': 'custom.burst', 'name': 'Burst fixture', 'category': 'custom',
        'binary_name': 'python3', 'description': 'Output collection fixture',
        'arg_template': ['-c', "for i in range(1800): print(f'row-{i:06d}:' + 'x'*80)"],
        'parameters': {}, 'required': [], 'requires_network': False,
    }))
    original = rt.store.append_event
    previews = []

    def slow_preview(**kwargs):
        if kwargs['event_type'].startswith('stream_'):
            previews.append(kwargs)
            time.sleep(0.015)
        return original(**kwargs)

    with patch.object(rt.store, 'append_event', side_effect=slow_preview):
        result = rt.job_start(capability_id='custom.burst', arguments={}, timeout_seconds=40)
    assert result['success'], result
    expected = ''.join(f'row-{i:06d}:' + 'x'*80 + '\n' for i in range(1800))
    evidence = rt.store.list_evidence(job_id=result['job']['job_id'])
    stdout = next(e for e in evidence if e.kind == 'stdout')
    assert (rt.workspace.base_dir / stdout.artifact_id).read_text() == expected
    assert len(previews) < 20


@pytest.mark.parametrize('flag', ['-d', '--depth'])
def test_feroxbuster_depth_argument_is_tool_specific(flag):
    from hexstrike.adapters.catalog import build_default_adapters, validate_safe_extra_flags
    from hexstrike.policy.engine import PolicyViolationError

    adapter = next(a for a in build_default_adapters() if a.descriptor.capability_id == 'web.feroxbuster')
    argv = adapter.build_argv('run', {'target': 'http://127.0.0.1', 'extra_flags': [flag, '1']})
    assert argv[-2:] == [flag, '1']
    with pytest.raises(PolicyViolationError):
        adapter.build_argv('run', {'target': 'http://127.0.0.1', 'extra_flags': [flag, 'other.example']})
    with pytest.raises(PolicyViolationError):
        validate_safe_extra_flags([flag, '1'])


def _checkov_report(kind, check_id, errors=0):
    return {'check_type': kind, 'summary': {'failed': 1, 'parsing_errors': errors},
            'results': {'failed_checks': [{'check_id': check_id, 'check_name': 'Fixture check',
                         'file_path': '/' + kind, 'resource': 'fixture',
                         'check_result': {'result': 'FAILED'}}]}}


@pytest.mark.parametrize('multiple', [False, True])
def test_checkov_parses_single_and_multiple_framework_reports(multiple):
    from hexstrike.adapters.catalog import parse_structured_cli_output
    reports = [_checkov_report('dockerfile', 'CKV_DOCKER_7'),
               _checkov_report('terraform', 'CKV_AWS_20')]
    payload = reports if multiple else reports[0]
    data, findings = parse_structured_cli_output('cloud.checkov', json.dumps(payload),
                                                'iac', 'eng', 'job', 'WSTG-CONF-01')
    assert data['failed_count'] == len(findings) == (2 if multiple else 1)
    assert all(f.state == FindingState.CANDIDATE for f in findings)


@pytest.mark.parametrize('exit_code,errors,completed', [(1, 0, True), (1, 1, False), (2, 0, False)])
def test_checkov_findings_exit_is_not_an_execution_failure(tmp_path, exit_code, errors, completed):
    from hexstrike.adapters.catalog import StandardCliScannerAdapter
    rt = HexStrikeRuntime(state_dir=tmp_path)
    payload = json.dumps([_checkov_report('dockerfile', 'CKV_DOCKER_7', errors),
                          _checkov_report('terraform', 'CKV_AWS_20')])
    adapter = StandardCliScannerAdapter(
        'cloud.checkov', 'Checkov contract fixture', 'cloud', 'cloud', 'python3',
        'Checkov process exit contract',
        lambda exe, args, extra: [exe, '-c', f'import sys; print({payload!r}); sys.exit({exit_code})'],
        requires_network=False,
    )
    rt.registry.register_adapter(adapter)
    result = rt.job_start(capability_id='cloud.checkov', arguments={'target': 'iac'})
    assert (result['job']['state'] == 'completed') is completed
    assert result['job']['exit_code'] == exit_code
    assert len(result['job']['finding_ids']) == 2


def test_trivy_misconfiguration_findings_exclude_passing_and_skipped_checks():
    from hexstrike.adapters.catalog import parse_structured_cli_output
    payload = {'Results': [{'Target': 'Dockerfile', 'Misconfigurations': [
        {'ID': 'DS-0001', 'Title': 'Latest image tag', 'Status': 'FAIL', 'Severity': 'MEDIUM',
         'Message': 'Pin the base image', 'Resolution': 'Use a versioned tag'},
        {'ID': 'DS-0002', 'Title': 'Root user', 'Status': 'PASS', 'Severity': 'HIGH'},
        {'ID': 'DS-0003', 'Title': 'Skipped check', 'Status': 'EXCEPTION', 'Severity': 'HIGH'},
    ]}, {'Target': 'pod.yaml', 'Misconfigurations': [
        {'ID': 'KSV-0017', 'Title': 'Privileged container', 'Status': 'FAIL', 'Severity': 'HIGH'}
    ]}]}
    data, findings = parse_structured_cli_output('cloud.trivy', json.dumps(payload),
                                                'iac', 'eng', 'job', 'WSTG-CONF-01')
    assert data['misconfiguration_count'] == len(findings) == 2
    assert data['vulnerability_count'] == 0
    assert [f.target for f in findings] == ['Dockerfile', 'pod.yaml']
    assert [f.severity for f in findings] == [Severity.MEDIUM, Severity.HIGH]
    assert findings[0].remediation == 'Use a versioned tag'


@pytest.mark.parametrize('condition', ['invalid_json', 'empty', 'count_mismatch', 'timeout', 'cancelled', 'truncated'])
def test_checkov_does_not_mask_incomplete_or_invalid_execution(condition):
    from hexstrike.adapters.catalog import build_default_adapters
    from hexstrike.execution.runner import ExecutionResult
    adapter = next(a for a in build_default_adapters() if a.descriptor.capability_id == 'cloud.checkov')
    report = _checkov_report('dockerfile', 'CKV_DOCKER_7')
    if condition == 'count_mismatch':
        report['summary']['failed'] = 10
    stdout = {'invalid_json': '{', 'empty': '[]'}.get(condition, json.dumps(report))
    result = ExecutionResult(success=False, return_code=1, stdout=stdout, stderr='', execution_time=0.1,
                             timed_out=condition == 'timeout', cancelled=condition == 'cancelled',
                             truncated=condition == 'truncated')
    assert not adapter.execution_succeeded(result)
