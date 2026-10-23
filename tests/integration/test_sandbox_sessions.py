"""Real execution contracts, enabled explicitly where a backend is installed."""
import os
import asyncio
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.execution.sandbox import SandboxManager
from hexstrike.domain.models import Principal
from hexstrike.policy.engine import PolicyViolationError


def test_host_execution_files_network_stdin_and_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXSTRIKE_API_TOKEN", "fixture-server-token")
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    host_dir = tmp_path / "outside-workspace"
    host_dir.mkdir()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"host-network-ok")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    script = """import os,sys,json,pathlib,urllib.request
p=pathlib.Path('created.txt'); p.write_text(sys.stdin.read()); p.write_text(p.read_text()+'-modified')
assert p.read_text()=='hello-modified'; p.rename('renamed.txt'); pathlib.Path('renamed.txt').unlink()
assert 'HEXSTRIKE_API_TOKEN' not in os.environ
network=urllib.request.urlopen(sys.argv[1],timeout=3).read().decode()
print(json.dumps({'network':network,'env':os.environ['FIXTURE_VALUE'],'literal':sys.argv[2]}))
"""
    try:
        result = rt.job_start(capability_id="execution.host", arguments={
            "argv": [sys.executable, "-c", script, f"http://127.0.0.1:{server.server_port}", "$(touch injected); echo nope"],
            "cwd": str(host_dir), "stdin": "hello", "env": {"FIXTURE_VALUE": "passed"}})
        assert result["success"], result
        output = result["job"]["structured_output"]
        assert not output["sandboxed"] and output["network"] == "host"
        assert json.loads(output["stdout_preview"]) == {
            "network": "host-network-ok", "env": "passed", "literal": "$(touch injected); echo nope"}
        assert list(host_dir.iterdir()) == []
        assert result["job"]["evidence_ids"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_host_execution_script_relative_cwd_and_explicit_shell(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    directory = rt.workspace.base_dir / "scripts"
    directory.mkdir()
    (directory / "task.py").write_text("from pathlib import Path;Path('output.txt').write_text('created')")
    result = rt.job_start(capability_id="execution.host", arguments={
        "argv": [sys.executable, "task.py"], "cwd": "scripts"})
    assert result["success"], result
    assert (directory / "output.txt").read_text() == "created"
    if os.name != "nt":
        result = rt.job_start(capability_id="execution.host", arguments={
            "argv": ["/bin/sh", "-c", "printf 'shell-ok' | tr a-z A-Z"]})
        assert result["success"] and result["job"]["structured_output"]["stdout_preview"] == "SHELL-OK"


@pytest.mark.parametrize("argv,expected", [(["hexstrike-nonexistent-fixture-command"], 127),
                                          ([sys.executable, "-c", "raise SystemExit(7)"], 7)])
def test_host_execution_reports_real_command_failure(tmp_path, argv, expected):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(capability_id="execution.host", arguments={"argv": argv})
    assert not result["success"] and result["job"]["state"] == "failed"
    assert result["job"]["exit_code"] == expected


def test_host_execution_timeout_and_cross_runtime_cancel(tmp_path):
    import psutil
    rt = HexStrikeRuntime(state_dir=tmp_path)
    timed = rt.job_start(capability_id="execution.host", arguments={
        "argv": [sys.executable, "-c", "import time;time.sleep(60)"]}, timeout_seconds=.3)
    assert timed["job"]["state"] == "timed_out", timed
    script = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); print(p.pid,flush=True);time.sleep(60)"
    pending = rt.job_start(capability_id="execution.host", arguments={"argv": [sys.executable, "-c", script]}, wait=False)
    job_id = pending["job"]["job_id"]
    deadline = time.monotonic() + 5
    children = []
    while time.monotonic() < deadline:
        job = rt.store.get_job(job_id)
        if job.pid:
            children = psutil.Process(job.pid).children()
        if children:
            break
        time.sleep(.05)
    assert children
    second = HexStrikeRuntime(state_dir=tmp_path)
    second.job_cancel(job_id)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if all(not child.is_running() or child.status() == psutil.STATUS_ZOMBIE for child in children):
            break
        time.sleep(.05)
    assert all(not child.is_running() or child.status() == psutil.STATUS_ZOMBIE for child in children)
    assert second.store.get_job(job_id).state.value == "cancelled"


def test_host_execution_requires_operator_and_valid_arguments(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    viewer = Principal("local_operator", "Viewer", role="viewer")
    with pytest.raises(PolicyViolationError, match="operator"):
        rt.action_prepare("execution.host", arguments={"argv": [sys.executable]}, principal=viewer)
    with pytest.raises(PolicyViolationError):
        rt.action_prepare("execution.host", arguments={"argv": [sys.executable, {"invalid": True}]})
    with pytest.raises(PolicyViolationError, match="connected MCP server"):
        rt.action_prepare("execution.host", arguments={"argv": [sys.executable]}, worker_target="other")
    with pytest.raises(PolicyViolationError, match="working directory"):
        rt.action_prepare("execution.host", arguments={"argv": [sys.executable], "cwd": "missing-dir"})
    with pytest.raises(PolicyViolationError, match="must not be empty"):
        rt.action_prepare("execution.host", arguments={"argv": [""]})


@pytest.mark.skipif(os.name != "posix", reason="Executable fixture uses a POSIX shebang")
def test_host_executes_new_unregistered_tool_from_relative_path(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state", workspace_dir=tmp_path / "custom-work")
    bin_dir = rt.workspace.base_dir / "bin"
    bin_dir.mkdir()
    program = bin_dir / "unregistered-fixture"
    program.write_text("#!/bin/sh\nprintf 'unregistered-tool-ok'")
    program.chmod(0o700)
    result = rt.job_start(capability_id="execution.host", arguments={
        "argv": [program.name], "env": {"PATH": "bin"}})
    assert result["success"], result
    assert result["job"]["structured_output"]["stdout_preview"] == "unregistered-tool-ok"
    assert result["job"]["structured_output"]["cwd"] == str(rt.workspace.base_dir)
    session = host_invoke(rt, "start", argv=[sys.executable, "-c", "from pathlib import Path;print(Path.cwd())"], timeout=5)
    output = host_until(rt, session["session_id"], lambda item: item["state"] == "completed")
    assert str(rt.workspace.base_dir) in output["stdout"]["content"]


def host_invoke(rt, operation, **arguments):
    result = rt.job_start(capability_id="execution.host", operation=operation, arguments=arguments)
    assert result["success"], result
    return result["job"]["structured_output"]


def host_until(rt, session_id, predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output = host_invoke(rt, "status", session_id=session_id)
        if predicate(output):
            return output
        time.sleep(.05)
    pytest.fail(f"Host session did not reach expected state: {output}")


@pytest.mark.skipif(os.name != "posix", reason="Durable host sessions require POSIX")
def test_host_pipe_session_reconnect_input_eof_and_evidence(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    session = host_invoke(rt, "start", argv=[sys.executable, "-u", "-c", "import sys;print('ready');print(sys.stdin.read())"], timeout=10)
    sid = session["session_id"]
    try:
        rejected = rt.job_start(capability_id="execution.sandbox", operation="start", arguments={
            "environment_id": session["environment_id"], "argv": [sys.executable, "-c", "print('must-not-run')"]})
        assert not rejected["success"] and "execution.host" in rejected["job"]["error_message"]
        second = HexStrikeRuntime(state_dir=tmp_path)
        host_until(second, sid, lambda output: "ready" in output["stdout"]["content"])
        assert any(item["session_id"] == sid for item in second.system_status()["detached_sessions"])
        host_invoke(second, "stdin", session_id=sid, data="reconnected-input\n")
        host_invoke(second, "eof", session_id=sid)
        output = host_until(second, sid, lambda output: output["state"] == "completed")
        assert "reconnected-input" in output["stdout"]["content"] and output["exit_code"] == 0
        assert output["evidence_ids"]
        for _ in range(2):
            stopped = host_invoke(second, "cancel", session_id=sid)
            assert stopped["accepted"] and stopped["already_terminal"] and stopped["state"] == "completed"
        assert host_invoke(second, "status", session_id=sid)["stdout"] == output["stdout"]
        assert all(second.store.get_evidence(eid).capability_id == "execution.host" for eid in output["evidence_ids"])
    finally:
        rt.job_cancel(cancel_all=True)


@pytest.mark.skipif(os.name != "posix", reason="PTY sessions require POSIX")
def test_host_pty_repl_preserves_state_and_accepts_interrupt(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    session = host_invoke(rt, "start", argv=[sys.executable, "-u", "-i", "-q"], tty=True, timeout=20)
    sid = session["session_id"]
    try:
        host_until(rt, sid, lambda output: ">>>" in output["stdout"]["content"])
        host_invoke(rt, "stdin", session_id=sid, data="value=17\n")
        second = HexStrikeRuntime(state_dir=tmp_path)
        host_invoke(second, "stdin", session_id=sid, data="print('answer',value+25)\n")
        host_until(second, sid, lambda output: "answer 42" in output["stdout"]["content"])
        host_invoke(second, "resize", session_id=sid, rows=40, columns=100)
        host_invoke(second, "stdin", session_id=sid, data="import os;print('terminal-size',os.get_terminal_size().columns)\n")
        host_until(second, sid, lambda output: "terminal-size 100" in output["stdout"]["content"])
        host_invoke(second, "stdin", session_id=sid, data="import time;time.sleep(60)\n")
        time.sleep(.2)
        host_invoke(second, "stdin", session_id=sid, data="\x03")
        host_until(second, sid, lambda output: "KeyboardInterrupt" in output["stdout"]["content"])
        host_invoke(second, "stdin", session_id=sid, data="exit()\n")
        output = host_until(second, sid, lambda output: output["state"] == "completed")
        assert output["tty"] and output["exit_code"] == 0
    finally:
        rt.job_cancel(cancel_all=True)


@pytest.mark.skipif(os.name != "posix", reason="Durable host sessions require POSIX")
def test_host_session_timeout_and_group_cancellation(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    slow = host_invoke(rt, "start", argv=[sys.executable, "-c", "import time;time.sleep(60)"], timeout=1)
    host_until(rt, slow["session_id"], lambda output: output["state"] == "timed_out")
    tree = host_invoke(rt, "start", argv=["/bin/sh", "-c", "sleep 60 & wait"], timeout=10)
    host_invoke(rt, "cancel", session_id=tree["session_id"])
    host_until(rt, tree["session_id"], lambda output: output["state"] == "cancelled")


@pytest.mark.skipif(os.name != "posix", reason="Durable host sessions require POSIX")
def test_host_session_large_output_is_bounded_and_paginated(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    session = host_invoke(rt, "start", argv=[sys.executable, "-c", "print('0123456789'*90000)"], timeout=10)
    output = host_until(rt, session["session_id"], lambda output: output["state"] == "completed")
    assert output["output_truncated"] and output["stdout"]["total_bytes"] == 512 * 1024
    page = host_invoke(rt, "status", session_id=session["session_id"], offset=101, limit=13)
    assert page["stdout"]["content"] == "1234567890123"
    assert page["stdout"]["next_offset"] == 114 and page["stdout"]["has_more"]


def invoke(rt, operation, **arguments):
    result = rt.job_start(capability_id="execution.sandbox", operation=operation, arguments=arguments)
    assert result["success"], result
    return result["job"]["structured_output"]


def terminal(rt, handle, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = invoke(rt, "status", session_id=handle)
        if data["state"] in ("completed", "cancelled", "timed_out"):
            return data
        time.sleep(.15)
    pytest.fail(f"Session did not terminate: {data}")


def test_execution_backend_missing_fails_without_host_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "")
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(capability_id="execution.sandbox", operation="create", arguments={"backend": "docker", "image": "example:local"})
    assert not result["success"]
    assert "not installed" in result["job"]["error_message"]


def test_nested_execution_arguments_rejected_before_persistence(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    from hexstrike.policy.engine import PolicyViolationError
    with pytest.raises(PolicyViolationError):
        rt.action_prepare("execution.sandbox", "start", {"environment_id": "a" * 32, "argv": ["python3", {"invalid": True}]})


@pytest.mark.skipif(not os.environ.get("HEXSTRIKE_TEST_SANDBOX"), reason="Set HEXSTRIKE_TEST_SANDBOX and HEXSTRIKE_TEST_IMAGE for real backend verification")
def test_sandbox_lifecycle_reconnect_stdin_limits_and_confinement(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    environment = invoke(rt, "create", backend=os.environ["HEXSTRIKE_TEST_SANDBOX"], image=os.environ.get("HEXSTRIKE_TEST_IMAGE", ""))
    handle = environment["environment_id"]
    (tmp_path / "server-secret").write_text("must-not-be-visible")
    script = '''import os, pathlib, socket
print("ready", flush=True)
value = input()
assert not pathlib.Path("SERVER_SECRET_PATH").exists()
assert not pathlib.Path("/var/run/docker.sock").exists()
pathlib.Path("result.txt").write_text(value)
print("received:" + value, flush=True)
'''.replace("SERVER_SECRET_PATH", str(tmp_path / "server-secret"))
    invoke(rt, "file_write", environment_id=handle, path="check.py", content=script)
    session = invoke(rt, "start", environment_id=handle, argv=["python3", "check.py"], timeout=15)
    sid = session["session_id"]
    # A new runtime reconnects to the original process, not a replacement command.
    second = HexStrikeRuntime(state_dir=tmp_path)
    invoke(second, "stdin", session_id=sid, data="hello\n")
    result = terminal(second, sid)
    assert result["exit_code"] == 0
    assert "received:hello" in result["stdout"]["content"]
    assert invoke(second, "file_read", environment_id=handle, path="result.txt")["content"] == "hello"
    blocked = second.job_start(capability_id="execution.sandbox", operation="file_read", arguments={"environment_id": handle, "path": "../server-secret"})
    assert not blocked["success"]
    with pytest.raises(ValueError, match="not found"):
        SandboxManager(tmp_path, "different-engagement").status(sid)
    from hexstrike.http.client import AuthenticationStore
    AuthenticationStore(tmp_path).put_execution("fixture-secret", "sensitive-env-value")
    secret_job = invoke(second, "start", environment_id=handle, env_refs={"TEST_VALUE": "fixture-secret"},
                        argv=["python3", "-c", "import os;print(os.environ['TEST_VALUE'])"], timeout=10)
    secret_result = terminal(second, secret_job["session_id"])
    assert "sensitive-env-value" not in str(secret_result)
    assert "[REDACTED_SECRET]" in secret_result["stdout"]["content"]
    noisy = invoke(second, "start", environment_id=handle, argv=["python3", "-c", "print('x'*900000)"], timeout=10)
    noisy_result = terminal(second, noisy["session_id"])
    assert noisy_result["output_truncated"]
    assert noisy_result["stdout"]["total_bytes"] == 512 * 1024
    slow = invoke(second, "start", environment_id=handle, argv=["python3", "-c", "import time;time.sleep(60)"], timeout=1)
    assert terminal(second, slow["session_id"])["state"] == "timed_out"
    tree = invoke(second, "start", environment_id=handle, argv=["/bin/sh", "-c", "sleep 60 & wait"], timeout=15)
    invoke(second, "cancel", session_id=tree["session_id"])
    assert terminal(second, tree["session_id"])["state"] == "cancelled"
    if os.environ["HEXSTRIKE_TEST_SANDBOX"] in ("docker", "podman"):
        limits = invoke(second, "start", environment_id=handle, argv=["python3", "-c",
            "from pathlib import Path;p=Path('/sys/fs/cgroup');assert (p/'memory.max').read_text().strip()=='536870912';assert (p/'pids.max').read_text().strip()=='64';q,t=(p/'cpu.max').read_text().split();assert q!='max' and int(q)==int(t);print('limits-enforced')"], timeout=10)
        assert terminal(second, limits["session_id"])["exit_code"] == 0
    input_session = invoke(second, "start", environment_id=handle, argv=["python3", "-c", "import sys;print(sys.stdin.read())"], timeout=15)
    invoke(second, "stdin", session_id=input_session["session_id"], data="ordered-input")
    invoke(second, "eof", session_id=input_session["session_id"])
    late = second.job_start(capability_id="execution.sandbox", operation="stdin", arguments={"session_id": input_session["session_id"], "data": "late"})
    assert not late["success"]
    assert "ordered-input" in terminal(second, input_session["session_id"])["stdout"]["content"]
    final = invoke(second, "start", environment_id=handle, argv=["python3", "-c", "import time;time.sleep(60)"], timeout=15)
    assert any(item["session_id"] == final["session_id"] for item in second.system_status()["detached_sessions"])
    from hexstrike.tui.dashboard import HexStrikeMonitorApp
    from textual.widgets import DataTable, TabbedContent

    async def stop_from_monitor():
        app = HexStrikeMonitorApp(runtime=second, poll_interval=.2)
        async with app.run_test(size=(100, 35)) as pilot:
            app.query_one(TabbedContent).active = "tab-sessions"
            await pilot.pause()
            table = app.query_one("#sessions-table", DataTable)
            assert any(table.get_row_at(i)[0] == final["session_id"] for i in range(table.row_count))
            await pilot.press("ctrl+x")
            await app.workers.wait_for_complete()
    asyncio.run(stop_from_monitor())
    assert terminal(second, final["session_id"])["state"] == "cancelled"
    invoke(second, "remove", environment_id=handle)
