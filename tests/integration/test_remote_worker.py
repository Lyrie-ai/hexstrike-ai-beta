"""Opt-in SSH worker acceptance using operator-supplied connection settings."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.execution.runner import SshWorkerBridge


WORKER_TARGET = os.environ.get("HEXSTRIKE_TEST_SSH_TARGET", "")


def _is_worker_reachable() -> bool:
    if os.environ.get("HEXSTRIKE_RUN_REMOTE_TESTS") != "1" or not WORKER_TARGET:
        return False
    bridge = SshWorkerBridge(ssh_target=WORKER_TARGET)
    probe = bridge.probe_worker(tool_names=["nmap", "httpx"])
    return bool(probe.get("reachable"))


@pytest.mark.skipif(not _is_worker_reachable(), reason="Remote test requires HEXSTRIKE_RUN_REMOTE_TESTS=1 and a reachable HEXSTRIKE_TEST_SSH_TARGET")
def test_remote_worker_nmap_execution(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)

    rt.engagement_manage(
        action="configure",
        engagement_id="default",
        worker_target=WORKER_TARGET,
    )

    res_nmap = rt.job_start(
        capability_id="network.nmap",
        operation="scan",
        arguments={"target": "127.0.0.1", "profile": "quick", "ports": "22"},
    )
    assert res_nmap["success"] is True
    job = res_nmap["job"]
    assert job["worker_target"] == WORKER_TARGET
    assert job["state"] == "completed"
    assert job["structured_output"]["parsed_xml"] is True

    # Verify live telemetry events were recorded for the TUI/CLI monitor
    events = rt.store.get_events(engagement_id="default", job_id=job["job_id"])
    assert len(events) >= 2


def test_worker_uses_account_path_and_never_guesses_container(tmp_path):
    import base64
    import json
    import subprocess
    import sys
    from hexstrike.execution.runner import REMOTE_WORKER_HARNESS
    binaries = tmp_path / 'custom tools'
    binaries.mkdir()
    command = binaries / 'unregistered-tool'
    command.write_text('#!/bin/sh\nprintf "account-tool:%s" "$HOME"\n')
    command.chmod(0o700)
    docker = binaries / 'docker'
    marker = tmp_path / 'docker-was-invoked'
    docker.write_text(f'#!/bin/sh\ntouch "{marker}"\nprintf "kali-container\\n"\n')
    docker.chmod(0o700)
    environment = {'PATH': str(binaries) + os.pathsep + os.defpath, 'HOME': str(tmp_path)}
    def call(argv):
        payload = base64.b64encode(json.dumps({'argv': argv, 'timeout': 3}).encode()).decode()
        with subprocess.Popen([sys.executable, '-c', REMOTE_WORKER_HARNESS, payload],
                              env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                frame = json.loads(line)
                if frame.get('type') == 'result':
                    process.wait(timeout=10)
                    return frame
        raise AssertionError('Worker did not return a result')
    result = call(['unregistered-tool'])
    assert 'account-tool:' + str(tmp_path) in json.dumps(result)
    missing = call(['tool-that-does-not-exist'])
    assert not missing.get('success', False)
    assert not marker.exists()
