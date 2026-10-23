"""Behavioral regression checks using isolated local fixtures."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from hexstrike.adapters.catalog import parse_structured_cli_output
from hexstrike.application.services import HexStrikeRuntime, resolve_default_state_dir
from hexstrike.cli.main import backup_state_dir, main as cli_main, restore_state_dir
from hexstrike.config.client_connectors import ClientConfigManager
from hexstrike.domain.models import Evidence
from hexstrike.policy.engine import PolicyViolationError
from hexstrike.transports.http_server import create_http_app
from hexstrike.workflows.engine import correlate_threat_indicators


def test_graph_match_predicate_is_enforced_or_explicitly_unsupported(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.memory.record_episode(
        "default",
        "observation",
        "10.10.10.5:8080",
        "This stored fact must not match WHERE false",
        relations=[("10.10.10.5", "exposes", "http_8080")],
    )
    driver = rt.memory.graphiti_adapter.driver
    assert driver is not None

    # 1. WHERE false must return empty list, and literal projection RETURN 1 AS n must return [{'n': 1}]
    lit_rows, _, _ = asyncio.run(driver.execute_query("RETURN 1 AS n"))
    assert lit_rows == [{"n": 1}]
    rows_false, _, _ = asyncio.run(driver.execute_query("MATCH (n) WHERE false RETURN n"))
    assert rows_false == [], "Accepted MATCH query ignored its WHERE predicate"

    # 2. WHERE true and property comparisons must filter accurately
    rows_true, _, _ = asyncio.run(
        driver.execute_query("MATCH (n) WHERE n.group_id = 'default' AND n.fact CONTAINS 'stored fact' RETURN n.name AS name")
    )
    assert len(rows_true) >= 1
    assert rows_true[0]["name"] == "observation"

    rows_mismatch, _, _ = asyncio.run(
        driver.execute_query("MATCH (n) WHERE n.group_id = 'nonexistent_group' RETURN n")
    )
    assert rows_mismatch == []

    # 3. Directed relationship pattern MATCH (a)-[r]->(b) WHERE ... RETURN ...
    rel_rows, _, _ = asyncio.run(
        driver.execute_query(
            "MATCH (a)-[r:exposes]->(b) WHERE a.name = '10.10.10.5' RETURN a.name AS src, r.name AS rel, b.name AS dst"
        )
    )
    assert rel_rows == [{"src": "10.10.10.5", "rel": "exposes", "dst": "http_8080"}]

    # 4. COUNT(*) aggregation
    cnt_rows, _, _ = asyncio.run(
        driver.execute_query("MATCH (n) WHERE n.group_id = 'default' RETURN count(*) AS total")
    )
    assert cnt_rows[0]["total"] >= 1

    # 5. Unsupported Cypher clauses (MERGE, CREATE, CALL, OPTIONAL MATCH) raise NotImplementedError
    with pytest.raises(NotImplementedError):
        asyncio.run(driver.execute_query("MERGE (n:Entity {name: 'x'}) RETURN n"))


def test_unknown_intelligence_does_not_invent_metrics_when_simulation_disabled(tmp_path: Path) -> None:
    result = correlate_threat_indicators(["CVE-2099-999999"], include_simulated=False)
    rows = result.get("correlations", [])
    assert not any(r.get("simulated") for r in rows), result
    assert all(r.get("cvss_score") is None and r.get("epss_score") is None for r in rows), result
    assert rows[0]["status"] == "unavailable"
    assert rows[0]["available"] is False

    # Positive control: versioned local cache with provenance, source filtering, and timeframe check
    cache_file = tmp_path / "feed_cache.json"
    cache_file.write_text(
        json.dumps(
            {
                "records": {
                    "CVE-2024-3094": {
                        "cve_id": "CVE-2024-3094",
                        "title": "XZ Utils liblzma backdoor",
                        "cvss_score": 10.0,
                        "epss_score": 0.64,
                        "kev_listed": False,
                        "exploits_found": 2,
                        "source": "nvd+epss",
                        "snapshot_date": "2026-10-15",
                        "simulated": False,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    verified = correlate_threat_indicators(
        ["CVE-2024-3094"],
        sources="nvd",
        cache_path=cache_file,
        include_simulated=False,
    )
    c_row = verified["correlations"][0]
    assert c_row["status"] == "verified"
    assert c_row["cvss_score"] == 10.0
    assert c_row["epss_score"] is None  # Filtered out because sources="nvd"
    assert c_row["provenance"]["cache_file_sha256"]


def test_binary_evidence_pagination_reaches_beyond_four_megabytes(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    offset = 4 * 1024 * 1024
    payload = b"A" * offset + b"EXPECTED_FINAL_BYTES"
    saved = rt.workspace.save_artifact("default", "r5-large", payload, extension="bin")
    assert saved["success"], saved
    ev = Evidence(
        evidence_id="r5-evidence",
        engagement_id="default",
        job_id="r5-job",
        capability_id="fixture.binary",
        kind="binary",
        summary="local pagination fixture",
        artifact_id=saved["path"],
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        content_preview="[binary fixture]",
    )
    rt.store.save_evidence(ev)
    result = rt.evidence_read(evidence_id=ev.evidence_id, offset=offset, limit=128)
    assert result["success"], result
    assert base64.b64decode(result["content"]) == b"EXPECTED_FINAL_BYTES", result
    assert result["total_bytes"] == len(payload) and result["integrity_verified"], result

    # Tamper with artifact on disk and verify corruption is explicitly reported
    art_full_path = rt.workspace.base_dir / saved["path"]
    art_full_path.write_bytes(b"CORRUPTED_BYTES")
    tampered = rt.evidence_read(evidence_id=ev.evidence_id, offset=0, limit=64)
    assert tampered["success"] is False
    assert tampered["integrity_verified"] is False
    assert tampered["corrupted"] is True
    assert tampered["code"] == "ARTIFACT_CORRUPTED"


def test_built_wheel_mcp_job_appears_in_shared_server_tui(tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from textual.widgets import DataTable

    from hexstrike.tui.dashboard import HexStrikeMonitorApp

    repo_root = Path(__file__).resolve().parents[2]
    wheel_dir = tmp_path / "wheelhouse"
    wheel_dir.mkdir(parents=True, exist_ok=True)
    build_proc = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheel_dir), str(repo_root)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert build_proc.returncode == 0, build_proc.stderr
    wheels = list(wheel_dir.glob("hexstrike_ai-*.whl"))
    assert len(wheels) == 1
    installed_dir = tmp_path / "installed_wheel"
    with zipfile.ZipFile(wheels[0]) as zf:
        zf.extractall(installed_dir)

    bootstrap = (
        "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); "
        "import hexstrike; assert hexstrike.__file__.startswith(sys.path[0]); "
        "runpy.run_module('hexstrike.transports.mcp_stdio',run_name='__main__')"
    )

    def payload(result: Any) -> Any:
        assert not getattr(result, "isError", getattr(result, "is_error", False)), result
        data = getattr(result, "structuredContent", getattr(result, "structured_content", None))
        if not isinstance(data, dict):
            data = json.loads(result.content[0].text)
        return data.get("result", data)

    state_dir = tmp_path / "shared_state"

    async def exercise() -> None:
        observer = HexStrikeRuntime(state_dir=state_dir)
        app = HexStrikeMonitorApp(runtime=observer, poll_interval=0.2)
        params = StdioServerParameters(
            command=sys.executable,
            args=["-I", "-c", bootstrap, str(installed_dir), "--state-dir", str(state_dir)],
            cwd=str(tmp_path),
        )
        async with app.run_test(size=(120, 40)) as pilot:
            async with stdio_client(params) as (reader, writer):
                async with ClientSession(reader, writer) as client:
                    await client.initialize()
                    assert len((await client.list_tools()).tools) == 10
                    result = payload(
                        await client.call_tool(
                            "job_start",
                            {
                                "capability_id": "api.jwt_analyzer",
                                "operation": "analyze",
                                "arguments": {"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."},
                                "wait": True,
                            },
                        )
                    )
                    assert result["success"], result
                    job_id = result["job"]["job_id"]
                    app.refresh_telemetry()
                    await pilot.pause()
                    table = app.query_one("#jobs-table", DataTable)
                    rows = [table.get_row_at(i) for i in range(table.row_count)]
                    assert any(row[0] == job_id and row[3] == "COMPLETED" for row in rows), rows
                    assert observer.store.get_events(job_id=job_id)

    asyncio.run(exercise())


def test_rate_limit_max_rate_per_minute_is_enforced_and_invalid_budgets_rejected(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    with pytest.raises(PolicyViolationError) as exc_info:
        rt.engagement_manage(action="configure", max_rate_per_minute=0)
    assert exc_info.value.code == "INVALID_BUDGET"

    rt.engagement_manage(action="configure", max_rate_per_minute=2)
    jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."
    r1 = rt.job_start(capability_id="api.jwt_analyzer", operation="analyze", arguments={"token": jwt})
    r2 = rt.job_start(capability_id="api.jwt_analyzer", operation="analyze", arguments={"token": jwt})
    assert r1["success"] and r2["success"]

    with pytest.raises(PolicyViolationError) as rate_exc:
        rt.job_start(capability_id="api.jwt_analyzer", operation="analyze", arguments={"token": jwt})
    assert rate_exc.value.code == "RATE_LIMIT_EXCEEDED"


def test_client_connect_topologies_and_state_backup_rollback_uninstall_lifecycle(tmp_path: Path) -> None:
    # 1. Verify default state dir resolves to a persistent path (not /tmp) when writable
    default_dir = resolve_default_state_dir()
    assert "hexstrike" in str(default_dir).lower()

    # 2. Verify client connector supports local, ssh-controller, and remote-http topologies
    mgr = ClientConfigManager()
    cfg_file = tmp_path / "cursor_mcp.json"
    ssh_res = mgr.connect(
        client="cursor",
        config_path=cfg_file,
        topology="ssh-controller",
        ssh_controller_host="operator@worker.example",
        remote_state_dir="/var/lib/hexstrike",
    )
    assert ssh_res["topology"] == "ssh-controller"
    assert ssh_res["entry"]["command"] == "ssh"
    assert "operator@worker.example" in ssh_res["entry"]["args"]
    assert "/var/lib/hexstrike" in ssh_res["entry"]["args"]
    assert "hexstrike --state-dir /var/lib/hexstrike tui" in ssh_res["tui_guidance"]

    http_res = mgr.connect(
        client="vscode",
        config_path=tmp_path / "vscode_mcp.json",
        topology="remote-http",
        remote_http_url="https://worker.example:8888/mcp",
    )
    assert http_res["topology"] == "remote-http"
    assert http_res["entry"]["type"] == "http"
    assert http_res["entry"]["url"] == "https://worker.example:8888/mcp"

    # 3. Verify state backup, modification, and state rollback
    state_dir = tmp_path / "app_state"
    rt = HexStrikeRuntime(state_dir=state_dir)
    rt.engagement_manage(action="configure", name="BeforeBackup")
    b_res = backup_state_dir(state_dir)
    assert b_res["success"]

    rt.engagement_manage(action="configure", name="AfterModification")
    assert rt.store.get_engagement("default").name == "AfterModification"

    r_res = restore_state_dir(state_dir)
    assert r_res["success"]
    assert rt.store.get_engagement("default").name == "BeforeBackup"

    # 4. Verify CLI uninstall with archive and evidence retention vs purge
    arch_dir = tmp_path / "archived_evidence"
    rc = cli_main(["--state-dir", str(state_dir), "uninstall", "--archive-to", str(arch_dir)])
    assert rc == 0
    assert state_dir.exists()  # Retained by default
    assert arch_dir.exists()

    rc_purge = cli_main(["--state-dir", str(state_dir), "uninstall", "--purge-data"])
    assert rc_purge == 0
    assert not state_dir.exists()


def test_remote_http_telemetry_endpoint_and_structured_cli_parsers(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.job_start(
        capability_id="api.jwt_analyzer",
        operation="analyze",
        arguments={"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."},
    )
    app = create_http_app(runtime=rt, api_token="telem-secret-token")
    client = app.test_client()

    # Unauthenticated request rejected
    unauth = client.get("/api/v6/telemetry")
    assert unauth.status_code == 401

    # Authenticated request returns live jobs, findings, and events
    auth_resp = client.get(
        "/api/v6/telemetry?engagement_id=default&since_seq=0",
        headers={"Authorization": "Bearer telem-secret-token"},
    )
    assert auth_resp.status_code == 200
    data = auth_resp.get_json()
    assert data["success"] is True
    assert len(data["jobs"]) == 1
    assert len(data["findings"]) >= 1
    assert len(data["events"]) >= 1

    # Verify structured CLI parsers for Nikto, WAFW00F, Masscan, Checkov, Checksec, ExifTool
    nikto_struct, nikto_finds = parse_structured_cli_output(
        "web.nikto",
        "+ Target IP: 127.0.0.1\n+ /admin/: Admin directory found\n",
        "http://127.0.0.1",
        "default",
        "job_1",
        "WSTG-CONF-04",
    )
    assert nikto_struct["count"] == 1 and len(nikto_finds) == 1

    waf_struct, waf_finds = parse_structured_cli_output(
        "web.wafw00f",
        "[+] The site http://127.0.0.1 is behind Cloudflare WAF.\n",
        "http://127.0.0.1",
        "default",
        "job_2",
        "WSTG-INFO-08",
    )
    assert waf_struct["waf_detected"] is True and waf_struct["waf_name"] == "Cloudflare" and len(waf_finds) == 1

    mass_struct, mass_finds = parse_structured_cli_output(
        "network.masscan",
        "Discovered open port 443/tcp on 10.0.0.1\n",
        "10.0.0.1",
        "default",
        "job_3",
        "WSTG-INFO-02",
    )
    assert mass_struct["count"] == 1 and len(mass_finds) == 1
