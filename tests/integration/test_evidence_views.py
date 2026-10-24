"""Evidence accuracy and compact transport results."""
import hashlib
import json

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.domain.models import Evidence, Finding, FindingState, Severity
from hexstrike.reporting.responses import compact_job_response
from hexstrike.workspace.confined_fs import redact_secrets


def test_repeated_finding_keeps_review_and_merges_evidence(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    first = Finding("first", "default", "job-a", "Header missing", Severity.LOW, FindingState.OBSERVATION, "https://example.org", "web.http_inspect", "same observation", evidence_ids=["a"])
    rt.store.record_finding(first)
    first.state = FindingState.REJECTED_FALSE_POSITIVE
    rt.store.save_finding(first)
    repeated = Finding("second", "default", "job-b", "Header missing", Severity.LOW, FindingState.OBSERVATION, "https://example.org", "web.http_inspect", "same observation", evidence_ids=["b"])
    rt.store.record_finding(repeated)
    assert repeated.finding_id == "first"
    assert rt.store.count_findings("default") == 1
    saved = rt.store.list_findings("default")[0]
    assert saved.state == FindingState.REJECTED_FALSE_POSITIVE
    assert saved.evidence_ids == ["a", "b"] and saved.job_id == "job-a"


def test_har_queries_and_corruption_checks(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    har = json.dumps({"log": {"entries": [
        {"request": {"url": "https://example.org/api", "method": "POST"}, "response": {"status": 401}},
        {"request": {"url": "https://example.org/style", "method": "GET"}, "response": {"status": 200}},
    ]}})
    path = rt.workspace.save_artifact("default", "fixture-har", har, extension="har")["path"]
    rt.store.save_evidence(Evidence("har", "default", "job", "browser.inspect", "har", "test", path, hashlib.sha256(har.encode()).hexdigest(), len(har), ""))
    result = rt.evidence_read("har", view="har", status_code=401, method="POST")
    assert result["total_matches"] == 1 and result["entries"][0]["url"].endswith("/api")
    rt.workspace.modify_file(path, "corrupted")
    import pytest
    with pytest.raises(ValueError, match="corrupted"):
        rt.evidence_read("har", view="har")


def test_compact_results_preserve_handles_and_remove_control_sequences():
    result = compact_job_response({"job": {"job_id": "job", "structured_output": {"large": "x" * 100000}, "evidence_ids": ["evidence"]}})
    assert result["job"]["structured_output"]["_omitted"]
    assert result["job"]["evidence_ids"] == ["evidence"]
    assert len(json.dumps(result)) < 1000
    assert redact_secrets("\x1b[31mred\x1b[0m\x1b]8;;https://untrusted\x07link\x1b]8;;\x07") == "redlink"


def test_screenshot_resource_returns_verified_bytes_over_mcp(tmp_path):
    import asyncio
    import base64
    import sys
    from pathlib import Path
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    rt = HexStrikeRuntime(state_dir=tmp_path)
    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a3ioAAAAASUVORK5CYII=")
    path = rt.workspace.save_artifact("default", "png-fixture", png, extension="png")["path"]
    rt.store.save_evidence(Evidence("image_fixture", "default", "job", "browser.inspect", "screenshot", "fixture", path, hashlib.sha256(png).hexdigest(), len(png), "", provenance={"mime_type": "image/png"}))
    source = str(Path(__file__).resolve().parents[2] / "src")
    bootstrap = "import sys;sys.path.insert(0,sys.argv.pop(1));from hexstrike.transports.mcp_stdio import main;main()"
    async def exercise():
        params = StdioServerParameters(command=sys.executable, args=["-I", "-c", bootstrap, source, "--state-dir", str(tmp_path)])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                assert len((await client.list_tools()).tools) == 10
                result = await client.read_resource("hexstrike://evidence/image_fixture/image")
                assert base64.b64decode(result.contents[0].blob) == png
    asyncio.run(exercise())


def test_workspace_patch_checks_exact_occurrence_and_source_digest(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    created = rt.workspace.create_file("program.py", "print('old')\n")
    result = rt.job_start(capability_id="workspace.files", operation="patch", arguments={"path": "program.py", "old_text": "old", "new_text": "new", "expected_sha256": created["sha256"]})
    assert result["success"], result
    stale = rt.job_start(capability_id="workspace.files", operation="patch", arguments={"path": "program.py", "old_text": "new", "new_text": "wrong", "expected_sha256": created["sha256"]})
    assert not stale["success"]
    found = rt.job_start(capability_id="workspace.files", operation="search", arguments={"path": "program.py", "query": "new"})
    assert found["job"]["structured_output"]["matches"] == [{"line": 1, "text": "print('new')"}]


def test_backup_restores_authentication_and_research_configuration(tmp_path):
    from pathlib import Path
    from hexstrike.application.state import backup_state_dir, restore_state_dir
    from hexstrike.http.client import AuthenticationStore
    state = tmp_path / "state"
    HexStrikeRuntime(state_dir=state)
    auth = AuthenticationStore(state)
    auth.put("example", {"origins": ["https://example.org"], "headers": {"Authorization": "fixture-secret"}})
    (state / "research.json").write_text('{"allow_private_networks":false}')
    snapshot = backup_state_dir(state)
    auth.put("example", {"origins": ["https://example.org"], "headers": {"Authorization": "changed"}})
    restored = restore_state_dir(state, Path(snapshot["backup_dir"]))
    assert restored["success"]
    assert AuthenticationStore(state).get("example", "https://example.org")["headers"]["Authorization"] == "fixture-secret"
    assert json.loads((state / "research.json").read_text())["allow_private_networks"] is False


def test_event_redaction_preserves_json_and_legacy_corruption_does_not_break_stream(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    seq = rt.store.append_event('default', 'test', 'fixture', payload={
        'output': ['password="synthetic-secret"', 'Set-Cookie: sid=synthetic-cookie; HttpOnly'],
        'nested': {'count': 2, 'enabled': True}})
    events = rt.store.get_events(since_seq=seq - 1)
    assert events[0]['payload']['nested'] == {'count': 2, 'enabled': True}
    assert 'synthetic-secret' not in json.dumps(events)
    assert 'synthetic-cookie' not in json.dumps(events)
    with rt.store._connect() as conn:
        conn.execute('UPDATE telemetry_events SET payload_json = ? WHERE seq = ?', ('{"broken":', seq))
    next_seq = rt.store.append_event('default', 'test', 'next event')
    events = rt.store.get_events(since_seq=seq - 1)
    assert events[0]['payload']['error'] == 'Stored event payload is invalid JSON'
    assert events[1]['seq'] == next_seq
