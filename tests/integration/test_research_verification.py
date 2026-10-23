"""Research isolation and ground-truth verification receipts."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hexstrike.application.services import HexStrikeRuntime


def test_research_does_not_expand_assessment_scope(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            data = json.dumps({"results": [{"title": "Fixture doc", "url": "https://example.org/doc", "content": "reference"}]}).encode() if self.path.startswith("/search") else b"<html><body>Reference material<script>hidden text</script><a href='/next'>Next</a></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if self.path.startswith("/search") else "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        rt = HexStrikeRuntime(state_dir=tmp_path)
        rt.engagement_manage("update", allow_all_targets=False, allowed_targets=["assessment.invalid"])
        url = f"http://127.0.0.1:{server.server_port}"
        blocked = rt.job_start(capability_id="research.web", operation="retrieve", arguments={"url": url})
        assert not blocked["success"]
        (tmp_path / "research.json").write_text(json.dumps({"allow_private_networks": True, "search_endpoint": url + "/search"}))
        retrieved = rt.job_start(capability_id="research.web", operation="retrieve", arguments={"url": url})
        assert retrieved["success"], retrieved
        assert "Reference material" in retrieved["job"]["structured_output"]["content"]
        assert "hidden text" not in retrieved["job"]["structured_output"]["content"]
        search = rt.job_start(capability_id="research.web", operation="search", arguments={"query": "fixture"})
        assert search["success"], search
        assert search["job"]["structured_output"]["results"][0]["title"] == "Fixture doc"
        assert rt.store.get_engagement("default").scope.allowed_targets == ["assessment.invalid"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_operator_verification_uses_actual_jobs_and_invalidates_receipts(tmp_path, monkeypatch):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.workspace.create_file("fixture.txt", "known-content")
    suite = [
        {"name": "positive", "operation": "read", "arguments": {"path": "fixture.txt"},
         "expected": {"/success": True, "/job/structured_output/content": "known-content"}, "negative_control": False},
        {"name": "missing", "operation": "read", "arguments": {"path": "absent.txt"},
         "expected": {"/success": False}, "negative_control": True},
    ]
    rt.workspace.create_file("verification.json", json.dumps(suite))
    result = rt.job_start(capability_id="tools.verify", arguments={"capability_id": "workspace.files", "suite_file": "verification.json"})
    assert result["success"], result
    receipt = rt.registry.describe_capabilities(["workspace.files"])[0]["verification"]
    assert receipt["integration_tested"] and receipt["smoke_tested"]
    assert len(receipt["cases"]) == 2 and all(case["job_id"] for case in receipt["cases"])
    monkeypatch.setattr("hexstrike.adapters.verification.code_digest", lambda: "changed-code")
    stale = rt.registry.describe_capabilities(["workspace.files"])[0]["verification"]
    assert not stale["integration_tested"]
