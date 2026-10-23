"""Interactive browser workflow using a real Chromium process and local server."""
import threading
import pytest
from hexstrike.policy.engine import PolicyViolationError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hexstrike.application.services import HexStrikeRuntime


@pytest.mark.parametrize("shared_downloads", [False, True])
def test_browser_session_form_upload_download_and_reconnect(tmp_path, monkeypatch, shared_downloads):
    downloads = tmp_path / "shared browser downloads"
    if shared_downloads:
        monkeypatch.setenv("HEXSTRIKE_BROWSER_DOWNLOAD_DIR", str(downloads))
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/download":
                data = b"artifact-content"
                self.send_response(200)
                self.send_header("Content-Disposition", 'attachment; filename="fixture.bin"')
            else:
                data = b'''<html><head><title>Browser Fixture</title></head><body>
<input id="name"><button id="go" onclick="document.querySelector('#out').textContent=document.querySelector('#name').value">Apply</button>
<div id="out"></div><input id="upload" type="file"><a id="download" href="/download">Download</a>
</body></html>'''
                self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    rt = HexStrikeRuntime(state_dir=tmp_path)
    def call(runtime, op, **args):
        result = runtime.job_start(capability_id="browser.session", operation=op, arguments=args)
        assert result["success"], result
        return result["job"]
    sid = None
    try:
        opened = call(rt, "open", url=f"http://127.0.0.1:{server.server_port}", lifetime=60)
        sid = opened["structured_output"]["session_id"]
        call(rt, "fill", session_id=sid, selector="#name", value="completed-workflow")
        second = HexStrikeRuntime(state_dir=tmp_path)
        clicked = call(second, "click", session_id=sid, selector="#go")
        assert "completed-workflow" in clicked["structured_output"]["dom_preview"]
        rt.workspace.create_file("upload.txt", "upload-data")
        call(second, "upload", session_id=sid, selector="#upload", path="upload.txt")
        screenshot = call(second, "screenshot", session_id=sid)
        assert any(rt.store.get_evidence(e).kind == "screenshot" for e in screenshot["evidence_ids"])
        download = call(second, "download", session_id=sid, selector="#download")
        binary = next(rt.store.get_evidence(e) for e in download["evidence_ids"] if rt.store.get_evidence(e).kind == "binary")
        assert rt.workspace.read_file(binary.artifact_id)["content"] == "artifact-content"
        call(second, "save", session_id=sid)
        with pytest.raises(PolicyViolationError):
            second.job_start(capability_id="browser.session", operation="navigate", arguments={"session_id": sid, "url": "file:///etc/passwd"})
    finally:
        if sid:
            call(rt, "close", session_id=sid)
        server.shutdown()
        server.server_close()
        thread.join()
    if shared_downloads:
        assert downloads.is_dir() and not list(downloads.iterdir())


def test_browser_websocket_scope_has_positive_and_negative_controls(tmp_path):
    import base64
    import hashlib
    received = []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            if self.path == "/ws":
                received.append("connected")
                accept = base64.b64encode(hashlib.sha1((self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept)
                self.end_headers()
                self.wfile.write(b"\x81\x09delivered")
                self.wfile.flush()
                self.connection.settimeout(5)
                try:
                    self.connection.recv(1024)
                except OSError:
                    pass
                self.close_connection = True
            else:
                body = b'''<html><body><div id="out">waiting</div><script>
let s=new WebSocket('ws://'+location.host+'/ws');s.onmessage=e=>document.querySelector('#out').textContent=e.data;
s.onclose=()=>{if(document.querySelector('#out').textContent==='waiting')document.querySelector('#out').textContent='blocked'};
</script></body></html>'''
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    rt = HexStrikeRuntime(state_dir=tmp_path)
    sessions = []
    def call(op, **args):
        result = rt.job_start(capability_id="browser.session", operation=op, arguments=args)
        assert result["success"], result
        return result["job"]["structured_output"]
    try:
        denied = call("open", url=f"http://127.0.0.1:{server.server_port}", lifetime=30)["session_id"]
        sessions.append(denied)
        call("wait", session_id=denied, selector="#out:has-text('blocked')")
        assert not received
        rt.engagement_manage("update", allowed_protocols=["http", "https", "ws"])
        allowed = call("open", url=f"http://127.0.0.1:{server.server_port}", lifetime=30)["session_id"]
        sessions.append(allowed)
        result = call("wait", session_id=allowed, selector="#out:has-text('delivered')")
        assert "delivered" in result["dom_preview"] and received
    finally:
        for sid in sessions:
            call("close", session_id=sid)
        server.shutdown()
        server.server_close()
        thread.join()
