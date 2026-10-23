"""Authenticated API workflows against a real, temporary HTTP server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.http.client import AuthenticationStore


@pytest.fixture
def api():
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            body = self.rfile.read(int(self.headers.get("content-length", "0")))
            seen.append({"method": self.command, "path": self.path, "body": body, "headers": dict(self.headers)})
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{self.server.server_port}/target")
                self.end_headers()
                return
            if self.path == "/login":
                payload = b"logged in"
            elif self.path == "/private":
                payload = json.dumps({"cookie": self.headers.get("Cookie"), "authorization": self.headers.get("Authorization")}).encode()
            else:
                payload = body or b"ok"
            self.send_response(200)
            if self.path == "/login":
                self.send_header("Set-Cookie", "sid=private-session-value; HttpOnly; Path=/")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", seen
    server.shutdown()
    server.server_close()
    thread.join()


def request(rt, url, **args):
    return rt.job_start(capability_id="web.http_inspect", operation="probe", arguments={"url": url, **args})


def test_http_methods_bodies_multipart_and_sessions(tmp_path, api):
    url, seen = api
    rt = HexStrikeRuntime(state_dir=tmp_path)
    for method in ("PUT", "PATCH", "DELETE"):
        result = request(rt, url, method=method, json_body={"name": "fixture"}, headers={"X-Test": "header"})
        assert result["success"], result
        assert seen[-1]["method"] == method
        assert json.loads(seen[-1]["body"]) == {"name": "fixture"}
        assert result["job"]["structured_output"]["tls"] == {"enabled": False}
    assert request(rt, url, method="POST", multipart=[{"name": "upload", "filename": "case.txt", "content": "sample"}])["success"]
    assert b'filename="case.txt"' in seen[-1]["body"]
    assert request(rt, url, method="POST", body_base64="AP8B")["success"]
    assert seen[-1]["body"] == b"\x00\xff\x01"
    assert request(rt, url, method="POST", multipart=[{"name": "binary", "filename": "blob.bin", "content_base64": "AP8B"}])["success"]
    assert b"\x00\xff\x01" in seen[-1]["body"]
    assert request(rt, url + "/login", session="api-test")["success"]
    resumed = HexStrikeRuntime(state_dir=tmp_path)
    result = request(resumed, url + "/private", session="api-test")
    assert result["success"], result
    assert "sid=private-session-value" in seen[-1]["headers"]["Cookie"]
    assert "private-session-value" not in json.dumps(result)


def test_credentials_are_origin_bound_redacted_and_not_saved_in_plans(tmp_path, api):
    url, seen = api
    rt = HexStrikeRuntime(state_dir=tmp_path)
    secret = "private-bearer-fixture-value"
    AuthenticationStore(tmp_path).put("fixture", {"origins": [url], "headers": {"Authorization": "Bearer " + secret}})
    result = request(rt, url + "/private", credential_ref="fixture")
    assert result["success"], result
    assert seen[-1]["headers"]["Authorization"] == "Bearer " + secret
    assert secret not in json.dumps(result)
    plan = rt.store.get_plan(result["job"]["plan_id"])
    assert secret not in json.dumps(plan.to_dict())
    crossed = request(rt, url + "/redirect", credential_ref="fixture", follow_redirects=True)
    assert not crossed["success"]
    assert not any(item["path"] == "/target" for item in seen)
    rejected = request(rt, url.replace("127.0.0.1", "localhost"), credential_ref="fixture")
    assert not rejected["success"]


def test_conflicting_body_modes_fail_before_network(tmp_path, api):
    url, seen = api
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = request(rt, url, method="POST", body="raw", json_body={})
    assert not result["success"] and not seen


def test_tls_metadata_and_client_certificate_authentication(tmp_path):
    import shutil
    import ssl
    import subprocess
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("OpenSSL CLI required for temporary TLS certificates")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.load_verify_locations(cert)
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        rt = HexStrikeRuntime(state_dir=tmp_path / "state")
        url = f"https://127.0.0.1:{server.server_port}"
        auth = AuthenticationStore(rt.base_root)
        auth.put("ca-only", {"origins": [url], "ca_file": str(cert)})
        auth.put("client", {"origins": [url], "ca_file": str(cert), "cert_file": str(cert), "key_file": str(key)})
        assert not request(rt, url, credential_ref="ca-only")["success"]
        secured = request(rt, url, credential_ref="client")
        assert secured["success"], secured
        tls = secured["job"]["structured_output"]["tls"]
        assert tls["enabled"] and tls["verified"] and tls["protocol"].startswith("TLS")
        assert len(tls["certificate_sha256"]) == 64
        repeated = request(rt, url, credential_ref="client")
        compared = rt.job_start(capability_id="evidence.compare", arguments={"left_job_id": secured["job"]["job_id"], "right_job_id": repeated["job"]["job_id"]})
        assert compared["success"]
        assert not compared["job"]["structured_output"]["body_changed"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
