"""Bounded HTTP transactions with explicit redirects and private authentication state."""
from __future__ import annotations


from contextlib import closing
import base64
import hashlib
import http.cookiejar
import json
from pathlib import Path
import re
import sqlite3
import ssl
import time
from urllib.parse import urljoin, urlsplit

import httpx

from hexstrike.persistence import database_connection
from hexstrike.workspace.confined_fs import redact_http_headers, redact_secrets


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Expected an HTTP(S) URL without embedded credentials")
    return (parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80))


class AuthenticationStore:
    """Server-owned secrets are referenced by name; their values never enter plans."""
    def __init__(self, root):
        self.path = Path(root) / "http_auth.db"
        with database_connection(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS execution_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS credentials (name TEXT PRIMARY KEY, data TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, cookies TEXT NOT NULL)")
        self.path.chmod(0o600)

    def put(self, name, data):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name):
            raise ValueError("Invalid credential name")
        if not isinstance(data, dict) or not data.get("origins"):
            raise ValueError("Credential JSON requires an explicit origins list")
        for url in data["origins"]:
            origin(url)
        unknown = set(data) - {"origins", "headers", "cookies", "body", "cert_file", "key_file", "ca_file"}
        if unknown:
            raise ValueError("Unknown credential fields: " + ", ".join(sorted(unknown)))
        with database_connection(self.path) as db:
            db.execute("INSERT OR REPLACE INTO credentials VALUES (?,?)", (name, json.dumps(data)))

    def put_execution(self, name, value):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name) or not 1 <= len(value) <= 65536 or "\x00" in value:
            raise ValueError("Invalid execution secret name or value")
        with database_connection(self.path) as db:
            db.execute("INSERT OR REPLACE INTO execution_secrets VALUES (?,?)", (name, value))

    def get(self, name, url):
        with database_connection(self.path) as db:
            row = db.execute("SELECT data FROM credentials WHERE name=?", (name,)).fetchone()
        if not row:
            raise ValueError("Credential reference not found")
        data = json.loads(row[0])
        if origin(url) not in [origin(item) for item in data["origins"]]:
            raise ValueError("Credential reference is not authorized for this origin")
        return data


def perform_request(args, scope, policy, timeout, state_root=None, engagement_id="default"):
    url = args["url"]
    origin(url)
    store = AuthenticationStore(state_root) if state_root else None
    credential = {}
    if args.get("credential_ref"):
        if not store:
            raise ValueError("Credential references require a local authenticated runtime")
        credential = store.get(args["credential_ref"], url)
    headers = {"User-Agent": "HexStrike-Inspector", **args.get("headers", {}), **credential.get("headers", {})}
    if any("\r" in str(value) or "\n" in str(value) for pair in headers.items() for value in pair):
        raise ValueError("HTTP headers cannot contain newlines")
    secret_values = [str(value) for value in credential.get("headers", {}).values()] + [str(value) for value in credential.get("cookies", {}).values()]
    secret_values += [str(value) for name, value in args.get("headers", {}).items() if name.lower() in ("authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token")]
    secret_values += list(args.get("cookies", {}).values())
    if credential.get("body"):
        secret_values.append(credential["body"])
    context = ssl.create_default_context(cafile=credential.get("ca_file"))
    if credential.get("cert_file"):
        context.load_cert_chain(credential["cert_file"], credential.get("key_file"))
    proxy = args.get("proxy") or None
    if proxy:
        origin(proxy)
        if scope is not None:
            policy.evaluate_target(proxy, scope)
    bodies = [key for key in ("body", "body_base64", "json_body", "multipart") if key in args]
    if len(bodies) > 1 or (bodies and "body" in credential):
        raise ValueError("Choose one raw, JSON, multipart or credential body")
    request_options = {}
    if "body" in args or "body" in credential:
        request_options["content"] = credential.get("body", args.get("body", "")).encode()
    elif "body_base64" in args:
        request_options["content"] = base64.b64decode(args["body_base64"], validate=True)
    elif "json_body" in args:
        request_options["json"] = args["json_body"]
    elif "multipart" in args:
        request_options["files"] = [(item["name"], (item.get("filename"), (base64.b64decode(item["content_base64"], validate=True) if "content_base64" in item else item["content"].encode()), item.get("content_type", "text/plain"))) for item in args["multipart"]]
    body_size = len(request_options.get("content", b""))
    if "json" in request_options:
        body_size += len(json.dumps(request_options["json"]).encode())
    if "files" in request_options:
        body_size += sum(len(value[1]) for _, value in request_options["files"])
    if body_size > 1024 * 1024:
        raise ValueError("HTTP request body exceeds the 1 MiB budget")
    cookie_values = {**args.get("cookies", {}), **credential.get("cookies", {})}
    session = args.get("session")
    db = None
    start = time.monotonic()
    try:
        with httpx.Client(verify=context, proxy=proxy, trust_env=False, follow_redirects=False, timeout=min(args.get("timeout", 10), timeout)) as client:
            session_key = None
            if session:
                if not store:
                    raise ValueError("HTTP sessions require a local authenticated runtime")
                # Origin partitioning prevents sibling subdomain cookie leakage between sessions.
                session_key = hashlib.sha256(json.dumps([engagement_id, session, origin(url)]).encode()).hexdigest()
                db = sqlite3.connect(store.path, timeout=min(timeout, 10))
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT cookies FROM sessions WHERE id=?", (session_key,)).fetchone()
                for cookie in json.loads(row[0]) if row else []:
                    client.cookies.jar.set_cookie(http.cookiejar.Cookie(**cookie))
            for name, value in cookie_values.items():
                client.cookies.set(name, value, domain=urlsplit(url).hostname, path="/")
            method = args.get("method", "GET")
            initial_origin = origin(url)
            history = []
            for _ in range(11):
                if scope is not None:
                    policy.evaluate_target(url, scope)
                request = client.build_request(method, url, headers=headers, **request_options)
                with closing(client.send(request, stream=True)) as response:
                    tls_object = response.extensions.get("network_stream")
                    tls_object = tls_object.get_extra_info("ssl_object") if tls_object else None
                    tls = {"enabled": tls_object is not None}
                    if tls_object:
                        cert = tls_object.getpeercert(True)
                        details = tls_object.getpeercert()
                        tls.update(protocol=tls_object.version(), cipher=tls_object.cipher(), certificate_sha256=hashlib.sha256(cert).hexdigest(), verified=True,
                                   certificate={key: details.get(key) for key in ("subject", "issuer", "notBefore", "notAfter", "serialNumber")})
                    if response.is_redirect and args.get("follow_redirects") and response.headers.get("location"):
                        destination = urljoin(url, response.headers["location"])
                        dest_origin = origin(destination)
                        if scope is not None:
                            policy.evaluate_target(destination, scope)
                        history.append({"status_code": response.status_code, "url": url, "location": destination})
                        if dest_origin != initial_origin:
                            # An authenticated transaction never transfers secrets or bodies across origins.
                            if credential or request_options or cookie_values or session or list(client.cookies.jar):
                                raise ValueError("Authenticated or body-bearing redirect crossed origins; issue a separate request")
                            headers = {"User-Agent": "HexStrike-Inspector"}
                        if response.status_code == 303 or (response.status_code in (301, 302) and method == "POST"):
                            method, request_options = "GET", {}
                        url = destination
                        continue
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=65536):
                        body.extend(chunk[:65537 - len(body)])
                        if len(body) > 65536:
                            break
                    declared = response.headers.get("content-length")
                    output = {"url": args["url"], "final_url": str(response.url), "status_code": response.status_code,
                              "method": method, "headers": redact_http_headers(dict(response.headers)), "tls": tls,
                              "body_length": min(len(body), 65536), "body_truncated": len(body) > 65536,
                              "declared_body_length": int(declared) if declared else None,
                              "body_sha256": hashlib.sha256(body[:65536]).hexdigest(),
                              "body_preview": bytes(body[:4000]).decode("utf-8", "replace"), "redirects": history,
                              "elapsed_seconds": round(time.monotonic() - start, 3), "session": session}
                    if db is not None:
                        cookies = [{key: getattr(cookie, key) for key in ("version", "name", "value", "port", "port_specified", "domain", "domain_specified", "domain_initial_dot", "path", "path_specified", "secure", "expires", "discard", "comment", "comment_url", "rfc2109")} | {"rest": cookie._rest} for cookie in client.cookies.jar]
                        db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?)", (session_key, json.dumps(cookies)))
                        db.commit()
                    # Include values acquired from the response or prior session in echo redaction.
                    secret_values += [cookie.value for cookie in client.cookies.jar]
                    def redact(value):
                        if isinstance(value, str):
                            return redact_secrets(value, secret_values)
                        if isinstance(value, dict):
                            return {key: redact(item) for key, item in value.items()}
                        if isinstance(value, list):
                            return [redact(item) for item in value]
                        return value
                    return redact(output)
            raise ValueError("HTTP redirect limit exceeded")
    finally:
        if db is not None:
            db.close()
