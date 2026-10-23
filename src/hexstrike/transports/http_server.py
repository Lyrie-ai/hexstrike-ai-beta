"""Authenticated compatibility HTTP API with typed execution and confined file access."""

from __future__ import annotations

import argparse
import hmac
import os
import secrets
import urllib.parse
from typing import Iterable, List, Optional, Tuple

from flask import Flask, Response, g, jsonify, request

from hexstrike import __version__
from hexstrike.application.services import HexStrikeRuntime
from hexstrike.application.state import state_access
from hexstrike.domain.models import Principal
from hexstrike.policy.engine import PolicyViolationError
from hexstrike.workflows.engine import correlate_threat_indicators


DEFAULT_ALLOWED_AUTHORITIES = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def extract_authority_hostname(authority_or_url: str, is_origin: bool = False) -> Optional[str]:
    if not authority_or_url or not isinstance(authority_or_url, str):
        return None
    raw = authority_or_url.strip()
    if is_origin:
        parsed = urllib.parse.urlsplit(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        return parsed.hostname.lower().rstrip(".")
    else:
        parsed = urllib.parse.urlsplit(f"http://{raw}")
        if not parsed.hostname:
            return None
        return parsed.hostname.lower().rstrip(".")


def is_allowed_authority(
    header_value: str,
    allowed_hosts: Iterable[str] = DEFAULT_ALLOWED_AUTHORITIES,
    is_origin: bool = False,
) -> bool:
    host = extract_authority_hostname(header_value, is_origin=is_origin)
    if not host:
        return False
    normalized_allowed = {h.strip().lower().strip("[]").rstrip(".") for h in allowed_hosts}
    return host.strip("[]") in normalized_allowed


class TokenAuthenticator:
    """
    Validates static Bearer API tokens or signed JWT tokens with issuer, audience,
    expiry, revocation, and scope checks.
    """

    def __init__(
        self,
        api_token: Optional[str] = None,
        jwt_secret: Optional[str] = None,
        expected_issuer: str = "https://auth.hexstrike.local",
        expected_audience: str = "hexstrike-api",
    ) -> None:
        self.api_token = api_token or os.environ.get("HEXSTRIKE_API_TOKEN") or secrets.token_urlsafe(32)
        self.jwt_secret = jwt_secret or os.environ.get("HEXSTRIKE_JWT_SECRET")
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.revoked_token_ids: set[str] = set()

    def revoke_jti(self, jti: str) -> None:
        self.revoked_token_ids.add(jti)

    def authenticate_header(self, auth_header: Optional[str]) -> Tuple[Optional[Principal], Optional[str]]:
        if not auth_header or not auth_header.startswith("Bearer "):
            return None, "Missing or malformed Authorization Bearer header"

        token = auth_header[len("Bearer ") :].strip()
        if not token:
            return None, "Empty Bearer token"

        if hmac.compare_digest(token, self.api_token):
            return (
                Principal(
                    principal_id="api_token_operator",
                    name="Authenticated API Operator",
                    role="operator",
                    authenticated=True,
                    scopes=("*",),
                ),
                None,
            )

        if self.jwt_secret and token.count(".") == 2:
            try:
                import jwt

                payload = jwt.decode(
                    token,
                    self.jwt_secret,
                    algorithms=["HS256"],
                    issuer=self.expected_issuer,
                    audience=self.expected_audience,
                    options={"require": ["exp", "iss", "aud", "sub"]},
                )
                jti = payload.get("jti")
                if jti and jti in self.revoked_token_ids:
                    return None, "Token has been revoked"
                scopes_raw = payload.get("scope", "*")
                scopes = tuple(scopes_raw.split()) if isinstance(scopes_raw, str) else ("*",)
                return (
                    Principal(
                        principal_id=str(payload["sub"]),
                        name=str(payload.get("name", payload["sub"])),
                        role=str(payload.get("role", "operator")),
                        authenticated=True,
                        scopes=scopes,
                    ),
                    None,
                )
            except Exception as exc:
                return None, f"Invalid JWT token: {exc}"

        return None, "Invalid authentication credentials"


def create_http_app(
    runtime: Optional[HexStrikeRuntime] = None,
    api_token: Optional[str] = None,
    jwt_secret: Optional[str] = None,
    expected_issuer: str = "https://auth.hexstrike.local",
    expected_audience: str = "hexstrike-api",
    allowed_hosts: Optional[Iterable[str]] = None,
) -> Flask:
    rt = runtime or HexStrikeRuntime()
    auth = TokenAuthenticator(
        api_token=api_token,
        jwt_secret=jwt_secret,
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
    )
    allowed_host_set = frozenset(allowed_hosts) if allowed_hosts else DEFAULT_ALLOWED_AUTHORITIES

    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    app.config["HEXSTRIKE_RUNTIME"] = rt
    app.config["HEXSTRIKE_AUTH"] = auth

    @app.before_request
    def _enforce_security_middleware() -> Optional[Tuple[Response, int]]:
        if "token" in request.args or "api_key" in request.args or "access_token" in request.args:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Credentials in URL query parameters are forbidden",
                        "code": "QUERY_CREDENTIAL_FORBIDDEN",
                    }
                ),
                400,
            )

        host_header = request.headers.get("Host")
        if host_header and not is_allowed_authority(host_header, allowed_host_set, is_origin=False):
            return (
                jsonify({"success": False, "error": "Forbidden Host header", "code": "INVALID_HOST"}),
                403,
            )

        origin = request.headers.get("Origin")
        if origin and not is_allowed_authority(origin, allowed_host_set, is_origin=True):
            return (
                jsonify({"success": False, "error": "Forbidden Origin header", "code": "INVALID_ORIGIN"}),
                403,
            )

        if request.path in ("/health", "/.well-known/oauth-protected-resource"):
            return None

        principal, err = auth.authenticate_header(request.headers.get("Authorization"))
        if principal is None:
            resp = jsonify({"success": False, "error": err or "Unauthorized", "code": "UNAUTHORIZED"})
            resp.headers["WWW-Authenticate"] = (
                'Bearer realm="hexstrike"'
            )
            return resp, 401

        request.environ["hexstrike.principal"] = principal
        return None

    @app.before_request
    def _hold_state_access():
        access = state_access(rt.base_root)
        try:
            access.__enter__()
        except ValueError:
            return jsonify({"success": False, "error": "Controller state is undergoing maintenance"}), 503
        g.state_access = access

    @app.teardown_request
    def _release_state_access(error):
        access = g.pop("state_access", None)
        if access is not None:
            access.__exit__(None, None, None)

    def _current_principal() -> Principal:
        return request.environ.get("hexstrike.principal") or Principal(
            principal_id="anonymous", name="Anonymous", authenticated=False
        )

    def _require_scope(required_scope: str) -> Optional[Tuple[Response, int]]:
        p = _current_principal()
        if "*" not in p.scopes and required_scope not in p.scopes:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": f"Missing required permission scope: {required_scope}",
                        "code": "INSUFFICIENT_SCOPE",
                    }
                ),
                403,
            )
        return None

    @app.route("/health", methods=["GET"])
    def health_check() -> Tuple[Response, int]:
        return jsonify({"status": "healthy", "version": __version__}), 200

    @app.route("/.well-known/oauth-protected-resource", methods=["GET"])
    def oauth_protected_resource() -> Tuple[Response, int]:
        return jsonify({"error": "OAuth authorization is not configured; use a bearer token"}), 404

    @app.route("/api/command", methods=["POST"])
    @app.route("/api/python/install", methods=["POST"])
    @app.route("/api/python/execute", methods=["POST"])
    @app.route("/api/process/execute-async", methods=["POST"])
    @app.route("/api/error-handling/execute-with-recovery", methods=["POST"])
    def retired_unsafe_endpoint() -> Tuple[Response, int]:
        return (
            jsonify(
                {
                    "success": False,
                    "error": (
                        "Arbitrary shell/script execution endpoint has been retired (CVE-2025-35028 / CVE-2026-90619). "
                        "Use typed capabilities via /api/v6/jobs/start or MCP job_start."
                    ),
                    "code": "ENDPOINT_RETIRED_UNSAFE",
                }
            ),
            410,
        )

    @app.route("/api/files/create", methods=["POST"])
    def create_file() -> Tuple[Response, int]:
        scope_err = _require_scope("workspace")
        if scope_err:
            return scope_err
        params = request.get_json(silent=True) or {}
        filename = params.get("filename", "")
        content = params.get("content", "")
        binary = bool(params.get("binary", False))
        if not filename:
            return jsonify({"success": False, "error": "Filename is required"}), 400
        res = rt.workspace.create_file(filename, content, binary=binary)
        return jsonify(res), (200 if res.get("success") else 400)

    @app.route("/api/files/modify", methods=["POST"])
    def modify_file() -> Tuple[Response, int]:
        scope_err = _require_scope("workspace")
        if scope_err:
            return scope_err
        params = request.get_json(silent=True) or {}
        filename = params.get("filename", "")
        content = params.get("content", "")
        append = bool(params.get("append", False))
        if not filename:
            return jsonify({"success": False, "error": "Filename is required"}), 400
        res = rt.workspace.modify_file(filename, content, append=append)
        return jsonify(res), (200 if res.get("success") else 400)

    @app.route("/api/files/delete", methods=["DELETE", "POST"])
    def delete_file() -> Tuple[Response, int]:
        scope_err = _require_scope("workspace")
        if scope_err:
            return scope_err
        params = request.get_json(silent=True) or {}
        filename = params.get("filename", "")
        if not filename:
            return jsonify({"success": False, "error": "Filename is required"}), 400
        res = rt.workspace.delete_file(filename)
        return jsonify(res), (200 if res.get("success") else 400)

    @app.route("/api/files/list", methods=["GET"])
    def list_files() -> Tuple[Response, int]:
        scope_err = _require_scope("read")
        if scope_err:
            return scope_err
        directory = request.args.get("directory", ".")
        res = rt.workspace.list_files(directory)
        return jsonify(res), (200 if res.get("success") else 400)

    @app.route("/api/tools/nmap", methods=["POST"])
    def tool_nmap() -> Tuple[Response, int]:
        scope_err = _require_scope("execute")
        if scope_err:
            return scope_err
        params = request.get_json(silent=True) or {}
        target = params.get("target", "")
        ports = params.get("ports", "")
        extra_raw = params.get("additional_args") or params.get("extra_flags") or []
        try:
            res = rt.job_start(
                capability_id="network.nmap",
                operation="scan",
                arguments={
                    "target": target,
                    "ports": ports,
                    "extra_flags": extra_raw if isinstance(extra_raw, list) else str(extra_raw).split(),
                },
                principal=_current_principal(),
            )
            return jsonify(res), 200
        except PolicyViolationError as exc:
            return jsonify({"success": False, "error": str(exc), "code": exc.code}), 400

    @app.route("/api/tools/<tool_slug>", methods=["POST"])
    def tool_generic_typed(tool_slug: str) -> Tuple[Response, int]:
        scope_err = _require_scope("execute")
        if scope_err:
            return scope_err
        params = request.get_json(silent=True) or {}
        slug_norm = tool_slug.replace("-", "_")
        matches = rt.registry.search_capabilities(query=slug_norm, limit=5)
        if not matches:
            return jsonify({"success": False, "error": f"Unsupported or disabled tool: {tool_slug}"}), 404
        cap_id = matches[0]["capability_id"]
        op_name = matches[0]["operations"][0]
        try:
            res = rt.job_start(
                capability_id=cap_id,
                operation=op_name,
                arguments=params,
                principal=_current_principal(),
            )
            return jsonify(res), 200
        except PolicyViolationError as exc:
            return jsonify({"success": False, "error": str(exc), "code": exc.code}), 400

    @app.route("/api/vuln-intel/threat-feeds", methods=["POST"])
    def threat_feeds() -> Tuple[Response, int]:
        scope_err = _require_scope("read")
        if scope_err:
            return scope_err
        params = request.get_json(silent=True) or {}
        indicators = params.get("indicators", [])
        if isinstance(indicators, str):
            indicators = [i.strip() for i in indicators.split(",") if i.strip()]
        if not indicators:
            return jsonify({"success": False, "error": "Indicators parameter is required"}), 400
        res = correlate_threat_indicators(
            indicators=indicators,
            timeframe=params.get("timeframe", "30d"),
            sources=params.get("sources", "all"),
            include_simulated=bool(params.get("include_simulated", False)),
        )
        return jsonify(res), 200

    @app.route("/api/v6/status", methods=["GET"])
    def v6_status() -> Tuple[Response, int]:
        eng_id = request.args.get("engagement_id", "default")
        try:
            return jsonify(rt.system_status(engagement_id=eng_id, principal=_current_principal())), 200
        except PolicyViolationError as exc:
            return jsonify({"success": False, "error": str(exc), "code": exc.code}), 403

    @app.route("/api/v6/capabilities", methods=["GET"])
    def v6_capabilities() -> Tuple[Response, int]:
        q = request.args.get("query", "")
        cat = request.args.get("category")
        return jsonify(rt.capabilities_search(query=q, category=cat)), 200

    @app.route("/api/v6/telemetry", methods=["GET"])
    def v6_telemetry() -> Tuple[Response, int]:
        scope_err = _require_scope("read")
        if scope_err:
            return scope_err
        eng_id = request.args.get("engagement_id", "default")
        try:
            since_seq = max(0, int(request.args.get("since_seq", "0")))
            limit = max(1, min(int(request.args.get("limit", "100")), 500))
        except ValueError:
            return jsonify({"success": False, "error": "Invalid pagination parameters"}), 400
        principal = _current_principal()
        try:
            status = rt.system_status(engagement_id=eng_id, principal=principal)
            jobs = [j.to_dict() for j in rt.store.list_jobs(engagement_id=eng_id, limit=30)]
            findings = [f.to_dict() for f in rt.store.list_findings(engagement_id=eng_id, limit=50)]
            events = rt.store.get_events(since_seq=since_seq, engagement_id=eng_id, limit=limit)
            return (
                jsonify(
                    {
                        "success": True,
                        "engagement_id": eng_id,
                        "status": status,
                        "jobs": jobs,
                        "findings": findings,
                        "events": events,
                        "capabilities": rt.capabilities_search(limit=100)["capabilities"],
                    }
                ),
                200,
            )
        except PolicyViolationError as exc:
            return jsonify({"success": False, "error": str(exc), "code": exc.code}), 403

    @app.route("/api/v6/jobs/cancel", methods=["POST"])
    def v6_jobs_cancel() -> Tuple[Response, int]:
        scope_err = _require_scope("execute")
        if scope_err:
            return scope_err
        params = request.get_json(silent=True) or {}
        if not isinstance(params.get("cancel_all", False), bool):
            return jsonify({"success": False, "error": "cancel_all must be a boolean"}), 400
        try:
            result = rt.job_cancel(job_id=params.get("job_id"), cancel_all=params.get("cancel_all", False), principal=_current_principal())
            return jsonify(result), 200 if result.get("success") else 400
        except PolicyViolationError as exc:
            return jsonify({"success": False, "error": str(exc), "code": exc.code}), 403

    @app.route("/api/v6/jobs/start", methods=["POST"])
    def v6_jobs_start() -> Tuple[Response, int]:
        scope_err = _require_scope("execute")
        if scope_err:
            return scope_err
        params = request.get_json(silent=True) or {}
        try:
            res = rt.job_start(
                plan_id=params.get("plan_id"),
                capability_id=params.get("capability_id"),
                operation=params.get("operation", "run"),
                arguments=params.get("arguments"),
                engagement_id=params.get("engagement_id", "default"),
                worker_target=params.get("worker_target"),
                idempotency_key=params.get("idempotency_key"),
                wait=bool(params.get("wait", True)),
                principal=_current_principal(),
            )
            return jsonify(res), 200
        except PolicyViolationError as exc:
            return jsonify({"success": False, "error": str(exc), "code": exc.code}), 400

    return app


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="HexStrike AI Authenticated HTTP Server")
    parser.add_argument(
        "--host",
        default=os.environ.get("HEXSTRIKE_HOST", "127.0.0.1"),
        help="Bind interface (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("HEXSTRIKE_PORT", "8888")),
        help="Bind port (default: 8888)",
    )
    parser.add_argument(
        "--allow-external-bind",
        action="store_true",
        help="Explicitly permit binding to non-loopback interface (requires TLS cert/key)",
    )
    parser.add_argument("--tls-cert", default=None, help="Path to TLS certificate PEM")
    parser.add_argument("--tls-key", default=None, help="Path to TLS private key PEM")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        if not args.allow_external_bind or not (args.tls_cert and args.tls_key):
            raise SystemExit(
                "Refusing to bind to non-loopback address without --allow-external-bind, --tls-cert, and --tls-key."
            )

    app = create_http_app()
    ssl_ctx = (args.tls_cert, args.tls_key) if (args.tls_cert and args.tls_key) else None
    app.run(host=args.host, port=args.port, debug=False, ssl_context=ssl_ctx)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
