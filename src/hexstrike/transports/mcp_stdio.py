"""Compact MCP interface over stdio or authenticated HTTP transports."""

from __future__ import annotations

import argparse
import contextvars
import json
import ipaddress
import logging
import os
import sys
from typing import Annotated, Any, Callable, Dict, Iterable, List, Optional

from pydantic import Field

from hexstrike import __version__
from hexstrike.transports.monitoring import MonitorState
from hexstrike.reporting.responses import compact_job_response
from hexstrike.application.services import HexStrikeRuntime
from hexstrike.domain.models import Principal
from hexstrike.policy.engine import PolicyViolationError
from hexstrike.transports.http_server import (
    DEFAULT_ALLOWED_AUTHORITIES,
    TokenAuthenticator,
    is_allowed_authority,
)


_CURRENT_MCP_PRINCIPAL: contextvars.ContextVar[Principal] = contextvars.ContextVar(
    "hexstrike_mcp_principal",
    default=Principal(principal_id="local_operator", name="Local Stdio Operator", role="operator"),
)


def _configure_stderr_logging() -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("[HexStrike MCP] %(asctime)s [%(levelname)s] %(message)s")
    )
    root.addHandler(handler)
    root.setLevel(logging.WARNING)


class _AuthenticatedMcpAsgiApp:
    """
    ASGI wrapper around Starlette MCP apps (`streamable_http_app` / `sse_app`)
    enforcing Bearer/JWT authentication, exact Host/Origin authority validation,
    and query-string token prohibition.
    """

    def __init__(
        self,
        inner_app: Any,
        authenticator: TokenAuthenticator,
        allowed_hosts: Iterable[str] = DEFAULT_ALLOWED_AUTHORITIES,
        monitor: Optional[MonitorState] = None,
    ) -> None:
        self._monitor = monitor
        self._inner = inner_app
        self._auth = authenticator
        self._allowed_hosts = frozenset(allowed_hosts)
        self.router = getattr(inner_app, "router", None)
        self.state = getattr(inner_app, "state", None)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    @staticmethod
    async def _send_json_error(
        send: Callable[[Dict[str, Any]], Any],
        status: int,
        payload: Dict[str, Any],
        extra_headers: Optional[List[tuple[bytes, bytes]]] = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self._inner(scope, receive, send)
            return

        query_bytes: bytes = scope.get("query_string") or b""
        query_str = query_bytes.decode("latin-1", errors="ignore")
        if any(k in query_str for k in ("token=", "api_key=", "access_token=")):
            await self._send_json_error(
                send,
                400,
                {
                    "jsonrpc": "2.0",
                    "error": {"code": -32600, "message": "Credentials in URL query parameters are forbidden"},
                },
            )
            return

        headers_dict: Dict[bytes, bytes] = {}
        for k, v in scope.get("headers") or []:
            headers_dict[bytes(k).lower()] = bytes(v)

        host_val = headers_dict.get(b"host", b"").decode("latin-1", errors="ignore")
        if host_val and not is_allowed_authority(host_val, self._allowed_hosts, is_origin=False):
            await self._send_json_error(
                send,
                403,
                {"jsonrpc": "2.0", "error": {"code": -32003, "message": "Forbidden Host authority"}},
            )
            return

        origin_val = headers_dict.get(b"origin", b"").decode("latin-1", errors="ignore")
        if origin_val and not is_allowed_authority(origin_val, self._allowed_hosts, is_origin=True):
            await self._send_json_error(
                send,
                403,
                {"jsonrpc": "2.0", "error": {"code": -32003, "message": "Forbidden Origin authority"}},
            )
            return

        path = scope.get("path", "")
        if path == "/health":
            await self._send_json_error(send, 200, {"status": "healthy"})
            return
        if path == "/.well-known/oauth-protected-resource":
            await self._send_json_error(send, 404, {"error": "OAuth authorization is not configured; use a bearer token"})
            return

        auth_header = headers_dict.get(b"authorization", b"").decode("latin-1", errors="ignore")
        principal, err = self._auth.authenticate_header(auth_header)
        if principal is None:
            await self._send_json_error(
                send,
                401,
                {"jsonrpc": "2.0", "error": {"code": -32001, "message": err or "Unauthorized"}},
                extra_headers=[
                    (
                        b"www-authenticate",
                        b'Bearer realm="hexstrike-mcp"',
                    )
                ],
            )
            return

        token = _CURRENT_MCP_PRINCIPAL.set(principal)
        try:
            if self._monitor is not None:
                await self._monitor.observe(self._inner, scope, receive, send, principal)
            else:
                await self._inner(scope, receive, send)
        finally:
            _CURRENT_MCP_PRINCIPAL.reset(token)


def _create_mcp_server_instance(name: str) -> Any:
    from mcp.server import MCPServer
    return MCPServer(name, version=__version__, instructions=(
        "HexStrike executes work on the connected server. Use execution.host for general commands, "
        "scripts and host filesystem/network access; no per-tool adapter is required. Discover installed "
        "executables with tools.inventory. execution.host.start with tty=true provides interactive sessions; "
        "use status/stdin/eof/cancel with the returned session_id. Typed scanner adapters are optional "
        "conveniences for structured arguments and findings. execution.sandbox is optional isolation, "
        "not required for host execution. Describe capabilities before use. For long batch jobs use "
        "job_start wait=false, job_status and job_cancel. Retrieve large outputs through evidence_read."
    ))


def create_hexstrike_mcp_server(
    runtime: Optional[HexStrikeRuntime] = None,
    api_token: Optional[str] = None,
    jwt_secret: Optional[str] = None,
    allowed_hosts: Optional[Iterable[str]] = None,
) -> Any:
    rt = runtime or HexStrikeRuntime()
    auth = TokenAuthenticator(api_token=api_token, jwt_secret=jwt_secret)
    allowed_host_set = frozenset(allowed_hosts) if allowed_hosts else DEFAULT_ALLOWED_AUTHORITIES
    mcp = _create_mcp_server_instance("HexStrike AI MCP")
    mcp.authenticator = auth
    monitor = MonitorState(rt)

    def artifact_bytes(evidence_id: str, image: bool = False) -> bytes:
        import hashlib
        with rt.store._lock:
            check = rt.evidence_read(evidence_id=evidence_id, limit=128, principal=_CURRENT_MCP_PRINCIPAL.get())
            if not check.get("success"):
                raise ValueError(check.get("error", "Artifact unavailable"))
            evidence = rt.store.get_evidence(evidence_id)
            if image and evidence.kind != "screenshot":
                raise ValueError("Expected screenshot evidence")
            if evidence.size_bytes > 10 * 1024 * 1024:
                raise ValueError("Artifact exceeds resource transfer limit; use evidence_read pagination")
            data = rt.workspace.read_file(evidence.artifact_id, binary=True, max_bytes=10 * 1024 * 1024)
            content = data.get("raw_bytes", b"")
            if not data.get("success") or len(content) != evidence.size_bytes or hashlib.sha256(content).hexdigest() != evidence.sha256:
                raise ValueError("Artifact integrity check failed")
            return content

    @mcp.resource("hexstrike://evidence/{evidence_id}/image", mime_type="image/png", description="Verified screenshot bytes; requires engagement access")
    def screenshot_resource(evidence_id: str) -> bytes:
        return artifact_bytes(evidence_id, image=True)

    @mcp.resource("hexstrike://evidence/{evidence_id}/artifact", mime_type="application/octet-stream", description="Verified artifact download, bounded to 10 MiB")
    def artifact_resource(evidence_id: str) -> bytes:
        return artifact_bytes(evidence_id)

    @mcp.tool(
        name="system_status",
        description="Fast core health, worker readiness, active engagement scope, and capability summary.",
    )
    def system_status(engagement_id: str = "default") -> Dict[str, Any]:
        try:
            return rt.system_status(
                engagement_id=engagement_id,
                principal=_CURRENT_MCP_PRINCIPAL.get(),
            )
        except PolicyViolationError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}

    @mcp.tool(
        name="capabilities_search",
        description="Find typed adapters and general capabilities. execution.host runs installed tools and scripts without registration; tools.inventory discovers server executables.",
    )
    def capabilities_search(
        query: str = "",
        category: Optional[str] = None,
        pack: Optional[str] = None,
        only_available: bool = False,
        limit: int = 25,
    ) -> Dict[str, Any]:
        return rt.capabilities_search(
            query=query,
            category=category,
            pack=pack,
            only_available=only_available,
            limit=limit,
        )

    @mcp.tool(
        name="capabilities_describe",
        description="Return operation schemas, supported versions, informational risk labels, and examples. Risk labels do not restrict execution.",
    )
    def capabilities_describe(
        capability_ids: List[str],
        probe_version: bool = False,
    ) -> Dict[str, Any]:
        return rt.capabilities_describe(
            capability_ids=capability_ids,
            probe_version=probe_version,
        )

    @mcp.tool(
        name="engagement_manage",
        description=(
            "Inspect, create, update, or revoke an engagement scope, port/protocol rules, "
            "rate/timeout budgets, and worker target. Risk labels do not restrict execution; max_risk_level is a legacy compatibility field."
        ),
    )
    def engagement_manage(
        action: str = "inspect",
        engagement_id: str = "default",
        name: Optional[str] = None,
        allowed_targets: Optional[List[str]] = None,
        excluded_targets: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        allowed_protocols: Optional[List[str]] = None,
        worker_target: Optional[str] = None,
        allow_all_targets: Optional[bool] = None,
        autonomous_mode: Optional[bool] = None,
        block_metadata_endpoints: Optional[bool] = None,
        max_risk_level: Annotated[Optional[str], Field(
            description="Legacy compatibility field, retained in stored settings but not enforced. Risk labels never block execution.",
            deprecated=True,
        )] = None,
        max_rate_per_minute: Optional[int] = None,
        max_concurrency: Optional[int] = None,
        max_timeout_seconds: Optional[int] = None,
        max_artifact_bytes: Optional[int] = None,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            return rt.engagement_manage(
                action=action,
                engagement_id=engagement_id,
                name=name,
                allowed_targets=allowed_targets,
                excluded_targets=excluded_targets,
                allowed_ports=allowed_ports,
                allowed_protocols=allowed_protocols,
                worker_target=worker_target,
                allow_all_targets=allow_all_targets,
                autonomous_mode=autonomous_mode,
                block_metadata_endpoints=block_metadata_endpoints,
                max_risk_level=max_risk_level,
                max_rate_per_minute=max_rate_per_minute,
                max_concurrency=max_concurrency,
                max_timeout_seconds=max_timeout_seconds,
                max_artifact_bytes=max_artifact_bytes,
                valid_from=valid_from,
                valid_until=valid_until,
                principal=_CURRENT_MCP_PRINCIPAL.get(),
            )
        except PolicyViolationError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    @mcp.tool(
        name="action_prepare",
        description=(
            "Validate a capability-specific argument object against its schema and return "
            "an immutable plan and approval grant."
        ),
    )
    def action_prepare(
        capability_id: str,
        operation: str = "run",
        arguments: Optional[Dict[str, Any]] = None,
        engagement_id: str = "default",
        worker_target: Optional[str] = None,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        try:
            return rt.action_prepare(
                capability_id=capability_id,
                operation=operation,
                arguments=arguments or {},
                engagement_id=engagement_id,
                worker_target=worker_target,
                timeout_seconds=timeout_seconds,
                principal=_CURRENT_MCP_PRINCIPAL.get(),
            )
        except PolicyViolationError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}
        except Exception as exc:
            return {"success": False, "error": str(exc), "code": "PREPARE_FAILED"}

    @mcp.tool(
        name="job_start",
        description=(
            "Start an authorized plan (via plan_id) OR directly prepare-and-start a capability "
            "(via capability_id + arguments) with optional idempotency key."
        ),
    )
    def job_start(
        plan_id: Optional[str] = None,
        capability_id: Optional[str] = None,
        operation: str = "run",
        arguments: Optional[Dict[str, Any]] = None,
        engagement_id: str = "default",
        worker_target: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        wait: bool = True,
        timeout_seconds: int = 300,
    ) -> Dict[str, Any]:
        try:
            return compact_job_response(rt.job_start(
                plan_id=plan_id,
                capability_id=capability_id,
                operation=operation,
                arguments=arguments,
                engagement_id=engagement_id,
                worker_target=worker_target,
                idempotency_key=idempotency_key,
                wait=wait,
                timeout_seconds=timeout_seconds,
                principal=_CURRENT_MCP_PRINCIPAL.get(),
            ))
        except PolicyViolationError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}
        except Exception as exc:
            return {"success": False, "error": str(exc), "code": "JOB_START_FAILED"}

    @mcp.tool(
        name="job_status",
        description="Query bounded job status, structured output, findings, and streaming events by job_id and cursor.",
    )
    def job_status(
        job_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        cursor_seq: int = 0,
    ) -> Dict[str, Any]:
        try:
            return compact_job_response(rt.job_status(
                job_id=job_id,
                engagement_id=engagement_id,
                cursor_seq=cursor_seq,
                principal=_CURRENT_MCP_PRINCIPAL.get(),
            ))
        except PolicyViolationError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}

    @mcp.tool(
        name="job_cancel",
        description="Cancel a running job (or all active jobs via cancel_all=True) and terminate its OS process group.",
    )
    def job_cancel(
        job_id: Optional[str] = None,
        cancel_all: bool = False,
    ) -> Dict[str, Any]:
        try:
            return rt.job_cancel(
                job_id=job_id,
                cancel_all=cancel_all,
                principal=_CURRENT_MCP_PRINCIPAL.get(),
            )
        except PolicyViolationError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}

    @mcp.tool(
        name="evidence_read",
        description="Paginated, redacted access to raw evidence artifacts by evidence_id or job_id.",
    )
    def evidence_read(
        evidence_id: Optional[str] = None,
        job_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 4000,
        view: str = "raw",
        url_contains: str = "",
        status_code: Optional[int] = None,
        method: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            return rt.evidence_read(
                evidence_id=evidence_id,
                job_id=job_id,
                engagement_id=engagement_id,
                offset=offset,
                limit=limit, view=view, url_contains=url_contains, status_code=status_code, method=method,
                principal=_CURRENT_MCP_PRINCIPAL.get(),
            )
        except PolicyViolationError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}

    @mcp.tool(
        name="memory_query",
        description="Bounded, engagement-scoped retrieval from local temporal memory and promoted lessons.",
    )
    def memory_query(
        query: str = "",
        engagement_id: str = "default",
        entity_type: Optional[str] = None,
        include_promoted_lessons: bool = True,
        limit: int = 20,
    ) -> Dict[str, Any]:
        try:
            return rt.memory_query(
                query=query,
                engagement_id=engagement_id,
                entity_type=entity_type,
                include_promoted_lessons=include_promoted_lessons,
                limit=limit,
                principal=_CURRENT_MCP_PRINCIPAL.get(),
            )
        except PolicyViolationError as exc:
            return {"success": False, "error": str(exc), "code": exc.code}

    def _with_monitor_routes(inner: Any) -> Any:
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        from starlette.concurrency import run_in_threadpool

        async def telemetry(request: Any) -> Any:
            principal = _CURRENT_MCP_PRINCIPAL.get()
            if principal is None or not ({"*", "read"} & set(principal.scopes)):
                return JSONResponse({"success": False, "error": "Read permission required"}, status_code=403)
            try:
                engagement_id = request.query_params.get("engagement_id", "default")
                since = max(0, int(request.query_params.get("since_seq", "0")))
                limit = max(1, min(500, int(request.query_params.get("limit", "100"))))
                def collect() -> Dict[str, Any]:
                    status = rt.system_status(engagement_id=engagement_id, principal=principal)
                    return {
                        "success": True,
                        "status": status,
                        "server": monitor.server_info(),
                        "clients": monitor.clients(principal.principal_id),
                        "engagements": rt.engagement_manage(action="list", principal=principal)["engagements"],
                        "jobs": [j.to_dict() for j in rt.store.list_jobs(engagement_id=engagement_id, limit=30)],
                        "findings": [f.to_dict() for f in rt.store.list_findings(engagement_id=engagement_id, limit=50)],
                        "events": rt.store.get_events(since_seq=since, engagement_id=engagement_id, limit=limit, latest=since == 0),
                        "capabilities": rt.capabilities_search(limit=100)["capabilities"],
                    }
                return JSONResponse(await run_in_threadpool(collect))
            except PolicyViolationError as exc:
                return JSONResponse({"success": False, "error": str(exc), "code": exc.code}, status_code=403)
            except ValueError:
                return JSONResponse({"success": False, "error": "Invalid pagination parameters"}, status_code=400)

        async def inventory(request: Any) -> Any:
            principal = _CURRENT_MCP_PRINCIPAL.get()
            if not ({"*", "read"} & set(principal.scopes)):
                return JSONResponse({"success": False, "error": "Read permission required"}, status_code=403)
            try:
                offset = max(0, int(request.query_params.get("offset", "0")))
                limit = max(1, min(100, int(request.query_params.get("limit", "100"))))
                query = request.query_params.get("query", "")[:200]
                result = await run_in_threadpool(monitor.inventory, query, offset, limit,
                                                request.query_params.get("refresh") == "1")
                return JSONResponse(result)
            except ValueError:
                return JSONResponse({"success": False, "error": "Invalid pagination parameters"}, status_code=400)

        async def cancel(request: Any) -> Any:
            principal = _CURRENT_MCP_PRINCIPAL.get()
            if principal is None or not ({"*", "execute"} & set(principal.scopes)):
                return JSONResponse({"success": False, "error": "Execute permission required"}, status_code=403)
            try:
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > 4096:
                        return JSONResponse({"success": False, "error": "Request too large"}, status_code=413)
                params = json.loads(body)
                if not isinstance(params, dict) or not isinstance(params.get("cancel_all", False), bool):
                    raise ValueError("Invalid cancellation parameters")
                result = await run_in_threadpool(rt.job_cancel, job_id=params.get("job_id"), cancel_all=params.get("cancel_all", False), principal=principal)
                return JSONResponse(result, status_code=200 if result.get("success") else 400)
            except PolicyViolationError as exc:
                return JSONResponse({"success": False, "error": str(exc), "code": exc.code}, status_code=403)
            except ValueError:
                return JSONResponse({"success": False, "error": "Invalid cancellation parameters"}, status_code=400)

        inner.router.routes.extend([
            Route("/api/v6/telemetry", telemetry, methods=["GET"]),
            Route("/api/v6/inventory", inventory, methods=["GET"]),
            Route("/api/v6/jobs/cancel", cancel, methods=["POST"]),
        ])
        return inner

    # Wrap network ASGI builders (streamable_http_app and sse_app) so every HTTP/SSE
    # request requires Bearer/JWT authentication and exact Host/Origin authority validation
    if hasattr(mcp, "streamable_http_app"):
        orig_streamable = mcp.streamable_http_app

        def _secured_streamable_http_app(*args: Any, **kwargs: Any) -> Any:
            inner = _with_monitor_routes(orig_streamable(*args, **kwargs))
            return _AuthenticatedMcpAsgiApp(inner, authenticator=auth, allowed_hosts=allowed_host_set, monitor=monitor)

        mcp.streamable_http_app = _secured_streamable_http_app

    if hasattr(mcp, "sse_app"):
        orig_sse = mcp.sse_app

        def _secured_sse_app(*args: Any, **kwargs: Any) -> Any:
            inner = _with_monitor_routes(orig_sse(*args, **kwargs))
            return _AuthenticatedMcpAsgiApp(inner, authenticator=auth, allowed_hosts=allowed_host_set, monitor=monitor)

        mcp.sse_app = _secured_sse_app

    return mcp


MCP_TOOL_NAMES = (
    "system_status",
    "capabilities_search",
    "capabilities_describe",
    "engagement_manage",
    "action_prepare",
    "job_start",
    "job_status",
    "job_cancel",
    "evidence_read",
    "memory_query",
)


def main(argv: Optional[List[str]] = None) -> int:
    _configure_stderr_logging()
    parser = argparse.ArgumentParser(description="HexStrike AI MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default="stdio",
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--worker",
        default=os.environ.get("HEXSTRIKE_WORKER", "local"),
        help="Default execution worker ('local' or configured SSH worker target)",
    )
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("HEXSTRIKE_HOME"),
        help="Directory for SQLite state, telemetry, and workspace",
    )
    parser.add_argument("--server", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--timeout", type=int, default=300, help=argparse.SUPPRESS)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--allow-external-bind", action="store_true")
    parser.add_argument("--allowed-host", action="append", default=[])
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--debug", action="store_true", help="Enable stderr debug logging")
    args = parser.parse_args(argv)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    rt = HexStrikeRuntime(state_dir=args.state_dir)
    if args.worker and args.worker != "local":
        rt.engagement_manage(
            action="configure",
            engagement_id="default",
            worker_target=args.worker,
        )

    allowed = set(DEFAULT_ALLOWED_AUTHORITIES) | set(args.allowed_host)
    mcp = create_hexstrike_mcp_server(rt, allowed_hosts=allowed)
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        if not (os.environ.get("HEXSTRIKE_API_TOKEN") or os.environ.get("HEXSTRIKE_JWT_SECRET")):
            parser.error("Network transports require HEXSTRIKE_API_TOKEN or HEXSTRIKE_JWT_SECRET")
        try:
            loopback = ipaddress.ip_address(args.host).is_loopback
        except ValueError:
            loopback = args.host == "localhost"
        if not loopback and not (args.allow_external_bind and args.allowed_host):
            parser.error("External bind requires --allow-external-bind and --allowed-host")
        if bool(args.tls_cert) != bool(args.tls_key):
            parser.error("Specify both --tls-cert and --tls-key")
        import uvicorn
        from mcp.server.transport_security import TransportSecuritySettings
        authorities = {f"[{host.strip('[]')}]" if ':' in host else host for host in allowed}
        security = TransportSecuritySettings(
            allowed_hosts=[authority for host in authorities for authority in (host, f"{host}:*")],
            allowed_origins=[f"{scheme}://{authority}" for host in authorities
                             for scheme in ("http", "https") for authority in (host, f"{host}:*")],
        )
        builder = mcp.streamable_http_app if args.transport == "streamable-http" else mcp.sse_app
        app = builder(host=args.host, transport_security=security)
        uvicorn.run(app, host=args.host, port=args.port, ssl_certfile=args.tls_cert, ssl_keyfile=args.tls_key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
