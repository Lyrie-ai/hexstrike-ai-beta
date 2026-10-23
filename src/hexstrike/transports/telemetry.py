"""Authenticated, bounded requests for terminal monitoring and cancellation."""

from __future__ import annotations

import ipaddress
import http.client
import socket
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class TelemetryError(ValueError):
    """A controller request failed without exposing credentials in its message."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _DirectHTTPSHandler(urllib.request.HTTPSHandler):
    """Dial a local listener while verifying its public certificate hostname."""

    def __init__(self, address: tuple[str, int]):
        super().__init__()
        self.address = address

    def https_open(self, request):
        address = self.address

        class Connection(http.client.HTTPSConnection):
            def connect(self):
                raw = socket.create_connection(address, self.timeout, self.source_address)
                try:
                    self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                except BaseException:
                    raw.close()
                    raise

        return self.do_open(Connection, request, context=self._context)


def controller_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Controller URL must be HTTP or HTTPS")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Controller URL must not contain credentials, a query, or a fragment")
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname == "localhost"
    if parsed.scheme == "http" and not loopback:
        raise ValueError("Remote controller connections require HTTPS")
    path = parsed.path.rstrip("/")
    if path.endswith(("/mcp", "/sse")):
        path = path.rsplit("/", 1)[0]
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class TelemetryClient:
    def __init__(self, url: str, token: str | None = None, timeout: float = 5.0,
                 connect_address: tuple[str, int] | None = None):
        self.url = controller_url(url)
        self.token = token
        self.timeout = timeout
        handlers = [_NoRedirect()]
        if connect_address or urllib.parse.urlsplit(self.url).hostname in ("127.0.0.1", "::1", "localhost"):
            handlers.append(urllib.request.ProxyHandler({}))
        if connect_address:
            handlers.append(_DirectHTTPSHandler(connect_address))
        self._opener = urllib.request.build_opener(*handlers)

    def _request(self, path: str, payload: dict | None = None) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload).encode()
        request = urllib.request.Request(self.url + path, data=data, headers=headers)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(1048577)
            if len(body) > 1048576:
                raise TelemetryError("Controller response exceeds the size limit")
            result = json.loads(body)
            if not isinstance(result, dict) or result.get("success") is not True:
                raise TelemetryError("Controller rejected the request")
            return result
        except urllib.error.HTTPError as exc:
            raise TelemetryError(f"Controller returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise TelemetryError("Controller is unreachable or the connection timed out") from None
        except (UnicodeError, json.JSONDecodeError):
            raise TelemetryError("Controller returned invalid JSON") from None

    def snapshot(self, engagement_id: str, since_seq: int = 0) -> dict[str, Any]:
        query = urllib.parse.urlencode({"engagement_id": engagement_id, "since_seq": since_seq, "limit": 100})
        result = self._request("/api/v6/telemetry?" + query)
        if not isinstance(result.get("status"), dict) or any(
            not isinstance(result.get(key), list) for key in ("jobs", "findings", "events")
        ):
            raise TelemetryError("Controller returned an invalid telemetry snapshot")
        return result

    def cancel_all(self) -> dict[str, Any]:
        return self._request("/api/v6/jobs/cancel", {"cancel_all": True})

    def inventory(self, query="", offset=0, refresh=False):
        params = urllib.parse.urlencode({"query": query, "offset": offset, "limit": 100, "refresh": int(refresh)})
        return self._request("/api/v6/inventory?" + params)
