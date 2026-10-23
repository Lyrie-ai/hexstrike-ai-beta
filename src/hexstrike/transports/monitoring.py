"""Bounded server inventory and authenticated MCP client activity for the monitor."""
from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import psutil


class MonitorState:
    def __init__(self, runtime):
        self.runtime = runtime
        self._lock = threading.RLock()
        self._inventory = None
        self._inventory_at = 0.0
        self._clients = {}

    def inventory(self, query="", offset=0, limit=100, refresh=False):
        with self._lock:
            now = time.monotonic()
            if refresh or self._inventory is None or now - self._inventory_at > 30:
                self._inventory = self.runtime.registry.discover_installed(limit=50000)
                self._inventory_at = now
            source = self._inventory
            items = [item for item in source['executables'] if query.casefold() in item['name'].casefold()]
            end = offset + limit
            return dict(source, executables=items[offset:end], total=len(items),
                        next_offset=end if end < len(items) else None,
                        scanned_at=datetime.fromtimestamp(time.time() - (now - self._inventory_at), timezone.utc).isoformat())

    @staticmethod
    def server_info():
        addresses = sorted({address.address.split('%')[0] for values in psutil.net_if_addrs().values()
                            for address in values if address.family in (socket.AF_INET, socket.AF_INET6)})
        return {'hostname': socket.gethostname(), 'addresses': addresses}

    def clients(self, principal_id):
        with self._lock:
            now = time.time()
            self._clients = {key: item for key, item in self._clients.items()
                             if item['active_requests'] or now - item['last_seen_epoch'] < 300}
            result = []
            for (owner, _), item in self._clients.items():
                if owner != principal_id:
                    continue
                row = {key: value for key, value in item.items() if key != 'last_seen_epoch'}
                row['state'] = 'closed' if row['closed'] else 'active request' if row['active_requests'] else 'idle / last seen'
                result.append(row)
            return sorted(result, key=lambda item: item['last_seen'], reverse=True)

    async def observe(self, inner, scope, receive, send, principal):
        """Observe accepted transport requests without consuming or changing their bodies."""
        path = scope.get('path', '').rstrip('/')
        if path not in ('/mcp', '/sse', '/messages'):
            return await inner(scope, receive, send)
        headers = {key.decode('latin-1').lower(): value.decode('latin-1') for key, value in scope.get('headers', [])}
        query = parse_qs(scope.get('query_string', b'').decode('latin-1'))
        session = headers.get('mcp-session-id') or (query.get('session_id') or [None])[0]
        peer = str((scope.get('client') or ('unknown',))[0])
        body = bytearray()
        key = None
        response_status = 0
        sse_endpoint = path == '/sse'

        async def read():
            message = await receive()
            if message['type'] == 'http.request' and len(body) <= 65536:
                body.extend(message.get('body', b'')[:65537 - len(body)])
            return message

        def begin(identifier):
            nonlocal key
            name = headers.get('user-agent', 'MCP client')[:120]
            version = ''
            try:
                payload = json.loads(body) if len(body) <= 65536 else {}
                if isinstance(payload, dict):
                    from mcp_types import CLIENT_INFO_META_KEY
                    params = payload.get('params', {})
                    info = params.get('clientInfo', {}) if payload.get('method') == 'initialize' else params.get('_meta', {}).get(CLIENT_INFO_META_KEY, {})
                    name, version = str(info.get('name', name))[:120], str(info.get('version', ''))[:80]
            except (ValueError, TypeError, AttributeError):
                pass
            with self._lock:
                identifier = identifier or 'stateless:' + peer + ':' + name + ':' + version
                key = (principal.principal_id, identifier)
                now = time.time()
                stamp = datetime.fromtimestamp(now, timezone.utc).isoformat(timespec='seconds')
                if key not in self._clients:
                    if len(self._clients) >= 512:
                        idle = [k for k, v in self._clients.items() if not v['active_requests']]
                        if not idle:
                            key = None
                            return
                        del self._clients[min(idle, key=lambda k: self._clients[k]['last_seen_epoch'])]
                    self._clients[key] = dict(session_id='client_' + hashlib.sha256(identifier.encode()).hexdigest()[:12],
                        name=name, version=version, peer=peer, transport='SSE' if path != '/mcp' else 'Streamable HTTP',
                        first_seen=stamp, last_seen=stamp, last_seen_epoch=now, active_requests=0, closed=False)
                row = self._clients[key]
                if version or name != headers.get('user-agent', 'MCP client')[:120]:
                    row.update(name=name, version=version)
                row.update(last_seen=stamp, last_seen_epoch=now, closed=False)
                row['active_requests'] += 1

        async def write(message):
            nonlocal response_status, session, key
            if message['type'] == 'http.response.start':
                response_status = message['status']
                if 200 <= response_status < 300:
                    response_headers = {k.decode('latin-1').lower(): v.decode('latin-1') for k, v in message.get('headers', [])}
                    session = response_headers.get('mcp-session-id', session)
                    if not sse_endpoint:
                        begin(session)
                elif response_status in (404, 410) and session:
                    with self._lock:
                        row = self._clients.get((principal.principal_id, session))
                        if row:
                            row['closed'] = True
            elif sse_endpoint and key is None and message['type'] == 'http.response.body' and response_status == 200:
                # SSE advertises the message endpoint before sending protocol messages.
                data = message.get('body', b'')[:4096].decode('utf-8', errors='replace')
                for line in data.splitlines():
                    if line.startswith('data:'):
                        values = parse_qs(urlsplit(line[5:].strip()).query)
                        if values.get('session_id'):
                            begin(values['session_id'][0])
                            break
            await send(message)

        try:
            await inner(scope, read, write)
        finally:
            with self._lock:
                if key in self._clients:
                    row = self._clients[key]
                    row['active_requests'] = max(0, row['active_requests'] - 1)
                    row['closed'] = row['closed'] or sse_endpoint or (scope.get('method') == 'DELETE' and response_status < 300)
