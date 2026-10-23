"""Exercise the saved launcher through real HTTP and MCP clients."""
import asyncio
from argparse import Namespace
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import tomllib

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from hexstrike.cli.server import configure, connection_text, load_settings, validate_settings


def settings_args(**kwargs):
    return Namespace(**kwargs)


def test_settings_persist_token_and_refuse_insecure_transport(tmp_path):
    first = configure(tmp_path, settings_args())
    assert len(first['token']) >= 32
    assert configure(tmp_path, settings_args()) == first
    assert (tmp_path / 'server.json').stat().st_mode & 0o777 == 0o600
    assert first['token'] not in connection_text(first)
    for client in ('cursor', 'vscode'):
        assert first['token'] in json.dumps(json.loads(connection_text(first, client, True)))
    assert tomllib.loads(connection_text(first, 'codex', True))['mcp_servers']['hexstrike']['http_headers']['Authorization'] == 'Bearer ' + first['token']
    with pytest.raises(ValueError):
        validate_settings({**first, 'host': '0.0.0.0'})
    with pytest.raises(ValueError):
        validate_settings({**first, 'url': 'http://remote.invalid/mcp'})
    (tmp_path / 'server.json').chmod(0o644)
    with pytest.raises(ValueError, match='0600'):
        load_settings(tmp_path)


def test_launcher_background_reopen_auth_and_real_mcp(tmp_path):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    root = tmp_path / 'state with spaces'
    args = [sys.executable, '-m', 'hexstrike.cli.main', '--state-dir', str(root), 'server']
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2] / 'src'))
    def call(*extra):
        return subprocess.run([*args, *extra], capture_output=True, text=True, env=env, timeout=35)
    try:
        result = call('--no-ui', '--port', str(port))
        assert result.returncode == 0, result.stdout + result.stderr
        first = json.loads((root / 'server-process.json').read_text())
        settings = load_settings(root)
        assert settings['token'] not in result.stdout + result.stderr
        again = call('--no-ui')
        assert again.returncode == 0, again.stdout + again.stderr
        assert json.loads((root / 'server-process.json').read_text()) == first
        assert httpx.get(f'http://127.0.0.1:{port}/api/v6/telemetry').status_code == 401

        async def exercise():
            async with httpx.AsyncClient(headers={'Authorization': 'Bearer ' + settings['token']}) as client:
                async with streamable_http_client(settings['url'], http_client=client) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        manifest = await session.list_tools()
                        assert len(manifest.tools) == 10
                        result = await session.call_tool('system_status', {})
                        assert not result.is_error
        asyncio.run(exercise())
        response = httpx.get(f'http://127.0.0.1:{port}/api/v6/telemetry', headers={'Authorization': 'Bearer ' + settings['token']})
        assert response.status_code == 200
        assert 'engagements' in response.json()
        assert settings['token'] not in response.text
    finally:
        result = call('--stop')
        assert result.returncode == 0, result.stdout + result.stderr
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                httpx.get(f'http://127.0.0.1:{port}/health', timeout=.2)
            except httpx.ConnectError:
                break
            time.sleep(.1)
        else:
            pytest.fail('Server kept listening after --stop')


def test_simultaneous_setup_keeps_one_generated_token(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: configure(tmp_path, settings_args()), range(16)))
    assert len({result['token'] for result in results}) == 1


def test_tailscale_setup_does_not_replace_an_existing_service(tmp_path):
    from unittest.mock import patch
    existing = {'TCP': {'443': {'TCPForward': '192.0.2.10:8443'}}}
    commands = []
    def run(argv, **kwargs):
        commands.append(argv)
        data = {'Self': {'DNSName': 'fixture.tail.example.'}, 'BackendState': 'Running'} if argv[1] == 'status' else existing
        return subprocess.CompletedProcess(argv, 0, json.dumps(data), '')
    with patch('hexstrike.cli.server.shutil.which', return_value='/usr/bin/tailscale'), patch('hexstrike.cli.server.subprocess.run', side_effect=run):
        with pytest.raises(ValueError, match='another application'):
            configure(tmp_path, settings_args(tailscale=True))
    assert not any('--bg' in command for command in commands)
    assert not (tmp_path / 'server.json').exists()


def test_server_monitor_works_before_public_dns_is_available(tmp_path):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    args = [sys.executable, '-m', 'hexstrike.cli.main', '--state-dir', str(tmp_path), 'server']
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2] / 'src'))
    try:
        result = subprocess.run([*args, '--url', 'https://unresolvable.invalid/mcp', '--port', str(port), '--no-ui'],
                                env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert load_settings(tmp_path)['url'] == 'https://unresolvable.invalid/mcp'
        assert httpx.get(f'http://127.0.0.1:{port}/health').status_code == 200
    finally:
        subprocess.run([*args, '--stop'], env=env, capture_output=True, timeout=30, check=True)


def test_direct_tls_monitor_still_validates_public_certificate_hostname(tmp_path, monkeypatch):
    import shutil
    import ssl
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from hexstrike.transports.telemetry import TelemetryClient, TelemetryError
    openssl = shutil.which('openssl')
    if not openssl:
        pytest.skip('OpenSSL is required for a temporary certificate')
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key),
                    '-out', str(cert), '-days', '1', '-subj', '/CN=fixture.invalid', '-addext',
                    'subjectAltName=DNS:fixture.invalid'], check=True, capture_output=True)
    monkeypatch.setenv('SSL_CERT_FILE', str(cert))
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            assert self.headers['Authorization'] == 'Bearer synthetic-token'
            body = json.dumps({'success': True, 'status': {}, 'jobs': [], 'findings': [], 'events': []}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    address = ('127.0.0.1', server.server_port)
    try:
        assert TelemetryClient('https://fixture.invalid', 'synthetic-token', connect_address=address).snapshot('default')['success']
        with pytest.raises(TelemetryError):
            TelemetryClient('https://wrong.invalid', 'synthetic-token', connect_address=address).snapshot('default')
    finally:
        server.shutdown()
        thread.join(5)
        server.server_close()


def test_connection_address_tracks_listener_without_rewriting_proxy(tmp_path):
    root = tmp_path / 'direct'
    first = configure(root, settings_args(host='::1', port=8765))
    assert first['url'] == 'http://[::1]:8765/mcp'
    changed = configure(root, settings_args(port=9876))
    assert changed['url'] == 'http://[::1]:9876/mcp'
    assert first['token'] == changed['token']
    proxy = tmp_path / 'proxy'
    configure(proxy, settings_args(url='https://example.invalid/mcp'))
    assert configure(proxy, settings_args(port=8765))['url'] == 'https://example.invalid/mcp'


def test_setup_defaults_to_local_without_optional_network_services(tmp_path, monkeypatch):
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr('builtins.input', lambda _: '')
    monkeypatch.setattr('getpass.getpass', lambda _: '')
    settings = configure(tmp_path, settings_args(configure=True))
    assert settings['url'] == 'http://127.0.0.1:8000/mcp'
