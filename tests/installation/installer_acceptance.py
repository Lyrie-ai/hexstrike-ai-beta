"""Exercise the network installer through a private HTTPS fixture and piped stdin.

Usage: python tests/installation/installer_acceptance.py SOURCE_ARCHIVE
Requires curl, openssl, and network access for the managed runtime.
"""
import functools
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading

source = Path(__file__).resolve().parents[2]
archive = Path(sys.argv[1]).resolve()
root = Path(tempfile.mkdtemp(prefix='hexstrike-curl-acceptance-'))
shutil.copy2(source / 'install.sh', root / 'install.sh')
shutil.copy2(archive, root / 'source.tar.gz')
(root / 'pyproject.toml').write_text('[project]\nname = \"unrelated-project\"\nversion = \"0.1.0\"\n')
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
trust = root / 'trust.pem'
trust.write_bytes(Path(ssl.get_default_verify_paths().cafile).read_bytes() + (root / 'cert.pem').read_bytes())
received_authorization = []
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        received_authorization.append(self.headers.get('Authorization'))
        super().do_GET()

    def log_message(self, *_):
        pass
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), functools.partial(Handler, directory=str(root)))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / 'cert.pem', root / 'key.pem')
server.socket = context.wrap_socket(server.socket, server_side=True)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
url = f'https://localhost:{server.server_port}'
token_canary = 'installer-auth-is-not-for-fixture-hosts'
env = dict(os.environ, SSL_CERT_FILE=str(trust), CURL_CA_BUNDLE=str(trust), HEXSTRIKE_ARCHIVE_URL=url + '/source.tar.gz', HEXSTRIKE_BIN_DIR=str(root / 'bin'), HEXSTRIKE_GITHUB_TOKEN=token_canary)
try:
    # No checkout is present in this working directory. Exercise piped stdin.
    with (root / 'install.log').open('w') as log:
        download = subprocess.Popen(['curl', '--fail', '--silent', '--show-error', url + '/install.sh'], env=env, stdout=subprocess.PIPE, stderr=log)
        install = subprocess.Popen(['sh', '-s', '--', '--prefix', str(root / 'runtime with spaces'), '--state-dir', str(root / 'state with spaces'), '--no-start'], env=env, cwd=root, stdin=download.stdout, stdout=log, stderr=log)
        download.stdout.close()
        assert download.wait(timeout=30) == 0
        assert install.wait(timeout=300) == 0, str(root / 'install.log')
    launcher = root / 'runtime with spaces/hexstrike'
    result = subprocess.run([str(launcher), 'status', '--json'], capture_output=True, text=True, timeout=30, check=True)
    assert json.loads(result.stdout)['status'] == 'ready', result.stdout
    assert 'Browser startup, JavaScript, screenshot and download checks passed.' in (root / 'install.log').read_text()
    assert received_authorization and not any(received_authorization)
    assert token_canary not in launcher.read_text()
    assert token_canary not in (root / 'install.log').read_text()
    print(json.dumps({'success': True, 'checks': ['HTTPS-script-download', 'curl-piped-stdin', 'HTTPS-source-archive', 'unrelated-project-cwd', 'managed-runtime', 'paths-with-spaces', 'browser-readiness', 'installed-launcher', 'github-token-isolation'], 'root': str(root)}))
finally:
    server.shutdown()
    server.server_close()
    thread.join()
