#!/bin/sh
# Install into a private runtime and keep the user's Python environment untouched.
set -eu
umask 077
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_root=${HEXSTRIKE_INSTALL_DIR:-"$HOME/.local/share/hexstrike"}
case $(uname -s) in
    Darwin) default_state="$HOME/Library/Application Support/HexStrike" ;;
    *) default_state="${XDG_STATE_HOME:-$HOME/.local/state}/hexstrike" ;;
esac
state_dir=${HEXSTRIKE_STATE_DIR:-"$default_state"}
archive_url=${HEXSTRIKE_ARCHIVE_URL:-https://api.github.com/repos/Lyrie-ai/hexstrike-ai-beta/tarball/main}
source_explicit=0
download_dir=
release_dir=
bootstrap_script=
complete=0
cleanup() {
    if [ "$complete" -eq 0 ] && [ -n "$release_dir" ]; then rm -rf -- "$release_dir"; fi
    if [ -n "$download_dir" ]; then rm -rf -- "$download_dir"; fi
    if [ -n "$bootstrap_script" ]; then rm -f -- "$bootstrap_script"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
start=1
browser=1
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix|--state-dir|--source)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then printf 'Missing value for %s\n' "$1" >&2; exit 2; fi ;;
    esac
    case "$1" in
        --prefix) install_root=$2; shift 2 ;;
        --state-dir) state_dir=$2; shift 2 ;;
        --source) source_dir=$2; source_explicit=1; shift 2 ;;
        --no-start) start=0; shift ;;
        --no-browser) browser=0; shift ;;
        --help) printf '%s\n' 'Usage: ./install.sh [--prefix DIR] [--state-dir DIR] [--source CHECKOUT_OR_WHEEL] [--no-start] [--no-browser]'; exit 0 ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done
case $(uname -s) in Linux|Darwin) ;; *) printf '%s\n' 'Use a Linux server, Linux VM, or macOS host.' >&2; exit 1 ;; esac
as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}
# Bootstrap a managed interpreter; distribution Python versions remain untouched.
mkdir -p "$install_root/bootstrap"
install_root=$(CDPATH= cd -- "$install_root" && pwd)
uv_bin="$install_root/bootstrap/uv"
uv_version=
if [ -x "$uv_bin" ]; then uv_version=$("$uv_bin" --version | cut -d ' ' -f 1-2); fi
if [ "$uv_version" != 'uv 0.13.5' ]; then
    bootstrap_script=$(mktemp "${TMPDIR:-/tmp}/hexstrike-uv.XXXXXXXX")
    if command -v curl >/dev/null 2>&1; then
        curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 https://astral.sh/uv/0.13.5/install.sh -o "$bootstrap_script"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -q https://astral.sh/uv/0.13.5/install.sh -O "$bootstrap_script"
    else
        printf '%s\n' 'Install curl or wget to download the runtime bootstrap.' >&2
        exit 1
    fi
    UV_INSTALL_DIR="$install_root/bootstrap" UV_NO_MODIFY_PATH=1 sh "$bootstrap_script"
    rm -f "$bootstrap_script"
fi
if [ -n "${HEXSTRIKE_PYTHON:-}" ]; then
    python_bin=$HEXSTRIKE_PYTHON
else
    "$uv_bin" python install 3.12.15
    python_bin=$("$uv_bin" python find --managed-python 3.12.15)
fi
"$python_bin" -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11 or newer is required"'
# The same script supports a checkout or a standalone download; no git is required.
if [ ! -f "$source_dir" ] && { [ ! -f "$source_dir/pyproject.toml" ] || [ ! -f "$source_dir/src/hexstrike/cli/server.py" ]; }; then
    if [ "$source_explicit" -eq 1 ]; then printf 'Source does not contain a HexStrike checkout: %s\n' "$source_dir" >&2; exit 2; fi
    download_dir=$(mktemp -d "${TMPDIR:-/tmp}/hexstrike-download.XXXXXXXX")
    "$python_bin" - "$archive_url" "$download_dir" <<'PYDOWNLOAD'
from pathlib import Path, PurePosixPath
import os, shutil, sys, tarfile, urllib.parse, urllib.request
url, directory = sys.argv[1:]
if not url.startswith('https://'):
    raise SystemExit('The source archive URL must use HTTPS')
root = Path(directory)
class ArchiveRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('Source download redirected to an insecure URL')
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if urllib.parse.urlsplit(req.full_url).netloc != urllib.parse.urlsplit(newurl).netloc:
            redirected.remove_header('Authorization')
        return redirected

request = urllib.request.Request(url)
token = os.environ.get('HEXSTRIKE_GITHUB_TOKEN')
if token and urllib.parse.urlsplit(url).netloc == 'api.github.com':
    request.add_header('Authorization', 'Bearer ' + token)
opener = urllib.request.build_opener(ArchiveRedirect())
with opener.open(request, timeout=60) as response, (root / 'source.tar.gz').open('wb') as output:
    if not response.url.startswith('https://'):
        raise SystemExit('Source download redirected to an insecure URL')
    total = 0
    while chunk := response.read(1024 * 1024):
        total += len(chunk)
        if total > 128 * 1024 * 1024:
            raise SystemExit('Source archive exceeds 128 MiB')
        output.write(chunk)
with tarfile.open(root / 'source.tar.gz') as archive:
    members = archive.getmembers()
    if len(members) > 20000 or sum(m.size for m in members) > 512 * 1024 * 1024:
        raise SystemExit('Source archive exceeds extraction limits')
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
            raise SystemExit('Source archive contains an unsupported or unsafe entry')
        target = root / 'source' / str(path)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('wb') as output:
                shutil.copyfileobj(source, output)
            target.chmod(member.mode & 0o755)
projects = list((root / 'source').glob('*/pyproject.toml'))
if len(projects) != 1 or not (projects[0].parent / 'src/hexstrike/cli/server.py').is_file():
    raise SystemExit('Downloaded revision does not contain the supported installer/server. Choose a released revision with HEXSTRIKE_ARCHIVE_URL.')
(root / 'source-path').write_text(str(projects[0].parent))
PYDOWNLOAD
    source_dir=$(cat "$download_dir/source-path")
fi
unset HEXSTRIKE_GITHUB_TOKEN
mkdir -p "$install_root/releases" "$state_dir"
install_root=$(CDPATH= cd -- "$install_root" && pwd)
state_dir=$(CDPATH= cd -- "$state_dir" && pwd)
release_dir=$(mktemp -d "$install_root/releases/runtime.XXXXXXXX")
if ! "$uv_bin" venv --seed --python "$python_bin" "$release_dir"; then
    printf '%s\n' 'Could not create the private runtime. Check the interpreter and filesystem diagnostics above.' >&2
    exit 1
fi
lock_root=$source_dir
if [ -f "$source_dir" ]; then lock_root=$(dirname -- "$source_dir"); fi
if [ ! -f "$lock_root/requirements.lock" ]; then
    printf '%s\n' 'This release is missing requirements.lock. Use the complete source archive or place its lock beside the wheel.' >&2
    exit 1
fi
"$uv_bin" pip install --python "$release_dir/bin/python" --require-hashes -r "$lock_root/requirements.lock"
"$uv_bin" pip install --python "$release_dir/bin/python" --no-deps "$source_dir"
"$release_dir/bin/python" -c 'import hexstrike, textual, mcp'
chromium_path=
browser_download_dir=
if [ "$browser" -eq 1 ]; then
    chromium_path=$("$release_dir/bin/python" -c 'from hexstrike.browser.inspector import find_chromium_executable; print(find_chromium_executable() or "")')
    if [ -z "$chromium_path" ] && [ "$(uname -s)" = Linux ]; then
        # Distribution packages include their platform's browser integration.
        if command -v apt-get >/dev/null 2>&1; then
            distro=$("$release_dir/bin/python" -c 'import platform; info = platform.freedesktop_os_release(); print(info.get("ID", "") + " " + info.get("ID_LIKE", ""))')
            case " $distro " in
                *" ubuntu "*) browser_package=chromium-browser ;;
                *) browser_package=chromium ;;
            esac
            as_root apt-get update
            as_root apt-get install -y "$browser_package"
        elif command -v dnf >/dev/null 2>&1; then
            as_root dnf install -y chromium
        elif command -v pacman >/dev/null 2>&1; then
            as_root pacman -S --needed --noconfirm chromium
        fi
        chromium_path=$("$release_dir/bin/python" -c 'from hexstrike.browser.inspector import find_chromium_executable; print(find_chromium_executable() or "")')
    fi
    if [ -z "$chromium_path" ]; then
        "$release_dir/bin/python" -m playwright install chromium
        if [ "$(uname -s)" = Linux ] && command -v apt-get >/dev/null 2>&1; then
            as_root "$release_dir/bin/python" -m playwright install-deps chromium
        fi
        chromium_path=$("$release_dir/bin/python" -c 'from playwright.sync_api import sync_playwright; p = sync_playwright().start(); print(p.chromium.executable_path); p.stop()')
    fi
    # Verify the actual executable before replacing a working launcher.
    browser_download_dir=$("$release_dir/bin/python" - "$chromium_path" <<'PYDIR'
from pathlib import Path
import sys
executable = Path(sys.argv[1])
snap_browser = Path('/snap/bin/chromium')
if snap_browser.exists() and (executable.resolve() == snap_browser.resolve() or executable.name == 'chromium-browser'):
    directory = Path.home() / 'snap/chromium/common/hexstrike-downloads'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    print(directory)
PYDIR
)
    "$release_dir/bin/python" - "$chromium_path" "$browser_download_dir" <<'PYBROWSER'
import sys, tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
try:
    with tempfile.TemporaryDirectory(dir=sys.argv[2] or None) as downloads, sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=sys.argv[1], downloads_path=downloads, chromium_sandbox=True, timeout=30000)
        page = browser.new_page()
        page.set_content('<title>HexStrike installation check</title><a download="fixture.txt" href="data:text/plain,download-ok">Download</a>')
        assert page.title() == 'HexStrike installation check'
        assert page.evaluate('6 * 7') == 42
        assert page.screenshot().startswith(b'\x89PNG\r\n\x1a\n')
        with page.expect_download() as download:
            page.locator('a').click()
        assert Path(download.value.path()).read_text() == 'download-ok'
        browser.close()
except Exception as exc:
    raise SystemExit('Browser startup check failed; the existing launcher was kept. '
                     'Check the browser diagnostics below, or choose --no-browser for a core-only installation.\n' + str(exc))
print('Browser startup, JavaScript, screenshot and download checks passed.')
PYBROWSER
fi
# Write a launcher with shell-quoted paths; no credentials are embedded in it.
"$release_dir/bin/python" - "$install_root" "$state_dir" "$release_dir" "$chromium_path" "$browser_download_dir" <<'PY'
from pathlib import Path
import os, shlex, sys, tempfile
root, state, release = map(Path, sys.argv[1:4])
chromium = sys.argv[4]
downloads = sys.argv[5]
launcher = root / 'hexstrike'
fd, name = tempfile.mkstemp(prefix='.hexstrike-', dir=root)
temporary = Path(name)
with os.fdopen(fd, 'w') as stream:
    stream.write('#!/bin/sh\n')
    if chromium:
        stream.write('if [ -z "${HEXSTRIKE_CHROMIUM_EXECUTABLE:-}" ]; then\n')
        stream.write('    export HEXSTRIKE_CHROMIUM_EXECUTABLE=' + shlex.quote(chromium) + '\nfi\n')
    if downloads:
        stream.write('if [ -z "${HEXSTRIKE_BROWSER_DOWNLOAD_DIR:-}" ]; then\n')
        stream.write('    export HEXSTRIKE_BROWSER_DOWNLOAD_DIR=' + shlex.quote(downloads) + '\nfi\n')
    stream.write('if [ "$#" -eq 0 ]; then set -- server; fi\n')
    stream.write('exec ' + shlex.quote(str(release / 'bin/hexstrike')) + ' --state-dir ' + shlex.quote(str(state)) + ' "$@"\n')
temporary.chmod(0o700)
os.replace(temporary, launcher)
bin_dir = Path(os.environ.get('HEXSTRIKE_BIN_DIR', str(Path.home() / '.local/bin'))).expanduser()
bin_dir.mkdir(parents=True, exist_ok=True)
link = bin_dir / 'hexstrike'
if not link.exists() or (link.is_symlink() and link.resolve() == launcher):
    link.unlink(missing_ok=True)
    link.symlink_to(launcher)
PY
complete=1
cleanup
download_dir=
printf '\nInstalled. Start or reopen with: %s/hexstrike\n' "$install_root"
if [ "$start" -eq 1 ]; then
    # A downloaded script may have stdin connected to a pipe, not the operator.
    if [ ! -t 0 ]; then
        if ( : < /dev/tty ) 2>/dev/null; then
            exec < /dev/tty
        else
            printf '%s\n' 'Run the command above in a terminal to configure and open the dashboard.'
            exit 0
        fi
    fi
    exec "$install_root/hexstrike" server
fi
