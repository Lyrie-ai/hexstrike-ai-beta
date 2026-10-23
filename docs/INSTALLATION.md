# Installation

[README](../README.md) · [Configuration](CONFIGURATION.md)

## Requirements

Run the server on Linux or macOS with `curl` or `wget` and internet access. Kali uses the same installer as other Linux distributions. Tools run with the account that starts HexStrike; native installations use CLI tools available in that account's PATH. The installer sets up HexStrike and its application dependencies; install additional security tools with your OS package manager as needed.

The installer bootstraps a versioned `uv` runtime manager and managed Python 3.12.15, then installs dependencies from `requirements.lock` with hash verification. The system Python remains untouched. `HEXSTRIKE_PYTHON` is an optional override for operators supplying their own Python 3.11+ interpreter. Download availability for the host's OS, architecture and libc is required; this is not a guarantee for every Linux distribution or CPU architecture.

Browser workflows need Chromium and its OS libraries. The installer respects `HEXSTRIKE_CHROMIUM_EXECUTABLE` and reuses an existing Chromium/Chrome executable. Otherwise it installs the distribution's browser through apt, dnf or pacman when available. Ubuntu uses its `chromium-browser` package, which installs the confined Chromium snap; Debian and Kali use `chromium`. Repository availability and the host's support for the package remain prerequisites. Without one of those package managers, the installer downloads Playwright Chromium; other minimal Linux images may need its OS libraries.

Before switching the launcher, installation tests actual browser startup, JavaScript execution, screenshot capture and downloading a file. Confined Chromium packages use a shared download directory configured by the installer. A failed browser check stops installation and retains the previous launcher. `--no-browser` skips browser binary installation and readiness checks; Python browser support remains installed. The installer does not disable AppArmor or Chromium's sandbox. Native Windows server execution is unsupported; Windows MCP clients can connect to a Linux server, VM or container.

## Install without cloning

```sh
curl -fsSL https://raw.githubusercontent.com/Lyrie-ai/hexstrike-ai-beta/main/install.sh | sh
```

The script downloads the source from `main`, installs HexStrike and opens guided setup. No Git or GitHub CLI installation is needed. Without a controlling terminal, installation prints the launcher path and exits; run that command in a terminal to complete setup.

To download and inspect the script first:

```sh
curl -fsSL https://raw.githubusercontent.com/Lyrie-ai/hexstrike-ai-beta/main/install.sh -o install-hexstrike.sh
less install-hexstrike.sh
sh install-hexstrike.sh
```

Set `HEXSTRIKE_ARCHIVE_URL` to an HTTPS archive URL for a specific tag or commit when you need a pinned source revision. Use an installer from the same revision. The installer validates the archive before extraction and rejects path traversal, links and special files.

## Install from a checkout

```sh
git clone https://github.com/Lyrie-ai/hexstrike-ai-beta.git
cd hexstrike-ai-beta
./install.sh
```

No manual virtual-environment creation is required. The installer does not install every security tool or replace your OS Python packages.

Setup asks how clients will reach the server and generates an authentication token unless you supply one. See [connection methods](CONFIGURATION.md#connection-methods). Reopen the dashboard with the launcher path printed after installation, normally:

```sh
~/.local/share/hexstrike/hexstrike
```

## Installer options

| Option | Purpose |
| --- | --- |
| `--prefix DIR` | Install private runtimes and launcher under DIR |
| `--state-dir DIR` | Use a specific persistent state directory |
| `--source PATH` | Install a local checkout, or a wheel with its matching requirements.lock beside it |
| `--no-start` | Install without starting the server or dashboard |
| `--no-browser` | Skip browser binary installation and browser readiness checks |

```sh
./install.sh --prefix "$HOME/apps/hexstrike" --state-dir "$HOME/hexstrike-state" --no-start
```

Environment overrides are `HEXSTRIKE_INSTALL_DIR`, `HEXSTRIKE_STATE_DIR`, `HEXSTRIKE_BIN_DIR`, `HEXSTRIKE_PYTHON` and `HEXSTRIKE_ARCHIVE_URL`. The command symlink defaults to `~/.local/bin/hexstrike`; an unrelated existing command is preserved. Paths containing spaces are supported.

Default state is `~/.local/state/hexstrike` on Linux (`XDG_STATE_HOME` is respected) and `~/Library/Application Support/HexStrike` on macOS. The launcher remembers the selected state path.

## Update and remove

Stop jobs and detached sessions before maintenance. Save state with:

```sh
hexstrike backup
```

Rerun the installer from the desired checkout or pass `--source` with the new wheel, using the same prefix and state directory. It creates a new runtime and switches the launcher after installation succeeds. The running process keeps its existing code until restarted:

```sh
hexstrike server --restart
```

A service-managed server must be restarted through its service manager. Previous runtimes are retained for rollback. Keep the previous artifact/runtime until the upgrade is accepted; inspect which runtime your launcher and service use before deleting old directories.

`hexstrike upgrade --package-source /path/to/package.whl` is an alternative package upgrade with state backup and import checks. State rollback does not reinstall the previous Python environment.

```sh
hexstrike uninstall --archive-to /path/to/backup --disconnect-clients --remove-package
```

Uninstall preserves state unless `--purge-data` is explicitly supplied. It removes the selected package, not the installer's entire release history. Remove an installer prefix or launcher symlink separately only after stopping its service and preserving any data you need.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `hexstrike: command not found` | Use the printed absolute launcher path or add `~/.local/bin` to PATH |
| Runtime installation fails | Check access to the runtime/package download hosts, disk space and the error log; `HEXSTRIKE_PYTHON` can select an existing interpreter |
| Browser fails at launch | Check Chromium's shared libraries, sandbox support and `HEXSTRIKE_CHROMIUM_EXECUTABLE` |
| Remote client cannot connect | Confirm the public URL, certificate, proxy/firewall and bearer token in Connect |
| Server fails to start | Read `server.log` in the selected state directory; check whether its port is already occupied |
| Clipboard buttons do not copy | Enable terminal OSC 52 support or reveal/select the configuration text |

`hexstrike doctor --json` reports runtime and installed adapter availability. An executable being present does not establish that its dependencies, privileges or external services are ready.
