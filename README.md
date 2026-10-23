# HexStrike AI MCP

<p align="center"><img src="assets/hexstrike-logo.png" alt="HexStrike AI" width="440"></p>

HexStrike connects AI assistants to the tools, terminal, files and browser on your server through the Model Context Protocol (MCP). Your AI client requests work; HexStrike runs it, records output and evidence, and shows progress in a terminal dashboard.

**Owner:** [0x4m4](https://github.com/0x4m4) · **License:** [MIT](LICENSE)

## What it does

- Runs installed command-line tools and custom scripts without requiring an adapter for each program.
- Supports persistent shells and REPLs, incremental input/output, terminal resizing, timeouts and cancellation.
- Provides browser navigation, forms, screenshots, uploads/downloads and saved sessions.
- Discovers server executables and offers optional typed adapters for structured arguments and results.
- Retains jobs, paginated evidence and local memory for subsequent review.
- Shows jobs, sessions, installed tools and connection settings in the server dashboard.

Ten MCP tools provide discovery, execution and result retrieval. Detailed capability schemas load when requested. Available software and the server account's OS permissions determine what can run.

## Install on your server

Clone the private beta repository using a GitHub account with access, then run:

```sh
git clone https://github.com/Lyrie-ai/hexstrike-ai-beta.git
cd hexstrike-ai-beta
./install.sh
```

Without cloning, if GitHub CLI is installed and authenticated with repository access:

```sh
gh api 'repos/Lyrie-ai/hexstrike-ai-beta/contents/install.sh?ref=main' \
  -H 'Accept: application/vnd.github.raw+json' | \
  HEXSTRIKE_GITHUB_TOKEN="$(gh auth token)" sh
```

The private repository requires GitHub authentication. Both commands use `main`. The download token is used only to fetch source and is not saved in HexStrike's launcher or configuration.

The installer downloads a managed Python runtime, installs dependencies from a hashed lock, sets up the dashboard and browser, and opens guided setup. You do not need to create a virtual environment or change your system Python. Linux—including Kali—and macOS need `curl` or `wget` and internet access; installing a missing Linux browser may request `sudo`. Windows users can run the server in a Linux VM.

Choose local access, an existing HTTPS proxy, TLS certificate files, or optional Tailscale HTTPS. Setup generates and saves an authentication token. Remote access needs a reachable HTTPS endpoint; the AI-client machine does not need HexStrike installed.

[Installation, platform requirements and troubleshooting](docs/INSTALLATION.md)

To install now and start later, use `./install.sh --no-start`. HexStrike uses command-line tools installed on the host; an adapter is not required for each program. A bundled container distribution is deferred to a later update.

## Connect and run

Reopen the dashboard on the server:

```sh
~/.local/share/hexstrike/hexstrike
```

If `~/.local/bin` is on your PATH, use `hexstrike`. Open **Connect** for the MCP URL, token and copyable Cursor, Claude Code, Codex or VS Code configuration. Closing the dashboard with **q** leaves the server running. **Clear view** hides displayed history without deleting evidence; **Refresh** restores it.

For unattended operation, configure a service manager. The background launcher does not install a boot service automatically.

[Server configuration and client connections](docs/CONFIGURATION.md)

## Documentation

| Guide | Contents |
| --- | --- |
| [Installation](docs/INSTALLATION.md) | One-command install, checkout install, platforms, upgrades and uninstall |
| [Configuration](docs/CONFIGURATION.md) | Authentication, HTTPS, state paths, clients, service operation and optional integrations |
| [Usage](docs/USAGE.md) | Native tools, terminals, browsers, evidence, adapters and dashboard controls |
| [Architecture](docs/ARCHITECTURE.md) | Components, execution flow, storage and trust boundaries |
| [Development](docs/DEVELOPMENT.md) | Tests, benchmarks, builds and repository hygiene |

## Execution model

Authenticated native execution has the server account's filesystem and network access. Optional isolated execution uses Docker, Podman or Bubblewrap when installed. Scanner findings and intelligence metadata need review; they are not proof of exploitability. Local memory supports retrieval and provenance, not automatic code rewriting.

The server supports POSIX systems. Client configuration formats, container engines and external tool versions need testing in their actual deployment environment. See the development guide for the automated checks and opt-in integration tests.
