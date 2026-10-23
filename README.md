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

Run on Linux, Kali or macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/Lyrie-ai/hexstrike-ai-beta/main/install.sh | sh
```

Or install from a checkout:

```sh
git clone https://github.com/Lyrie-ai/hexstrike-ai-beta.git
cd hexstrike-ai-beta
./install.sh
```

The installer handles Python, dependencies and browser setup, then starts the server and opens the dashboard without a setup questionnaire. You do not need to create a virtual environment or change your system Python. Internet access and `curl` or `wget` are required; installing a missing Linux browser may request `sudo`. Windows users can run the server in a Linux VM.

First startup generates and saves an authentication token and listens at `http://127.0.0.1:8000/mcp`. Existing connection settings are reused. For access from another machine, configure an HTTPS endpoint using the [connection guide](docs/CONFIGURATION.md#connection-methods); the installer does not create a public HTTPS endpoint automatically. The AI-client machine does not need HexStrike installed.

[Installation, platform requirements and troubleshooting](docs/INSTALLATION.md)

To install now and start later, use `./install.sh --no-start`. HexStrike uses command-line tools installed on the host; an adapter is not required for each program.

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
