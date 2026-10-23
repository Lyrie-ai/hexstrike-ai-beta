# Configuration

[README](../README.md) · [Installation](INSTALLATION.md) · [Usage](USAGE.md)

## Saved settings and authentication

Run `hexstrike server --configure` for guided setup. First setup generates a token unless `HEXSTRIKE_API_TOKEN` is supplied or you enter one. Saved `server.json` contains the token, listener address/port, public URL and optional certificate paths. It must be a regular file with permissions `0600`. The token persists across restarts; it is masked in the dashboard until revealed.

Stop the server before changing connection settings. The public URL is operator configuration: interface discovery cannot infer your DNS, NAT, reverse proxy or certificate name. The dashboard displays that configured URL and the host's current interface addresses.

The saved launcher uses static bearer authentication over Streamable HTTP. Clients send `Authorization: Bearer <token>`. Built-in OAuth login is not provided. Authentication permits native execution as the server account; OS permissions determine its reach.

## Connection methods

### This machine only

```sh
hexstrike server
```

The default listener is `127.0.0.1:8000`, with endpoint `http://127.0.0.1:8000/mcp`. This URL is reachable only on the server itself. Select a remote method to connect from another computer.

### Existing HTTPS reverse proxy

```sh
hexstrike server --url https://hexstrike.example.org/mcp --no-ui
```

Replace the example hostname with your endpoint. Forward `/mcp` and `/api/v6/` to the local listener at `127.0.0.1:8000`, preserving authorization and MCP session headers. The proxy must support streaming responses. Configure proxy timeouts for long-running connections. The saved launcher's URL must end in `/mcp` at the endpoint root.

### Direct TLS listener

```sh
hexstrike server --url https://hexstrike.example.org:8443/mcp \
  --host 0.0.0.0 --port 8443 \
  --tls-cert /path/to/fullchain.pem --tls-key /path/to/privkey.pem --no-ui
```

Supply actual server-local certificate paths, a hostname covered by the certificate and network/firewall access to the port. Certificate issuance and renewal are handled by your certificate provider or deployment tooling. The server's local monitor connects directly to the listener while verifying the public certificate hostname.

### Optional Tailscale HTTPS

```sh
hexstrike server --tailscale --no-ui
```

Tailscale must already be installed, signed in and configured for HTTPS. The endpoint comes from that machine's Tailscale identity. Setup refuses to replace an existing port-443 Serve mapping for another application. Tailscale is not required for other connection methods.

## MCP clients

Open **Connect** on the server and select the client. Copy the generated configuration; it contains the actual URL and token. The dashboard provides Cursor, Claude Code, Codex and VS Code formats. Treat copied configurations as credentials.

To print the equivalent configuration explicitly:

```sh
hexstrike server --connection --client cursor
hexstrike server --connection --client claude
hexstrike server --connection --client codex
hexstrike server --connection --client vscode
```

These commands print the token. Terminal clipboard copying uses OSC 52 and depends on terminal support. The server remains running when the UI closes; clients do not need a local HexStrike installation for HTTPS access.

The `connect` command can instead write client settings on the machine where it is run. It preserves unrelated entries and supports `--dry-run`. Remote HTTP entries use an environment token reference rather than embedding a secret:

```sh
hexstrike connect cursor --topology remote-http \
  --remote-http-url https://hexstrike.example.org/mcp --dry-run
```

The connector also includes Gemini CLI HTTP configuration. Claude Desktop and Antigravity generators support local/SSH stdio; they do not generate HTTP credential settings. Verify a real initialization and tool call in the actual client version you deploy.

For a client spawning a local stdio server, use command `hexstrike-mcp`, arguments `--transport stdio`, and select the intended state through `HEXSTRIKE_STATE_DIR` in that client's process environment. Stdio reserves stdout for MCP frames.

## Controller and worker placement

To run the controller through SSH stdio:

```sh
hexstrike connect cursor --topology ssh-controller \
  --ssh-controller operator@server --dry-run
```

The destination needs HexStrike and Python installed. Use `--remote-python` for an interpreter outside PATH and `--remote-state-dir` to override the remote account's default state directory.

A local controller can separately dispatch supported tool operations to an SSH worker. In that topology, jobs and evidence remain on the controller. SSH execution uses the remote account's PATH and home directory; container selection is explicit. Advanced HTTP authentication and browser session workflows should connect to the worker's own MCP server.

A local state-reading monitor must share the controller's host and PID namespace. A separate machine or container uses authenticated remote telemetry instead.

## Paths and optional components

| Setting | Purpose |
| --- | --- |
| `--state-dir` | Explicit state directory for the current invocation; place before the subcommand |
| `HEXSTRIKE_STATE_DIR` | State override when no CLI path is provided |
| `HEXSTRIKE_HOME` | Compatibility state-directory override |
| `XDG_STATE_HOME` | Linux/POSIX state base when no explicit state path is set |
| `HEXSTRIKE_CHROMIUM_EXECUTABLE` | Explicit browser executable path |
| `PATH` | Executable discovery and native command lookup |

The installer launcher always supplies its selected state path. Use that same launcher for server management and maintenance. Keep state outside the checkout. It contains databases, evidence, credentials, browser state and execution files.

The installer and bundled image include the core, UI, browser and Graphiti Python dependencies. Local SQLite memory is available without an external service; configure Graphiti separately when using its integration. Installing Graphiti does not by itself establish improved findings or an external inference service.

## Service operation

```sh
hexstrike server --no-ui
hexstrike server --stop
hexstrike server --restart
```

`--no-ui` starts the background process and returns. `--restart` requires idle jobs and sessions. Closing the dashboard does not stop the process. The background launcher does not automatically start after a reboot or restart a crashed server.

For systemd, launchd or another supervisor, configure the actual absolute launcher path, the intended OS account and foreground command `server --headless`. Set `HEXSTRIKE_SERVICE_MANAGED=1` in the service environment. Manage restarts through that supervisor. There is no assumed service name, username or install prefix.

`server.log` lives in the state directory. Remote telemetry is authenticated; `/health` only reports liveness. The lower-level `hexstrike mcp --transport streamable-http` command requires credentials supplied separately and does not load the saved launcher's token automatically. `hexstrike-server` is the compatibility HTTP API, not an MCP endpoint.

## Credentials, research and maintenance

Use `execution-secret NAME` to provision an environment secret from stdin, then pass `env_refs={"VARIABLE":"NAME"}` to `start`. Container environment values must be single-line strings. References are stored in plans; resolved values are delivered privately and redacted from retained process streams. Do not place credentials in command-line arguments or script contents. HTTP credentials use `credential NAME` and a JSON object such as:

```json
{"origins":["https://assessment.example"],"headers":{"Authorization":"Bearer replace-on-server"}}
```

Optional fields are `cookies`, `body`, `ca_file`, `cert_file`, and `key_file`; certificate paths are server-local. Authentication is checked against exact scheme/host/port origins. Body-bearing and authenticated redirects across origins require a separate request. Raw request arguments are part of the audit plan: use references for sensitive values. HTTP cookie sessions and saved browser authentication state are private server data and must be included in backup protection.

Research configuration lives in `research.json` in the state directory:

```json
{"search_endpoint":"https://search.example/search","allow_private_networks":false}
```

The endpoint must provide the SearXNG JSON API. Private-network retrieval is disabled unless the operator enables it. Research requests do not modify engagement scan targets. Responses retain source URLs and are treated as external material, not executable instructions or verified vulnerabilities.


Stop active jobs before maintenance. Backups are immutable snapshots under `<state_dir>.backups`; `backup --output-dir` selects a different destination. Symlinks, hard links and special files in the captured workspace are rejected. Snapshot integrity hashes detect accidental changes, not a malicious party capable of replacing the manifest itself.

`rollback --state` validates the snapshot and replaces databases, workspace and custom adapters. Files added after the snapshot are removed. Restart controllers after restore. If replacement is interrupted, the next maintenance operation recovers the previous directory before proceeding; controller startup refuses to bypass a pending recovery journal. Preserve snapshot and recovery directories when investigating storage failures.

`upgrade --package-source` requires an explicit package source, saves state, installs the package and checks imports in a fresh interpreter. It does not restore an older Python environment automatically. On failure, reinstall the previous package before restoring the matching snapshot. Keep the previous wheel or environment for that purpose. Snapshot restore rejects incompatible application versions.

`setup --install-extras` uses the local checkout when present, otherwise the installed version's dependency set. Use `--package-source` to select a different source. Installer failures return nonzero status. Install into a virtual environment; do not overwrite distribution-managed Python packages.

Uninstall retains state unless `--purge-data` is specified. `--archive-to` creates a snapshot before removal. `--disconnect-clients` removes configured HexStrike entries. Package removal requires `--remove-package`; failures are reported separately from data retention/removal.
