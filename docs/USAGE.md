# Usage

[README](../README.md) · [Configuration](CONFIGURATION.md)

## MCP interface

The top-level tools are `system_status`, `capabilities_search`, `capabilities_describe`, `engagement_manage`, `action_prepare`, `job_start`, `job_status`, `job_cancel`, `evidence_read` and `memory_query`. Discover capabilities and request their schemas before constructing arguments. Use `wait=false` for long jobs and poll with the returned cursor to avoid repeating output.

Capability risk labels are informational. `max_risk_level` remains accepted for compatibility, but status reports `risk_tiers_enforced: false`. Engagement ownership, operator-supplied targets, resource budgets and OS permissions remain separate controls. Native host commands are not constrained by typed-adapter target filtering.

## Dashboard

Jobs show execution state; selecting a row opens details. Sessions separates recent authenticated MCP activity from detached execution sessions. An idle HTTP entry represents recent activity rather than proof of a live socket. Stdio clients do not have HTTP activity records.

Tools lists the server account's executable inventory with search, pagination and Rescan. Connect provides the endpoint and client settings. About shows project metadata and capabilities. The event filter only changes the displayed log.

| Control | Effect |
| --- | --- |
| **q / Close** | Close the dashboard and leave the server running |
| **r / Refresh** | Reload telemetry and restore hidden history |
| **s / Stop jobs**, **Ctrl+X** | Request cancellation of the operator's jobs and detached sessions, including other engagements |
| **c / Reset filter** | Clear the event filter |
| **Clear view** | Hide currently displayed finished jobs, closed clients and past events for this dashboard session; retain evidence and active work |
| **k / Connect** | Open connection settings |
| **Esc** | Return focus from an input to the active pane |

## Installed tools and offline analysis

`tools.inventory` inventories executable names on the server's PATH, with bounded results and pagination. It distinguishes installed programs from registered adapters. The equivalent CLI command is `hexstrike tools discover --installed --query tshark`. Discovery does not execute unknown binaries or claim they have tested integration.

Use `capabilities_describe` to obtain schemas, then `job_start` to run file identification, capture metadata (`capinfos`), packet inspection (`tshark`), ELF headers (`readelf`), sections (`objdump`), strings, and ExifTool. Inputs are workspace-relative files. Analysis uses private snapshots; evidence records the source hash, size, mode and modification time. TShark inspects up to the requested packet limit; a filtered result is not proof that the entire capture was inspected. DNSenum requires an explicit resolver and a workspace wordlist. Masscan needs raw-socket privileges; an installed binary alone does not make it usable by an unprivileged server account.

For authenticated operators, `workspace.files` creates, reads, lists and updates files through the same job and evidence lifecycle. Creation refuses to overwrite an existing file. `tools.adapters` requires the operator role and installs or removes operator-trusted custom manifests through MCP, so a client can create an analysis program, register its parameters, execute it and read the resulting report without adding another top-level MCP tool. Custom programs run with the server account's OS permissions: the manifest is an execution extension, not a sandbox. Install only code you trust. Core file inspection confinement does not sandbox custom programs.

Live SSH-worker acceptance is opt-in: set `HEXSTRIKE_RUN_REMOTE_TESTS=1` and `HEXSTRIKE_TEST_SSH_TARGET` to your configured SSH destination. The default test suite does not assume a particular hostname or root account.

## Execution and interactive workflows

`execution.host.run` executes installed commands and scripts directly on the connected MCP server, with its service account's filesystem and network access. No custom adapter, container or target allowlist is needed for this capability. Pass `argv` as an array, an optional host `cwd`, environment overrides and one-shot `stdin`; use an explicit shell such as `["/bin/sh", "-c", "command1 | command2"]` for shell syntax. Relative working directories resolve from the server workspace. Host commands can create, modify and delete files wherever the OS account has permission, and can access the server's network. They do not automatically acquire root privileges. The operator role and engagement ownership are required; target filtering cannot constrain arbitrary host programs. Server credentials are not automatically copied into the child environment. Use `wait=false` for long commands, `job_status` to monitor and `job_cancel` to stop them. Output is streamed to telemetry and retained as bounded evidence.

For a persistent host shell or REPL, use `execution.host.start` with `tty=true`, for example `argv=["/bin/sh", "-i"]`. The returned `session_id` supports `status`, `stdin`, `eof`, `resize`, and `cancel`. Shell working directory and variables persist inside that session across MCP reconnects. With `tty=false`, programs receive ordinary pipes and still support incremental stdin. PTY output merges stdout and stderr and may contain terminal escape sequences. Status uses byte offsets; retention is capped at 512 KiB per stream and reports truncation. Save large results to files when the complete artifact is needed. Sessions run on POSIX hosts independently of the MCP transport process, retain evidence and appear in the monitor; they remain subject to the configured wall-clock timeout and concurrency budget. `tools.inventory` discovers all executable names on the server PATH with pagination. Any discovered executable can be passed to `execution.host`; an adapter is optional and discovery alone does not prove that a tool's dependencies or privileges are satisfied.

`execution.sandbox` runs argv or script files without installing a custom adapter. Create an environment using a **locally installed image**, write a script with `file_write`, then `start` it with an argv such as `["python3", "analysis.py"]` or `["/bin/sh", "task.sh"]`. Container image tags are resolved to immutable image IDs at creation. Files persist in the environment until `remove`; dependencies can be installed into that workspace. The backend never falls back to executing the program directly on the server.

Docker and Podman use a read-only root filesystem, a dedicated writable workspace, dropped capabilities, no-new-privileges, and container memory/CPU/process limits. Networking defaults to `none`. `outbound` requires an unrestricted network policy explicitly configured by the operator because arbitrary programs cannot enforce a target allowlist from their command-line arguments. Requests still go through authentication, ownership and job checks. No host root, Docker socket or server state is mounted into execution containers.

Linux also supports Bubblewrap with read-only system software and a private PID/network/filesystem namespace. Its limits are per-process or shared host-UID limits, **not container cgroup quotas**, and its system software is not an immutable image. Use a container backend when aggregate resource isolation or a reproducible root filesystem is required. Native Windows server execution remains unsupported; Windows clients can connect to a Linux/WSL/container server.

Sessions survive MCP reconnects and expose incremental `status`, `stdin`, `eof`, and `cancel` operations. `system_status` lists detached sessions; `job_cancel(cancel_all=True)` includes execution and browser sessions. Session output appears in server telemetry. A completed *start job* means the session was created; inspect the session for the actual program exit status. Output retention is bounded and truncation is reported.

`web.http_inspect` supports GET/HEAD/OPTIONS/POST/PUT/PATCH/DELETE, headers, cookies, JSON/raw/multipart bodies, proxies, persistent cookie sessions, TLS metadata and client certificates. `evidence.compare` compares recorded responses. Sensitive authentication should use origin-bound `credential_ref` values, provisioned on the server with `hexstrike credential NAME` reading JSON from stdin. Secrets are stored under the private state directory, never in the repository; filesystem permissions protect them at rest. They are not encrypted by HexStrike.

`browser.session` keeps a Chromium context alive across navigation, click, fill, wait, upload/download, screenshot and save/close calls. Authentication state stays in the private state directory. HTTP requests, subresources and WebSockets follow the current engagement policy; allow `ws`/`wss` explicitly when needed. Playwright 1.48+ and a working Chromium sandbox are required. `browser.inspect` remains available for single-page inspections and redacted HAR capture.

`research.web` retrieves bounded text/HTML/JSON sources under a separate research policy. Search uses a configured SearXNG JSON endpoint; no provider key or account is assumed. `tools.verify` runs an operator-supplied positive/negative fixture suite through real jobs and records assertions, job handles and code/binary/schema identity. Installation alone is not recorded as integration verification.

Job responses stay compact. Use `evidence_read` for artifact handles and pagination, or `view="har"` with URL/method/status filters for network captures. Clients supporting MCP resources can retrieve PNG screenshots at `hexstrike://evidence/{evidence_id}/image` and other artifacts at `hexstrike://evidence/{evidence_id}/artifact` (10 MiB transfer limit). Workspace text editing also supports exact-match `patch` with a SHA-256 precondition and bounded literal `search`.

## Adapter verification

`tools.verify` takes a capability ID and a workspace-relative JSON suite. Each case contains `name`, `operation`, `arguments`, `expected` JSON-pointer assertions over the job response, and `negative_control`. At least one positive and one negative case are required. Receipts retain job handles and binary, source, schema and platform identity. They establish the supplied assertions rather than universal tool correctness.

Threat-intelligence correlation requires supplied feed/cache records or explicitly enabled providers. Missing records remain unavailable. Opt-in simulated input records stay labelled simulated and do not count as verified data; the server does not generate substitute reputation records.
