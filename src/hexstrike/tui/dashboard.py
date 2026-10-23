"""Terminal dashboard for server execution, installed tools, and MCP connections."""

from __future__ import annotations

import asyncio
import os
import json
from collections import deque
from typing import Any, Dict, Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from rich.text import Text
from textual.events import Resize
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, DataTable, Header, Input, RichLog, Select, Static, TabbedContent, TabPane, TextArea

from hexstrike.transports.telemetry import TelemetryClient, TelemetryError
from hexstrike.transports.monitoring import MonitorState
from hexstrike.application.services import HexStrikeRuntime
from hexstrike.policy.engine import PolicyViolationError
from hexstrike.reporting.formatter import sanitize_terminal_text


CRIMSON_BANNER_ASCII = (
    '██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗    █████╗  ██╗   ███╗   ███╗  ██████╗ ██████╗ \n'
    '██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝   ██╔══██╗ ██║   ████╗ ████║ ██╔════╝ ██╔══██╗\n'
    '███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗     ███████║ ██║   ██╔████╔██║ ██║      ██████╔╝\n'
    '██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝     ██╔══██║ ██║   ██║╚██╔╝██║ ██║      ██╔═══╝ \n'
    '██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗   ██║  ██║ ██║   ██║ ╚═╝ ██║ ╚██████╗ ██║     \n'
    '╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝  ╚═╝ ╚═╝   ╚═╝     ╚═╝  ╚═════╝ ╚═╝     '
)

CRIMSON_CSS = """
Screen {
    background: #0d0204;
    color: #f5e6e8;
}

#banner-box {
    height: auto;
    padding: 0 2;
    background: #1a0408;
    border: tall #b71c1c;
    color: #ff3b3b;
    text-style: bold;
}

#status-strip {
    height: auto;
    min-height: 3;
    max-height: 6;
    padding: 0 2;
    background: #2b060d;
    border-bottom: solid #d32f2f;
    color: #ffdde0;
    content-align: left middle;
}

#main-split {
    height: 1fr;
}

#left-pane {
    width: 55%;
    height: 1fr;
    padding: 0 1;
}

#right-pane {
    width: 45%;
    height: 1fr;
    padding: 0 1;
}

Screen.compact #main-split {
    layout: vertical;
}

Screen.compact #left-pane {
    width: 100%;
    height: 70%;
}

Screen.compact #right-pane {
    width: 100%;
    height: 30%;
}

Screen.compact #banner-box, Screen.short #banner-box {
    display: none;
}

DataTable {
    background: #120307;
    color: #f5e6e8;
    border: solid #8b111e;
    height: 1fr;
}

DataTable > .datatable--header {
    background: #5c0913;
    color: #ffffff;
    text-style: bold;
}

DataTable > .datatable--cursor {
    background: #b71c1c;
    color: #ffffff;
}

RichLog {
    background: #0a0103;
    color: #f0d5d8;
    border: solid #b71c1c;
    height: 1fr;
    padding: 0 1;
}

#filter-input {
    background: #1a0408;
    border: solid #8b111e;
    color: #ffffff;
    dock: bottom;
}

Header {
    background: #7f0000;
    color: #ffffff;
}

#actions { dock: bottom; height: 1; background: #3d040b; }
#actions Button { height: 1; min-height: 1; min-width: 0; width: auto; border: none; padding: 0 1; background: #3d040b; color: #ffdde0; }
#actions Button:hover, #actions Button:focus { background: #b71c1c; }
Screen.compact #actions { height: 2; layout: grid; grid-size: 4 2; grid-rows: 1 1; }
#about-pane { padding: 1 2; }
#about-pane Static { height: auto; margin-bottom: 1; }

#engagement-picker { height: 3; margin: 0 1; }
ModalScreen { align: center middle; background: #000000 65%; }
.dialog { width: 90%; max-width: 100; height: 90%; padding: 1 2; background: #1a0408; border: solid #b71c1c; }
.dialog Static { height: auto; margin-bottom: 1; }
.dialog Input, .dialog Select { height: 3; }
.dialog TextArea { height: 1fr; margin: 1 0; }
.dialog Horizontal { height: 3; }
.dialog Button { margin-right: 1; min-width: 12; }
#tools-controls { height: auto; }
#tools-controls Horizontal { height: 3; }
#tools-controls Input { height: 3; }
#tools-controls Button { min-width: 8; margin-right: 1; }
#tools-summary, #sessions-help { height: auto; padding: 0 1; }
.connection-pane { height: 1fr; padding: 0 1; }
.connection-pane Static { height: auto; }
.connection-pane TextArea { height: 9; margin-bottom: 1; }
.connection-pane #connection-url, .connection-pane #connection-token { height: 3; }
.connection-pane Select { height: 3; }
.connection-pane Horizontal { height: 3; margin-bottom: 1; }
.connection-pane Button { min-width: 10; margin-right: 1; }

Screen.compact #tools-summary, Screen.compact #sessions-help { display: none; }
Screen.compact #tools-controls Input { height: 1; border: none; padding: 0; }
Screen.compact #tools-controls Horizontal { height: 1; }
Screen.compact #tools-controls Button { height: 1; min-height: 1; border: none; padding: 0 1; }

Screen.compact #status-strip { min-height: 2; max-height: 3; }
Screen.compact #filter-input { height: 1; border: none; padding: 0; }

"""


class ConnectionPane(VerticalScroll):
    def __init__(self, url: str, token: str):
        super().__init__(classes="connection-pane")
        self.settings = {"url": url, "token": token}
        self.revealed = False
        self.client = "cursor"

    def compose(self):
        yield Static("Remote MCP connection", markup=False)
        yield Static("Server address information loads with telemetry.", id="connection-server", markup=False)
        yield TextArea(self.settings["url"], read_only=True, id="connection-url")
        yield TextArea("••••••••" if self.settings["token"] else "No token configured in this monitor", read_only=True, id="connection-token")
        with Horizontal():
            yield Button("Copy URL", id="copy-url")
            yield Button("Copy token", id="copy-token", disabled=not self.settings["token"])
            yield Button("Reveal token", id="reveal-token", disabled=not self.settings["token"])
        yield Select([("Cursor", "cursor"), ("Claude Code", "claude"), ("Codex", "codex"), ("VS Code", "vscode")],
                     value="cursor", allow_blank=False, id="connection-client")
        yield TextArea(self._config(), read_only=True, id="connection-config")
        yield Button("Copy config", id="copy-config", variant="primary", disabled=not self.settings["token"])
        yield Static("Use this URL and bearer token in your AI client's remote MCP settings. "
                     "Claude Code: run the command above. Cursor: add the JSON to MCP settings. "
                     "Codex: add the TOML to its config. VS Code: use .vscode/mcp.json. "
                     "Copy uses your terminal clipboard support. If unavailable, reveal and select the text. "
                     "HTTPS names must remain unchanged for certificate verification.", markup=False)

    def on_mount(self):
        for button in self.query(Button):
            button.active_effect_duration = 0

    def _config(self, reveal=None):
        from hexstrike.cli.server import connection_text
        if not self.settings['url']:
            return "Launch hexstrike server to configure the MCP URL and token."
        return connection_text(self.settings, self.client, self.revealed if reveal is None else reveal)

    def on_select_changed(self, event: Select.Changed):
        if event.select.id == "connection-client" and isinstance(event.value, str):
            self.client = event.value
            self.query_one("#connection-config", TextArea).load_text(self._config())

    def on_button_pressed(self, event: Button.Pressed):
        identifier = event.button.id
        if identifier == "reveal-token":
            self.revealed = not self.revealed
            self.query_one("#connection-token", TextArea).load_text(self.settings['token'] if self.revealed else "••••••••")
            event.button.label = "Hide token" if self.revealed else "Reveal token"
            self.query_one("#connection-config", TextArea).load_text(self._config())
        elif identifier in ("copy-url", "copy-token", "copy-config"):
            value = self._config(reveal=True) if identifier == "copy-config" else self.settings['url' if identifier == 'copy-url' else 'token']
            self.app.copy_to_clipboard(value)
            self.notify("Sent to terminal clipboard; support depends on your terminal")
        else:
            return
        event.stop()


class DetailScreen(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]

    def __init__(self, detail):
        super().__init__()
        self.detail = detail

    def compose(self):
        with Vertical(classes="dialog"):
            yield Static("Record details — Esc to close", markup=False)
            yield TextArea(json.dumps(self.detail, indent=2, default=str), read_only=True)
            yield Button("Close", id="close-dialog")

    def on_button_pressed(self, event: Button.Pressed):
        self.dismiss()


class HexStrikeMonitorApp(App[None]):
    """
    Live server telemetry while the connected AI client drives execution.
    """

    TITLE = "Dashboard"
    ENABLE_COMMAND_PALETTE = False
    CSS = CRIMSON_CSS
    BINDINGS = [
        Binding("q", "quit", "Close UI"),
        Binding("r", "refresh_now", "Refresh"),
        Binding("s", "stop_all_jobs", "STOP ALL JOBS"),
        Binding("ctrl+x", "stop_all_jobs", "Stop jobs", show=False),
        Binding("c", "clear_filter", "Clear filter"),
        Binding("k", "connection", "Connect"),
        Binding("escape", "focus_table", "Focus table", show=False),
    ]

    def __init__(
        self,
        runtime: Optional[HexStrikeRuntime] = None,
        engagement_id: str = "default",
        poll_interval: float = 0.75,
        remote_url: Optional[str] = None,
        api_token: Optional[str] = None,
        connection_url: Optional[str] = None,
        connect_address: Optional[tuple[str, int]] = None,
    ) -> None:
        super().__init__()
        self.runtime = runtime or (None if remote_url else HexStrikeRuntime())
        self.engagement_id = engagement_id
        self.poll_interval = poll_interval
        self.remote_url = remote_url.rstrip("/") if remote_url else None
        self.connection_url = connection_url or remote_url
        self.api_token = api_token or os.environ.get("HEXSTRIKE_API_TOKEN")
        self._events = deque(maxlen=1000)
        self._records = {}
        self._hidden_jobs = set()
        self._hidden_clients = set()
        self._snapshot = None
        self._details = {}
        self._engagement_options = []
        self._monitor = MonitorState(self.runtime) if self.runtime else None
        self._tools_offset = 0
        self._tools_next = None
        self._tools_query = ""
        self._inventory_generation = 0
        self._tools_timer = None
        self._inventory_total = None
        self._last_event_seq = 0
        self._filter_text = ""
        self._polling = False
        self._remote = TelemetryClient(remote_url, self.api_token, connect_address=connect_address) if remote_url else None

    def _fetch_remote_telemetry(self) -> Optional[Dict[str, Any]]:
        if self._remote is None:
            return None
        return self._remote.snapshot(self.engagement_id, self._last_event_seq)

    async def _poll_remote(self) -> None:
        try:
            engagement = self.engagement_id
            snapshot = await asyncio.to_thread(self._fetch_remote_telemetry)
            if snapshot is not None and engagement == self.engagement_id:
                self._render_snapshot(snapshot)
        except TelemetryError as exc:
            if self.screen_stack and self.query("#status-strip"):
                self.query_one("#status-strip", Static).update(f"DISCONNECTED — {exc}. Displayed data may be stale.")
        finally:
            self._polling = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(CRIMSON_BANNER_ASCII, id="banner-box", markup=False)
        yield Select([(self.engagement_id, self.engagement_id)], value=self.engagement_id, allow_blank=False, id="engagement-picker")
        yield Static("Initializing live telemetry...", id="status-strip", markup=False)
        with Horizontal(id="main-split"):
            with Vertical(id="left-pane"):
                with TabbedContent(initial="tab-jobs"):
                    with TabPane("Jobs", id="tab-jobs"):
                        yield DataTable(id="jobs-table")
                    with TabPane("Sessions", id="tab-sessions"):
                        yield Static("MCP clients: recent authenticated activity, not a permanent connection. "
                                     "Execution sessions are listed separately below them.", id="sessions-help", markup=False)
                        yield DataTable(id="sessions-table")
                    with TabPane("Tools", id="tab-tools"):
                        with Vertical(id="tools-controls"):
                            yield Input(placeholder="Search installed server executables…", id="tools-query")
                            with Horizontal():
                                yield Button("Previous", id="tools-prev", disabled=True)
                                yield Button("Next", id="tools-next", disabled=True)
                                yield Button("Rescan", id="tools-refresh")
                        yield Static("Loading server inventory…", id="tools-summary", markup=False)
                        yield DataTable(id="tools-table")
                    with TabPane("Connect", id="tab-connect"):
                        yield ConnectionPane(self.connection_url or "", self.api_token or "")
                    with TabPane("About", id="tab-about"):
                        with VerticalScroll(id="about-pane"):
                            from importlib.metadata import metadata
                            from hexstrike import __version__
                            package = metadata("hexstrike-ai")
                            yield Static("HexStrike AI MCP", markup=False)
                            yield Static(f"Version: {__version__}\nOwner: {package.get('Author', 'Unknown')}", markup=False)
                            urls = package.get_all("Project-URL") or []
                            self._repository_url = next((url.split(", ", 1)[1] for url in urls if url.startswith("Repository, ")), "")
                            yield Static(self._repository_url or "Repository metadata unavailable", id="about-repository", markup=False)
                            yield Static(
                                "HexStrike AI MCP connects AI assistants to a server's security tools, "
                                "terminal, files and browser through the Model Context Protocol (MCP). "
                                "The assistant plans and requests work; HexStrike executes it on the server "
                                "and returns results to the connected client.", markup=False)
                            yield Static(
                                "Run installed command-line tools and custom scripts, create and edit files, "
                                "manage interactive terminal sessions, and automate browser workflows. "
                                "Tools can run without a registered adapter; optional adapters provide "
                                "structured inputs and parsed results.", markup=False)
                            yield Static(
                                "Use the server's installed tools for network and web assessment, "
                                "forensics, binary analysis and other security workflows. "
                                "The dashboard shows jobs, execution output, client activity and tool inventory, "
                                "while recorded evidence remains available for review and reporting.", markup=False)
            with Vertical(id="right-pane") :
                yield RichLog(highlight=False, markup=False, wrap=True, min_width=1, max_lines=2000, id="event-log")
                yield Input(placeholder="Filter events…", id="filter-input")
        with Horizontal(id="actions"):
            for name, label in [("quit", "q Close"), ("refresh", "r Refresh"), ("stop", "s Stop jobs"),
                                ("filter", "c Reset filter"), ("clear", "Clear view"), ("connect", "k Connect"), ("about", "About")]:
                yield Button(label, id=f"action-{name}")

    def on_mount(self) -> None:
        self.screen.set_class(self.size.width < 100, "compact")
        self.screen.set_class(self.size.height < 30, "short")
        self.query_one("#engagement-picker").display = False
        jobs_tbl = self.query_one("#jobs-table", DataTable)
        jobs_tbl.cursor_type = "row"
        jobs_tbl.add_columns("Job ID", "Capability", "Worker", "State", "Progress", "Exit")
        self.query_one("#sessions-table", DataTable).add_columns("Kind", "Client / Session", "Peer", "State", "Last seen")

        tools_tbl = self.query_one("#tools-table", DataTable)
        tools_tbl.add_columns("Executable", "Server path", "Optional adapter")

        self._populate_tools_table()
        self.refresh_telemetry()
        self.set_interval(self.poll_interval, self.refresh_telemetry)
        self.set_interval(30, self._populate_tools_table)
        for table in self.query(DataTable):
            table.cursor_type = "row"
        for button in self.query(Button):
            button.active_effect_duration = 0
        jobs_tbl.focus()
        self._update_banner(self.size.width)

    def _update_banner(self, width):
        if self.screen_stack and self.screen_stack[0].query("#banner-box"):
            banner = CRIMSON_BANNER_ASCII if width >= max(map(len, CRIMSON_BANNER_ASCII.splitlines())) + 6 else "HEXSTRIKE AI MCP"
            self.screen_stack[0].query_one("#banner-box", Static).update(banner)

    def on_resize(self, event: Resize) -> None:
        if self.screen_stack:
            self.screen_stack[0].set_class(event.size.width < 100, "compact")
            self.screen_stack[0].set_class(event.size.height < 30, "short")
            self._update_banner(event.size.width)

    def _populate_tools_table(self, refresh=False) -> None:
        self._inventory_generation += 1
        generation = self._inventory_generation
        self.run_worker(self._load_inventory(generation, refresh), group="inventory", exclusive=True)

    async def _load_inventory(self, generation, refresh):
        try:
            query, offset = self._tools_query, self._tools_offset
            if self._remote:
                result = await asyncio.to_thread(self._remote.inventory, query, offset, refresh)
            else:
                result = await asyncio.to_thread(self._monitor.inventory, query, offset, 100, refresh)
            if generation != self._inventory_generation or not self.screen_stack or isinstance(self.screen, ModalScreen):
                return
            self._tools_next = result['next_offset']
            items = result['executables']
            self._inventory_total = result['total'] if not query else self._inventory_total
            self._details['tools-table'] = {item['path']: item for item in items}
            self._sync_rows('tools-table', [(item['path'], (
                sanitize_terminal_text(item['name']), sanitize_terminal_text(item['path']),
                ', '.join(item['capability_ids']) or 'Not required',
            )) for item in items])
            self.query_one('#tools-prev', Button).disabled = offset == 0
            self.query_one('#tools-next', Button).disabled = self._tools_next is None
            self.query_one('#tools-summary', Static).update(
                f"{offset + 1 if items else 0}–{offset + len(items)} of {result['total']} installed executables. "
                "Run through execution.host; no adapter required." +
                (" Scan limit reached." if result.get('scan_truncated') else ""))
        except (TelemetryError, OSError, ValueError) as exc:
            self.query_one('#tools-summary', Static).update(f"Inventory unavailable: {exc}")

    def on_button_pressed(self, event: Button.Pressed):
        actions = {"action-quit": self.action_quit, "action-refresh": self.action_refresh_now,
                   "action-stop": self.action_stop_all_jobs, "action-filter": self.action_clear_filter,
                   "action-clear": self.action_clear_view, "action-connect": self.action_connection}
        if event.button.id in actions:
            actions[event.button.id]()
            return
        if event.button.id == "action-about":
            self.query_one(TabbedContent).active = "tab-about"
            return
        if event.button.id == 'tools-next'  and self._tools_next is not None:
            self._tools_offset = self._tools_next
        elif event.button.id == 'tools-prev':
            self._tools_offset = max(0, self._tools_offset - 100)
        elif event.button.id == 'tools-refresh':
            self._tools_offset = 0
        else:
            return
        self._populate_tools_table(refresh=event.button.id == 'tools-refresh')

    def refresh_telemetry(self) -> None:
        if self.screen_stack and isinstance(self.screen, ModalScreen):
            return
        if self._remote is not None:
            if self.is_running and not self._polling:
                self._polling = True
                self.run_worker(self._poll_remote(), group="telemetry")
            return
        assert self.runtime is not None
        try:
            status = self.runtime.system_status(engagement_id=self.engagement_id)
        except PolicyViolationError as exc:
            self.query_one("#jobs-table", DataTable).clear()
            self.query_one("#event-log", RichLog).clear()
            self.query_one("#status-strip", Static).update(
                f"Telemetry unavailable ({exc.code}). Check the engagement ID and use the "
                "authenticated remote monitor for engagements owned by an MCP client."
            )
            return
        self._render_snapshot({
            "status": status,
            "server": self._monitor.server_info(),
            "clients": [],
            "engagements": self.runtime.engagement_manage(action="list")["engagements"],
            "jobs": [j.to_dict() for j in self.runtime.store.list_jobs(engagement_id=self.engagement_id, limit=30)],
            "findings": [f.to_dict() for f in self.runtime.store.list_findings(engagement_id=self.engagement_id, limit=50)],
            "events": self.runtime.store.get_events(since_seq=self._last_event_seq, engagement_id=self.engagement_id, limit=100, latest=self._last_event_seq == 0),
        })

    def _render_snapshot(self, snapshot: Dict[str, Any]) -> None:
        # A request can finish while the screen is being unmounted.
        if not self.screen_stack or isinstance(self.screen, ModalScreen) or not self.query("#status-strip"):
            return
        self._snapshot = snapshot
        options = [(Text.from_markup(sanitize_terminal_text(str(e.get("name") or e["engagement_id"]))), e["engagement_id"])
                   for e in snapshot.get("engagements", []) if e.get("status") != "revoked" or e["engagement_id"] == self.engagement_id]
        if options and options != self._engagement_options:
            self._engagement_options = options
            picker = self.query_one("#engagement-picker", Select)
            picker.display = len(options) > 1
            picker.set_options(options)
            picker.value = self.engagement_id
        status = snapshot["status"]
        job_dicts = snapshot["jobs"]
        new_events = snapshot["events"]

        eng = status.get("engagement", {})
        jobs_info = status.get("jobs", {})
        sessions = status.get("detached_sessions", [])

        server = snapshot.get('server', {})
        addresses = ', '.join(server.get('addresses', [])) or 'unavailable'
        host = server.get('hostname', 'server')
        endpoint = self.connection_url or 'Local monitor'
        self.query_one('#connection-server', Static).update(f"Server: {host} | Interfaces: {addresses}")
        clients = snapshot.get('clients', [])
        self.query_one("#status-strip", Static).update(
            f"SERVER: {host}  |  MCP: {endpoint}  |  "
            f"ENGAGEMENT: {eng.get('engagement_id', self.engagement_id)}  |  "
            f"RUNNING JOBS: {jobs_info.get('running_count', 0)}  |  "
            f"MCP CLIENTS (recent): {len(clients)}  |  EXECUTION SESSIONS: {len(sessions)}  |  "
            f"INSTALLED TOOLS: {self._inventory_total if self._inventory_total is not None else 'loading'}"
        )
        session_rows = []
        self._details['sessions-table'] = {}
        for item in clients:
            if item['session_id'] in self._hidden_clients and item.get('state') == 'closed':
                continue
            key = 'mcp:' + item['session_id']
            self._details['sessions-table'][key] = item
            session_rows.append((key, tuple(sanitize_terminal_text(str(value)) for value in (
                'MCP client', item.get('name', 'Client'), item.get('peer', ''), item['state'], item.get('last_seen', ''),
            ))))
        for item in sessions:
            key = 'execution:' + item['session_id']
            self._details['sessions-table'][key] = item
            session_rows.append((key, (str(item.get('kind', 'execution')), item['session_id'], 'server', str(item['state']), '')))
        self._sync_rows('sessions-table', session_rows)

        self._records = {str(jd.get("job_id")): jd for jd in job_dicts}
        self._details["jobs-table"] = self._records
        rows = []
        for jd in job_dicts:
            if str(jd.get('job_id')) in self._hidden_jobs and str(jd.get('state')).lower() not in ('running', 'queued', 'cancelling'):
                continue
            key = str(jd.get("job_id", ""))
            state = str(jd.get("state", "queued")).upper()
            progress = jd.get("progress_reported")
            progress_text = f"{float(progress) * 100:.0f}%" if progress is not None else (
                "ACTIVE" if state == "RUNNING" else state
            )
            rows.append((key, (key,
                str(jd.get("capability_id", "")) + "." + str(jd.get("operation", "")),
                str(jd.get("worker_target", "local")), state, progress_text,
                str(jd.get("exit_code") if jd.get("exit_code") is not None else "—"))))
        self._sync_rows("jobs-table", rows)

        for ev in new_events:
            if int(ev["seq"]) > self._last_event_seq:
                self._events.append(ev)
                self._last_event_seq = int(ev["seq"])
        if new_events:
            self._render_events()

    def _sync_rows(self, table_id, rows):
        """Update cells in place; retain selection and viewport when rows change."""
        table = self.query_one(f"#{table_id}", DataTable)
        keys = [key for key, _ in rows]
        existing = [row.key.value for row in table.ordered_rows]
        selected = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value if table.row_count else None
        scroll_x, scroll_y = table.scroll_x, table.scroll_y
        if existing == keys:
            columns = list(table.columns)
            for key, cells in rows:
                previous = table.get_row(key)
                for column, before, after in zip(columns, previous, cells):
                    if before != after:
                        table.update_cell(key, column, after, update_width=True)
            return
        table.clear()
        for key, cells in rows:
            table.add_row(*cells, key=key)
        if selected in keys:
            table.move_cursor(row=table.get_row_index(selected), scroll=False)
        self.call_after_refresh(table.scroll_to, x=scroll_x, y=scroll_y, animate=False)

    def action_focus_table(self) -> None:
        active = self.query_one(TabbedContent).active
        if active == 'tab-connect':
            self.query_one('#connection-client', Select).focus()
        elif active == 'tab-about':
            self.query_one('#about-pane', VerticalScroll).focus()
        else:
            self.query_one(f"#{active.removeprefix('tab-')}-table", DataTable).focus()

    def _render_events(self):
        log = self.query_one("#event-log", RichLog)
        at_end = log.is_vertical_scroll_end
        scroll = log.scroll_y
        log.clear()
        for ev in self._events:
            msg = Text.from_markup(sanitize_terminal_text(str(ev.get("message", "")))).plain
            if self._filter_text.casefold() not in msg.casefold():
                continue
            if ev.get("event_type") == "plan_prepared":
                msg = msg.partition(" -> ")[0]
            elif ev.get("event_type") == "job_started":
                msg = msg.partition(": ")[0]
            level = str(ev.get("level", "INFO")).upper()
            color = "red" if level in ("ERROR", "CRITICAL") else "yellow" if level == "WARNING" else "#ff8a80"
            line = Text(f"[{str(ev.get('created_at', ''))[11:19]}] [{level}] ", style=None if os.environ.get("NO_COLOR") else color)
            line.append(msg)
            log.write(line, scroll_end=at_end)
        if not at_end:
            self.call_after_refresh(log.scroll_to, y=scroll, animate=False)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "tools-query":
            self._inventory_generation += 1
            self._tools_query = event.value.strip()
            self._tools_offset = 0
            if self._tools_timer:
                self._tools_timer.stop()
            self._tools_timer = self.set_timer(.25, self._populate_tools_table)
        elif event.input.id == "filter-input":
            self._filter_text = event.value.strip()
            self._render_events()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "engagement-picker" and isinstance(event.value, str) and event.value != self.engagement_id:
            self.engagement_id = event.value
            self._hidden_jobs.clear()
            self._hidden_clients.clear()
            self._last_event_seq = 0
            self._events.clear()
            self.query_one("#event-log", RichLog).clear()
            self.refresh_telemetry()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        detail = self._details.get(event.data_table.id, {}).get(event.row_key.value)
        if detail is not None:
            self.push_screen(DetailScreen(detail))

    def action_connection(self) -> None:
        self.query_one(TabbedContent).active = 'tab-connect'
        self.query_one('#connection-client', Select).focus()

    def action_clear_view(self) -> None:
        if self._snapshot:
            self._hidden_jobs.update(str(j['job_id']) for j in self._snapshot['jobs']
                                     if str(j.get('state')).lower() not in ('running', 'queued', 'cancelling'))
            self._hidden_clients.update(c['session_id'] for c in self._snapshot.get('clients', []) if c.get('state') == 'closed')
        self._events.clear()
        self.action_clear_filter()
        if self._snapshot:
            self._render_snapshot(self._snapshot)
        self.notify("View cleared. Evidence and running work retained; Refresh restores history.")

    def action_refresh_now(self) -> None:
        self._hidden_jobs.clear()
        self._hidden_clients.clear()
        self._last_event_seq = 0
        self._events.clear()
        self._populate_tools_table()
        self.refresh_telemetry()

    def action_stop_all_jobs(self) -> None:
        if not self.is_running:
            return
        if self._remote is not None:
            self.run_worker(self._cancel_remote(), group="cancellation", exclusive=True)
        else:
            self.run_worker(self._cancel_local(), group="cancellation", exclusive=True)

    async def _cancel_local(self) -> None:
        result = await asyncio.to_thread(self.runtime.job_cancel, cancel_all=True)
        self._notify_cancellation(result)
        self.refresh_telemetry()

    def _notify_cancellation(self, result: Dict[str, Any]) -> None:
        self.notify(f"Cancellation requested for {result.get('cancelled_jobs', 0)} jobs and "
                    f"{len(result.get('detached_sessions', []))} live sessions")

    async def _cancel_remote(self) -> None:
        try:
            result = await asyncio.to_thread(self._remote.cancel_all)
            self._notify_cancellation(result)
            self.refresh_telemetry()
        except TelemetryError as exc:
            self.notify(str(exc), severity="error")

    def action_clear_filter(self) -> None:
        self._filter_text = ""
        inp = self.query_one("#filter-input", Input)
        inp.value = ""
        self._render_events()
