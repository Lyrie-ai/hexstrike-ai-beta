"""
Headless Textual TUI tests and CLI command tests.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.cli.main import main as cli_main
from hexstrike.tui.dashboard import HexStrikeMonitorApp
from textual.widgets import DataTable, RichLog, TabbedContent
from hexstrike.domain.models import Principal


def test_textual_tui_headless_render_and_key_actions(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    # Record a sample job & finding so the TUI tables and event log populate
    rt.job_start(
        capability_id="api.jwt_analyzer",
        operation="analyze",
        arguments={"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."},
    )

    async def _run_pilot() -> None:
        app = HexStrikeMonitorApp(runtime=rt, poll_interval=5.0)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            strip = app.query_one("#status-strip")
            assert strip is not None
            await pilot.press("r")
            await pilot.press("c")
            await pilot.press("ctrl+x")

    asyncio.run(_run_pilot())


def test_cli_commands_status_doctor_watch_and_tools(tmp_path: Path, capsys: object) -> None:
    state_arg = ["--state-dir", str(tmp_path)]

    assert cli_main([*state_arg, "status", "--json"]) == 0
    assert cli_main([*state_arg, "doctor", "--json"]) == 0
    assert cli_main([*state_arg, "watch", "--once"]) == 0

    manifest_file = tmp_path / "custom_echo.json"
    assert cli_main([*state_arg, "tools", "scaffold", "custom.echo_probe", "--output", str(manifest_file)]) == 0
    assert manifest_file.exists()
    assert cli_main([*state_arg, "tools", "validate", str(manifest_file)]) == 0
    assert cli_main([*state_arg, "tools", "install-adapter", str(manifest_file)]) == 0
    assert cli_main([*state_arg, "tools", "disable", "custom.echo_probe"]) == 0
    assert cli_main([*state_arg, "tools", "enable", "custom.echo_probe"]) == 0
    assert cli_main([*state_arg, "tools", "remove", "custom.echo_probe"]) == 0


def test_local_dashboard_handles_engagement_owned_by_remote_client(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.engagement_manage(action="create", engagement_id="remote-client",
                         principal=Principal("remote-operator", "Remote operator"))

    async def exercise():
        app = HexStrikeMonitorApp(runtime=rt, engagement_id="remote-client")
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert app.query_one("#jobs-table", DataTable).row_count == 0
            assert "authenticated remote monitor" in str(app.query_one("#status-strip").render())
            await pilot.press("r")
            await pilot.pause()

    asyncio.run(exercise())


def test_dashboard_resize_tabs_and_bounded_untrusted_event_stream(tmp_path: Path) -> None:
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.job_start(capability_id="api.jwt_analyzer", operation="analyze",
                 arguments={"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."})

    async def exercise():
        app = HexStrikeMonitorApp(runtime=rt, poll_interval=60)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert app.query_one("#jobs-table", DataTable).row_count == 1
            tabs = app.query_one(TabbedContent)
            for tab in ("tab-connect", "tab-tools", "tab-sessions", "tab-jobs"):
                tabs.active = tab
                await pilot.pause()
            snapshot = {"status": rt.system_status(), "jobs": [], "findings": [], "events": [
                {"seq": 10000 + i, "level": "INFO", "created_at": "2026-01-01T00:00:00",
                 "message": f"event-{i}: [red]literal markup[/red] \x1b[2J"} for i in range(2500)]}
            app._render_snapshot(snapshot)
            await pilot.pause()
            log = app.query_one("#event-log", RichLog)
            assert len(log.lines) <= 2000
            rendered_tail = "".join(line.text for line in log.lines[-3:])
            assert "[red]literal markup[/red]" in rendered_tail
            assert "\x1b" not in rendered_tail
            for width, height in ((80, 24), (60, 20), (160, 50)):
                await pilot.resize_terminal(width, height)
                await pilot.pause()
                assert app.screen.has_class("compact") == (width < 100)
                for selector in ("#jobs-table", "#event-log", "#filter-input"):
                    assert app.query_one(selector).region.height > 0
                if os.environ.get("HEXSTRIKE_UI_SCREENSHOTS"):
                    directory = Path(os.environ["HEXSTRIKE_UI_SCREENSHOTS"])
                    directory.mkdir(parents=True, exist_ok=True)
                    (directory / f"dashboard-{width}x{height}.svg").write_text(app.export_screenshot())
    asyncio.run(exercise())


def test_connection_reveal_copy_filter_and_job_selection(tmp_path):
    from textual.widgets import Input, Select, TextArea
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.job_start(capability_id="api.jwt_analyzer", operation="analyze",
                 arguments={"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."})

    async def exercise():
        app = HexStrikeMonitorApp(runtime=rt, poll_interval=60,
            connection_url='https://fixture.invalid/mcp', api_token='synthetic-ui-connection-token')
        async with app.run_test(size=(140, 50)) as pilot:
            await pilot.pause()
            app._render_snapshot({"status": rt.system_status(), "jobs": [], "findings": [], "events": [
                {"seq": 10001, "message": "alpha unique", "level": "INFO"},
                {"seq": 10002, "message": "beta unique", "level": "INFO"}]})
            app.query_one('#filter-input', Input).value = 'alpha unique'
            await pilot.pause()
            log = app.query_one('#event-log', RichLog)
            assert len(log.lines) == 1 and 'alpha unique' in log.lines[0].text
            app.action_clear_filter()
            await pilot.pause()
            assert any('beta unique' in line.text for line in log.lines)
            await pilot.click("#action-connect")
            await pilot.pause()
            assert app.query_one(TabbedContent).active == 'tab-connect'
            assert app.api_token not in app.query_one('#connection-config', TextArea).text
            for identifier, expected in [('copy-url', app.connection_url), ('copy-token', app.api_token)]:
                button = app.query_one('#'+identifier)
                button.scroll_visible(animate=False)
                await pilot.pause()
                await pilot.click(button)
                assert app.clipboard == expected
            for width, height in ((80, 24), (140, 50)):
                await pilot.resize_terminal(width, height)
                await pilot.pause()
                app.query_one('#reveal-token').scroll_visible(animate=False)
                await pilot.pause()
                await pilot.click('#reveal-token')
                await pilot.pause(.25)
                assert app.api_token in app.query_one('#connection-config', TextArea).text
                await pilot.click('#reveal-token')
                await pilot.pause(.25)
                assert app.api_token not in app.query_one('#connection-config', TextArea).text
            for client, marker in [('cursor','mcpServers'), ('claude','claude mcp add'), ('codex','http_headers'), ('vscode','servers')]:
                app.query_one('#connection-client', Select).value = client
                await pilot.pause()
                app.query_one('#copy-config').scroll_visible(animate=False)
                await pilot.pause()
                await pilot.click('#copy-config')
                assert marker in app.clipboard and app.api_token in app.clipboard
            await pilot.click('#--content-tab-tab-jobs')
            app.refresh_telemetry()
            await pilot.pause()
            table = app.query_one('#jobs-table', DataTable)
            table.focus()
            await pilot.press('enter')
            await pilot.pause()
            assert 'api.jwt_analyzer' in app.screen.query_one(TextArea).text
            await pilot.press('escape')
    asyncio.run(exercise())


def test_polling_preserves_inventory_table_selection(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    async def exercise():
        app = HexStrikeMonitorApp(runtime=rt, poll_interval=60)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            snapshot = {"status": rt.system_status(), "jobs": [], "findings": [], "events": [],
                        "capabilities": rt.capabilities_search(limit=100)["capabilities"]}
            app._render_snapshot(snapshot)
            table = app.query_one('#tools-table', DataTable)
            table.move_cursor(row=10)
            app._render_snapshot(snapshot)
            assert table.cursor_row == 10
            app._remote = None
    asyncio.run(exercise())


def test_live_refresh_preserves_job_viewport_and_mouse_controls(tmp_path):
    from textual.widgets import Input, TextArea
    from hexstrike.tui.dashboard import DetailScreen
    rt = HexStrikeRuntime(state_dir=tmp_path)

    async def exercise():
        app = HexStrikeMonitorApp(runtime=rt, poll_interval=60)
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            jobs = [{"job_id": f"job_{i:012d}", "capability_id": "execution.host", "operation": "run",
                     "state": "running", "worker_target": "local", "progress_reported": .2} for i in range(80)]
            snapshot = {"status": rt.system_status(), "jobs": jobs, "findings": [], "events": []}
            app._render_snapshot(snapshot)
            await pilot.pause()
            table = app.query_one('#jobs-table', DataTable)
            table.move_cursor(row=50)
            await pilot.pause()
            table.scroll_to(x=12, y=40, animate=False)
            await pilot.pause()
            position = (table.scroll_x, table.scroll_y)
            assert position[1] > 0
            for _ in range(3):
                app._render_snapshot(snapshot)
                await pilot.pause()
                assert table.cursor_row == 50
                assert (table.scroll_x, table.scroll_y) == position
            jobs[50]['state'] = 'completed'
            jobs[50]['progress_reported'] = 1
            app._render_snapshot(snapshot)
            await pilot.pause()
            assert table.get_row('job_000000000050')[3:5] == ['COMPLETED', '100%']
            assert (table.scroll_x, table.scroll_y) == position
            snapshot['jobs'] = [dict(jobs[0], job_id='job_new')] + jobs
            app._render_snapshot(snapshot)
            await pilot.pause()
            assert table.cursor_row == 51
            assert (table.scroll_x, table.scroll_y) == position
            await pilot.press('enter')
            await pilot.pause()
            assert isinstance(app.screen, DetailScreen)
            assert 'job_000000000050' in app.screen.query_one(TextArea).text
            await pilot.click('#close-dialog')
            await pilot.pause()
            for tab in ('sessions', 'connect', 'tools', 'jobs'):
                await pilot.click(f'#--content-tab-tab-{tab}')
                await pilot.pause()
                assert app.query_one(TabbedContent).active == f'tab-{tab}'
            await pilot.click('#filter-input')
            await pilot.press('s', 'c', 'r')
            assert app.query_one('#filter-input', Input).value == 'scr'
            await pilot.press('escape')
            assert table.has_focus
            await pilot.press('c')
            assert app.query_one('#filter-input', Input).value == ''
            assert app.query_one('#banner-box').display
            assert not app.query_one('#engagement-picker').display
            await pilot.resize_terminal(140, 24)
            await pilot.pause()
            assert not app.query_one('#banner-box').display
    asyncio.run(exercise())


def test_mouse_opens_records_in_every_table(tmp_path):
    from textual.widgets import TextArea
    from hexstrike.tui.dashboard import DetailScreen
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(capability_id="api.jwt_analyzer", operation="analyze",
                         arguments={"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."})
    assert result['success']

    async def exercise():
        app = HexStrikeMonitorApp(runtime=rt, poll_interval=60)
        async with app.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            status = rt.system_status()
            status['detached_sessions'] = [{'session_id': 'session_fixture', 'kind': 'host', 'state': 'running'}]
            app._render_snapshot({'status': status, 'jobs': [j.to_dict() for j in rt.store.list_jobs()],
                                  'findings': [f.to_dict() for f in rt.store.list_findings()], 'events': []})
            for tab, field in [('jobs', 'job_id'), ('sessions', 'session_id'),
                               ('tools', 'path')]:
                await pilot.click(f'#--content-tab-tab-{tab}')
                await pilot.pause()
                table = app.query_one(f'#{tab}-table', DataTable)
                assert table.row_count > 0
                await pilot.click(table, offset=(5, 2))
                await pilot.pause()
                assert isinstance(app.screen, DetailScreen)
                assert field in app.screen.query_one(TextArea).text
                await pilot.click('#close-dialog')
                await pilot.pause()
    asyncio.run(exercise())


def test_inventory_search_pagination_and_rescan_without_executing_tools(tmp_path):
    from textual.widgets import Input, Button
    rt = HexStrikeRuntime(state_dir=tmp_path / 'state')
    binaries = tmp_path / 'bin'
    binaries.mkdir()
    for i in range(125):
        path = binaries / f'fixture-tool-{i:03d}'
        path.write_text('#!/bin/sh\nexit 99\n')
        path.chmod(0o700)
    rt.registry.search_paths = [str(binaries)]

    async def exercise():
        app = HexStrikeMonitorApp(runtime=rt, poll_interval=60)
        async with app.run_test(size=(140, 45)) as pilot:
            await pilot.pause(.5)
            await pilot.click('#--content-tab-tab-tools')
            await pilot.pause()
            table = app.query_one('#tools-table', DataTable)
            assert table.row_count == 100
            assert table.get_row_at(0)[2] == 'Not required'
            await pilot.click('#tools-next')
            await pilot.pause(.5)
            assert table.row_count == 25
            assert table.get_row_at(0)[0] == 'fixture-tool-100'
            assert app.query_one('#tools-next', Button).disabled
            app.query_one('#tools-query', Input).value = 'fixture-tool-124'
            await pilot.pause(.5)
            assert table.row_count == 1 and table.get_row_at(0)[0] == 'fixture-tool-124'
            new = binaries / 'fixture-tool-125'
            new.write_text('#!/bin/sh\nexit 99\n')
            new.chmod(0o700)
            app.query_one('#tools-query', Input).value = 'fixture-tool-125'
            await pilot.pause(.5)
            assert table.row_count == 0
            await pilot.click('#tools-refresh')
            await pilot.pause(.5)
            assert table.row_count == 1 and table.get_row_at(0)[0] == 'fixture-tool-125'
            assert rt.store.list_jobs() == []
            await pilot.resize_terminal(60, 20)
            await pilot.pause()
            assert table.content_region.height >= 2
            await pilot.click(table, offset=(4, 2))
            await pilot.pause()
            from hexstrike.tui.dashboard import DetailScreen
            assert isinstance(app.screen, DetailScreen)
    asyncio.run(exercise())


def test_persistent_controls_clear_view_and_about(tmp_path):
    from textual.widgets import Input
    from hexstrike import __version__
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = rt.job_start(capability_id='api.jwt_analyzer', operation='analyze',
                          arguments={'token': 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ.'})
    stored_jobs = [j.to_dict() for j in rt.store.list_jobs()]
    async def exercise():
        app = HexStrikeMonitorApp(runtime=rt, poll_interval=60)
        async with app.run_test(size=(144, 50)) as pilot:
            await pilot.pause()
            app.query_one('#filter-input', Input).focus()
            await pilot.press('s', 'q', 'r', 'c')
            assert app.query_one('#filter-input', Input).value == 'sqrc'
            for width, height in [(144, 50), (80, 24), (60, 20)]:
                await pilot.resize_terminal(width, height)
                await pilot.pause()
                for button in app.query('#actions Button'):
                    assert button.region.height > 0
                    assert button.region.bottom <= height
                    assert button.region.right <= width
                await pilot.click('#action-filter')
                assert app.query_one('#filter-input', Input).value == ''
            snapshot = {'status': rt.system_status(), 'jobs': stored_jobs + [
                {'job_id': 'active-fixture', 'state': 'running'}], 'events': [], 'clients': []}
            app._render_snapshot(snapshot)
            await pilot.click('#action-clear')
            await pilot.pause()
            table = app.query_one('#jobs-table', DataTable)
            assert table.row_count == 1 and table.get_row_at(0)[0] == 'active-fixture'
            app._render_snapshot(snapshot)
            assert table.row_count == 1
            assert not app.query_one('#event-log', RichLog).lines
            assert rt.store.get_job(result['job']['job_id']) is not None
            await pilot.click('#action-refresh')
            await pilot.pause()
            assert table.row_count == len(stored_jobs)
            await pilot.click('#action-about')
            await pilot.pause()
            assert app.query_one(TabbedContent).active == 'tab-about'
            assert __version__ in str(app.query_one('#about-pane').children[1].render())
            assert not app.query('#copy-repository')
            assert "Owner: 0x4m4" in str(app.query_one('#about-pane').children[1].render())
            assert "OTT" not in str(app.query_one('#about-pane').children[1].render())
            assert 'https://github.com/Lyrie-ai/hexstrike-ai-beta' in str(app.query_one('#about-repository').render())
            await pilot.press('escape')
    asyncio.run(exercise())
    assert len(rt.store.list_jobs()) == len(stored_jobs)
