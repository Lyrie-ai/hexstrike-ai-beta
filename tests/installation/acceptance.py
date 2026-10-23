"""Exercise a freshly installed distribution without importing the checkout."""
import asyncio
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

if sys.prefix == sys.base_prefix:
    raise SystemExit("Run installation acceptance in a disposable virtual environment; it removes its own package")

root = Path(tempfile.mkdtemp(prefix="hexstrike-install-acceptance-"))
state = root / "state with spaces"
wheel = Path(sys.argv[1]).resolve()
checks = []


def cli(*arguments):
    result = subprocess.run([sys.executable, "-m", "hexstrike.cli.main", "--state-dir", str(state), *arguments],
                            capture_output=True, text=True, timeout=180, cwd=root)
    assert result.returncode == 0, (arguments, result.stdout, result.stderr)
    return json.loads(result.stdout) if result.stdout.lstrip().startswith("{") else result.stdout


def payload(result):
    assert not getattr(result, "isError", getattr(result, "is_error", False)), result
    data = getattr(result, "structuredContent", getattr(result, "structured_content", None))
    if not isinstance(data, dict):
        data = json.loads(result.content[0].text)
    return data.get("result", data)


async def protocol():
    params = StdioServerParameters(command=sys.executable,
        args=["-I", "-m", "hexstrike.transports.mcp_stdio", "--state-dir", str(state)], cwd=str(root))
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as client:
            await client.initialize()
            assert len((await client.list_tools()).tools) == 10
            async def call(tool_name, **args):
                result = payload(await client.call_tool(tool_name, args))
                assert result.get("success", True), (tool_name, result)
                checks.append(tool_name)
                return result
            await call("system_status")
            await call("capabilities_search", query="workspace")
            await call("capabilities_describe", capability_ids=["workspace.files", "execution.host"])
            await call("engagement_manage", action="update", name="Installation acceptance", max_rate_per_minute=1000)
            prepared = await call("action_prepare", capability_id="workspace.files", operation="create",
                                  arguments={"path": "fixture.txt", "content": "portable content"})
            result = await call("job_start", plan_id=prepared["plan"]["plan_id"])
            job_id = result["job"]["job_id"]
            await call("job_status", job_id=job_id)
            await call("evidence_read", job_id=job_id)
            await call("memory_query", query="fixture.txt")
            native = await call("job_start", capability_id="execution.host", operation="run",
                arguments={"argv": [sys.executable, "-c", "print('installed-native-execution')"], "cwd": str(root)})
            assert native["job"]["structured_output"]["stdout_preview"] == "installed-native-execution\n"
            assert native["job"]["structured_output"]["sandboxed"] is False
            checks.append("installed-host-execution")
            await call("job_cancel", cancel_all=True)
            # Concurrent retries must refer to one execution, not duplicate jobs.
            outcomes = await asyncio.gather(*(call("job_start", capability_id="api.jwt_analyzer", operation="analyze",
                arguments={"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ."}, idempotency_key="install-concurrent") for _ in range(12)))
            assert len({outcome["job"]["job_id"] for outcome in outcomes}) == 1
            checks.append("concurrent-idempotency")
    async with stdio_client(params) as (reader, writer):
        async with ClientSession(reader, writer) as client:
            await client.initialize()
            result = payload(await client.call_tool("job_start", {"capability_id": "workspace.files", "operation": "read",
                "arguments": {"path": "fixture.txt"}}))
            assert result["job"]["structured_output"]["content"] == "portable content", result
            checks.append("stdio-reconnect")


async def monitor():
    from hexstrike.application.services import HexStrikeRuntime
    from hexstrike.tui.dashboard import HexStrikeMonitorApp
    from textual.widgets import DataTable
    app = HexStrikeMonitorApp(runtime=HexStrikeRuntime(state_dir=state), poll_interval=60)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.query_one("#jobs-table", DataTable).row_count >= 3
        await pilot.resize_terminal(140, 45)
        await pilot.press("r")
        checks.append("installed-ui")


started = time.monotonic()
cli("setup", "--client", "cursor", "--config-path", str(root / "cursor.json"))
cli("status", "--json")
cli("doctor", "--json")
cli("watch", "--once")
checks.append("setup-status-doctor-watch")
asyncio.run(protocol())
asyncio.run(monitor())
cli("upgrade", "--package-source", str(wheel))
assert cli("status", "--json")["engagement"]["name"] == "Installation acceptance"
checks.append("upgrade-preserves-state")
cli("uninstall", "--archive-to", str(root / "archives"), "--remove-package")
assert state.is_dir() and list((root / "archives").iterdir())
assert subprocess.run([sys.executable, "-I", "-c", "import hexstrike"], capture_output=True).returncode != 0
checks.append("uninstall-removes-package-retains-evidence")
print(json.dumps({"success": True, "platform": platform.platform(), "python": platform.python_version(),
                  "root": str(root), "checks": sorted(set(checks)), "elapsed_seconds": round(time.monotonic() - started, 2)}))
