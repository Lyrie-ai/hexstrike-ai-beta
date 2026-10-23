"""Persistent Playwright contexts, addressed independently of an MCP connection."""
from __future__ import annotations

import hashlib
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import threading
import time
import uuid

from hexstrike.adapters.management import ManagementAdapter, operation
from hexstrike.browser.inspector import find_chromium_executable, DEFAULT_SECURE_CHROMIUM_ARGS, sanitize_dom_preview, route_scoped_websockets
from hexstrike.domain.models import CapabilityDescriptor, Evidence, RiskLevel, SideEffectClass, new_id
from hexstrike.evidence.store import StateStore
from hexstrike.execution.runner import ExecutionResult, SafeSubprocessRunner, get_process_create_time, is_pid_alive
from hexstrike.execution.sandbox import atomic_json, HANDLE
from hexstrike.http.client import AuthenticationStore, origin
from hexstrike.policy.engine import PolicyEngine
from hexstrike.workspace.confined_fs import ConfinedWorkspace, redact_secrets


class BrowserSessionAdapter(ManagementAdapter):
    operator_only = True

    def __init__(self, state_root):
        self.state_root = Path(state_root)
        session = {"session_id": {"type": "string", "pattern": "^[a-f0-9]{32}$"}}
        selector = {"selector": {"type": "string", "minLength": 1, "maxLength": 1000}}
        self.descriptor = CapabilityDescriptor(
            capability_id="browser.session", name="Interactive browser sessions", category="browser", pack="browser",
            description="Persistent Chromium contexts with navigation, click, fill, upload, download, screenshots and private saved authentication state.",
            binary_name=None, risk_level=RiskLevel.MEDIUM, side_effects=SideEffectClass.NETWORK_PROBE,
            requires_network=False,
            operations={
                "open": operation("Start an isolated browser context", {"url": {"type": "string"},
                    "lifetime": {"type": "integer", "minimum": 10, "maximum": 3600, "default": 900},
                    "restore_session": {"type": "string", "pattern": "^[a-f0-9]{32}$"}}, ["url"]),
                "navigate": operation("Navigate within the current context", {**session, "url": {"type": "string"}}, ["session_id", "url"]),
                "click": operation("Click a visible element", {**session, **selector}, ["session_id", "selector"]),
                "fill": operation("Fill a field with text or an origin-bound credential body", {**session, **selector,
                    "value": {"type": "string", "minLength": 0, "maxLength": 10000},
                    "credential_ref": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,80}$"}}, ["session_id", "selector"]),
                "wait": operation("Wait for a visible element", {**session, **selector}, ["session_id", "selector"]),
                "inspect": operation("Read bounded, sanitized rendered DOM", session, ["session_id"]),
                "screenshot": operation("Capture a PNG evidence artifact", session, ["session_id"]),
                "upload": operation("Upload a confined workspace file", {**session, **selector, "path": {"type": "string"}}, ["session_id", "selector", "path"]),
                "download": operation("Click and capture a download as an evidence artifact", {**session, **selector}, ["session_id", "selector"]),
                "save": operation("Persist private authentication state without returning credentials", session, ["session_id"]),
                "close": operation("Save state and close the browser process", session, ["session_id"]),
            })

    def extract_targets(self, operation, arguments):
        return [arguments["url"]] if "url" in arguments else []

    def execute_context(self, operation, args, engagement_id, job_id, scope):
        start = time.monotonic()
        root = self.state_root / "browser_sessions" / hashlib.sha256(engagement_id.encode()).hexdigest()
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        reservation = None
        try:
            if operation == "open":
                reservation = sqlite3.connect(root / "sessions.db", timeout=10)
                reservation.execute("CREATE TABLE IF NOT EXISTS guard (id INTEGER)")
                reservation.execute("BEGIN IMMEDIATE")
                from hexstrike.execution.lifecycle import active_sessions
                if sum(session["kind"] == "browser" for session in active_sessions(self.state_root, engagement_id)) >= scope.max_concurrency:
                    reservation.close()
                    raise ValueError("Browser session concurrency limit reached")
                sid = uuid.uuid4().hex
                session = root / sid
                session.mkdir(mode=0o700)
                (session / "requests").mkdir(mode=0o700)
                (session / "responses").mkdir(mode=0o700)
                atomic_json(session / "config.json", {"engagement_id": engagement_id, "state_root": str(self.state_root),
                            "lifetime": min(args["lifetime"], scope.max_timeout_seconds), "restore_session": args.get("restore_session")})
                bootstrap = "import sys;sys.path.insert(0,sys.argv[1]);from hexstrike.browser.sessions import serve;serve(sys.argv[2])"
                proc = subprocess.Popen([sys.executable, "-I", "-c", bootstrap, str(Path(__file__).resolve().parents[2]), str(session)],
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                atomic_json(session / "owner.json", {"pid": proc.pid, "created": get_process_create_time(proc.pid)})
                threading.Thread(target=proc.wait, daemon=True).start()
                reservation.commit()
                reservation.close()
            else:
                sid = args["session_id"]
                session = root / sid
                if not HANDLE.fullmatch(sid) or not session.is_dir():
                    raise ValueError("Browser session not found in this engagement")
            request_id = str(time.time_ns()) + "-" + uuid.uuid4().hex
            atomic_json(session / "requests" / (request_id + ".json"), {"operation": "navigate" if operation == "open" else operation,
                        "arguments": args, "job_id": job_id})
            store = StateStore(self.state_root / "hexstrike.db")
            plan = store.get_plan(store.get_job(job_id).plan_id)
            deadline = time.monotonic() + min(plan.timeout_seconds, 30)
            response = session / "responses" / (request_id + ".json")
            while not response.exists():
                owner = json.loads((session / "owner.json").read_text())
                if not is_pid_alive(owner["pid"], owner["created"]):
                    error = json.loads((session / "status.json").read_text()) if (session / "status.json").exists() else {}
                    raise ValueError(error.get("error", "Browser session exited"))
                current = store.get_job(job_id)
                if time.monotonic() > deadline or current.state.value in ("cancelling", "cancelled"):
                    SafeSubprocessRunner().cancel(job_id, persisted_pid=owner["pid"], expected_create_time=owner["created"])
                    raise ValueError("Browser operation cancelled or timed out; context closed")
                time.sleep(.05)
            output = json.loads(response.read_text())
            response.unlink()
            output["session_id"] = sid
            success = output.get("success", True)
            if operation == "close" and success:
                owner = json.loads((session / "owner.json").read_text())
                # A close response is complete only after browser cleanup exits.
                while is_pid_alive(owner["pid"], owner["created"]):
                    current = store.get_job(job_id)
                    if time.monotonic() > deadline or current.state.value in ("cancelling", "cancelled"):
                        SafeSubprocessRunner().cancel(job_id, persisted_pid=owner["pid"], expected_create_time=owner["created"])
                        raise ValueError("Browser shutdown cancelled or timed out")
                    time.sleep(.05)
                status = json.loads((session / "status.json").read_text())
                if status.get("state") != "closed":
                    raise ValueError(status.get("error", "Browser shutdown did not complete"))
        except Exception as exc:
            output, success = {"error": redact_secrets(str(exc))}, False
        finally:
            if reservation:
                reservation.close()
        return ExecutionResult(success, 0 if success else 1, json.dumps(output), "" if success else output.get("error", "Browser operation failed"), time.monotonic() - start)


async def serve_async(directory):
    os.umask(0o077)
    root = Path(directory)
    config = json.loads((root / "config.json").read_text())
    state = Path(config["state_root"])
    store = StateStore(state / "hexstrike.db")
    workspace = ConfinedWorkspace(state / "workspace")
    policy = PolicyEngine()
    def scope():
        engagement = store.get_engagement(config["engagement_id"])
        if not engagement or engagement.status == "revoked":
            raise ValueError("Engagement revoked")
        policy.verify_scope_window(engagement.scope)
        return engagement.scope
    def artifact(content, extension, kind, job_id):
        if len(content) > scope().max_artifact_bytes:
            raise ValueError("Artifact exceeds engagement budget")
        saved = workspace.save_artifact(config["engagement_id"], new_id("art"), content, extension=extension)
        if not saved["success"]:
            raise ValueError(saved["error"])
        evidence = Evidence(new_id("ev"), config["engagement_id"], job_id, "browser.session", kind,
                            "Browser " + kind, saved["path"], hashlib.sha256(content).hexdigest(), len(content), "",
                            provenance={"mime_type": "image/png" if kind == "screenshot" else "application/octet-stream"})
        store.save_evidence(evidence)
        return evidence.evidence_id
    downloads = None
    try:
        from playwright.async_api import async_playwright
        download_parent = os.environ.get("HEXSTRIKE_BROWSER_DOWNLOAD_DIR")
        if download_parent:
            Path(download_parent).mkdir(parents=True, exist_ok=True, mode=0o700)
        downloads = tempfile.TemporaryDirectory(prefix="hexstrike-download-", dir=download_parent)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(executable_path=find_chromium_executable(), headless=True,
                                                  args=list(DEFAULT_SECURE_CHROMIUM_ARGS), chromium_sandbox=True,
                                                  downloads_path=downloads.name)
            try:
                storage = None
                if config.get("restore_session"):
                    storage = str(root.parent / config["restore_session"] / "storage.json")
                context = await browser.new_context(storage_state=storage, service_workers="block", accept_downloads=True)
                async def route(request):
                    try:
                        origin(request.request.url)
                        policy.evaluate_target(request.request.url, scope())
                        await request.continue_()
                    except Exception:
                        await request.abort("blockedbyclient")
                await context.route("**/*", route)
                await route_scoped_websockets(context, scope, policy)
                sensitive_values = []
                page = await context.new_page()
                page.set_default_timeout(15000)
                deadline = time.monotonic() + config["lifetime"]
                closed = False
                atomic_json(root / "status.json", {"state": "running"})
                while time.monotonic() < deadline and not closed:
                    scope()
                    for request in sorted((root / "requests").glob("*.json")):
                        data = json.loads(request.read_text())
                        request.unlink()
                        op, args, job_id = data["operation"], data["arguments"], data["job_id"]
                        output = {"success": True}
                        try:
                            if op == "navigate":
                                origin(args["url"])
                                policy.evaluate_target(args["url"], scope())
                                await page.goto(args["url"], wait_until="domcontentloaded")
                            elif op == "click":
                                await page.locator(args["selector"]).click()
                            elif op == "fill":
                                if ("value" in args) == ("credential_ref" in args):
                                    raise ValueError("Provide exactly one value or credential_ref")
                                value = args.get("value")
                                if "credential_ref" in args:
                                    value = AuthenticationStore(state).get(args["credential_ref"], page.url)["body"]
                                    sensitive_values.append(value)
                                await page.locator(args["selector"]).fill(value)
                            elif op == "wait":
                                await page.locator(args["selector"]).wait_for(state="visible")
                            elif op == "screenshot":
                                output["artifact_evidence_ids"] = [artifact(await page.screenshot(), "png", "screenshot", job_id)]
                            elif op == "upload":
                                file = workspace.read_file(args["path"], binary=True, max_bytes=min(10 * 1024 * 1024, scope().max_artifact_bytes) + 1)
                                if not file["success"] or file["has_more"] or len(file.get("raw_bytes", b"")) > min(10 * 1024 * 1024, scope().max_artifact_bytes):
                                    raise ValueError("Upload file missing, unsafe or too large")
                                await page.locator(args["selector"]).set_input_files({"name": Path(args["path"]).name, "mimeType": "application/octet-stream", "buffer": file["raw_bytes"]})
                            elif op == "download":
                                async with page.expect_download() as download:
                                    await page.locator(args["selector"]).click()
                                downloaded = await download.value
                                path = Path(await downloaded.path())
                                if path.stat().st_size > scope().max_artifact_bytes:
                                    raise ValueError("Download exceeds artifact budget")
                                output["artifact_evidence_ids"] = [artifact(path.read_bytes(), "bin", "binary", job_id)]
                                await downloaded.delete()
                            elif op in ("save", "close"):
                                await context.storage_state(path=str(root / "storage.json"))
                                closed = op == "close"
                            output.update(url=page.url, title=await page.title(), dom_preview=redact_secrets(sanitize_dom_preview(await page.content()), sensitive_values + [cookie["value"] for cookie in await context.cookies()]))
                        except Exception as exc:
                            output = {"success": False, "error": redact_secrets(str(exc))[:1000]}
                        atomic_json(root / "responses" / request.name, output)
                    if not closed:
                        await asyncio.sleep(.1)
                await context.close()
            finally:
                await browser.close()
        downloads.cleanup()
        downloads = None
        atomic_json(root / "status.json", {"state": "closed"})
    except Exception as exc:
        atomic_json(root / "status.json", {"state": "failed", "error": redact_secrets(str(exc))[:1000]})
    finally:
        if downloads is not None:
            downloads.cleanup()


def serve(directory):
    asyncio.run(serve_async(directory))
