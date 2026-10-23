"""Shared visibility and emergency cancellation for detached execution contexts."""
import hashlib
import json
from pathlib import Path

from hexstrike.execution.runner import SafeSubprocessRunner, is_pid_alive
from hexstrike.execution.sandbox import SandboxManager, TERMINAL


def active_sessions(state_root, engagement_id):
    suffix = hashlib.sha256(engagement_id.encode()).hexdigest()
    result = []
    for category in ("environments", "browser_sessions"):
        root = Path(state_root) / category / suffix
        for path in root.glob("*/owner.json"):
            owner = json.loads(path.read_text())
            status_path = path.parent / "status.json"
            status = json.loads(status_path.read_text()) if status_path.exists() else {"state": "starting"}
            if status["state"] in TERMINAL or status["state"] == "closed":
                continue
            if is_pid_alive(owner["pid"], owner["created"]):
                result.append({"session_id": path.parent.name, "kind": "execution" if category == "environments" else "browser",
                               "state": status["state"], "owner": owner})
    return result


def cancel_sessions(state_root, engagement_id, session_id=None):
    outcomes = []
    for session in active_sessions(state_root, engagement_id):
        if session_id and session["session_id"] != session_id:
            continue
        if session["kind"] == "execution":
            outcome = SandboxManager(state_root, engagement_id).control(session["session_id"], "cancel")
        else:
            owner = session["owner"]
            terminated = SafeSubprocessRunner().cancel(session["session_id"], persisted_pid=owner["pid"], expected_create_time=owner["created"])
            outcome = {"session_id": session["session_id"], "terminated": terminated}
        outcomes.append(outcome)
    return outcomes
