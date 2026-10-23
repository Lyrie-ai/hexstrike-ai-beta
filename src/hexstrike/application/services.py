"""
Primary application orchestrator coordinating capabilities, policy, execution,
evidence persistence, memory, and real-time visual telemetry.

All transports (MCP stdio, authenticated HTTP, CLI, and TUI) use this single service.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from hexstrike import __version__
from hexstrike.adapters.catalog import ToolAdapter
from hexstrike.adapters.offline import run_workspace_tool, validate_workspace_inputs
from hexstrike.domain.models import (
    Engagement,
    Evidence,
    InvocationPlan,
    Job,
    JobState,
    Principal,
    RiskLevel,
    ScopePolicy,
    ToolStatus,
    new_id,
    utc_now_iso,
)
from hexstrike.evidence.store import StateStore
from hexstrike.execution.remote_protocol import build_remote_builtin_argv
from hexstrike.execution.lifecycle import active_sessions, cancel_sessions
from hexstrike.execution.runner import (
    ExecutionResult,
    SafeSubprocessRunner,
    SshWorkerBridge,
    get_process_create_time,
    is_pid_alive,
)
from hexstrike.memory.store import LocalMemoryStore
from hexstrike.policy.engine import PolicyEngine, PolicyViolationError, parse_port_spec
from hexstrike.registry.catalog_registry import CapabilityRegistry
from hexstrike.workflows.engine import WorkflowRunner
from hexstrike.workspace.confined_fs import ConfinedWorkspace, redact_secrets
from hexstrike.application.state import state_access, state_operation


DEFAULT_SUMMARY_CHAR_LIMIT = 4000
TERMINAL_JOB_STATES = {
    JobState.COMPLETED,
    JobState.FAILED,
    JobState.CANCELLED,
    JobState.TIMED_OUT,
    JobState.INTERRUPTED,
}


def resolve_default_state_dir() -> Path:
    """
    Resolve a durable per-user/service state directory rather than a transient /tmp directory.
    Order of precedence:
      1. $HEXSTRIKE_STATE_DIR or $HEXSTRIKE_HOME
      2. $XDG_STATE_HOME/hexstrike
      3. ~/Library/Application Support/HexStrike (macOS) or ~/.local/state/hexstrike (Linux/POSIX)
      State creation fails explicitly if the selected directory is not writable.
    """
    env_dir = os.environ.get("HEXSTRIKE_STATE_DIR") or os.environ.get("HEXSTRIKE_HOME")
    if env_dir:
        return Path(env_dir).expanduser()

    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        candidate = Path(xdg_state).expanduser() / "hexstrike"
    elif platform.system().lower() == "darwin":
        candidate = Path.home() / "Library" / "Application Support" / "HexStrike"
    else:
        candidate = Path.home() / ".local" / "state" / "hexstrike"

    return candidate


class HexStrikeRuntime:
    """
    Unified application coordinator for AI-client-driven security assessments.
    """

    def __init__(
        self,
        state_dir: Optional[str | Path] = None,
        workspace_dir: Optional[str | Path] = None,
        resolve_dns: bool = False,
        max_workers: int = 8,
    ) -> None:
        base_root = Path(state_dir).expanduser() if state_dir else resolve_default_state_dir()
        if base_root.is_symlink():
            raise ValueError("State directory must not be a symbolic link")
        self.base_root = base_root.resolve()

        with state_access(self.base_root):
            self.base_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            info = self.base_root.stat()
            self._state_identity = (info.st_dev, info.st_ino)
            self.store = StateStore(db_path=self.base_root / "hexstrike.db")
            self.memory = LocalMemoryStore(db_path=self.base_root / "hexstrike_memory.db")
            self.workspace = ConfinedWorkspace(
                base_dir=workspace_dir or (self.base_root / "workspace")
            )
            self.policy = PolicyEngine(resolve_dns=resolve_dns)
            self.runner = SafeSubprocessRunner()
            self.registry = CapabilityRegistry(
                custom_manifests_dir=self.base_root / "custom_adapters",
                store=self.store,
                workspace=self.workspace,
            )
            self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="hexstrike-job")
            self._ssh_bridges: Dict[str, SshWorkerBridge] = {}
            self._concurrency_lock = threading.Lock()
            self._engagement_semaphores: Dict[str, Tuple[int, threading.BoundedSemaphore]] = {}
            self._start_monotonic = time.monotonic()
            self._reconcile_orphaned_jobs()

    def _reconcile_orphaned_jobs(self) -> None:
        """
        Reconcile jobs left in `running` or `queued` state whose owning executor OS
        process has died (e.g. abrupt crash/restart), without interrupting jobs owned
        by a still-live executor process.
        """
        for state_val in (JobState.RUNNING.value, JobState.QUEUED.value):
            for job in self.store.list_jobs(state=state_val, limit=200):
                if job.executor_pid is not None:
                    alive = is_pid_alive(job.executor_pid, expected_create_time=job.executor_create_time)
                    if not alive:
                        if job.pid is not None:
                            self.runner.cancel(
                                job.job_id,
                                persisted_pid=job.pid,
                                expected_create_time=job.pid_create_time,
                            )
                        job.state = JobState.INTERRUPTED
                        job.completed_at = utc_now_iso()
                        job.error_message = f"Executor process (PID {job.executor_pid}) exited before job completion"
                        job.summary = f"Interrupted: {job.error_message}"
                        self.store.save_job(job, allow_overwrite_cancelled=True)
                        self.store.release_concurrency_lease(job.job_id)

    def _acquire_engagement_lease(
        self,
        job_id: str,
        engagement_id: str,
        executor_pid: int,
        executor_create_time: Optional[float],
        timeout: float = 30.0,
    ) -> bool:
        deadline = time.monotonic() + max(1.0, timeout)
        while time.monotonic() < deadline:
            cur = self.store.get_job(job_id)
            if cur and cur.state in (JobState.CANCELLING, JobState.CANCELLED):
                return False
            if self.store.try_acquire_concurrency_lease(
                job_id=job_id,
                engagement_id=engagement_id,
                executor_pid=executor_pid,
                executor_create_time=executor_create_time,
                alive_check_fn=lambda pid, ctime: is_pid_alive(pid, expected_create_time=ctime),
            ):
                return True
            time.sleep(0.03)
        return False

    def _get_ssh_bridge(self, worker_target: str) -> SshWorkerBridge:
        container: Optional[str] = None
        ssh_host = worker_target
        if "#" in worker_target:
            ssh_host, container = worker_target.split("#", 1)
        if worker_target not in self._ssh_bridges:
            self._ssh_bridges[worker_target] = SshWorkerBridge(
                ssh_target=ssh_host,
                runner=self.runner,
                container=container,
            )
        return self._ssh_bridges[worker_target]

    @state_operation
    def system_status(
        self,
        engagement_id: str = "default",
        principal: Optional[Principal] = None,
    ) -> Dict[str, Any]:
        caller = principal or Principal(principal_id="local_operator", name="Local Operator", role="operator")
        eng = self.store.get_engagement(engagement_id)
        if eng is None:
            raise PolicyViolationError(f"Engagement '{engagement_id}' not found", code="ENGAGEMENT_NOT_FOUND")
        self.policy.verify_engagement_ownership(caller, eng)
        self._reconcile_orphaned_jobs()
        counts = self.registry.summary_counts()
        active_jobs = self.store.list_jobs(engagement_id=engagement_id, state=JobState.RUNNING.value, limit=25)
        findings_count = self.store.count_findings(engagement_id)
        return {
            "status": "ready",
            "risk_tiers_enforced": False,
            "version": __version__,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "uptime_seconds": round(time.monotonic() - self._start_monotonic, 2),
            "engagement": {
                "engagement_id": eng.engagement_id,
                "name": eng.name,
                "owner_principal_id": eng.owner_principal_id,
                "status": eng.status,
                "autonomous_mode": eng.scope.autonomous_mode,
                "allow_all_targets": eng.scope.allow_all_targets,
                "worker_target": eng.scope.worker_target,
                "allowed_targets": eng.scope.allowed_targets,
                "excluded_targets": eng.scope.excluded_targets,
                "allowed_ports": eng.scope.allowed_ports,
                "max_concurrency": eng.scope.max_concurrency,
                "max_rate_per_minute": eng.scope.max_rate_per_minute,
                "max_timeout_seconds": eng.scope.max_timeout_seconds,
            },
            "capabilities": counts,
            "jobs": {
                "running_count": len(active_jobs),
                "running_job_ids": [j.job_id for j in active_jobs],
            },
            "detached_sessions": [{key: value for key, value in session.items() if key != "owner"} for session in active_sessions(self.base_root, engagement_id)],
            "findings_count": findings_count,
            "workspace_root": str(self.workspace.base_dir),
            "telemetry_db": str(self.store.db_path),
        }

    @state_operation
    def capabilities_search(
        self,
        query: str = "",
        category: Optional[str] = None,
        pack: Optional[str] = None,
        only_available: bool = False,
        limit: int = 25,
    ) -> Dict[str, Any]:
        items = self.registry.search_capabilities(
            query=query,
            category=category,
            pack=pack,
            only_available=only_available,
            limit=limit,
        )
        return {
            "count": len(items),
            "capabilities": items,
        }

    @state_operation
    def capabilities_describe(
        self,
        capability_ids: Sequence[str],
        probe_version: bool = False,
    ) -> Dict[str, Any]:
        details = self.registry.describe_capabilities(
            capability_ids=capability_ids,
            probe_version=probe_version,
            runner=self.runner if probe_version else None,
        )
        return {
            "count": len(details),
            "descriptors": details,
        }

    @state_operation
    def engagement_manage(
        self,
        action: str = "inspect",
        engagement_id: str = "default",
        name: Optional[str] = None,
        allowed_targets: Optional[List[str]] = None,
        excluded_targets: Optional[List[str]] = None,
        allowed_ports: Optional[List[int]] = None,
        allowed_protocols: Optional[List[str]] = None,
        worker_target: Optional[str] = None,
        allow_all_targets: Optional[bool] = None,
        autonomous_mode: Optional[bool] = None,
        block_metadata_endpoints: Optional[bool] = None,
        max_risk_level: Optional[str] = None,
        max_rate_per_minute: Optional[int] = None,
        max_concurrency: Optional[int] = None,
        max_timeout_seconds: Optional[int] = None,
        max_artifact_bytes: Optional[int] = None,
        valid_from: Optional[str] = None,
        valid_until: Optional[str] = None,
        principal: Optional[Principal] = None,
    ) -> Dict[str, Any]:
        caller = principal or Principal(principal_id="local_operator", name="Local Operator", role="operator")
        if not caller.authenticated:
            raise PolicyViolationError("Principal is not authenticated", code="UNAUTHENTICATED")

        if action == "list":
            engs = self.store.list_engagements()
            visible = []
            for e in engs:
                try:
                    self.policy.verify_engagement_ownership(caller, e)
                    visible.append(e.to_dict())
                except PolicyViolationError:
                    continue
            return {"engagements": visible, "count": len(visible), "risk_tiers_enforced": False}

        if action == "inspect":
            eng = self.store.get_engagement(engagement_id)
            if not eng:
                raise PolicyViolationError(f"Engagement '{engagement_id}' not found", code="NOT_FOUND")
            self.policy.verify_engagement_ownership(caller, eng)
            return {"engagement": eng.to_dict(), "risk_tiers_enforced": False}

        if action in ("create", "update", "configure"):
            for param_name, param_val in (
                ("max_rate_per_minute", max_rate_per_minute),
                ("max_concurrency", max_concurrency),
                ("max_timeout_seconds", max_timeout_seconds),
                ("max_artifact_bytes", max_artifact_bytes),
            ):
                if param_val is not None and int(param_val) < 1:
                    raise PolicyViolationError(
                        f"Engagement budget '{param_name}' must be >= 1 (got {param_val})",
                        code="INVALID_BUDGET",
                    )

            existing = self.store.get_engagement(engagement_id)
            if existing is None:
                scope = ScopePolicy(
                    allow_all_targets=True if allow_all_targets is None else allow_all_targets,
                    autonomous_mode=True if autonomous_mode is None else autonomous_mode,
                    allowed_targets=list(allowed_targets or []),
                    excluded_targets=list(excluded_targets or []),
                    allowed_ports=list(allowed_ports or []),
                    allowed_protocols=(
                        list(allowed_protocols)
                        if allowed_protocols is not None
                        else ["http", "https", "tcp", "udp", "icmp", "ssh", "dns", "smb"]
                    ),
                    worker_target=worker_target or "local",
                    block_metadata_endpoints=(
                        True if block_metadata_endpoints is None else bool(block_metadata_endpoints)
                    ),
                    max_risk_level=RiskLevel(max_risk_level) if max_risk_level else RiskLevel.CRITICAL,
                    max_rate_per_minute=int(max_rate_per_minute) if max_rate_per_minute is not None else 600,
                    max_concurrency=max(1, int(max_concurrency)) if max_concurrency is not None else 8,
                    max_timeout_seconds=int(max_timeout_seconds) if max_timeout_seconds is not None else 1800,
                    max_artifact_bytes=(
                        int(max_artifact_bytes) if max_artifact_bytes is not None else 100 * 1024 * 1024
                    ),
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
                eng = Engagement(
                    engagement_id=engagement_id,
                    name=name or f"Engagement {engagement_id}",
                    owner_principal_id=caller.principal_id,
                    scope=scope,
                    metadata={"revision": 1},
                )
            else:
                self.policy.verify_engagement_ownership(caller, existing)
                eng = existing
                if name is not None:
                    eng.name = name
                if allowed_targets is not None:
                    eng.scope.allowed_targets = list(allowed_targets)
                if excluded_targets is not None:
                    eng.scope.excluded_targets = list(excluded_targets)
                if allowed_ports is not None:
                    eng.scope.allowed_ports = list(allowed_ports)
                if allowed_protocols is not None:
                    eng.scope.allowed_protocols = list(allowed_protocols)
                if worker_target is not None:
                    eng.scope.worker_target = worker_target
                if allow_all_targets is not None:
                    eng.scope.allow_all_targets = bool(allow_all_targets)
                if autonomous_mode is not None:
                    eng.scope.autonomous_mode = bool(autonomous_mode)
                if block_metadata_endpoints is not None:
                    eng.scope.block_metadata_endpoints = bool(block_metadata_endpoints)
                if max_risk_level is not None:
                    eng.scope.max_risk_level = RiskLevel(max_risk_level)
                if max_rate_per_minute is not None:
                    eng.scope.max_rate_per_minute = int(max_rate_per_minute)
                if max_concurrency is not None:
                    eng.scope.max_concurrency = max(1, int(max_concurrency))
                if max_timeout_seconds is not None:
                    eng.scope.max_timeout_seconds = int(max_timeout_seconds)
                if max_artifact_bytes is not None:
                    eng.scope.max_artifact_bytes = int(max_artifact_bytes)
                if valid_from is not None:
                    eng.scope.valid_from = valid_from
                if valid_until is not None:
                    eng.scope.valid_until = valid_until
                eng.status = "active"
                eng.metadata["revision"] = int(eng.metadata.get("revision", 1)) + 1

            self.store.save_engagement(eng)
            self.store.append_event(
                engagement_id=eng.engagement_id,
                event_type="engagement_updated",
                message=f"Engagement '{eng.engagement_id}' updated (worker={eng.scope.worker_target}, autonomous={eng.scope.autonomous_mode})",
                payload=eng.to_dict(),
            )
            return {"success": True, "engagement": eng.to_dict(), "risk_tiers_enforced": False}

        if action == "revoke":
            eng = self.store.get_engagement(engagement_id)
            if not eng:
                raise PolicyViolationError(f"Engagement '{engagement_id}' not found", code="NOT_FOUND")
            self.policy.verify_engagement_ownership(caller, eng)
            eng.status = "revoked"
            eng.metadata["revision"] = int(eng.metadata.get("revision", 1)) + 1
            self.store.save_engagement(eng)

            revoked_grants = self.store.revoke_engagement_grants(engagement_id, reason="Operator/client revocation")
            active_jobs = [
                *self.store.list_jobs(engagement_id=engagement_id, state=JobState.RUNNING.value),
                *self.store.list_jobs(engagement_id=engagement_id, state=JobState.QUEUED.value),
            ]
            cancelled_jobs = []
            for j in active_jobs:
                self.job_cancel(j.job_id, principal=caller)
                cancelled_jobs.append(j.job_id)
            return {
                "success": True,
                "engagement_id": engagement_id,
                "status": "revoked",
                "revoked_grants": revoked_grants,
                "cancelled_jobs": cancelled_jobs,
            }

        raise PolicyViolationError(f"Unsupported engagement_manage action: {action}", code="INVALID_ACTION")

    @state_operation
    def action_prepare(
        self,
        capability_id: str,
        operation: str = "run",
        arguments: Optional[Dict[str, Any]] = None,
        engagement_id: str = "default",
        worker_target: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        principal: Optional[Principal] = None,
    ) -> Dict[str, Any]:
        caller = principal or Principal(principal_id="local_operator", name="Local Operator", role="operator")
        eng = self.store.get_engagement(engagement_id)
        if not eng:
            raise PolicyViolationError(f"Engagement '{engagement_id}' does not exist", code="ENGAGEMENT_NOT_FOUND")

        self.policy.verify_engagement_ownership(caller, eng)

        adapter = self.registry.get_adapter(capability_id)
        if not adapter:
            raise PolicyViolationError(
                f"Capability '{capability_id}' is not registered or is disabled",
                code="CAPABILITY_NOT_FOUND",
            )

        if getattr(adapter, "operator_only", False) and caller.role != "operator":
            raise PolicyViolationError("Server-wide workspace and adapter management requires the operator role", code="OPERATOR_REQUIRED")

        if operation not in adapter.descriptor.operations:
            if len(adapter.descriptor.operations) == 1:
                operation = next(iter(adapter.descriptor.operations.keys()))

        validated_args = adapter.validate_arguments(operation, arguments or {})
        effective_worker = worker_target or eng.scope.worker_target or "local"

        if capability_id == "web.http_inspect":
            advanced = set(validated_args) - {"url", "method", "timeout", "follow_redirects"}
            if effective_worker != "local" and advanced:
                raise PolicyViolationError("Advanced HTTP requests require connection to the worker MCP endpoint", code="WORKER_PROTOCOL_UNSUPPORTED")
            if validated_args.get("credential_ref") and caller.role != "operator":
                raise PolicyViolationError("Server credential references require the operator role", code="OPERATOR_REQUIRED")
        if getattr(adapter, "local_only", False) and effective_worker != "local":
            raise PolicyViolationError("This capability operates on the connected MCP server", code="LOCAL_CAPABILITY_REQUIRED")
        if adapter.input_file_parameters:
            if effective_worker != "local":
                raise PolicyViolationError("File inspection requires a workspace on this MCP server; connect to the worker's MCP endpoint", code="WORKER_WORKSPACE_REQUIRED")
            validate_workspace_inputs(adapter, validated_args, self.workspace)

        ident = self.registry.get_binary_identity(adapter.descriptor.binary_name, probe_version=False)
        if effective_worker == "local" and ident.status == ToolStatus.RESTRICTED:
            raise PolicyViolationError(ident.notes, code="WORKER_PRIVILEGE_REQUIRED")
        if effective_worker == "local" and ident.status == ToolStatus.INCOMPATIBLE:
            raise PolicyViolationError(
                ident.notes or f"Binary '{adapter.descriptor.binary_name}' is incompatible",
                code="INCOMPATIBLE_BINARY",
            )

        exe_for_argv = (
            ident.executable_path
            if (effective_worker == "local" and ident.executable_path and ident.executable_path != "builtin")
            else (adapter.descriptor.binary_name or "builtin")
        )
        argv_preview = adapter.build_argv(operation, validated_args, binary_path=exe_for_argv)
        targets = adapter.extract_targets(operation, validated_args)

        plan, grant = self.policy.validate_plan_request(
            principal=caller,
            engagement=eng,
            capability=adapter.descriptor,
            operation=operation,
            arguments=validated_args,
            targets=targets,
            argv_preview=argv_preview,
            binary_digest=ident.sha256,
            timeout_seconds=timeout_seconds,
            worker_target=effective_worker,
        )

        self.store.save_plan(plan)
        if grant:
            self.store.save_grant(grant)

        self.store.append_event(
            engagement_id=eng.engagement_id,
            event_type="plan_prepared",
            message=f"Prepared {capability_id}.{operation} -> {' '.join(argv_preview)}",
            payload={"plan_id": plan.plan_id, "worker": effective_worker, "targets": targets},
        )

        return {
            "success": True,
            "plan": plan.to_dict(),
            "grant": grant.to_dict() if grant else None,
            "ready_to_start": grant is not None,
        }

    def _wait_for_job_terminal(self, job_id: str, timeout: float = 30.0) -> Job:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            j = self.store.get_job(job_id)
            if j and j.state in TERMINAL_JOB_STATES:
                return j
            time.sleep(0.02)
        j = self.store.get_job(job_id)
        if not j:
            raise RuntimeError(f"Job {job_id} disappeared while waiting")
        return j

    @state_operation
    def job_start(
        self,
        plan_id: Optional[str] = None,
        capability_id: Optional[str] = None,
        operation: str = "run",
        arguments: Optional[Dict[str, Any]] = None,
        engagement_id: str = "default",
        worker_target: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        wait: bool = True,
        timeout_seconds: Optional[float] = None,
        principal: Optional[Principal] = None,
        parent_job_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        caller = principal or Principal(principal_id="local_operator", name="Local Operator", role="operator")
        if not caller.authenticated:
            raise PolicyViolationError("Principal is not authenticated", code="UNAUTHENTICATED")

        if idempotency_key:
            existing_job = self.store.get_job_by_idempotency(
                principal_id=caller.principal_id,
                engagement_id=engagement_id,
                idempotency_key=idempotency_key,
            )
            if existing_job:
                if wait and existing_job.state not in TERMINAL_JOB_STATES:
                    existing_job = self._wait_for_job_terminal(existing_job.job_id)
                return {
                    "success": existing_job.state == JobState.COMPLETED if wait else True,
                    "deduplicated": True,
                    "job": existing_job.to_dict(),
                }

        if not plan_id:
            if not capability_id:
                raise PolicyViolationError(
                    "Either 'plan_id' or 'capability_id' must be provided to job_start",
                    code="MISSING_PLAN_OR_CAPABILITY",
                )
            prep = self.action_prepare(
                capability_id=capability_id,
                operation=operation,
                arguments=arguments,
                engagement_id=engagement_id,
                worker_target=worker_target,
                timeout_seconds=timeout_seconds,
                principal=caller,
            )
            plan_id = prep["plan"]["plan_id"]

        plan = self.store.get_plan(plan_id)
        if not plan:
            raise PolicyViolationError(f"Plan '{plan_id}' not found", code="PLAN_NOT_FOUND")

        eng = self.store.get_engagement(plan.engagement_id)
        if not eng:
            raise PolicyViolationError(f"Engagement '{plan.engagement_id}' not found", code="ENGAGEMENT_NOT_FOUND")

        self.policy.verify_engagement_ownership(caller, eng)
        if plan.principal_id != caller.principal_id:
            if not (
                eng.engagement_id == "default"
                and eng.owner_principal_id == "local_operator"
                and caller.principal_id in ("local_operator", "ai_client", "api_token_operator")
                and plan.principal_id in ("local_operator", "ai_client", "api_token_operator")
            ):
                raise PolicyViolationError(
                    f"Principal '{caller.principal_id}' cannot execute plan prepared by '{plan.principal_id}'",
                    code="FORBIDDEN",
                )

        if eng.status == "revoked":
            raise PolicyViolationError(
                f"Engagement '{eng.engagement_id}' is revoked",
                code="ENGAGEMENT_REVOKED",
            )

        grant = self.store.get_grant_for_plan(plan.plan_id)
        if not grant or not grant.is_valid_for(plan):
            raise PolicyViolationError(
                f"Plan '{plan.plan_id}' lacks a valid unrevoked approval grant",
                code="APPROVAL_INVALID_OR_REVOKED",
            )

        requested_ports: Optional[List[int]] = None
        if "ports" in plan.arguments and plan.arguments["ports"]:
            requested_ports = parse_port_spec(str(plan.arguments["ports"]))
        for t in plan.targets:
            self.policy.evaluate_target(t, eng.scope, requested_ports=requested_ports)

        adapter = self.registry.get_adapter(plan.capability_id)
        if not adapter:
            raise PolicyViolationError(
                f"Adapter '{plan.capability_id}' is no longer enabled",
                code="CAPABILITY_DISABLED",
            )

        if adapter.descriptor.schema_digest != plan.schema_digest:
            raise PolicyViolationError(
                f"Plan '{plan.plan_id}' is stale due to capability schema change",
                code="STALE_PLAN",
            )

        if parent_job_id is not None:
            p_job = self.store.get_job(parent_job_id)
            if not p_job or p_job.engagement_id != plan.engagement_id or p_job.capability_id not in ("workflow.wstg", "tools.verify"):
                raise PolicyViolationError(
                    f"Invalid parent_job_id '{parent_job_id}' for engagement '{plan.engagement_id}'",
                    code="INVALID_PARENT_JOB",
                )

        my_pid = os.getpid()
        my_ctime = get_process_create_time(my_pid)

        candidate_job = Job(
            job_id=new_id("job"),
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            engagement_id=plan.engagement_id,
            principal_id=caller.principal_id,
            capability_id=plan.capability_id,
            operation=plan.operation,
            worker_target=plan.worker_target,
            state=JobState.QUEUED,
            idempotency_key=idempotency_key,
            parent_job_id=parent_job_id,
            executor_pid=my_pid,
            executor_create_time=my_ctime,
            argv=list(plan.argv_preview),
        )

        # Enforce user-configured engagement `max_rate_per_minute` across top-level jobs
        if parent_job_id is None:
            rate_ok, cur_rate, max_rate = self.store.check_and_record_rate_limit(
                plan.engagement_id, candidate_job.job_id
            )
            if not rate_ok:
                raise PolicyViolationError(
                    f"Engagement rate limit exceeded ({cur_rate}/{max_rate} jobs per minute)",
                    code="RATE_LIMIT_EXCEEDED",
                )

        job, won_reservation = self.store.reserve_or_get_job(candidate_job)
        if not won_reservation:
            if wait and job.state not in TERMINAL_JOB_STATES:
                job = self._wait_for_job_terminal(job.job_id)
            return {
                "success": job.state == JobState.COMPLETED if wait else True,
                "deduplicated": True,
                "job": job.to_dict(),
            }

        self.store.append_event(
            engagement_id=job.engagement_id,
            job_id=job.job_id,
            event_type="job_queued",
            message=f"[{job.job_id}] Queued {job.capability_id}.{job.operation} on {job.worker_target}",
            payload={"argv": job.argv, "parent_job_id": parent_job_id},
        )

        if wait:
            self._execute_job_sync(job, plan, adapter, eng.scope)
            refreshed = self.store.get_job(job.job_id) or job
            artifact_errors = refreshed.structured_output.get("_artifact_errors", []) if isinstance(refreshed.structured_output, dict) else []
            return {
                "success": (refreshed.state == JobState.COMPLETED) and not artifact_errors,
                "partial": bool(artifact_errors or refreshed.structured_output.get("_output_truncated")),
                "deduplicated": False,
                "job": refreshed.to_dict(),
            }
        else:
            self._executor.submit(self._execute_job_sync, job, plan, adapter, eng.scope)
            return {
                "success": True,
                "deduplicated": False,
                "job": job.to_dict(),
            }

    @state_operation
    def _execute_job_sync(
        self,
        job: Job,
        plan: InvocationPlan,
        adapter: ToolAdapter,
        scope: ScopePolicy,
    ) -> None:
        # Acquire cross-runtime SQLite concurrency lease for top-level jobs
        # (Child jobs spawned inside a parent workflow share their parent's lease so
        # max_concurrency=1 never deadlocks a workflow).
        needs_lease = job.parent_job_id is None
        lease_acquired = False
        if needs_lease:
            lease_acquired = self._acquire_engagement_lease(
                job_id=job.job_id,
                engagement_id=job.engagement_id,
                executor_pid=job.executor_pid or os.getpid(),
                executor_create_time=job.executor_create_time,
                timeout=float(plan.timeout_seconds),
            )
            if not lease_acquired:
                current = self.store.get_job(job.job_id)
                if current and current.state not in (JobState.CANCELLED, JobState.CANCELLING):
                    job.state = JobState.TIMED_OUT
                    job.completed_at = utc_now_iso()
                    job.error_message = "Timed out waiting for engagement concurrency slot"
                    job.summary = job.error_message
                    self.store.save_job(job)
                return

        try:
            current = self.store.get_job(job.job_id)
            if current and current.state in (JobState.CANCELLED, JobState.CANCELLING):
                return
            if job.parent_job_id:
                parent_job = self.store.get_job(job.parent_job_id)
                if parent_job and parent_job.state in (JobState.CANCELLING, JobState.CANCELLED):
                    job.state = JobState.CANCELLED
                    job.completed_at = utc_now_iso()
                    job.summary = "Cancelled because parent workflow was cancelled"
                    self.store.save_job(job, allow_overwrite_cancelled=True)
                    return

            # Revalidate latest engagement status, capability state, and user-configured
            # target and port scope after waiting in the queue, immediately before dispatch.
            latest_eng = self.store.get_engagement(job.engagement_id)
            if not latest_eng or latest_eng.status == "revoked":
                job.state = JobState.CANCELLED
                job.completed_at = utc_now_iso()
                job.summary = "Cancelled due to engagement revocation"
                self.store.save_job(job, allow_overwrite_cancelled=True)
                return

            active_scope = latest_eng.scope
            if self.registry.get_adapter(plan.capability_id) is None:
                job.state = JobState.FAILED
                job.completed_at = utc_now_iso()
                job.error_message = f"Capability '{plan.capability_id}' was disabled or quarantined before dispatch"
                job.summary = job.error_message
                self.store.save_job(job)
                return

            try:
                requested_ports: Optional[List[int]] = None
                if "ports" in plan.arguments and plan.arguments["ports"]:
                    requested_ports = parse_port_spec(str(plan.arguments["ports"]))
                for t in plan.targets:
                    self.policy.evaluate_target(t, active_scope, requested_ports=requested_ports)
            except PolicyViolationError as scope_exc:
                job.state = JobState.FAILED
                job.completed_at = utc_now_iso()
                job.error_message = f"Policy revalidation failed at dispatch ({scope_exc.code}): {scope_exc}"
                job.summary = job.error_message
                self.store.save_job(job)
                return

            job.transition_to(JobState.RUNNING)
            job = self.store.save_job(job)
            if job.state == JobState.CANCELLED:
                return

            self.store.append_event(
                engagement_id=job.engagement_id,
                job_id=job.job_id,
                event_type="job_started",
                message=f"[{job.job_id}] EXECUTING on {job.worker_target}: {' '.join(job.argv)}",
                payload={"argv": job.argv, "worker": job.worker_target},
            )

            def _record_pid(pid: int) -> None:
                ctime = get_process_create_time(pid)
                job.pid = pid
                job.pid_create_time = ctime
                self.store.update_job_pid(job.job_id, pid, pid_create_time=ctime)

            def _is_cancelled() -> bool:
                latest = self.store.get_job(job.job_id)
                if latest and latest.state in (JobState.CANCELLING, JobState.CANCELLED):
                    return True
                if job.parent_job_id:
                    p_latest = self.store.get_job(job.parent_job_id)
                    if p_latest and p_latest.state in (JobState.CANCELLING, JobState.CANCELLED):
                        return True
                return False

            preview_lock = threading.Lock()
            preview_times: Dict[str, float] = {}
            suppressed_previews: Dict[str, int] = {}

            def _stream_line(stream_name: str, line: str) -> None:
                if line.strip():
                    # UI previews are sampled; complete output is retained as evidence.
                    # A database write for every line can stall the subprocess pipes.
                    with preview_lock:
                        now = time.monotonic()
                        if now - preview_times.get(stream_name, float('-inf')) < 0.25:
                            suppressed_previews[stream_name] = suppressed_previews.get(stream_name, 0) + 1
                            return
                        preview_times[stream_name] = now
                    self.store.append_event(
                        engagement_id=job.engagement_id,
                        job_id=job.job_id,
                        event_type=f"stream_{stream_name}",
                        level="INFO" if stream_name == "stdout" else "WARNING",
                        message=f"[{job.capability_id}] {line[:300]}",
                        payload={"stream": stream_name},
                    )

            if plan.capability_id == "execution.host" and plan.operation == "run":
                exec_res = self.runner.run(
                    plan.argv_preview, job_id=job.job_id, cwd=plan.arguments["cwd"],
                    timeout=plan.timeout_seconds, env=plan.arguments["env"],
                    stdin_data=plan.arguments.get("stdin"),
                    host_execution=True,
                    on_start=_record_pid, on_output=_stream_line, is_cancelled_fn=_is_cancelled,
                )
            elif hasattr(adapter, "execute_runtime"):
                exec_res = adapter.execute_runtime(self, job, plan, active_scope)
            elif hasattr(adapter, "execute_context"):
                exec_res = adapter.execute_context(plan.operation, plan.arguments, job.engagement_id, job.job_id, active_scope)
            elif adapter.input_file_parameters:
                ident = self.registry.get_binary_identity(adapter.descriptor.binary_name, probe_version=False)
                exec_res = run_workspace_tool(
                    adapter, plan.operation, plan.arguments, self.workspace, self.runner,
                    ident.executable_path or adapter.descriptor.binary_name,
                    job_id=job.job_id, cwd=self.workspace.base_dir, timeout=plan.timeout_seconds,
                    on_start=_record_pid, on_output=_stream_line, is_cancelled_fn=_is_cancelled,
                )
            elif plan.capability_id == "workflow.wstg":
                wf_start = time.monotonic()
                wf_runner = WorkflowRunner(self)
                wf_out = wf_runner.execute_workflow(
                    workflow_name=str(plan.arguments.get("workflow_name", "web_baseline")),
                    target=str(plan.arguments["target"]),
                    engagement_id=job.engagement_id,
                    worker_target=plan.worker_target,
                    principal=Principal(principal_id=job.principal_id, name=job.principal_id),
                    parent_job_id=job.job_id,
                    timeout_seconds=plan.timeout_seconds,
                )
                exec_res = ExecutionResult(
                    success=bool(wf_out.get("success", False)),
                    return_code=0 if wf_out.get("success") else 1,
                    stdout=json.dumps(wf_out),
                    stderr="" if wf_out.get("success") else f"Failed or cancelled workflow steps: {wf_out.get('failed_steps')}",
                    execution_time=time.monotonic() - wf_start,
                    cancelled=bool(wf_out.get("cancelled", False)),
                    timed_out=bool(wf_out.get("timed_out", False)),
                    worker_target=plan.worker_target,
                    argv=list(plan.argv_preview),
                )
            elif plan.worker_target == "local" and plan.capability_id in ("web.http_inspect", "browser.inspect", "intel.threat_correlate", "research.web"):
                bootstrap = (
                    "import sys; sys.path.insert(0, sys.argv[1]); "
                    "from hexstrike.execution.remote_protocol import run_local_builtin; run_local_builtin()"
                )
                exec_res = self.runner.run(
                    [sys.executable, "-I", "-c", bootstrap, str(Path(__file__).resolve().parents[2])],
                    job_id=job.job_id,
                    cwd=self.workspace.base_dir,
                    timeout=plan.timeout_seconds,
                    env={key: os.environ[key] for key in ("HEXSTRIKE_CHROMIUM_EXECUTABLE",) if key in os.environ},
                    stdin_data=json.dumps({"capability_id": plan.capability_id, "operation": plan.operation,
                                           "arguments": plan.arguments, "scope": active_scope.to_dict(),
                                           "timeout": plan.timeout_seconds + 1, "state_root": str(self.base_root), "engagement_id": job.engagement_id}),
                    on_start=_record_pid,
                    is_cancelled_fn=_is_cancelled,
                )
            elif plan.worker_target != "local" and adapter.descriptor.requires_network:
                bridge = self._get_ssh_bridge(plan.worker_target)
                if adapter.descriptor.binary_name is None:
                    remote_argv = build_remote_builtin_argv(
                        capability_id=plan.capability_id,
                        operation=plan.operation,
                        arguments=plan.arguments,
                        scope=active_scope,
                        job_id=job.job_id,
                    )
                else:
                    remote_argv = adapter.build_argv(
                        plan.operation, plan.arguments, binary_path=adapter.descriptor.binary_name
                    )
                exec_res = bridge.execute_argv(
                    remote_argv,
                    job_id=job.job_id,
                    timeout=plan.timeout_seconds,
                    on_start=_record_pid,
                    on_output=_stream_line,
                    is_cancelled_fn=_is_cancelled,
                )
            else:
                direct_res = adapter.execute_direct(
                    plan.operation,
                    plan.arguments,
                    timeout=plan.timeout_seconds,
                    scope=active_scope,
                    policy=self.policy,
                )
                if direct_res is not None:
                    exec_res = direct_res
                elif plan.worker_target != "local":
                    bridge = self._get_ssh_bridge(plan.worker_target)
                    remote_argv = adapter.build_argv(
                        plan.operation, plan.arguments, binary_path=adapter.descriptor.binary_name
                    )
                    exec_res = bridge.execute_argv(
                        remote_argv,
                        job_id=job.job_id,
                        timeout=plan.timeout_seconds,
                        on_start=_record_pid,
                        on_output=_stream_line,
                        is_cancelled_fn=_is_cancelled,
                    )
                else:
                    ident = self.registry.get_binary_identity(adapter.descriptor.binary_name, probe_version=False)
                    if ident.status == ToolStatus.MISSING:
                        exec_res = ExecutionResult(
                            success=False,
                            return_code=127,
                            stdout="",
                            stderr=(
                                f"Required binary '{adapter.descriptor.binary_name}' is not installed locally. "
                                f"Configure engagement worker_target to a Linux worker or install '{adapter.descriptor.binary_name}'."
                            ),
                            execution_time=0.001,
                            argv=list(plan.argv_preview),
                        )
                    else:
                        exec_res = self.runner.run(
                            plan.argv_preview,
                            job_id=job.job_id,
                            cwd=self.workspace.base_dir,
                            timeout=plan.timeout_seconds,
                            on_start=_record_pid,
                            on_output=_stream_line,
                            is_cancelled_fn=_is_cancelled,
                        )

            if suppressed_previews:
                self.store.append_event(
                    engagement_id=job.engagement_id,
                    job_id=job.job_id,
                    event_type="output_preview_sampled",
                    message="High-volume output previews sampled; retrieve complete output from evidence.",
                    payload={"suppressed_previews": dict(suppressed_previews)},
                )

            if exec_res.pid is not None:
                job.pid = exec_res.pid
            job.exit_code = exec_res.return_code

            # Enforce user-configured `active_scope.max_artifact_bytes` and check
            # artifact persistence results before marking a job completed!
            evidence_ids: List[str] = []
            artifact_errors: List[str] = []
            max_art_budget = max(1, int(active_scope.max_artifact_bytes))

            def _save_budgeted_artifact(
                art_prefix: str, content_val: bytes | str, ext: str, label: str
            ) -> Optional[str]:
                raw_len = len(content_val) if isinstance(content_val, bytes) else len(content_val.encode("utf-8", errors="replace"))
                if raw_len > max_art_budget:
                    artifact_errors.append(
                        f"{label} artifact size ({raw_len} bytes) exceeds engagement max_artifact_bytes ({max_art_budget} bytes)"
                    )
                    return None
                save_res = self.workspace.save_artifact(
                    job.engagement_id, new_id(art_prefix), content_val, extension=ext
                )
                if not save_res.get("success") or not save_res.get("path"):
                    artifact_errors.append(f"{label} artifact storage failed: {save_res.get('error')}")
                    return None
                return str(save_res["path"])

            if exec_res.stdout:
                if job.capability_id == "browser.inspect" and exec_res.stdout.lstrip().startswith("{"):
                    try:
                        b_data = json.loads(exec_res.stdout)
                        if b_data.get("har") is not None:
                            har_str = json.dumps(b_data["har"], indent=2)
                            har_path_rel = _save_budgeted_artifact("art_har", har_str, "har", "HAR")
                            if har_path_rel:
                                ev_har = Evidence(
                                    evidence_id=new_id("ev"),
                                    engagement_id=job.engagement_id,
                                    job_id=job.job_id,
                                    capability_id=job.capability_id,
                                    kind="har",
                                    summary=f"Browser HAR network capture ({len(har_str)} bytes)",
                                    artifact_id=har_path_rel,
                                    sha256=hashlib.sha256(har_str.encode("utf-8")).hexdigest(),
                                    size_bytes=len(har_str.encode("utf-8")),
                                    content_preview=redact_secrets(har_str[:2000]),
                                    provenance={"worker_target": exec_res.worker_target},
                                )
                                self.store.save_evidence(ev_har)
                                evidence_ids.append(ev_har.evidence_id)
                        if b_data.get("screenshot_png_b64"):
                            png_bytes = base64.b64decode(b_data["screenshot_png_b64"])
                            png_path_rel = _save_budgeted_artifact("art_png", png_bytes, "png", "Screenshot")
                            if png_path_rel:
                                ev_png = Evidence(
                                    evidence_id=new_id("ev"),
                                    engagement_id=job.engagement_id,
                                    job_id=job.job_id,
                                    capability_id=job.capability_id,
                                    kind="screenshot",
                                    summary=f"Browser PNG screenshot ({len(png_bytes)} bytes)",
                                    artifact_id=png_path_rel,
                                    sha256=hashlib.sha256(png_bytes).hexdigest(),
                                    size_bytes=len(png_bytes),
                                    content_preview=f"[PNG Screenshot Artifact: {png_path_rel}]",
                                    provenance={"worker_target": exec_res.worker_target, "mime_type": "image/png"},
                                )
                                self.store.save_evidence(ev_png)
                                evidence_ids.append(ev_png.evidence_id)
                        b_data.pop("har", None)
                        b_data.pop("screenshot_png_b64", None)
                        b_data["artifact_evidence_ids"] = list(evidence_ids)
                        exec_res.stdout = json.dumps(b_data)
                    except Exception as exc:
                        artifact_errors.append(f"Browser artifact processing failed: {exc}")

                out_path_rel = _save_budgeted_artifact("art_out", exec_res.stdout, "log", "Stdout")
                if out_path_rel:
                    ev_out = Evidence(
                        evidence_id=new_id("ev"),
                        engagement_id=job.engagement_id,
                        job_id=job.job_id,
                        capability_id=job.capability_id,
                        kind="stdout",
                        summary=f"Standard output from {job.capability_id}.{job.operation} ({len(exec_res.stdout)} bytes)",
                        artifact_id=out_path_rel,
                        sha256=hashlib.sha256(exec_res.stdout.encode("utf-8", errors="replace")).hexdigest(),
                        size_bytes=len(exec_res.stdout.encode("utf-8", errors="replace")),
                        content_preview=redact_secrets(exec_res.stdout[:DEFAULT_SUMMARY_CHAR_LIMIT]),
                        provenance={
                            "worker_target": exec_res.worker_target,
                            "argv": exec_res.argv,
                            "return_code": exec_res.return_code,
                            "execution_time": round(exec_res.execution_time, 3),
                            "truncated": exec_res.truncated,
                            "input_files": exec_res.input_files,
                        },
                    )
                    self.store.save_evidence(ev_out)
                    evidence_ids.append(ev_out.evidence_id)

            if exec_res.stderr:
                err_path_rel = _save_budgeted_artifact("art_err", exec_res.stderr, "err", "Stderr")
                if err_path_rel:
                    ev_err = Evidence(
                        evidence_id=new_id("ev"),
                        engagement_id=job.engagement_id,
                        job_id=job.job_id,
                        capability_id=job.capability_id,
                        kind="stderr",
                        summary=f"Error output from {job.capability_id}.{job.operation} ({len(exec_res.stderr)} bytes)",
                        artifact_id=err_path_rel,
                        sha256=hashlib.sha256(exec_res.stderr.encode("utf-8", errors="replace")).hexdigest(),
                        size_bytes=len(exec_res.stderr.encode("utf-8", errors="replace")),
                        content_preview=redact_secrets(exec_res.stderr[:2000]),
                        provenance={
                            "worker_target": exec_res.worker_target,
                            "return_code": exec_res.return_code,
                        },
                    )
                    self.store.save_evidence(ev_err)
                    evidence_ids.append(ev_err.evidence_id)

            structured, findings = adapter.parse_output(
                plan.operation,
                plan.arguments,
                exec_res,
                job.engagement_id,
                job.job_id,
            )
            if exec_res.input_files and isinstance(structured, dict):
                structured["input_files"] = exec_res.input_files
            if artifact_errors and isinstance(structured, dict):
                structured["_artifact_errors"] = artifact_errors
            if exec_res.truncated and isinstance(structured, dict):
                structured["_output_truncated"] = True

            finding_ids: List[str] = []
            for f in findings:
                f.evidence_ids = list(evidence_ids)
                self.store.record_finding(f)
                if f.finding_id not in finding_ids:
                    finding_ids.append(f.finding_id)
                self.store.append_event(
                    engagement_id=job.engagement_id,
                    job_id=job.job_id,
                    event_type="finding_recorded",
                    level="WARNING" if f.severity.value in ("high", "critical") else "INFO",
                    message=f"[{f.severity.value.upper()}] {f.title} ({f.target})",
                    payload=f.to_dict(),
                )

            job.structured_output = structured
            if job.capability_id == "browser.session":
                for evidence_id in structured.get("artifact_evidence_ids", []):
                    evidence = self.store.get_evidence(evidence_id)
                    if evidence and evidence.job_id == job.job_id and evidence.engagement_id == job.engagement_id:
                        evidence_ids.append(evidence_id)
            job.evidence_ids = evidence_ids
            job.finding_ids = finding_ids
            if job.capability_id == "workflow.wstg":
                # Child findings retain their original provenance; the parent references them.
                finding_ids = list(dict.fromkeys(structured.get("finding_ids", [])))
                job.finding_ids = finding_ids

            if exec_res.cancelled or _is_cancelled():
                job.state = JobState.CANCELLED
                job.completed_at = utc_now_iso()
                job.summary = f"Cancelled {job.capability_id}.{job.operation} after {exec_res.execution_time:.2f}s."
            elif exec_res.timed_out:
                job.transition_to(JobState.TIMED_OUT)
                job.summary = f"Timed out after {exec_res.execution_time:.2f}s."
                job.error_message = "Execution timed out"
            elif artifact_errors:
                job.transition_to(JobState.FAILED)
                job.error_message = "; ".join(artifact_errors)
                job.summary = f"Evidence persistence failed for {job.capability_id}.{job.operation}: {job.error_message}"
            elif adapter.execution_succeeded(exec_res):
                job.transition_to(JobState.COMPLETED)
                job.summary = (
                    f"Completed {job.capability_id}.{job.operation} on {job.worker_target} "
                    f"in {exec_res.execution_time:.2f}s ({len(finding_ids)} findings, {len(evidence_ids)} evidence artifacts)."
                )
                if job.capability_id == "execution.sandbox" and job.operation == "start":
                    job.summary = f"Created execution session {structured.get('session_id')} ({structured.get('state')}); inspect the session for its exit status."
                if exec_res.truncated:
                    job.summary += " Output was truncated; results are partial."
            else:
                job.transition_to(JobState.FAILED)
                job.error_message = redact_secrets(exec_res.stderr[:500] or f"Exited with code {exec_res.return_code}")
                job.summary = f"Failed {job.capability_id}.{job.operation}: {job.error_message}"

            job = self.store.save_job(job)

            try:
                self.memory.record_episode(
                    engagement_id=job.engagement_id,
                    entity_type="tool_outcome",
                    subject=f"{job.capability_id}:{','.join(plan.targets) or 'local'}",
                    content=job.summary,
                    source_artifact_ids=evidence_ids,
                    confidence=0.9 if job.state == JobState.COMPLETED else 0.5,
                    relations=[(t, "tested_by", job.capability_id) for t in plan.targets],
                    metadata={"job_id": job.job_id, "state": job.state.value, "findings": len(finding_ids)},
                )
            except Exception:
                pass

            self.store.append_event(
                engagement_id=job.engagement_id,
                job_id=job.job_id,
                event_type="job_finished",
                level="INFO" if job.state == JobState.COMPLETED else "ERROR",
                message=f"[{job.job_id}] {job.summary}",
                payload={"state": job.state.value, "exit_code": job.exit_code, "findings": finding_ids},
            )
        except Exception as exc:
            job.state = JobState.FAILED
            job.completed_at = utc_now_iso()
            job.error_message = str(exc)
            job.summary = f"Unhandled execution failure: {exc}"
            self.store.save_job(job)
            self.store.append_event(
                engagement_id=job.engagement_id,
                job_id=job.job_id,
                event_type="job_error",
                level="ERROR",
                message=f"[{job.job_id}] {exc}",
            )
        finally:
            if lease_acquired:
                self.store.release_concurrency_lease(job.job_id)

    @state_operation
    def job_status(
        self,
        job_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        cursor_seq: int = 0,
        principal: Optional[Principal] = None,
    ) -> Dict[str, Any]:
        caller = principal or Principal(principal_id="local_operator", name="Local Operator", role="operator")
        self._reconcile_orphaned_jobs()
        if not job_id:
            target_eng_id = engagement_id or "default"
            eng = self.store.get_engagement(target_eng_id)
            if not eng:
                return {"error": f"Engagement '{target_eng_id}' not found", "code": "NOT_FOUND"}
            self.policy.verify_engagement_ownership(caller, eng)
            jobs = self.store.list_jobs(engagement_id=target_eng_id, limit=25)
            return {
                "engagement_id": target_eng_id,
                "count": len(jobs),
                "jobs": [j.to_dict() for j in jobs],
            }

        job = self.store.get_job(job_id)
        if not job:
            return {"error": f"Job '{job_id}' not found", "code": "JOB_NOT_FOUND"}

        eng = self.store.get_engagement(job.engagement_id)
        if eng:
            self.policy.verify_engagement_ownership(caller, eng)
        if engagement_id is not None and job.engagement_id != engagement_id:
            return {"error": "Cross-engagement job handle access denied", "code": "FORBIDDEN"}

        events = self.store.get_events(since_seq=cursor_seq, job_id=job_id, limit=50)
        next_cursor = events[-1]["seq"] if events else cursor_seq
        return {
            "job": job.to_dict(),
            "events": events,
            "next_cursor": next_cursor,
        }

    @state_operation
    def job_cancel(
        self,
        job_id: Optional[str] = None,
        cancel_all: bool = False,
        principal: Optional[Principal] = None,
    ) -> Dict[str, Any]:
        caller = principal or Principal(principal_id="local_operator", name="Local Operator", role="operator")
        if cancel_all:
            detached_outcomes = []
            for engagement in self.store.list_engagements():
                try:
                    self.policy.verify_engagement_ownership(caller, engagement)
                except PolicyViolationError:
                    continue
                detached_outcomes.extend(cancel_sessions(self.base_root, engagement.engagement_id))
            active_candidates = [
                *self.store.list_jobs(state=JobState.RUNNING.value, limit=100),
                *self.store.list_jobs(state=JobState.QUEUED.value, limit=100),
                *self.store.list_jobs(state=JobState.CANCELLING.value, limit=100),
            ]
            authorized_running: List[Job] = []
            seen_ids: set[str] = set()
            for j in active_candidates:
                if j.job_id in seen_ids:
                    continue
                seen_ids.add(j.job_id)
                eng = self.store.get_engagement(j.engagement_id)
                if eng:
                    try:
                        self.policy.verify_engagement_ownership(caller, eng)
                    except PolicyViolationError:
                        continue
                authorized_running.append(j)

            killed = 0
            for j in authorized_running:
                j.state = JobState.CANCELLING
                self.store.save_job(j, allow_overwrite_cancelled=True)
                if self.runner.cancel(
                    j.job_id,
                    persisted_pid=j.pid,
                    expected_create_time=j.pid_create_time,
                ):
                    killed += 1
                j.state = JobState.CANCELLED
                j.completed_at = utc_now_iso()
                j.summary = "Cancelled via emergency stop-all"
                self.store.save_job(j, allow_overwrite_cancelled=True)

            self.store.append_event(
                engagement_id="default",
                event_type="emergency_stop_all",
                level="WARNING",
                message=f"Emergency stop-all cancelled {len(authorized_running)} jobs ({killed} active OS processes).",
            )
            return {
                "success": True,
                "cancelled_jobs": len(authorized_running),
                "processes_terminated": killed,
                "detached_sessions": detached_outcomes,
            }

        if not job_id:
            return {"error": "job_id is required unless cancel_all=True", "code": "MISSING_JOB_ID"}

        job = self.store.get_job(job_id)
        if not job:
            return {"error": f"Job '{job_id}' not found", "code": "JOB_NOT_FOUND"}

        eng = self.store.get_engagement(job.engagement_id)
        if eng:
            self.policy.verify_engagement_ownership(caller, eng)

        if job.capability_id in ("execution.sandbox", "browser.session") and job.operation in ("start", "open"):
            session_id = job.structured_output.get("session_id")
            if session_id:
                outcomes = cancel_sessions(self.base_root, job.engagement_id, session_id)
                if outcomes:
                    return {"success": True, "job_id": job.job_id, "detached_sessions": outcomes}

        if job.state in TERMINAL_JOB_STATES:
            return {
                "success": True,
                "job_id": job.job_id,
                "state": job.state.value,
                "already_finished": True,
                "process_terminated": False,
            }

        if job.state in (JobState.PREPARED, JobState.WAITING_APPROVAL, JobState.QUEUED, JobState.RUNNING):
            job.state = JobState.CANCELLING
            self.store.save_job(job, allow_overwrite_cancelled=True)

        # Also cancel any active child jobs spawned by this parent workflow job
        for child_candidate in self.store.list_jobs(engagement_id=job.engagement_id, limit=50):
            if child_candidate.parent_job_id == job.job_id and child_candidate.state not in TERMINAL_JOB_STATES:
                self.job_cancel(job_id=child_candidate.job_id, principal=caller)

        if job.pid is None and job.capability_id not in ("workflow.wstg", "tools.verify"):
            wait_pid_deadline = time.monotonic() + 0.15
            while time.monotonic() < wait_pid_deadline:
                refreshed = self.store.get_job(job_id)
                if refreshed and refreshed.pid is not None:
                    job = refreshed
                    break
                time.sleep(0.02)

        terminated = self.runner.cancel(
            job_id,
            persisted_pid=job.pid,
            expected_create_time=job.pid_create_time,
        )

        job.state = JobState.CANCELLED
        job.completed_at = utc_now_iso()
        job.summary = "Cancelled by caller"
        self.store.save_job(job, allow_overwrite_cancelled=True)
        self.store.release_concurrency_lease(job.job_id)

        self.store.append_event(
            engagement_id=job.engagement_id,
            job_id=job.job_id,
            event_type="job_cancelled",
            level="WARNING",
            message=f"Cancelled job {job.job_id} (process_terminated={terminated})",
        )
        return {
            "success": True,
            "job_id": job.job_id,
            "state": job.state.value,
            "already_finished": False,
            "process_terminated": terminated,
        }

    @state_operation
    def evidence_read(
        self,
        evidence_id: Optional[str] = None,
        job_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        offset: int = 0,
        limit: int = 4000,
        principal: Optional[Principal] = None,
        view: str = "raw",
        url_contains: str = "",
        status_code: Optional[int] = None,
        method: Optional[str] = None,
    ) -> Dict[str, Any]:
        caller = principal or Principal(principal_id="local_operator", name="Local Operator", role="operator")
        bounded_limit = max(128, min(limit, 32768))
        if not evidence_id:
            target_eng_id = engagement_id or "default"
            eng = self.store.get_engagement(target_eng_id)
            if not eng:
                return {"error": f"Engagement '{target_eng_id}' not found", "code": "NOT_FOUND"}
            self.policy.verify_engagement_ownership(caller, eng)
            items = self.store.list_evidence(engagement_id=target_eng_id, job_id=job_id, limit=50)
            return {
                "engagement_id": target_eng_id,
                "count": len(items),
                "evidence": [{**e.to_dict(), "resource_uri": f"hexstrike://evidence/{e.evidence_id}/" + ("image" if e.kind == "screenshot" else "artifact")} for e in items],
            }

        ev = self.store.get_evidence(evidence_id)
        if not ev:
            return {"error": f"Evidence '{evidence_id}' not found", "code": "EVIDENCE_NOT_FOUND"}

        eng = self.store.get_engagement(ev.engagement_id)
        if eng:
            self.policy.verify_engagement_ownership(caller, eng)
        if engagement_id is not None and ev.engagement_id != engagement_id:
            return {"error": "Cross-engagement evidence handle access denied", "code": "FORBIDDEN"}

        if view == "har":
            from hexstrike.evidence.views import har_page
            return har_page(self.workspace, ev, offset, limit, url_contains, status_code, method)
        if view != "raw":
            raise ValueError("Evidence view must be raw or har")

        # Retrieve artifact with true file-offset pagination beyond 4 MiB,
        # base64 fidelity for binary/screenshot artifacts, full-file SHA-256 verification,
        # and explicit missing/corrupted artifact reporting!
        is_binary_kind = ev.kind in ("screenshot", "binary") or str(ev.artifact_id or "").endswith((".png", ".bin"))
        if ev.artifact_id:
            read_res = self.workspace.read_file(
                ev.artifact_id,
                max_bytes=bounded_limit,
                binary=is_binary_kind,
                offset=offset,
                compute_full_sha256=True,
            )
            if not read_res.get("success"):
                return {
                    "success": False,
                    "error": f"Artifact file missing or unreadable: {read_res.get('error')}",
                    "code": read_res.get("code", "ARTIFACT_READ_ERROR"),
                    "artifact_missing": True,
                    "partial": True,
                    "evidence": ev.to_dict(),
                    "preview_fallback": ev.content_preview,
                }

            total_bytes = int(read_res.get("total_bytes", 0))
            actual_sha256 = str(read_res.get("sha256", ""))
            integrity_ok = bool(
                (not ev.sha256 or actual_sha256 == ev.sha256)
                and (not ev.size_bytes or total_bytes == ev.size_bytes)
            )
            has_more = bool(read_res.get("has_more", False))
            next_offset = read_res.get("next_offset")

            if is_binary_kind:
                chunk_bytes: bytes = read_res.get("raw_bytes") or b""
                resp: Dict[str, Any] = {
                    "success": integrity_ok,
                    "evidence": ev.to_dict(),
                    "encoding": "base64",
                    "mime_type": ev.provenance.get("mime_type", "application/octet-stream"),
                    "offset": int(read_res.get("offset", offset)),
                    "limit": bounded_limit,
                    "chunk_bytes": len(chunk_bytes),
                    "total_bytes": total_bytes,
                    "sha256": actual_sha256,
                    "chunk_sha256": read_res.get("chunk_sha256"),
                    "integrity_verified": integrity_ok,
                    "corrupted": not integrity_ok,
                    "has_more": has_more,
                    "next_offset": next_offset,
                    "content": base64.b64encode(chunk_bytes).decode("ascii"),
                }
                if not integrity_ok:
                    resp["error"] = "Artifact on-disk digest or size does not match recorded evidence metadata"
                    resp["code"] = "ARTIFACT_CORRUPTED"
                return resp

            chunk_text = redact_secrets(read_res.get("content", ""))
            text_resp: Dict[str, Any] = {
                "success": integrity_ok,
                "evidence": ev.to_dict(),
                "encoding": "utf-8",
                "offset": int(read_res.get("offset", offset)),
                "limit": bounded_limit,
                "total_bytes": total_bytes,
                "total_chars": total_bytes,
                "sha256": actual_sha256,
                "chunk_sha256": read_res.get("chunk_sha256"),
                "integrity_verified": integrity_ok,
                "corrupted": not integrity_ok,
                "has_more": has_more,
                "next_offset": next_offset,
                "content": chunk_text,
            }
            if not integrity_ok:
                text_resp["error"] = "Artifact on-disk digest or size does not match recorded evidence metadata"
                text_resp["code"] = "ARTIFACT_CORRUPTED"
            return text_resp

        return {
            "success": False,
            "error": "Evidence record has no persisted artifact handle",
            "code": "ARTIFACT_MISSING",
            "artifact_missing": True,
            "partial": True,
            "evidence": ev.to_dict(),
            "preview_fallback": ev.content_preview,
        }

    @state_operation
    def memory_query(
        self,
        query: str = "",
        engagement_id: str = "default",
        entity_type: Optional[str] = None,
        include_promoted_lessons: bool = True,
        limit: int = 20,
        principal: Optional[Principal] = None,
    ) -> Dict[str, Any]:
        caller = principal or Principal(principal_id="local_operator", name="Local Operator", role="operator")
        eng = self.store.get_engagement(engagement_id)
        if eng:
            self.policy.verify_engagement_ownership(caller, eng)

        # Compute the set of engagements owned by (or accessible to) `caller`,
        # AND exclude lessons from any engagement owned by a DIFFERENT user!
        owned_eng_ids: List[str] = [engagement_id]
        forbidden_eng_ids: List[str] = []
        for candidate_eng in self.store.list_engagements():
            try:
                self.policy.verify_engagement_ownership(caller, candidate_eng)
                if candidate_eng.engagement_id not in owned_eng_ids:
                    owned_eng_ids.append(candidate_eng.engagement_id)
            except PolicyViolationError:
                forbidden_eng_ids.append(candidate_eng.engagement_id)

        return self.memory.query(
            engagement_id=engagement_id,
            query_text=query,
            entity_type=entity_type,
            include_promoted_lessons=include_promoted_lessons,
            limit=limit,
            allowed_source_engagement_ids=owned_eng_ids,
            forbidden_source_engagement_ids=forbidden_eng_ids,
        )
