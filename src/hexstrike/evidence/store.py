"""
Transactional SQLite store for engagements, plans, approval grants, jobs,
capability state persistence, evidence records, findings, and real-time visual telemetry events.
"""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator

import json
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hexstrike.persistence import database_connection
from hexstrike.domain.models import (
    ApprovalGrant,
    Engagement,
    Evidence,
    Finding,
    FindingState,
    InvocationPlan,
    Job,
    JobState,
    RiskLevel,
    ScopePolicy,
    Severity,
    SideEffectClass,
    utc_now_iso,
)
from hexstrike.workspace.confined_fs import redact_secrets


class StateStore:
    """Thread-safe SQLite backing store for state and live telemetry."""

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        if db_path is None:
            default_dir = Path(tempfile.gettempdir()) / "hexstrike_state"
            default_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.db_path = default_dir / "hexstrike.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        self._lock = threading.RLock()
        self._init_schema()
        self._ensure_default_engagement()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with database_connection(str(self.db_path), timeout=30.0, check_same_thread=False) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            yield conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS engagements (
                    engagement_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner_principal_id TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    credentials_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS capability_states (
                    capability_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS plans (
                    plan_id TEXT PRIMARY KEY,
                    plan_digest TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    plan_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_grants (
                    grant_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    grant_json TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    plan_digest TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    worker_target TEXT NOT NULL,
                    state TEXT NOT NULL,
                    idempotency_key TEXT,
                    job_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_idempotency
                ON jobs (principal_id, engagement_id, idempotency_key)
                WHERE idempotency_key IS NOT NULL;

                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    state TEXT NOT NULL,
                    target TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    finding_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS telemetry_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT NOT NULL,
                    job_id TEXT,
                    event_type TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS concurrency_leases (
                    job_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    executor_pid INTEGER NOT NULL,
                    executor_create_time REAL,
                    acquired_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_leases_engagement
                ON concurrency_leases (engagement_id);

                CREATE TABLE IF NOT EXISTS rate_limit_window (
                    job_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    recorded_at_epoch REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rate_limit_engagement
                ON rate_limit_window (engagement_id, recorded_at_epoch);
                """
            )

    def _ensure_default_engagement(self) -> None:
        if self.get_engagement("default") is None:
            default_eng = Engagement(
                engagement_id="default",
                name="Default Autonomous Assessment",
                owner_principal_id="local_operator",
                scope=ScopePolicy(allow_all_targets=True, autonomous_mode=True),
                description="Default autonomous engagement controlled by the connected AI client.",
                metadata={"revision": 1},
            )
            self.save_engagement(default_eng)

    # ------------------------------------------------------------------
    # Capability enable/disable/quarantine persistence
    # ------------------------------------------------------------------
    def set_capability_state(self, capability_id: str, status: str, reason: str = "") -> None:
        now = utc_now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO capability_states (capability_id, status, reason, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(capability_id) DO UPDATE SET
                    status = excluded.status,
                    reason = excluded.reason,
                    updated_at = excluded.updated_at
                """,
                (capability_id, status, reason, now),
            )

    def get_capability_state(self, capability_id: str) -> Optional[str]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT status FROM capability_states WHERE capability_id = ?",
                (capability_id,),
            ).fetchone()
            return str(row["status"]) if row else None

    def list_capability_states(self) -> Dict[str, str]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT capability_id, status FROM capability_states").fetchall()
            return {str(r["capability_id"]): str(r["status"]) for r in rows}

    # ------------------------------------------------------------------
    # Engagement persistence
    # ------------------------------------------------------------------
    def save_engagement(self, engagement: Engagement) -> None:
        engagement.updated_at = utc_now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO engagements (
                    engagement_id, name, owner_principal_id, scope_json,
                    description, created_at, updated_at, status,
                    credentials_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id) DO UPDATE SET
                    name = excluded.name,
                    owner_principal_id = excluded.owner_principal_id,
                    scope_json = excluded.scope_json,
                    description = excluded.description,
                    updated_at = excluded.updated_at,
                    status = excluded.status,
                    credentials_json = excluded.credentials_json,
                    metadata_json = excluded.metadata_json
                """,
                (
                    engagement.engagement_id,
                    engagement.name,
                    engagement.owner_principal_id,
                    json.dumps(engagement.scope.to_dict()),
                    engagement.description,
                    engagement.created_at,
                    engagement.updated_at,
                    engagement.status,
                    json.dumps(engagement.credentials_refs),
                    json.dumps(engagement.metadata),
                ),
            )

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM engagements WHERE engagement_id = ?", (engagement_id,)
            ).fetchone()
            if not row:
                return None
            return Engagement(
                engagement_id=row["engagement_id"],
                name=row["name"],
                owner_principal_id=row["owner_principal_id"],
                scope=ScopePolicy.from_dict(json.loads(row["scope_json"])),
                description=row["description"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                status=row["status"],
                credentials_refs=json.loads(row["credentials_json"]),
                metadata=json.loads(row["metadata_json"]),
            )

    def list_engagements(self) -> List[Engagement]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT engagement_id FROM engagements ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            eng = self.get_engagement(r["engagement_id"])
            if eng:
                result.append(eng)
        return result

    # ------------------------------------------------------------------
    # Plan & Grant persistence
    # ------------------------------------------------------------------
    def save_plan(self, plan: InvocationPlan) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO plans (
                    plan_id, plan_digest, engagement_id, principal_id,
                    capability_id, operation, plan_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(plan_id) DO UPDATE SET
                    plan_json = excluded.plan_json
                """,
                (
                    plan.plan_id,
                    plan.plan_digest,
                    plan.engagement_id,
                    plan.principal_id,
                    plan.capability_id,
                    plan.operation,
                    json.dumps(plan.to_dict()),
                    plan.created_at,
                ),
            )

    def get_plan(self, plan_id: str) -> Optional[InvocationPlan]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT plan_json FROM plans WHERE plan_id = ?", (plan_id,)).fetchone()
            if not row:
                return None
            data = json.loads(row["plan_json"])
            return InvocationPlan(
                plan_id=data["plan_id"],
                engagement_id=data["engagement_id"],
                principal_id=data["principal_id"],
                capability_id=data["capability_id"],
                operation=data["operation"],
                arguments=data["arguments"],
                targets=tuple(data["targets"]),
                argv_preview=tuple(data["argv_preview"]),
                worker_target=data["worker_target"],
                risk_level=RiskLevel(data["risk_level"]),
                side_effects=SideEffectClass(data["side_effects"]),
                schema_digest=data["schema_digest"],
                binary_digest=data["binary_digest"],
                timeout_seconds=data["timeout_seconds"],
                created_at=data["created_at"],
                expires_at=data.get("expires_at"),
                policy_explanation=data.get("policy_explanation", ""),
            )

    def save_grant(self, grant: ApprovalGrant) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approval_grants (
                    grant_id, plan_id, plan_digest, engagement_id,
                    principal_id, grant_json, revoked, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(grant_id) DO UPDATE SET
                    grant_json = excluded.grant_json,
                    revoked = excluded.revoked
                """,
                (
                    grant.grant_id,
                    grant.plan_id,
                    grant.plan_digest,
                    grant.engagement_id,
                    grant.principal_id,
                    json.dumps(grant.to_dict()),
                    1 if grant.revoked else 0,
                    grant.created_at,
                ),
            )

    def get_grant_for_plan(self, plan_id: str) -> Optional[ApprovalGrant]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT grant_json FROM approval_grants WHERE plan_id = ? ORDER BY created_at DESC LIMIT 1",
                (plan_id,),
            ).fetchone()
            if not row:
                return None
            data = json.loads(row["grant_json"])
            return ApprovalGrant(**data)

    def revoke_engagement_grants(self, engagement_id: str, reason: str = "Revoked") -> int:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT grant_id, grant_json FROM approval_grants WHERE engagement_id = ? AND revoked = 0",
                (engagement_id,),
            ).fetchall()
            count = 0
            for row in rows:
                data = json.loads(row["grant_json"])
                data["revoked"] = True
                data["revoked_reason"] = reason
                conn.execute(
                    "UPDATE approval_grants SET revoked = 1, grant_json = ? WHERE grant_id = ?",
                    (json.dumps(data), row["grant_id"]),
                )
                count += 1
            return count

    # ------------------------------------------------------------------
    # Cross-Runtime Transactional Concurrency Leases
    # ------------------------------------------------------------------
    def try_acquire_concurrency_lease(
        self,
        job_id: str,
        engagement_id: str,
        executor_pid: int,
        executor_create_time: Optional[float],
        alive_check_fn: Any = None,
    ) -> bool:
        """
        Atomically check active leases for `engagement_id` against the engagement's
        current `max_concurrency` in SQLite (using `BEGIN IMMEDIATE`), pruning any dead
        executor leases, and insert `job_id` if capacity is available.
        """
        now = utc_now_iso()
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), timeout=30.0, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("BEGIN IMMEDIATE")
                eng_row = conn.execute(
                    "SELECT scope_json, status FROM engagements WHERE engagement_id = ?",
                    (engagement_id,),
                ).fetchone()
                if not eng_row or str(eng_row["status"]) == "revoked":
                    conn.execute("ROLLBACK")
                    return False

                scope_data = json.loads(eng_row["scope_json"])
                limit = max(1, int(scope_data.get("max_concurrency", 8)))

                lease_rows = conn.execute(
                    "SELECT job_id, executor_pid, executor_create_time FROM concurrency_leases WHERE engagement_id = ?",
                    (engagement_id,),
                ).fetchall()

                active_count = 0
                for lr in lease_rows:
                    l_jid = str(lr["job_id"])
                    if l_jid == job_id:
                        conn.execute("COMMIT")
                        return True
                    l_pid = int(lr["executor_pid"])
                    l_ctime = lr["executor_create_time"]
                    if alive_check_fn is not None and not alive_check_fn(l_pid, l_ctime):
                        conn.execute("DELETE FROM concurrency_leases WHERE job_id = ?", (l_jid,))
                    else:
                        active_count += 1

                if active_count >= limit:
                    conn.execute("ROLLBACK")
                    return False

                conn.execute(
                    """
                    INSERT OR REPLACE INTO concurrency_leases (
                        job_id, engagement_id, executor_pid, executor_create_time, acquired_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (job_id, engagement_id, executor_pid, executor_create_time, now),
                )
                conn.execute("COMMIT")
                return True
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                return False
            finally:
                conn.close()

    def release_concurrency_lease(self, job_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM concurrency_leases WHERE job_id = ?", (job_id,))

    def check_and_record_rate_limit(
        self, engagement_id: str, job_id: str, window_seconds: float = 60.0
    ) -> Tuple[bool, int, int]:
        """
        Atomically enforce the engagement's `max_rate_per_minute` sliding window across
        all runtimes sharing this SQLite store.
        Returns `(allowed, current_count, max_rate_per_minute)`.
        """
        now_epoch = time.time()
        cutoff = now_epoch - max(1.0, window_seconds)
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), timeout=30.0, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("BEGIN IMMEDIATE")
                eng_row = conn.execute(
                    "SELECT scope_json FROM engagements WHERE engagement_id = ?",
                    (engagement_id,),
                ).fetchone()
                if not eng_row:
                    conn.execute("ROLLBACK")
                    return False, 0, 0
                scope_data = json.loads(eng_row["scope_json"])
                max_rate = max(1, int(scope_data.get("max_rate_per_minute", 120)))

                conn.execute("DELETE FROM rate_limit_window WHERE recorded_at_epoch < ?", (cutoff,))
                existing = conn.execute(
                    "SELECT 1 FROM rate_limit_window WHERE job_id = ?", (job_id,)
                ).fetchone()
                cnt_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM rate_limit_window WHERE engagement_id = ? AND recorded_at_epoch >= ?",
                    (engagement_id, cutoff),
                ).fetchone()
                current_cnt = int(cnt_row["cnt"]) if cnt_row else 0
                if existing:
                    conn.execute("COMMIT")
                    return True, current_cnt, max_rate

                if current_cnt >= max_rate:
                    conn.execute("ROLLBACK")
                    return False, current_cnt, max_rate

                conn.execute(
                    "INSERT INTO rate_limit_window (job_id, engagement_id, recorded_at_epoch) VALUES (?, ?, ?)",
                    (job_id, engagement_id, now_epoch),
                )
                conn.execute("COMMIT")
                return True, current_cnt + 1, max_rate
            except Exception:
                try:
                    conn.execute("ROLLBACK")
                except Exception:
                    pass
                return False, 0, 0
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Atomic Job Reservation & Persistence
    # ------------------------------------------------------------------
    def reserve_or_get_job(self, job: Job) -> Tuple[Job, bool]:
        """
        Atomically insert a new job or return the existing job if a concurrent caller
        already reserved `(principal_id, engagement_id, idempotency_key)`.
        Returns `(job, True)` if this call created the reservation, or `(existing_job, False)`
        if deduplicated against an existing reservation.
        """
        now = utc_now_iso()
        with self._lock, self._connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO jobs (
                        job_id, plan_id, plan_digest, engagement_id, principal_id,
                        capability_id, operation, worker_target, state,
                        idempotency_key, job_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job.job_id,
                        job.plan_id,
                        job.plan_digest,
                        job.engagement_id,
                        job.principal_id,
                        job.capability_id,
                        job.operation,
                        job.worker_target,
                        job.state.value,
                        job.idempotency_key,
                        json.dumps(job.to_dict()),
                        job.created_at,
                        now,
                    ),
                )
                return job, True
            except sqlite3.IntegrityError:
                if job.idempotency_key is not None:
                    row = conn.execute(
                        """
                        SELECT job_json FROM jobs
                        WHERE principal_id = ? AND engagement_id = ? AND idempotency_key = ?
                        """,
                        (job.principal_id, job.engagement_id, job.idempotency_key),
                    ).fetchone()
                    if row:
                        return self._job_from_dict(json.loads(row["job_json"])), False
                raise

    def save_job(self, job: Job, allow_overwrite_cancelled: bool = False) -> Job:
        """
        Persist job state keyed strictly by `job_id` (never `INSERT OR REPLACE` across
        idempotency keys). Also prevents late worker completions from overwriting a
        job that was concurrently transitioned to `cancelling` or `cancelled`.
        """
        now = utc_now_iso()
        with self._lock, self._connect() as conn:
            existing_row = conn.execute(
                "SELECT state, job_json FROM jobs WHERE job_id = ?",
                (job.job_id,),
            ).fetchone()
            if existing_row and not allow_overwrite_cancelled:
                db_state = str(existing_row["state"])
                if db_state == JobState.CANCELLED.value and job.state != JobState.CANCELLED:
                    return self._job_from_dict(json.loads(existing_row["job_json"]))
                if db_state == JobState.CANCELLING.value and job.state not in (
                    JobState.CANCELLING,
                    JobState.CANCELLED,
                ):
                    job.state = JobState.CANCELLED
                    job.completed_at = now
                    job.summary = "Cancelled during execution"

            conn.execute(
                """
                INSERT INTO jobs (
                    job_id, plan_id, plan_digest, engagement_id, principal_id,
                    capability_id, operation, worker_target, state,
                    idempotency_key, job_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    state = excluded.state,
                    job_json = excluded.job_json,
                    updated_at = excluded.updated_at
                """,
                (
                    job.job_id,
                    job.plan_id,
                    job.plan_digest,
                    job.engagement_id,
                    job.principal_id,
                    job.capability_id,
                    job.operation,
                    job.worker_target,
                    job.state.value,
                    job.idempotency_key,
                    json.dumps(job.to_dict()),
                    job.created_at,
                    now,
                ),
            )
            return job

    def update_job_pid(self, job_id: str, pid: int, pid_create_time: Optional[float] = None) -> None:
        now = utc_now_iso()
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT job_json FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not row:
                return
            data = json.loads(row["job_json"])
            data["pid"] = pid
            if pid_create_time is not None:
                data["pid_create_time"] = pid_create_time
            conn.execute(
                "UPDATE jobs SET job_json = ?, updated_at = ? WHERE job_id = ?",
                (json.dumps(data), now, job_id),
            )

    def get_job(self, job_id: str) -> Optional[Job]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT job_json FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not row:
                return None
            return self._job_from_dict(json.loads(row["job_json"]))

    def get_job_by_idempotency(
        self, principal_id: str, engagement_id: str, idempotency_key: str
    ) -> Optional[Job]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT job_json FROM jobs
                WHERE principal_id = ? AND engagement_id = ? AND idempotency_key = ?
                """,
                (principal_id, engagement_id, idempotency_key),
            ).fetchone()
            if not row:
                return None
            return self._job_from_dict(json.loads(row["job_json"]))

    def list_jobs(
        self, engagement_id: Optional[str] = None, state: Optional[str] = None, limit: int = 50
    ) -> List[Job]:
        query = "SELECT job_json FROM jobs WHERE 1=1"
        params: List[Any] = []
        if engagement_id:
            query += " AND engagement_id = ?"
            params.append(engagement_id)
        if state:
            query += " AND state = ?"
            params.append(state)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._job_from_dict(json.loads(r["job_json"])) for r in rows]

    @staticmethod
    def _job_from_dict(data: Dict[str, Any]) -> Job:
        copied = dict(data)
        copied["state"] = JobState(copied["state"])
        return Job(**copied)

    # ------------------------------------------------------------------
    # Evidence, Findings & Telemetry Events
    # ------------------------------------------------------------------
    def save_evidence(self, evidence: Evidence) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence (
                    evidence_id, engagement_id, job_id, capability_id,
                    kind, sha256, size_bytes, evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.evidence_id,
                    evidence.engagement_id,
                    evidence.job_id,
                    evidence.capability_id,
                    evidence.kind,
                    evidence.sha256,
                    evidence.size_bytes,
                    json.dumps(evidence.to_dict()),
                    evidence.created_at,
                ),
            )

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT evidence_json FROM evidence WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
            if not row:
                return None
            return Evidence(**json.loads(row["evidence_json"]))

    def list_evidence(
        self, engagement_id: Optional[str] = None, job_id: Optional[str] = None, limit: int = 50
    ) -> List[Evidence]:
        query = "SELECT evidence_json FROM evidence WHERE 1=1"
        params: List[Any] = []
        if engagement_id:
            query += " AND engagement_id = ?"
            params.append(engagement_id)
        if job_id:
            query += " AND job_id = ?"
            params.append(job_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [Evidence(**json.loads(r["evidence_json"])) for r in rows]

    def save_finding(self, finding: Finding) -> None:
        finding.updated_at = utc_now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (
                    finding_id, engagement_id, job_id, severity, state,
                    target, capability_id, finding_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.finding_id,
                    finding.engagement_id,
                    finding.job_id,
                    finding.severity.value,
                    finding.state.value,
                    finding.target,
                    finding.capability_id,
                    json.dumps(finding.to_dict()),
                    finding.created_at,
                    finding.updated_at,
                ),
            )

    def record_finding(self, finding: Finding) -> None:
        """Merge repeated identical observations while retaining review and evidence."""
        with self._lock, self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT finding_json FROM findings WHERE engagement_id=? AND capability_id=? AND target=?",
                (finding.engagement_id, finding.capability_id, finding.target),
            ).fetchall()
            for row in rows:
                old = json.loads(row["finding_json"])
                if (old["title"], old["description"], old.get("cve_id")) != (finding.title, finding.description, finding.cve_id):
                    continue
                finding.finding_id = old["finding_id"]
                finding.created_at = old["created_at"]
                finding.job_id = old["job_id"]
                finding.state = FindingState(old["state"])
                finding.severity = Severity(old["severity"])
                finding.remediation = old["remediation"]
                finding.confidence = old["confidence"]
                for field in ("cvss_score", "epss_score", "kev_listed"):
                    setattr(finding, field, old[field])
                finding.negative_control_verified = old["negative_control_verified"]
                finding.evidence_ids = list(dict.fromkeys(old["evidence_ids"] + finding.evidence_ids))
                finding.updated_at = utc_now_iso()
                conn.execute("UPDATE findings SET finding_json=?, updated_at=? WHERE finding_id=?",
                             (json.dumps(finding.to_dict()), finding.updated_at, finding.finding_id))
                return
            conn.execute(
                "INSERT INTO findings (finding_id,engagement_id,job_id,severity,state,target,capability_id,finding_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (finding.finding_id, finding.engagement_id, finding.job_id, finding.severity.value, finding.state.value,
                 finding.target, finding.capability_id, json.dumps(finding.to_dict()), finding.created_at, finding.updated_at),
            )

    def count_findings(self, engagement_id: str) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE engagement_id = ?", (engagement_id,)
            ).fetchone()
        return int(row[0])

    def list_findings(
        self, engagement_id: Optional[str] = None, state: Optional[str] = None, limit: int = 100
    ) -> List[Finding]:
        query = "SELECT finding_json FROM findings WHERE 1=1"
        params: List[Any] = []
        if engagement_id:
            query += " AND engagement_id = ?"
            params.append(engagement_id)
        if state:
            query += " AND state = ?"
            params.append(state)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        result: List[Finding] = []
        for r in rows:
            data = json.loads(r["finding_json"])
            data["severity"] = Severity(data["severity"])
            data["state"] = FindingState(data["state"])
            result.append(Finding(**data))
        return result

    def append_event(
        self,
        engagement_id: str,
        event_type: str,
        message: str,
        level: str = "INFO",
        job_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> int:
        safe_msg = redact_secrets(message)
        def redact_value(value):
            if isinstance(value, dict):
                return {key: redact_value(item) for key, item in value.items()}
            if isinstance(value, list):
                return [redact_value(item) for item in value]
            return redact_secrets(value) if isinstance(value, str) else value
        safe_payload = json.dumps(redact_value(json.loads(json.dumps(payload or {}, default=str))))
        now = utc_now_iso()
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO telemetry_events (
                    engagement_id, job_id, event_type, level, message, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (engagement_id, job_id, event_type, level, safe_msg, safe_payload, now),
            )
            return int(cur.lastrowid or 0)

    def get_events(
        self,
        since_seq: int = 0,
        engagement_id: Optional[str] = None,
        job_id: Optional[str] = None,
        limit: int = 100,
        *, latest: bool = False,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM telemetry_events WHERE seq > ?"
        params: List[Any] = [since_seq]
        if engagement_id:
            query += " AND engagement_id = ?"
            params.append(engagement_id)
        if job_id:
            query += " AND job_id = ?"
            params.append(job_id)
        query += " ORDER BY seq DESC LIMIT ?" if latest else " ORDER BY seq ASC LIMIT ?"
        params.append(limit)
        with self._lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        if latest:
            rows.reverse()
        def decode_payload(raw):
            try:
                return json.loads(raw)
            except (ValueError, TypeError):
                # Preserve the original database row without breaking the event stream.
                return {"error": "Stored event payload is invalid JSON"}
        return [
            {
                "seq": r["seq"],
                "engagement_id": r["engagement_id"],
                "job_id": r["job_id"],
                "event_type": r["event_type"],
                "level": r["level"],
                "message": r["message"],
                "payload": decode_payload(r["payload_json"]),
                "created_at": r["created_at"],
            }
            for r in rows
        ]
