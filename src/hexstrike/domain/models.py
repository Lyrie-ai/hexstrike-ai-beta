"""
Core typed domain contracts for HexStrike AI.

Zero external framework imports.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_canonical_digest(payload: Any) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class RiskLevel(str, Enum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SideEffectClass(str, Enum):
    READ_ONLY = "read_only"
    LOCAL_COMPUTE = "local_compute"
    NETWORK_PROBE = "network_probe"
    ACTIVE_SCAN = "active_scan"
    MUTATING_TEST = "mutating_test"
    WORKSPACE_IO = "workspace_io"


class ToolStatus(str, Enum):
    DISCOVERED = "discovered"
    RECOGNIZED = "recognized"
    VERSION_SUPPORTED = "version_supported"
    VALIDATED = "validated"
    ENABLED = "enabled"
    MISSING = "missing"
    RESTRICTED = "restricted"
    INCOMPATIBLE = "incompatible"
    QUARANTINED = "quarantined"


class JobState(str, Enum):
    PREPARED = "prepared"
    WAITING_APPROVAL = "waiting_approval"
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    INTERRUPTED = "interrupted"


VALID_JOB_TRANSITIONS: Dict[JobState, set[JobState]] = {
    JobState.PREPARED: {
        JobState.WAITING_APPROVAL,
        JobState.QUEUED,
        JobState.RUNNING,
        JobState.CANCELLED,
        JobState.FAILED,
    },
    JobState.WAITING_APPROVAL: {
        JobState.QUEUED,
        JobState.RUNNING,
        JobState.CANCELLED,
        JobState.FAILED,
    },
    JobState.QUEUED: {
        JobState.RUNNING,
        JobState.CANCELLING,
        JobState.CANCELLED,
        JobState.FAILED,
        JobState.INTERRUPTED,
    },
    JobState.RUNNING: {
        JobState.CANCELLING,
        JobState.CANCELLED,
        JobState.COMPLETED,
        JobState.FAILED,
        JobState.TIMED_OUT,
        JobState.INTERRUPTED,
    },
    JobState.CANCELLING: {
        JobState.CANCELLED,
        JobState.COMPLETED,
        JobState.FAILED,
        JobState.TIMED_OUT,
    },
    JobState.CANCELLED: set(),
    JobState.COMPLETED: set(),
    JobState.FAILED: set(),
    JobState.TIMED_OUT: set(),
    JobState.INTERRUPTED: {JobState.CANCELLED, JobState.FAILED},
}


class FindingState(str, Enum):
    OBSERVATION = "observation"
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    REJECTED_FALSE_POSITIVE = "rejected_false_positive"
    HUMAN_REVIEWED = "human_reviewed"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LessonState(str, Enum):
    CANDIDATE = "candidate"
    EVALUATED = "evaluated"
    REVIEWED = "reviewed"
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled_back"


@dataclass(frozen=True)
class Principal:
    principal_id: str
    name: str
    role: str = "ai_agent"
    authenticated: bool = True
    scopes: tuple[str, ...] = ("*",)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScopePolicy:
    """
    Engagement scope policy.

    Defaults to autonomous execution with open target scope so AI clients can
    orchestrate assessments directly, while enforcing SSRF metadata protections
    and explicit inclusion/exclusion rules when configured.
    """

    allow_all_targets: bool = True
    autonomous_mode: bool = True
    allowed_targets: List[str] = field(default_factory=list)
    excluded_targets: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=list)
    allowed_protocols: List[str] = field(
        default_factory=lambda: ["http", "https", "tcp", "udp", "icmp", "ssh", "dns", "smb"]
    )
    # Retained for persisted-state and client compatibility; not an execution limit.
    max_risk_level: RiskLevel = RiskLevel.CRITICAL
    max_rate_per_minute: int = 600
    max_concurrency: int = 8
    max_timeout_seconds: int = 1800
    max_artifact_bytes: int = 100 * 1024 * 1024
    block_metadata_endpoints: bool = True
    worker_target: str = "local"  # "local" or SSH spec e.g. "operator@worker"
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["max_risk_level"] = self.max_risk_level.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScopePolicy":
        copied = dict(data)
        if "max_risk_level" in copied and isinstance(copied["max_risk_level"], str):
            copied["max_risk_level"] = RiskLevel(copied["max_risk_level"])
        return cls(**copied)


@dataclass
class Engagement:
    engagement_id: str
    name: str
    owner_principal_id: str
    scope: ScopePolicy = field(default_factory=ScopePolicy)
    description: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    status: str = "active"
    credentials_refs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "name": self.name,
            "owner_principal_id": self.owner_principal_id,
            "scope": self.scope.to_dict(),
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "status": self.status,
            "credentials_refs": list(self.credentials_refs),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class CapabilityDescriptor:
    capability_id: str
    name: str
    category: str
    description: str
    binary_name: Optional[str]
    operations: Dict[str, Dict[str, Any]]
    risk_level: RiskLevel = RiskLevel.MEDIUM
    side_effects: SideEffectClass = SideEffectClass.ACTIVE_SCAN
    supported_platforms: tuple[str, ...] = ("linux", "darwin", "win32")
    supported_versions: str = ">=1.0"
    license_name: str = "Open Source"
    requires_network: bool = True
    requires_root: bool = False
    pack: str = "core"
    examples: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def schema_digest(self) -> str:
        return compute_canonical_digest(
            {
                "capability_id": self.capability_id,
                "operations": self.operations,
                "risk_level": self.risk_level.value,
                "side_effects": self.side_effects.value,
            }
        )

    def to_summary_dict(self, install_status: str = "recognized") -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "name": self.name,
            "category": self.category,
            "pack": self.pack,
            "binary_name": self.binary_name,
            "risk_level": self.risk_level.value,
            "side_effects": self.side_effects.value,
            "operations": list(self.operations.keys()),
            "status": install_status,
            "description": self.description,
        }

    def to_detail_dict(self, install_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "name": self.name,
            "category": self.category,
            "pack": self.pack,
            "description": self.description,
            "binary_name": self.binary_name,
            "risk_level": self.risk_level.value,
            "side_effects": self.side_effects.value,
            "supported_platforms": list(self.supported_platforms),
            "supported_versions": self.supported_versions,
            "license": self.license_name,
            "requires_network": self.requires_network,
            "requires_root": self.requires_root,
            "schema_digest": self.schema_digest,
            "operations": self.operations,
            "examples": self.examples,
            "installation": install_info or {},
        }


@dataclass(frozen=True)
class InvocationPlan:
    plan_id: str
    engagement_id: str
    principal_id: str
    capability_id: str
    operation: str
    arguments: Dict[str, Any]
    targets: tuple[str, ...]
    argv_preview: tuple[str, ...]
    worker_target: str
    risk_level: RiskLevel
    side_effects: SideEffectClass
    schema_digest: str
    binary_digest: str
    timeout_seconds: float = 300
    created_at: str = field(default_factory=utc_now_iso)
    expires_at: Optional[str] = None
    policy_explanation: str = "Authorized by engagement policy"

    @property
    def plan_digest(self) -> str:
        return compute_canonical_digest(
            {
                "engagement_id": self.engagement_id,
                "principal_id": self.principal_id,
                "capability_id": self.capability_id,
                "operation": self.operation,
                "arguments": self.arguments,
                "targets": list(self.targets),
                "argv_preview": list(self.argv_preview),
                "worker_target": self.worker_target,
                "schema_digest": self.schema_digest,
                "binary_digest": self.binary_digest,
                "timeout_seconds": self.timeout_seconds,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "engagement_id": self.engagement_id,
            "principal_id": self.principal_id,
            "capability_id": self.capability_id,
            "operation": self.operation,
            "arguments": dict(self.arguments),
            "targets": list(self.targets),
            "argv_preview": list(self.argv_preview),
            "worker_target": self.worker_target,
            "risk_level": self.risk_level.value,
            "side_effects": self.side_effects.value,
            "schema_digest": self.schema_digest,
            "binary_digest": self.binary_digest,
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "policy_explanation": self.policy_explanation,
        }


@dataclass
class ApprovalGrant:
    grant_id: str
    plan_id: str
    plan_digest: str
    engagement_id: str
    principal_id: str
    approved_by: str
    created_at: str = field(default_factory=utc_now_iso)
    expires_at: Optional[str] = None
    revoked: bool = False
    revoked_reason: Optional[str] = None

    def is_valid_for(self, plan: InvocationPlan) -> bool:
        if self.revoked:
            return False
        if self.plan_id != plan.plan_id or self.plan_digest != plan.plan_digest:
            return False
        if self.engagement_id != plan.engagement_id:
            return False
        if self.expires_at:
            now = datetime.now(timezone.utc)
            exp = datetime.fromisoformat(self.expires_at)
            if now > exp:
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Job:
    job_id: str
    plan_id: str
    plan_digest: str
    engagement_id: str
    principal_id: str
    capability_id: str
    operation: str
    worker_target: str
    state: JobState = JobState.PREPARED
    idempotency_key: Optional[str] = None
    parent_job_id: Optional[str] = None
    executor_pid: Optional[int] = None
    executor_create_time: Optional[float] = None
    pid: Optional[int] = None
    pid_create_time: Optional[float] = None
    argv: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    exit_code: Optional[int] = None
    summary: str = ""
    structured_output: Dict[str, Any] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    progress_reported: Optional[float] = None  # None = indeterminate

    def can_transition_to(self, next_state: JobState) -> bool:
        if self.state == next_state:
            return True
        return next_state in VALID_JOB_TRANSITIONS.get(self.state, set())

    def transition_to(self, next_state: JobState) -> None:
        if not self.can_transition_to(next_state):
            raise ValueError(f"Invalid job state transition: {self.state.value} -> {next_state.value}")
        self.state = next_state
        now = utc_now_iso()
        if next_state == JobState.RUNNING and not self.started_at:
            self.started_at = now
        elif next_state in {
            JobState.COMPLETED,
            JobState.FAILED,
            JobState.CANCELLED,
            JobState.TIMED_OUT,
            JobState.INTERRUPTED,
        }:
            self.completed_at = now

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


@dataclass
class Evidence:
    evidence_id: str
    engagement_id: str
    job_id: str
    capability_id: str
    kind: str  # "stdout", "stderr", "xml", "json", "screenshot", "har", "dom", "finding_proof"
    summary: str
    artifact_id: Optional[str]
    sha256: str
    size_bytes: int
    content_preview: str
    provenance: Dict[str, Any] = field(default_factory=dict)
    simulated: bool = False
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    finding_id: str
    engagement_id: str
    job_id: str
    title: str
    severity: Severity
    state: FindingState
    target: str
    capability_id: str
    description: str
    evidence_ids: List[str] = field(default_factory=list)
    remediation: str = ""
    confidence: float = 0.75
    wstg_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    kev_listed: bool = False
    negative_control_verified: bool = False
    simulated: bool = False
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["state"] = self.state.value
        return data


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"
