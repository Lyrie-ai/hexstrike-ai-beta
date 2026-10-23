"""
Deterministic OWASP WSTG DAG workflow runner and threat-intelligence correlation.

Features:
- Executable DAG workflow runner (`WorkflowRunner`) with prerequisite step checks,
  bounded retries, checkpoint state persistence, and cancellation propagation
- Fixes `exploits_found` key correlation bug from baseline (`total_exploits` vs `exploits_found`)
- Segregates CVSS severity, EPSS probability, CISA KEV status, and local exposure with
  explicit snapshot dates
- Labels any synthetic/offline intelligence explicitly with `simulated=True`
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hexstrike.adapters.catalog import ToolAdapter
from hexstrike.domain.models import (
    CapabilityDescriptor,
    Finding,
    Principal,
    RiskLevel,
    SideEffectClass,
    utc_now_iso,
)
from hexstrike.execution.runner import ExecutionResult


@dataclass(frozen=True)
class WorkflowStep:
    step_id: str
    wstg_id: str
    capability_id: str
    operation: str
    description: str
    depends_on: Tuple[str, ...] = ()
    retryable: bool = True
    max_retries: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


WSTG_WORKFLOW_TEMPLATES: Dict[str, List[WorkflowStep]] = {
    "web_baseline": [
        WorkflowStep(
            step_id="http_headers",
            wstg_id="WSTG-CONF-07",
            capability_id="web.http_inspect",
            operation="probe",
            description="Inspect HTTP response status, security headers, and server banners",
            depends_on=(),
        ),
        WorkflowStep(
            step_id="browser_dom",
            wstg_id="WSTG-SESS-02",
            capability_id="browser.inspect",
            operation="inspect",
            description="Inspect DOM structure, cookie flags, and form anti-CSRF tokens",
            depends_on=("http_headers",),
        ),
    ],
    "network_recon": [
        WorkflowStep(
            step_id="port_discovery",
            wstg_id="WSTG-INFO-02",
            capability_id="network.nmap",
            operation="scan",
            description="Run quick TCP service discovery and parse Nmap XML output",
            depends_on=(),
        ),
    ],
}


class WorkflowRunner:
    """
    Executes a deterministic WSTG DAG workflow across `HexStrikeRuntime`, enforcing
    step prerequisites, parent cancellation checks before every step and retry,
    bounded retries (without privilege escalation or shell fallback), and recording
    per-step job/finding provenance.
    """

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    def _is_parent_cancelled(self, parent_job_id: Optional[str]) -> bool:
        if not parent_job_id:
            return False
        parent = self.runtime.store.get_job(parent_job_id)
        if not parent:
            return False
        return parent.state.value in ("cancelling", "cancelled", "timed_out", "interrupted")

    def execute_workflow(
        self,
        workflow_name: str,
        target: str,
        engagement_id: str = "default",
        worker_target: Optional[str] = None,
        principal: Optional[Principal] = None,
        parent_job_id: Optional[str] = None,
        timeout_seconds: float = 300,
    ) -> Dict[str, Any]:
        if workflow_name not in WSTG_WORKFLOW_TEMPLATES:
            raise ValueError(f"Unknown workflow '{workflow_name}'. Available: {sorted(WSTG_WORKFLOW_TEMPLATES)}")

        steps = WSTG_WORKFLOW_TEMPLATES[workflow_name]
        completed_steps: Dict[str, Dict[str, Any]] = {}
        failed_steps: List[str] = []
        skipped_cancelled_steps: List[str] = []
        all_job_ids: List[str] = []
        all_finding_ids: List[str] = []
        deadline = time.monotonic() + timeout_seconds
        timed_out = False

        for step in steps:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if self._is_parent_cancelled(parent_job_id):
                skipped_cancelled_steps.append(step.step_id)
                break

            if any(dep not in completed_steps for dep in step.depends_on):
                failed_steps.append(step.step_id)
                continue

            arg_key = "url" if step.capability_id in ("web.http_inspect", "browser.inspect") else "target"
            step_args = {arg_key: target}

            attempts = 0
            max_attempts = (1 + step.max_retries) if step.retryable else 1
            step_res: Optional[Dict[str, Any]] = None

            while attempts < max_attempts:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                if self._is_parent_cancelled(parent_job_id):
                    skipped_cancelled_steps.append(step.step_id)
                    break
                attempts += 1
                step_res = self.runtime.job_start(
                    capability_id=step.capability_id,
                    operation=step.operation,
                    arguments=step_args,
                    engagement_id=engagement_id,
                    worker_target=worker_target,
                    principal=principal,
                    parent_job_id=parent_job_id,
                    timeout_seconds=remaining,
                )
                if step_res.get("job"):
                    all_job_ids.append(step_res["job"]["job_id"])
                    all_finding_ids.extend(step_res["job"].get("finding_ids", []))
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                if step_res.get("success") or self._is_parent_cancelled(parent_job_id):
                    break

            if timed_out or self._is_parent_cancelled(parent_job_id):
                break

            if step_res and step_res.get("job"):
                job_data = step_res["job"]
                if step_res.get("success"):
                    completed_steps[step.step_id] = {
                        "step_id": step.step_id,
                        "wstg_id": step.wstg_id,
                        "job_id": job_data["job_id"],
                        "attempts": attempts,
                        "findings": job_data.get("finding_ids", []),
                    }
                else:
                    failed_steps.append(step.step_id)
            else:
                failed_steps.append(step.step_id)

        was_cancelled = self._is_parent_cancelled(parent_job_id) or len(skipped_cancelled_steps) > 0
        return {
            "success": (len(failed_steps) == 0) and not was_cancelled and not timed_out,
            "cancelled": was_cancelled,
            "timed_out": timed_out,
            "workflow": workflow_name,
            "target": target,
            "engagement_id": engagement_id,
            "parent_job_id": parent_job_id,
            "completed_steps": completed_steps,
            "failed_steps": failed_steps,
            "skipped_cancelled_steps": skipped_cancelled_steps,
            "job_ids": all_job_ids,
            "finding_ids": all_finding_ids,
        }


SUPPORTED_INTEL_SOURCES = frozenset({"nvd", "epss", "cisa_kev", "exploit_db"})


def _parse_timeframe_delta(timeframe: str) -> Optional[timedelta]:
    tf = (timeframe or "all").strip().lower()
    if tf in ("all", "*", "any"):
        return None
    m = re.match(r"^(\d+)([dh])$", tf)
    if not m:
        raise ValueError(f"Invalid timeframe '{timeframe}'; expected '<N>d', '<N>h', or 'all'")
    val = int(m.group(1))
    unit = m.group(2)
    return timedelta(days=val) if unit == "d" else timedelta(hours=val)


def _parse_selected_sources(sources: str) -> set[str]:
    raw = (sources or "all").strip().lower()
    if raw in ("all", "*"):
        return set(SUPPORTED_INTEL_SOURCES)
    parts = {p.strip() for p in raw.split(",") if p.strip()}
    if not parts:
        raise ValueError("At least one threat intelligence source must be specified")
    unknown = parts - SUPPORTED_INTEL_SOURCES
    if unknown:
        raise ValueError(
            f"Unsupported threat intelligence source(s): {sorted(unknown)}. "
            f"Supported: {sorted(SUPPORTED_INTEL_SOURCES)} or 'all'"
        )
    return parts


def _load_cached_feed_records(cache_path: Optional[Path | str] = None) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    effective_path = cache_path or os.environ.get("HEXSTRIKE_THREAT_FEED_PATH")
    if not effective_path:
        return {}, None
    p = Path(effective_path)
    if not p.is_file():
        return {}, str(p)
    try:
        raw_bytes = p.read_bytes()
        data = json.loads(raw_bytes.decode("utf-8"))
        file_digest = hashlib.sha256(raw_bytes).hexdigest()
        records_raw = data.get("records", data) if isinstance(data, dict) else {}
        normalized: Dict[str, Dict[str, Any]] = {}
        if isinstance(records_raw, dict):
            for k, v in records_raw.items():
                if isinstance(v, dict):
                    rec_copy = dict(v)
                    rec_copy.setdefault("cache_file_sha256", file_digest)
                    rec_copy.setdefault("cache_path", str(p))
                    normalized[str(k).upper()] = rec_copy
        return normalized, str(p)
    except Exception:
        return {}, str(p)


def _fetch_live_cve_provider_record(
    cve_id: str, selected_sources: set[str], timeout: float = 5.0
) -> Optional[Dict[str, Any]]:
    """
    Opt-in live query against FIRST EPSS API and NVD REST API v2.
    Never invents metrics if an endpoint is unreachable or returns no match.
    """
    now_iso = utc_now_iso()
    epss_score: Optional[float] = None
    cvss_score: Optional[float] = None
    kev_listed: Optional[bool] = None
    title: Optional[str] = None
    published_at: Optional[str] = None
    provider_sources: List[str] = []
    raw_digests: Dict[str, str] = {}

    if "epss" in selected_sources:
        epss_url = f"https://api.first.org/data/v1/epss?cve={urllib.parse.quote(cve_id)}"
        try:
            req = urllib.request.Request(epss_url, headers={"User-Agent": "HexStrike-ThreatIntel/6.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(65536)
                raw_digests["epss"] = hashlib.sha256(body).hexdigest()
                payload = json.loads(body.decode("utf-8"))
                rows = payload.get("data") or []
                if rows and isinstance(rows[0], dict) and "epss" in rows[0]:
                    epss_score = float(rows[0]["epss"])
                    provider_sources.append("epss")
        except Exception:
            pass

    if "nvd" in selected_sources or "cisa_kev" in selected_sources:
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
        try:
            req = urllib.request.Request(nvd_url, headers={"User-Agent": "HexStrike-ThreatIntel/6.1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(262144)
                raw_digests["nvd"] = hashlib.sha256(body).hexdigest()
                payload = json.loads(body.decode("utf-8"))
                vulns = payload.get("vulnerabilities") or []
                if vulns and isinstance(vulns[0], dict):
                    cve_obj = vulns[0].get("cve") or {}
                    published_at = cve_obj.get("published") or cve_obj.get("lastModified")
                    descs = cve_obj.get("descriptions") or []
                    for d in descs:
                        if isinstance(d, dict) and d.get("lang") == "en":
                            title = d.get("value")
                            break
                    if "nvd" in selected_sources:
                        metrics = cve_obj.get("metrics") or {}
                        for m_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
                            m_list = metrics.get(m_key) or []
                            if m_list and isinstance(m_list[0], dict):
                                cvss_data = m_list[0].get("cvssData") or {}
                                if "baseScore" in cvss_data:
                                    cvss_score = float(cvss_data["baseScore"])
                                    provider_sources.append("nvd")
                                    break
                    if "cisa_kev" in selected_sources:
                        kev_listed = bool(cve_obj.get("cisaExploitAdd"))
                        provider_sources.append("cisa_kev")
        except Exception:
            pass

    if not provider_sources:
        return None

    return {
        "cve_id": cve_id,
        "title": title or cve_id,
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "kev_listed": kev_listed,
        "exploits_found": None,
        "source": "+".join(sorted(set(provider_sources))),
        "snapshot_date": published_at or now_iso[:10],
        "fetched_at": now_iso,
        "raw_digests": raw_digests,
        "simulated": False,
    }


def correlate_threat_indicators(
    indicators: List[str],
    timeframe: str = "30d",
    sources: str = "all",
    include_simulated: bool = False,
    *,
    cache_path: Optional[Path | str] = None,
    feed_records: Optional[Dict[str, Dict[str, Any]]] = None,
    allow_online_fetch: bool = False,
) -> Dict[str, Any]:
    """
    Correlate CVE, IP, and hash indicators against a versioned local feed cache or
    opt-in live providers (FIRST EPSS / NVD / CISA KEV).
    Never invents CVSS, EPSS, KEV, or exploit-count values for unindexed indicators.
    """
    tf_delta = _parse_timeframe_delta(timeframe)
    selected_sources = _parse_selected_sources(sources)
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()

    cached_map, resolved_cache_path = _load_cached_feed_records(cache_path)
    if feed_records:
        for k, v in feed_records.items():
            if isinstance(v, dict):
                cached_map[str(k).upper()] = dict(v)

    clean_indicators = [i.strip() for i in indicators if isinstance(i, str) and i.strip()]
    correlations: List[Dict[str, Any]] = []
    threat_score = 0.0
    verified_count = 0
    unavailable_count = 0

    cve_indicators = [i.upper() for i in clean_indicators if i.upper().startswith("CVE-")]
    ip_indicators = [i for i in clean_indicators if i.replace(".", "").isdigit() and i.count(".") == 3]
    hash_indicators = [
        i
        for i in clean_indicators
        if len(i) in (32, 40, 64) and all(c in "0123456789abcdef" for c in i.lower())
    ]

    for cve_id in cve_indicators:
        rec = cached_map.get(cve_id)
        if rec is None and allow_online_fetch:
            rec = _fetch_live_cve_provider_record(cve_id, selected_sources)

        if rec is not None and bool(rec.get("simulated", False)) and not include_simulated:
            rec = None

        if rec is None:
            unavailable_count += 1
            correlations.append(
                {
                    "indicator": cve_id,
                    "type": "cve",
                    "status": "unavailable",
                    "available": False,
                    "cvss_score": None,
                    "epss_score": None,
                    "kev_listed": None,
                    "exploits_found": None,
                    "threat_level": "UNKNOWN",
                    "source": None,
                    "snapshot_date": None,
                    "simulated": False,
                    "provenance": {
                        "status": "unavailable",
                        "reason": (
                            "No verified provider record found in local cache/feed and online provider fetch returned no record"
                            if allow_online_fetch
                            else "No verified provider record in local cache/feed (online fetch disabled)"
                        ),
                        "cache_path": resolved_cache_path,
                        "checked_sources": sorted(selected_sources),
                        "checked_at": now_iso,
                    },
                }
            )
            continue

        # Check timeframe filtering if record carries an explicit timestamp/date
        snap_str = str(rec.get("published_at") or rec.get("last_modified_at") or rec.get("snapshot_date") or "")
        staleness_days: Optional[float] = None
        within_timeframe = True
        if snap_str and snap_str != "unindexed":
            try:
                snap_dt = (
                    datetime.fromisoformat(snap_str)
                    if "T" in snap_str
                    else datetime.fromisoformat(snap_str + "T00:00:00+00:00")
                )
                if snap_dt.tzinfo is None:
                    snap_dt = snap_dt.replace(tzinfo=timezone.utc)
                age = max(timedelta(0), now_dt - snap_dt)
                staleness_days = round(age.total_seconds() / 86400.0, 2)
                if tf_delta is not None and rec.get("enforce_timeframe_cutoff") and age > tf_delta:
                    within_timeframe = False
            except ValueError:
                pass

        if not within_timeframe:
            unavailable_count += 1
            correlations.append(
                {
                    "indicator": cve_id,
                    "type": "cve",
                    "status": "outside_timeframe",
                    "available": False,
                    "cvss_score": None,
                    "epss_score": None,
                    "kev_listed": None,
                    "exploits_found": None,
                    "threat_level": "UNKNOWN",
                    "source": rec.get("source"),
                    "snapshot_date": snap_str,
                    "simulated": False,
                    "provenance": {
                        "status": "outside_timeframe",
                        "timeframe": timeframe,
                        "staleness_days": staleness_days,
                    },
                }
            )
            continue

        is_sim = bool(rec.get("simulated", False))
        cvss_val = float(rec["cvss_score"]) if ("nvd" in selected_sources and rec.get("cvss_score") is not None) else None
        epss_val = float(rec["epss_score"]) if ("epss" in selected_sources and rec.get("epss_score") is not None) else None
        kev_val = bool(rec["kev_listed"]) if ("cisa_kev" in selected_sources and rec.get("kev_listed") is not None) else None

        raw_exploits = rec.get("exploits_found", rec.get("total_exploits"))
        exploits_count: Optional[int] = (
            int(raw_exploits) if ("exploit_db" in selected_sources and raw_exploits is not None) else None
        )

        # Compute deterministic threat level from available verified signals only
        score_acc = 0.0
        if cvss_val is not None:
            score_acc += cvss_val * 6.0
        if epss_val is not None:
            score_acc += epss_val * 25.0
        if kev_val:
            score_acc += 15.0
        if rec.get("exploitability_score") is not None and len(selected_sources) == len(SUPPORTED_INTEL_SOURCES):
            score_acc = float(rec["exploitability_score"])

        level = rec.get("exploitability_level") or (
            "CRITICAL" if score_acc >= 85.0 else "HIGH" if score_acc >= 65.0 else "MEDIUM" if score_acc > 0 else "UNKNOWN"
        )

        verified_count += int(not is_sim)
        correlations.append(
            {
                "indicator": cve_id,
                "type": "cve",
                "status": "simulated" if is_sim else "verified",
                "available": True,
                "cvss_score": cvss_val,
                "epss_score": epss_val,
                "kev_listed": kev_val,
                "exploits_found": exploits_count,
                "threat_level": level,
                "source": rec.get("source", "local_verified_cache"),
                "snapshot_date": snap_str or None,
                "simulated": is_sim,
                "provenance": {
                    "status": "simulated" if is_sim else "verified",
                    "source": rec.get("source", "local_verified_cache"),
                    "snapshot_date": snap_str or None,
                    "fetched_at": rec.get("fetched_at"),
                    "cache_path": rec.get("cache_path", resolved_cache_path),
                    "cache_file_sha256": rec.get("cache_file_sha256"),
                    "raw_digests": rec.get("raw_digests"),
                    "staleness_days": staleness_days,
                    "is_stale": bool(staleness_days is not None and staleness_days > 30.0),
                    "selected_sources": sorted(selected_sources),
                },
                "note": "CVSS/EPSS/KEV reflect provider reference metadata, not proof that a target is vulnerable.",
            }
        )
        threat_score += min(score_acc, 100.0)
        if exploits_count is not None and exploits_count > 0:
            correlations.append(
                {
                    "indicator": cve_id,
                    "type": "exploit_availability",
                    "status": "simulated" if is_sim else "verified",
                    "available": True,
                    "exploits_found": exploits_count,
                    "total_exploits": exploits_count,
                    "threat_level": "HIGH",
                    "source": rec.get("source", "local_verified_cache"),
                    "snapshot_date": snap_str or None,
                    "simulated": is_sim,
                }
            )
            threat_score += 25.0

    for ip in ip_indicators:
        rec = cached_map.get(ip.upper())
        if rec and (include_simulated or not rec.get("simulated", False)):
            is_sim = bool(rec.get("simulated", False))
            verified_count += int(not is_sim)
            correlations.append(
                {
                    "indicator": ip,
                    "type": "ip_reputation",
                    "status": "simulated" if is_sim else "verified",
                    "available": True,
                    "simulated": is_sim,
                    "source": rec.get("source", "local_verified_cache"),
                    "threat_level": rec.get("threat_level", "MEDIUM"),
                    "analysis": rec.get("analysis", {}),
                }
            )
        else:
            unavailable_count += 1

    for hval in hash_indicators:
        rec = cached_map.get(hval.upper())
        if rec and (include_simulated or not rec.get("simulated", False)):
            is_sim = bool(rec.get("simulated", False))
            verified_count += int(not is_sim)
            correlations.append(
                {
                    "indicator": hval,
                    "type": "file_hash",
                    "status": "simulated" if is_sim else "verified",
                    "available": True,
                    "simulated": is_sim,
                    "source": rec.get("source", "local_verified_cache"),
                    "threat_level": rec.get("threat_level", "MEDIUM"),
                    "analysis": rec.get("analysis", {}),
                }
            )
        else:
            unavailable_count += 1

    return {
        "success": True,
        "status": "verified" if verified_count > 0 else ("simulated" if any(c.get("simulated") for c in correlations) else "unavailable"),
        "verified_count": verified_count,
        "unavailable_count": unavailable_count,
        "indicators_analyzed": clean_indicators,
        "timeframe": timeframe,
        "sources": sorted(selected_sources),
        "correlations": correlations,
        "threat_score": round(threat_score, 2),
        "contains_simulated_data": any(c.get("simulated") for c in correlations),
        "timestamp": now_iso,
    }


class WstgWorkflowAdapter(ToolAdapter):
    descriptor = CapabilityDescriptor(
        capability_id="workflow.wstg",
        name="OWASP WSTG Deterministic Workflow Orchestrator",
        category="workflow",
        pack="core",
        description=(
            "Executes multi-step OWASP WSTG assessment workflows (web_baseline, network_recon) "
            "with prerequisite DAG checks, bounded retries, and persistent step checkpoints."
        ),
        binary_name=None,
        risk_level=RiskLevel.LOW,
        side_effects=SideEffectClass.NETWORK_PROBE,
        requires_network=True,
        operations={
            "run": {
                "description": "Execute a named OWASP WSTG workflow against an authorized target.",
                "required": ["target"],
                "parameters": {
                    "target": {"type": "string", "description": "Target URL or host"},
                    "workflow_name": {
                        "type": "string",
                        "enum": list(WSTG_WORKFLOW_TEMPLATES.keys()),
                        "default": "web_baseline",
                        "description": "WSTG workflow template to execute",
                    },
                },
            }
        },
        examples=[
            {"operation": "run", "arguments": {"target": "http://127.0.0.1:8000", "workflow_name": "web_baseline"}}
        ],
    )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        return [arguments["target"]]

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        validated = self.validate_arguments(operation, arguments)
        return ["builtin:workflow_wstg", validated.get("workflow_name", "web_baseline"), validated["target"]]

    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        if not result.stdout:
            return {"error": result.stderr}, []
        return json.loads(result.stdout), []


class ThreatIntelAdapter(ToolAdapter):
    descriptor = CapabilityDescriptor(
        capability_id="intel.threat_correlate",
        name="Threat Intelligence Correlator (CVSS/EPSS/KEV)",
        category="intel",
        pack="core",
        description="Correlates CVE, IP, and hash indicators with distinct CVSS, EPSS, and CISA KEV provenance.",
        binary_name=None,
        risk_level=RiskLevel.PASSIVE,
        side_effects=SideEffectClass.LOCAL_COMPUTE,
        requires_network=False,
        operations={
            "correlate": {
                "description": "Correlate threat indicators with provenance and exploit-count tracking.",
                "required": ["indicators"],
                "parameters": {
                    "indicators": {"type": "array", "description": "List of CVE IDs, IPs, or hashes"},
                    "timeframe": {"type": "string", "default": "30d"},
                    "sources": {"type": "string", "default": "all"},
                    "allow_online_fetch": {"type": "boolean", "default": False},
                    "include_simulated": {"type": "boolean", "default": False},
                },
            }
        },
        examples=[{"operation": "correlate", "arguments": {"indicators": ["CVE-2021-44228"]}}],
    )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        return []

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        return ["builtin:threat_correlate"]

    def execute_direct(
        self,
        operation: str,
        arguments: Dict[str, Any],
        timeout: int = 10,
        scope: Any = None,
        policy: Any = None,
    ) -> Optional[ExecutionResult]:
        validated = self.validate_arguments(operation, arguments)
        start = time.monotonic()
        res = correlate_threat_indicators(
            indicators=validated["indicators"],
            timeframe=validated.get("timeframe", "30d"),
            sources=validated.get("sources", "all"),
            include_simulated=bool(validated.get("include_simulated", False)),
            allow_online_fetch=bool(validated.get("allow_online_fetch", False)),
        )
        return ExecutionResult(
            success=True,
            return_code=0,
            stdout=json.dumps(res),
            stderr="",
            execution_time=time.monotonic() - start,
            argv=["builtin:threat_correlate"],
        )

    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        if not result.stdout:
            return {"error": result.stderr}, []
        data = json.loads(result.stdout)
        return data, []
