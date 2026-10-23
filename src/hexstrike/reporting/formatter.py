"""
Evidence-linked reporting and ANSI/OSC terminal output sanitization.
"""

from __future__ import annotations

import html
import re
from typing import Any, Dict, List

from hexstrike.domain.models import Engagement, Evidence, Finding, FindingState, Job
from hexstrike.workspace.confined_fs import redact_secrets


# Strips CSI, OSC, DCS, APC, PM, SOS, and non-printable control bytes from untrusted tool output
ANSI_OSC_ESCAPE_RE = re.compile(
    r"(?:\x1b\][^\x07\x1b]*(?:\x07|\x1b\\))|"
    r"(?:\x1b[P^_X][^\x1b]*\x1b\\)|"
    r"(?:\x1b\[[0-?]*[ -/]*[@-~])|"
    r"(?:\x1b[@-_])|"
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)


def sanitize_terminal_text(untrusted_text: str) -> str:
    """
    Sanitize untrusted scanner/target output before rendering in a terminal or TUI
    to prevent ANSI/OSC escape injection and Rich/Textual markup spoofing.
    """
    if not untrusted_text:
        return ""
    stripped = ANSI_OSC_ESCAPE_RE.sub("", untrusted_text)
    redacted = redact_secrets(stripped)
    return redacted.replace("[", "\\[")


def build_engagement_report(
    engagement: Engagement,
    findings: List[Finding],
    jobs: List[Job],
    evidence_list: List[Evidence],
) -> Dict[str, Any]:
    validated = [f for f in findings if f.state in (FindingState.VALIDATED, FindingState.HUMAN_REVIEWED)]
    candidates = [f for f in findings if f.state == FindingState.CANDIDATE]
    observations = [f for f in findings if f.state == FindingState.OBSERVATION]
    rejected = [f for f in findings if f.state == FindingState.REJECTED_FALSE_POSITIVE]

    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.state != FindingState.REJECTED_FALSE_POSITIVE:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    return {
        "engagement": engagement.to_dict(),
        "summary": {
            "total_jobs": len(jobs),
            "total_evidence_artifacts": len(evidence_list),
            "validated_findings_count": len(validated),
            "candidate_findings_count": len(candidates),
            "observations_count": len(observations),
            "rejected_false_positives_count": len(rejected),
            "severity_breakdown": by_severity,
        },
        "validated_findings": [f.to_dict() for f in validated],
        "candidate_findings": [f.to_dict() for f in candidates],
        "observations": [f.to_dict() for f in observations],
    }


def render_html_report(report_data: Dict[str, Any]) -> str:
    eng = report_data.get("engagement", {})
    summary = report_data.get("summary", {})
    rows_html = []
    for section in ("validated_findings", "candidate_findings", "observations"):
        for item in report_data.get(section, []):
            rows_html.append(
                "<tr>"
                f"<td>{html.escape(str(item.get('severity', '')).upper())}</td>"
                f"<td>{html.escape(str(item.get('state', '')))}</td>"
                f"<td>{html.escape(str(item.get('title', '')))}</td>"
                f"<td>{html.escape(str(item.get('target', '')))}</td>"
                f"<td>{html.escape(str(item.get('description', '')))}</td>"
                "</tr>"
            )
    table_body = "\n".join(rows_html) or "<tr><td colspan='5'>No findings recorded.</td></tr>"
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        f"<title>HexStrike Assessment Report - {html.escape(str(eng.get('name', 'Default')))}</title>"
        "</head><body>"
        f"<h1>HexStrike Assessment Report: {html.escape(str(eng.get('name', 'Default')))}</h1>"
        f"<p>Validated: {int(summary.get('validated_findings_count', 0))} | "
        f"Candidates: {int(summary.get('candidate_findings_count', 0))} | "
        f"Observations: {int(summary.get('observations_count', 0))}</p>"
        "<table border='1'><thead><tr><th>Severity</th><th>State</th><th>Title</th><th>Target</th><th>Description</th></tr></thead>"
        f"<tbody>{table_body}</tbody></table></body></html>"
    )
