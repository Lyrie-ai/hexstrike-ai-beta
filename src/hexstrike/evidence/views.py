"""Artifact-specific views that avoid embedding binary or full network captures."""
import json


def har_page(workspace, evidence, offset, limit, url_contains="", status_code=None, method=None):
    maximum = 16 * 1024 * 1024
    if evidence.kind != "har":
        raise ValueError("HAR view requires a HAR evidence handle")
    if evidence.size_bytes > maximum:
        raise ValueError("HAR exceeds query budget; retrieve the paginated raw artifact")
    read = workspace.read_file(evidence.artifact_id, max_bytes=maximum, compute_full_sha256=True)
    if not read["success"] or read["sha256"] != evidence.sha256 or read["total_bytes"] != evidence.size_bytes:
        raise ValueError("HAR artifact is missing or corrupted")
    entries = json.loads(read["content"]).get("log", {}).get("entries", [])
    selected = []
    for index, entry in enumerate(entries):
        request, response = entry.get("request", {}), entry.get("response", {})
        if url_contains not in request.get("url", ""):
            continue
        if status_code is not None and response.get("status") != status_code:
            continue
        if method and request.get("method", "").upper() != method.upper():
            continue
        selected.append({"index": index, "url": request.get("url"), "method": request.get("method"),
                         "status": response.get("status"), "time_ms": entry.get("time"),
                         "mime_type": response.get("content", {}).get("mimeType"),
                         "body_size": response.get("bodySize")})
    offset, limit = max(0, offset), max(1, min(limit, 100))
    end = offset + limit
    return {"success": True, "evidence_id": evidence.evidence_id, "view": "har", "entries": selected[offset:end],
            "total_matches": len(selected), "next_offset": end if end < len(selected) else None,
            "integrity_verified": True}


def compare_http_jobs(store, engagement_id, left_id, right_id):
    left, right = store.get_job(left_id), store.get_job(right_id)
    if not left or not right or any(job.engagement_id != engagement_id for job in (left, right)):
        raise ValueError("Both job handles must belong to this engagement")
    if any(job.capability_id != "web.http_inspect" or job.state.value != "completed" for job in (left, right)):
        raise ValueError("Comparison requires two completed HTTP inspection jobs")
    a, b = left.structured_output, right.structured_output
    headers_a = {key.lower(): value for key, value in a.get("headers", {}).items()}
    headers_b = {key.lower(): value for key, value in b.get("headers", {}).items()}
    return {"left_job_id": left_id, "right_job_id": right_id,
            "status": {"before": a.get("status_code"), "after": b.get("status_code")},
            "header_changes": {key: {"before": headers_a.get(key), "after": headers_b.get(key)}
                               for key in sorted(headers_a.keys() | headers_b.keys()) if headers_a.get(key) != headers_b.get(key)},
            "body_changed": a.get("body_sha256") != b.get("body_sha256"),
            "body_comparison_partial": bool(a.get("body_truncated") or b.get("body_truncated")),
            "tls_changed": a.get("tls") != b.get("tls"),
            "authentication_values_compared": False}
