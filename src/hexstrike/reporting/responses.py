"""Bounded transport views; full results remain in the evidence store."""

import json


def compact_job_response(response, limit=6000):
    result = dict(response)
    def compact(job):
        job = dict(job)
        output = job.get("structured_output", {})
        if len(json.dumps(output, ensure_ascii=False)) > limit:
            job["structured_output"] = {
                "_omitted": True,
                "keys": list(output)[:40] if isinstance(output, dict) else [],
                "retrieve": "Use evidence_read with this job_id for artifact handles and paginated content.",
            }
        job["argv"] = [str(part)[:256] for part in job.get("argv", [])[:32]]
        return job
    if result.get("job"):
        result["job"] = compact(result["job"])
    if "jobs" in result:
        result["jobs"] = [compact(job) for job in result["jobs"]]
    if "events" in result:
        result["events"] = [{**event, "payload": {}, "message": event.get("message", "")[:400]} for event in result["events"]]
    return result
