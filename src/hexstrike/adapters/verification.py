"""Operator-supplied ground-truth suites run through the normal job pipeline."""
import hashlib
import json
import platform
import time
from pathlib import Path

from hexstrike.persistence import database_connection
from hexstrike.adapters.management import ManagementAdapter, operation
from hexstrike.domain.models import CapabilityDescriptor, Principal, RiskLevel, SideEffectClass
from hexstrike.execution.runner import ExecutionResult


def code_digest():
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parents[1]
    for source in sorted(root.rglob("*.py")):
        digest.update(str(source.relative_to(root)).encode())
        digest.update(source.read_bytes())
    return digest.hexdigest()


def verification_identity(adapter, identity):
    return {"schema": adapter.descriptor.schema_digest, "binary": identity.sha256,
            "code": code_digest(), "platform": platform.platform()}


def read_receipt(store, capability_id, identity):
    with database_connection(store.db_path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS verifications (capability_id TEXT PRIMARY KEY, receipt TEXT NOT NULL)")
        row = db.execute("SELECT receipt FROM verifications WHERE capability_id=?", (capability_id,)).fetchone()
    if not row:
        return {"smoke_tested": False, "integration_tested": False, "reason": "No operator verification receipt"}
    receipt = json.loads(row[0])
    if receipt["identity"] != identity:
        return {"smoke_tested": False, "integration_tested": False, "reason": "Code, schema, platform or binary changed since verification"}
    return receipt


def resolve_pointer(document, pointer):
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError("Expected a JSON pointer starting with /")
    for part in pointer[1:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        document = document[int(key)] if isinstance(document, list) else document[key]
    return document


class VerificationAdapter(ManagementAdapter):
    operator_only = True

    def __init__(self):
        self.descriptor = CapabilityDescriptor(
            capability_id="tools.verify", name="Capability verification", category="system", pack="core",
            description="Run explicit positive and negative ground-truth fixtures through real jobs. Receipts are invalidated by code, binary, schema or platform changes.",
            binary_name=None, requires_network=False, risk_level=RiskLevel.CRITICAL, side_effects=SideEffectClass.WORKSPACE_IO,
            operations={"run": operation("Verify a capability using a confined JSON suite file", {
                "capability_id": {"type": "string"}, "suite_file": {"type": "string"}}, ["capability_id", "suite_file"])})

    def execute_runtime(self, runtime, job, plan, scope):
        start = time.monotonic()
        args = plan.arguments
        adapter = runtime.registry.get_adapter(args["capability_id"])
        if not adapter or args["capability_id"] in ("tools.verify", "workflow.wstg"):
            raise ValueError("Choose an individual registered capability")
        raw = runtime.workspace.read_file(args["suite_file"], max_bytes=65537, binary=True)
        if not raw["success"] or raw["has_more"] or len(raw["raw_bytes"]) > 65536:
            raise ValueError("Verification suite is missing, unsafe or too large")
        suite = json.loads(raw["raw_bytes"])
        if not isinstance(suite, list) or not 2 <= len(suite) <= 20:
            raise ValueError("Suite requires 2–20 positive/negative cases")
        for case in suite:
            if not isinstance(case, dict) or set(case) != {"name", "operation", "arguments", "expected", "negative_control"}:
                raise ValueError("Each case requires name, operation, arguments, expected JSON-pointer map, negative_control")
            if not isinstance(case["negative_control"], bool) or not isinstance(case["expected"], dict) or not case["expected"]:
                raise ValueError("Cases require explicit assertions and a boolean negative_control")
        if {case["negative_control"] for case in suite} != {False, True}:
            raise ValueError("Provide both a positive case and a negative control")
        identity = runtime.registry.get_binary_identity(adapter.descriptor.binary_name, probe_version=True)
        result = {"capability_id": args["capability_id"], "identity": verification_identity(adapter, identity),
                  "installed": identity.executable_path is not None, "compatible": identity.status.value, "binary_version": identity.version,
                  "suite_sha256": raw["sha256"], "tested_at": time.time(), "cases": []}
        deadline = start + plan.timeout_seconds
        for case in suite:
            assertions = []
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Verification deadline exceeded")
                output = runtime.job_start(capability_id=args["capability_id"], operation=case["operation"], arguments=case["arguments"],
                    engagement_id=job.engagement_id, parent_job_id=job.job_id, timeout_seconds=remaining,
                    principal=Principal(job.principal_id, job.principal_id, role="operator"))
                for pointer, expected in case["expected"].items():
                    try:
                        actual = resolve_pointer(output, pointer)
                        assertions.append({"pointer": pointer, "passed": actual == expected})
                    except (KeyError, IndexError, ValueError, TypeError):
                        assertions.append({"pointer": pointer, "passed": False, "error": "Result path missing"})
                result["cases"].append({"name": case["name"], "negative_control": case["negative_control"],
                    "job_id": output.get("job", {}).get("job_id"), "execution_succeeded": output.get("success", False),
                    "passed": all(item["passed"] for item in assertions), "assertions": assertions})
            except Exception as exc:
                result["cases"].append({"name": case["name"], "passed": False, "error": str(exc)})
        result["smoke_tested"] = any(item.get("execution_succeeded") for item in result["cases"])
        result["integration_tested"] = all(item["passed"] for item in result["cases"]) and all(item.get("execution_succeeded") for item in result["cases"] if not item.get("negative_control", False))
        with database_connection(runtime.store.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS verifications (capability_id TEXT PRIMARY KEY, receipt TEXT NOT NULL)")
            db.execute("INSERT OR REPLACE INTO verifications VALUES (?,?)", (args["capability_id"], json.dumps(result)))
        passed = result["integration_tested"]
        return ExecutionResult(passed, 0 if passed else 1, json.dumps(result), "" if passed else "Capability fixture assertions failed", time.monotonic() - start)
