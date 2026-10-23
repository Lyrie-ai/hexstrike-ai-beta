"""Local workspace and installed-tool management through the job lifecycle."""

from __future__ import annotations

import base64
import json
import time

from hexstrike.adapters.catalog import ToolAdapter, CustomAdapterManifest
from hexstrike.domain.models import CapabilityDescriptor, RiskLevel, SideEffectClass
from hexstrike.execution.runner import ExecutionResult
from hexstrike.policy.engine import PolicyViolationError


def operation(description, parameters, required=()):
    return {
        "description": description,
        "parameters": parameters,
        "required": list(required),
    }


class ManagementAdapter(ToolAdapter):
    local_only = True

    def extract_targets(self, operation, arguments):
        return []

    def build_argv(self, operation, arguments, binary_path=None):
        self.validate_arguments(operation, arguments)
        return ["builtin", self.descriptor.capability_id, operation]

    def parse_output(self, operation, arguments, result, engagement_id, job_id):
        return json.loads(result.stdout) if result.stdout else {}, []

    def execute_direct(self, operation, arguments, timeout=60, scope=None, policy=None):
        start = time.monotonic()
        try:
            output = self.perform(operation, arguments, scope)
        except (ValueError, OSError, PolicyViolationError) as exc:
            output = {"success": False, "error": str(exc)}
        success = output.get("success", True)
        return ExecutionResult(
            success,
            0 if success else 1,
            json.dumps(output),
            "" if success else output.get("error", "Operation failed"),
            time.monotonic() - start,
        )


class WorkspaceAdapter(ManagementAdapter):
    operator_only = True

    def __init__(self, workspace):
        self.workspace = workspace
        path = {"type": "string", "description": "Workspace-relative path"}
        page = {
            "offset": {"type": "integer", "default": 0, "minimum": 0},
            "limit": {"type": "integer", "default": 100, "minimum": 1, "maximum": 1000},
        }
        self.descriptor = CapabilityDescriptor(
            capability_id="workspace.files",
            name="Workspace files",
            category="workspace",
            pack="core",
            description="Create, read, list, and update workspace files; binary content uses base64.",
            binary_name=None,
            requires_network=False,
            risk_level=RiskLevel.LOW,
            side_effects=SideEffectClass.WORKSPACE_IO,
            operations={
                "create": operation(
                    "Create a new file without overwriting",
                    {
                        "path": path,
                        "content": {"type": "string", "minLength": 0},
                        "encoding": {
                            "type": "string",
                            "enum": ["utf8", "base64"],
                            "default": "utf8",
                        },
                    },
                    ["path", "content"],
                ),
                "update": operation(
                    "Replace an existing file",
                    {"path": path, "content": {"type": "string", "minLength": 0}},
                    ["path", "content"],
                ),
                "read": operation(
                    "Read a bounded text chunk", {"path": path, **page}, ["path"]
                ),
                "patch": operation("Replace an exact text occurrence with a digest precondition", {
                    "path": path, "old_text": {"type": "string", "minLength": 1},
                    "new_text": {"type": "string", "minLength": 0},
                    "expected_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}},
                    ["path", "old_text", "new_text", "expected_sha256"]),
                "search": operation("Search literal text in a bounded file", {
                    "path": path, "query": {"type": "string", "minLength": 1}, **page}, ["path", "query"]),
                "list": operation(
                    "List a directory with pagination",
                    {"path": {**path, "default": "."}, **page},
                ),
            },
        )

    def perform(self, operation, args, scope):
        if self.workspace is None:
            raise ValueError("Workspace is not attached")
        if operation in ("create", "update"):
            content = (
                base64.b64decode(args["content"], validate=True)
                if args.get("encoding") == "base64"
                else args["content"].encode()
            )
            if len(content) > min(
                self.workspace.max_file_size,
                scope.max_artifact_bytes if scope else self.workspace.max_file_size,
            ):
                raise ValueError("Content exceeds workspace or engagement file budget")
            if operation == "create":
                return self.workspace.create_file(args["path"], content, exclusive=True)
            return self.workspace.modify_file(args["path"], content)
        if operation in ("patch", "search"):
            maximum = min(5 * 1024 * 1024, scope.max_artifact_bytes if scope else self.workspace.max_file_size)
            read = self.workspace.read_file(args["path"], binary=True, max_bytes=maximum + 1)
            if not read["success"]:
                return read
            if read["has_more"] or len(read["raw_bytes"]) > maximum:
                raise ValueError("File exceeds patch/search budget")
            content = read["raw_bytes"].decode("utf-8")
            if operation == "patch":
                if read["sha256"] != args["expected_sha256"]:
                    raise ValueError("File digest changed; patch was not applied")
                if content.count(args["old_text"]) != 1:
                    raise ValueError("Patch requires exactly one matching occurrence")
                changed = content.replace(args["old_text"], args["new_text"], 1)
                if len(changed.encode()) > maximum:
                    raise ValueError("Patched file exceeds budget")
                return self.workspace.modify_file(args["path"], changed, expected_sha256=args["expected_sha256"])
            matches = [{"line": index, "text": line[:500]} for index, line in enumerate(content.splitlines(), 1) if args["query"] in line]
            end = args["offset"] + args["limit"]
            return {"matches": matches[args["offset"]:end], "total": len(matches), "next_offset": end if end < len(matches) else None}
        if operation == "read":
            return self.workspace.read_file(
                args["path"],
                offset=args["offset"],
                max_bytes=args["limit"],
                compute_full_sha256=False,
            )
        result = self.workspace.list_files(args["path"])
        if result["success"]:
            entries = result["files"]
            end = args["offset"] + args["limit"]
            result.update(
                files=entries[args["offset"] : end],
                total=len(entries),
                next_offset=end if end < len(entries) else None,
            )
        return result


class ToolInventoryAdapter(ManagementAdapter):
    def __init__(self, registry):
        self.registry = registry
        self.descriptor = CapabilityDescriptor(
            capability_id="tools.inventory",
            name="Installed tool inventory",
            category="system",
            pack="core",
            description="Discover installed executables on PATH, including those without adapters. Run any executable through execution.host; typed adapters provide optional parameter and result handling.",
            binary_name=None,
            requires_network=False,
            risk_level=RiskLevel.PASSIVE,
            side_effects=SideEffectClass.READ_ONLY,
            operations={
                "run": operation(
                    "Search installed executables",
                    {
                        "query": {"type": "string", "default": ""},
                        "offset": {"type": "integer", "default": 0, "minimum": 0},
                        "limit": {
                            "type": "integer",
                            "default": 25,
                            "minimum": 1,
                            "maximum": 100,
                        },
                    },
                )
            },
        )

    def perform(self, operation, args, scope):
        return self.registry.discover_installed(**args)


class CustomToolAdapter(ManagementAdapter):
    operator_only = True

    def __init__(self, registry):
        self.registry = registry
        self.descriptor = CapabilityDescriptor(
            capability_id="tools.adapters",
            name="Custom adapter management",
            category="system",
            pack="core",
            description="Install or remove operator-trusted custom command adapters. Custom programs run with the server account permissions; they are not sandboxed.",
            binary_name=None,
            requires_network=False,
            risk_level=RiskLevel.CRITICAL,
            side_effects=SideEffectClass.WORKSPACE_IO,
            operations={
                "install": operation(
                    "Install a trusted declarative adapter",
                    {
                        "manifest": {
                            "type": "string",
                            "description": "JSON custom adapter manifest",
                        }
                    },
                    ["manifest"],
                ),
                "remove": operation(
                    "Remove a custom adapter",
                    {"capability_id": {"type": "string"}},
                    ["capability_id"],
                ),
            },
        )

    def perform(self, operation, args, scope):
        if operation == "install":
            manifest = CustomAdapterManifest.from_dict(json.loads(args["manifest"]))
            adapter = self.registry.register_custom_adapter(manifest)
            return {"success": True, "capability_id": adapter.descriptor.capability_id}
        success = self.registry.remove_custom_capability(args["capability_id"])
        return {
            "success": success,
            "capability_id": args["capability_id"],
            **({} if success else {"error": "Custom adapter not found"}),
        }


class EvidenceComparisonAdapter(ManagementAdapter):
    def __init__(self, store):
        self.store = store
        self.descriptor = CapabilityDescriptor(
            capability_id="evidence.compare", name="HTTP response comparison", category="evidence", pack="core",
            description="Compare status, redacted headers, captured body hashes and TLS metadata between two HTTP jobs.",
            binary_name=None, requires_network=False, risk_level=RiskLevel.PASSIVE, side_effects=SideEffectClass.READ_ONLY,
            operations={"run": operation("Compare two completed HTTP jobs in this engagement", {
                "left_job_id": {"type": "string"}, "right_job_id": {"type": "string"}}, ["left_job_id", "right_job_id"])})

    def execute_context(self, operation, args, engagement_id, job_id, scope):
        from hexstrike.evidence.views import compare_http_jobs
        start = time.monotonic()
        try:
            output = compare_http_jobs(self.store, engagement_id, args["left_job_id"], args["right_job_id"])
            return ExecutionResult(True, 0, json.dumps(output), "", time.monotonic() - start)
        except ValueError as exc:
            return ExecutionResult(False, 1, "", str(exc), time.monotonic() - start)
