"""Host commands and isolated sessions exposed through the capability/job API."""
import json
import os
from pathlib import Path
import shutil
import sys
import time

from hexstrike.adapters.management import ManagementAdapter, operation
from hexstrike.adapters.catalog import ToolAdapter
from hexstrike.domain.models import CapabilityDescriptor, RiskLevel, SideEffectClass
from hexstrike.execution.runner import ExecutionResult
from hexstrike.execution.sandbox import SandboxManager
from hexstrike.policy.engine import PolicyViolationError
from hexstrike.workspace.confined_fs import ConfinedWorkspace


class HostExecutionAdapter(ToolAdapter):
    """Explicit operator execution with the connected server account's permissions."""

    operator_only = True
    local_only = True

    def __init__(self, state_root, workspace):
        self.state_root = Path(state_root)
        self.workspace = Path(workspace)
        self.descriptor = CapabilityDescriptor(
            capability_id="execution.host", name="Host command execution", category="execution",
            supported_platforms=["linux", "darwin"],
            pack="core", binary_name=None, requires_network=False, risk_level=RiskLevel.CRITICAL,
            side_effects=SideEffectClass.MUTATING_TEST,
            description=("Run installed CLIs, scripts or an explicit shell directly on the connected server. "
                         "Uses the server account's filesystem and network permissions, without a sandbox "
                         "or target filtering. Does not elevate privileges. Output, timeout and cancellation "
                         "use the normal job lifecycle. Use execution.sandbox when isolation is wanted."),
            operations={"run": operation("Execute argv; use wait=false for long jobs and job_status/job_cancel", {
                "argv": {"type": "array", "minItems": 1, "maxItems": 256,
                         "items": {"type": "string", "maxLength": 65536, "pattern": "^[^\\u0000]*$"}},
                "cwd": {"type": "string", "minLength": 1, "default": str(self.workspace),
                        "description": "Host directory; relative paths are resolved from the server workspace"},
                "env": {"type": "object", "default": {}, "maxProperties": 64,
                        "propertyNames": {"pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
                        "additionalProperties": {"type": "string", "maxLength": 65536, "pattern": "^[^\\u0000]*$"}},
                "stdin": {"type": "string", "minLength": 0, "maxLength": 1048576,
                          "description": "Optional input sent once, followed by EOF"},
            }, ["argv"])})
        command = self.descriptor.operations["run"]["parameters"]
        handle = {"type": "string", "pattern": "^[a-f0-9]{32}$"}
        session = {"session_id": handle}
        self.descriptor.operations.update({
            "start": operation("Start a durable host process; tty=true enables interactive shells and REPLs", {
                **{key: value for key, value in command.items() if key != "stdin"},
                "tty": {"type": "boolean", "default": False},
                "columns": {"type": "integer", "minimum": 20, "maximum": 500, "default": 120},
                "rows": {"type": "integer", "minimum": 5, "maximum": 200, "default": 30},
                "timeout": {"type": "integer", "minimum": 1, "maximum": 86400, "default": 1800},
            }, ["argv"]),
            "status": operation("Read process state and bounded output; PTY output combines stdout and stderr", {
                **session, "offset": {"type": "integer", "minimum": 0, "default": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 32768, "default": 4000}}, ["session_id"]),
            "stdin": operation("Send input or terminal control characters to a running host session", {
                **session, "data": {"type": "string", "minLength": 0, "maxLength": 65536}}, ["session_id", "data"]),
            "eof": operation("Close pipe input, or send terminal EOF for a PTY", session, ["session_id"]),
            "cancel": operation("Terminate the host session process group", session, ["session_id"]),
            "resize": operation("Resize an active PTY", {**session,
                "columns": {"type": "integer", "minimum": 20, "maximum": 500},
                "rows": {"type": "integer", "minimum": 5, "maximum": 200}}, ["session_id", "columns", "rows"]),
        })

    def validate_arguments(self, operation, arguments):
        args = super().validate_arguments(operation, arguments)
        if operation not in ("run", "start"):
            return args
        directory = Path(args["cwd"])
        if not directory.is_absolute():
            directory = self.workspace / directory
        try:
            args["cwd"] = str(directory.resolve(strict=True))
            if not directory.is_dir():
                raise ValueError("Host working directory is not a directory")
        except (OSError, ValueError) as exc:
            raise PolicyViolationError("Host working directory is unavailable or is not a directory", code="INVALID_CWD") from exc
        if not args["argv"][0]:
            raise PolicyViolationError("Executable name must not be empty", code="INVALID_ARGUMENT")
        return args

    def extract_targets(self, operation, arguments):
        # Arbitrary programs cannot be target-constrained by parsing their arguments.
        return []

    def build_argv(self, operation, arguments, binary_path=None):
        args = self.validate_arguments(operation, arguments)
        if operation not in ("run", "start"):
            return ["builtin", "execution.host", operation]
        argv = list(args["argv"])
        if not os.path.isabs(argv[0]) and os.path.dirname(argv[0]):
            argv[0] = str(Path(args["cwd"]) / argv[0])
        else:
            path = args["env"].get("PATH", os.environ.get("PATH", os.defpath))
            search_path = os.pathsep.join(
                entry if os.path.isabs(entry) else str(Path(args["cwd"]) / entry)
                for entry in path.split(os.pathsep)
            )
            argv[0] = shutil.which(argv[0], path=search_path) or argv[0]
        return argv

    def parse_output(self, operation, arguments, result, engagement_id, job_id):
        if operation != "run":
            return json.loads(result.stdout) if result.stdout else {}, []
        return {"execution_mode": "host", "sandboxed": False, "network": "host",
                "cwd": arguments["cwd"], "argv": result.argv, "exit_code": result.return_code,
                "stdout_preview": result.stdout[:2000], "stderr_preview": result.stderr[:2000],
                "timed_out": result.timed_out, "cancelled": result.cancelled,
                "output_truncated": result.truncated}, []

    def execute_context(self, operation, args, engagement_id, job_id, scope):
        started = time.monotonic()
        try:
            manager = SandboxManager(self.state_root, engagement_id)
            if operation == "start":
                environment = manager.create("host", "")
                options = {**args, "argv": self.build_argv(operation, args), "network": "host", "env_refs": {},
                           "memory_mb": 0, "processes": 0, "cpus": 0, "file_mb": 0}
                output = manager.start(environment["environment_id"], options, scope, job_id)
            else:
                manager.require_backend(args["session_id"], "host")
                if operation == "status":
                    output = manager.status(args["session_id"], args["offset"], args["limit"])
                else:
                    data = json.dumps({key: args[key] for key in ("columns", "rows")}) if operation == "resize" else args.get("data", "")
                    output = manager.control(args["session_id"], operation, data)
            success = output.get("state") not in ("failed", "interrupted")
        except (ValueError, OSError, RuntimeError) as exc:
            output, success = {"error": str(exc)}, False
        return ExecutionResult(success, 0 if success else 1, json.dumps(output),
                               "" if success else output.get("error", "Host session failed"), time.monotonic() - started)


class ExecutionSessionAdapter(ManagementAdapter):
    operator_only = True

    def __init__(self, state_root):
        self.state_root = state_root
        handle = {"type": "string", "pattern": "^[a-f0-9]{32}$"}
        environment = {"environment_id": handle}
        session = {"session_id": handle}
        page = {"offset": {"type": "integer", "minimum": 0, "default": 0},
                "limit": {"type": "integer", "minimum": 1, "maximum": 32768, "default": 4000}}
        self.descriptor = CapabilityDescriptor(
            capability_id="execution.sandbox", name="Isolated execution environments", category="execution",
            pack="core", binary_name=None, requires_network=False, risk_level=RiskLevel.CRITICAL,
            side_effects=SideEffectClass.WORKSPACE_IO,
            description="Run programs in Docker/Podman containers or Linux Bubblewrap. Durable sessions support stdin, bounded output, cancellation and reconnect. Never falls back to host execution.",
            operations={
                "backends": operation("Discover installed isolation backends; create performs the readiness check", {}),
                "create": operation("Create an environment from a locally installed image or Linux system software", {
                    "backend": {"type": "string", "enum": ["docker", "podman", "bubblewrap"], "default": "docker"},
                    "image": {"type": "string", "default": "", "maxLength": 256}}, []),
                "start": operation("Start a detached program; use python3 or /bin/sh with a script written by file_write", {
                    **environment,
                    "argv": {"type": "array", "minItems": 1, "maxItems": 256,
                             "items": {"type": "string", "maxLength": 65536, "pattern": "^[^\\u0000]*$"}},
                    "cwd": {"type": "string", "default": "."},
                    "env_refs": {"type": "object", "default": {}, "maxProperties": 32,
                                 "propertyNames": {"pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
                                 "additionalProperties": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,80}$"}},
                    "network": {"type": "string", "enum": ["none", "outbound"], "default": "none"},
                    "timeout": {"type": "integer", "minimum": 1, "maximum": 86400, "default": 300},
                    "memory_mb": {"type": "integer", "minimum": 64, "maximum": 16384, "default": 512},
                    "processes": {"type": "integer", "minimum": 4, "maximum": 512, "default": 64},
                    "cpus": {"type": "integer", "minimum": 1, "maximum": 64, "default": 1},
                    "file_mb": {"type": "integer", "minimum": 1, "maximum": 1024, "default": 100},
                }, ["environment_id", "argv"]),
                "status": operation("Read session state and independently paginated stdout/stderr", {**session, **page}, ["session_id"]),
                "stdin": operation("Queue text for a running process; include a newline when the program expects one", {
                    **session, "data": {"type": "string", "minLength": 0, "maxLength": 65536}}, ["session_id", "data"]),
                "eof": operation("Close process input after queued writes", session, ["session_id"]),
                "cancel": operation("Terminate the container or PID namespace including descendants", session, ["session_id"]),
                "file_write": operation("Write a UTF-8 file in the isolated environment", {**environment,
                    "path": {"type": "string"}, "content": {"type": "string", "minLength": 0, "maxLength": 1048576}}, ["environment_id", "path", "content"]),
                "file_read": operation("Read an environment file without escaping its workspace", {**environment,
                    "path": {"type": "string"}, **page}, ["environment_id", "path"]),
                "remove": operation("Remove an idle environment and its files", environment, ["environment_id"]),
            })

    def execute_context(self, operation, args, engagement_id, job_id, scope):
        start = time.monotonic()
        try:
            manager = SandboxManager(self.state_root, engagement_id)
            if "environment_id" in args:
                identity = json.loads((manager.location(args["environment_id"]) / "environment.json").read_text())
                if identity["backend"] == "host":
                    raise ValueError("Host environments must be controlled through execution.host")
            if "session_id" in args:
                manager.require_backend(args["session_id"], ("docker", "podman", "bubblewrap"))
            if operation == "backends":
                output = {"platform": sys.platform, "backends": [{"name": name, "installed": bool(shutil.which(executable)),
                    "ready": "unverified until create"} for name, executable in (("docker", "docker"), ("podman", "podman"), ("bubblewrap", "bwrap"))]}
            elif operation == "create":
                output = manager.create(args["backend"], args["image"])
            elif operation == "start":
                output = manager.start(args["environment_id"], args, scope, job_id)
            elif operation == "status":
                output = manager.status(args["session_id"], args["offset"], args["limit"])
            elif operation in ("stdin", "eof", "cancel"):
                output = manager.control(args["session_id"], operation, args.get("data", ""))
            elif operation == "remove":
                output = manager.remove(args["environment_id"])
            else:
                workspace = ConfinedWorkspace(manager.location(args["environment_id"]) / "work", max_file_size=scope.max_artifact_bytes)
                if operation == "file_write":
                    output = workspace.create_file(args["path"], args["content"])
                else:
                    output = workspace.read_file(args["path"], offset=args["offset"], max_bytes=args["limit"], compute_full_sha256=False)
            success = output.get("success", True) and output.get("state") not in ("failed", "interrupted")
        except (ValueError, OSError, RuntimeError) as exc:
            output, success = {"error": str(exc)}, False
        return ExecutionResult(success, 0 if success else 1, json.dumps(output),
                               "" if success else output.get("error", "Session failed"), time.monotonic() - start)
