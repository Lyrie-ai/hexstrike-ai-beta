"""Execution backends and durable, transport-independent process sessions.

Isolated backends expose only their writable workspace and never fall back to
host execution. The explicit host backend uses the service account's permissions.
"""
from __future__ import annotations


import hashlib
import errno
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import tempfile
import time
import uuid

import psutil

from hexstrike.persistence import database_connection
from hexstrike.evidence.store import StateStore
from hexstrike.domain.models import Evidence, ScopePolicy, new_id
from hexstrike.policy.engine import PolicyEngine
from hexstrike.execution.runner import build_minimal_env, get_process_create_time, is_pid_alive
from hexstrike.workspace.confined_fs import ConfinedWorkspace, redact_secrets

TERMINAL = {"completed", "failed", "cancelled", "timed_out", "interrupted"}
HANDLE = re.compile(r"^[a-f0-9]{32}$")
MAX_OUTPUT = 512 * 1024


def atomic_json(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def command_json(argv, timeout=15):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise ValueError(redact_secrets(result.stderr[:1000]) or "Backend command failed")
    return json.loads(result.stdout)


class ContainerBackend:
    def __init__(self, name):
        self.name = name
        self.executable = shutil.which(name)
        if not self.executable:
            raise ValueError(f"{name} is not installed; install/configure a backend before execution")

    def identity(self, image):
        if not image or image.startswith("-"):
            raise ValueError("A locally installed container image is required")
        info = command_json([self.executable, "info", "--format", "json" if self.name == "podman" else "{{json .}}"])
        rootless = (bool(info.get("host", {}).get("security", {}).get("rootless")) if self.name == "podman"
                    else any("rootless" in item for item in info.get("SecurityOptions", [])))
        if self.name == "docker" and not all(info.get(key) for key in ("MemoryLimit", "PidsLimit", "CpuCfsQuota")):
            raise ValueError("Docker engine does not support the required memory, process and CPU limits")
        if self.name == "podman" and rootless:
            controllers = set(info.get("host", {}).get("cgroupControllers", []))
            if not {"cpu", "memory", "pids"}.issubset(controllers):
                raise ValueError("Rootless Podman requires delegated cpu, memory and pids cgroup controllers")
        data = command_json([self.executable, "image", "inspect", image])[0]
        if data.get("Os", "linux") != "linux":
            raise ValueError("The execution image must be a Linux container image")
        return {"backend": self.name, "image": data["Id"], "architecture": data.get("Architecture"),
                "requested_image": image, "rootless": rootless, "reproducible_rootfs": True, "limits": "container cgroup memory, CPU and process limits"}

    def argv(self, config, work, session_id):
        limits = config["limits"]
        user = f"{os.getuid() if hasattr(os, 'getuid') else 1000}:{os.getgid() if hasattr(os, 'getgid') else 1000}"
        user_namespace = []
        if config["identity"].get("rootless"):
            if self.name == "podman":
                user_namespace = ["--userns=keep-id"]
            else:
                user = "0:0"  # Root in a rootless daemon maps to the unprivileged host owner.
        return [self.executable, "run", "--rm", "--pull=never", "--name", "hexstrike-" + session_id,
                "--label", "io.hexstrike.session=" + session_id, "--interactive",
                "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--network", "none" if config["network"] == "none" else "bridge",
                "--memory", str(limits["memory_mb"]) + "m", "--memory-swap", str(limits["memory_mb"]) + "m",
                "--ulimit", f"fsize={limits['file_mb'] * 1024 * 1024}:{limits['file_mb'] * 1024 * 1024}",
                "--pids-limit", str(limits["processes"]), "--cpus", str(limits["cpus"]),
                "--user", user, *user_namespace,
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                "--mount", f"type=bind,source={work},target=/work",
                "--workdir", "/work/" + config["cwd"], "--env", "HOME=/work",
                "--env", "PYTHONUNBUFFERED=1", "--env", "NO_COLOR=1",
                "--entrypoint", config["argv"][0], config["identity"]["image"], *config["argv"][1:]]

    def stop(self, session_id):
        # Names are generated internally. A failed stop is never silently successful.
        result = subprocess.run([self.executable, "rm", "--force", "hexstrike-" + session_id],
                                capture_output=True, text=True, timeout=15)
        if result.returncode and "No such" not in result.stderr and "does not exist" not in result.stderr:
            raise RuntimeError(result.stderr[:1000])


class BubblewrapBackend:
    name = "bubblewrap"

    def __init__(self):
        self.executable = shutil.which("bwrap")
        self.prlimit = shutil.which("prlimit")
        if sys.platform != "linux" or not self.executable or not self.prlimit:
            raise ValueError("Bubblewrap requires Linux with bwrap and prlimit; use Docker or Podman on other hosts")

    def base(self):
        args = [self.executable, "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL"]
        # Expose system software, never the host root, home, runtime sockets or state.
        for name in ("usr", "bin", "sbin", "lib", "lib64"):
            path = Path("/" + name)
            if path.is_symlink():
                args += ["--symlink", os.readlink(path), str(path)]
            elif path.is_dir():
                args += ["--ro-bind", str(path), str(path)]
        return args + ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--clearenv",
                       "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin", "--setenv", "HOME", "/work",
                       "--setenv", "PYTHONUNBUFFERED", "1", "--setenv", "NO_COLOR", "1"]

    def identity(self, image):
        probe = subprocess.run(self.base() + ["/usr/bin/true"], capture_output=True, text=True, timeout=10)
        if probe.returncode:
            raise ValueError("Bubblewrap isolation probe failed: " + probe.stderr[:500])
        version = subprocess.run([self.executable, "--version"], capture_output=True, text=True, timeout=5).stdout.strip()
        return {"backend": self.name, "version": version, "image": None, "reproducible_rootfs": False,
                "limits": "per-process address space, CPU time, file size and additional per-user process allowance; not aggregate cgroups or a CPU-rate quota"}

    def argv(self, config, work, session_id):
        if config["network"] != "none":
            raise ValueError("Bubblewrap backend supports isolated networking only; use a container backend for outbound networking")
        limits = config["limits"]
        # RLIMIT_NPROC is shared by the host UID, including existing server threads.
        baseline = 0
        for process in psutil.process_iter(["uids", "num_threads"]):
            try:
                if process.info["uids"].real == os.getuid():
                    baseline += process.info["num_threads"] or 1
            except (psutil.Error, AttributeError):
                continue
        return [self.prlimit, f"--as={limits['memory_mb'] * 1024 * 1024}",
                f"--nproc={baseline + limits['processes'] + 4}", f"--cpu={config['timeout']}",
                f"--fsize={limits['file_mb'] * 1024 * 1024}", "--core=0", "--"] + self.base() + [
                    "--bind", str(work), "/work", "--chdir", "/work/" + config["cwd"], "--", *config["argv"]]

    def stop(self, session_id):
        pass  # Killing the namespace supervisor terminates every process in its PID namespace.


class HostBackend:
    """Native execution without filesystem or network namespaces."""

    name = "host"

    def __init__(self):
        self.pid = None
        self.created = None

    def identity(self, image):
        if os.name != "posix":
            raise ValueError("Durable host sessions require a POSIX server")
        return {"backend": "host", "platform": sys.platform, "uid": os.getuid(),
                "sandboxed": False, "network": "host", "reproducible_rootfs": False,
                "limits": "wall-clock timeout and output retention; OS account permissions apply"}

    def argv(self, config, work, session_id):
        return list(config["argv"])

    def stop(self, session_id):
        if self.pid is None:
            return
        actual = get_process_create_time(self.pid)
        if actual is not None and self.created is not None and abs(actual - self.created) > 1:
            return
        # The group may outlive its leader; terminate descendants before closing logs.
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def backend(name):
    if name == "host":
        return HostBackend()
    return BubblewrapBackend() if name == "bubblewrap" else ContainerBackend(name)


class SandboxManager:
    def __init__(self, state_root, engagement_id):
        self.state_root = Path(state_root)
        self.engagement_id = engagement_id
        self.root = self.state_root / "environments" / hashlib.sha256(engagement_id.encode()).hexdigest()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def location(self, handle):
        if not HANDLE.fullmatch(handle):
            raise ValueError("Invalid environment or session handle")
        path = self.root / handle
        if not path.is_dir() or path.is_symlink():
            raise ValueError("Handle not found in this engagement")
        return path

    def create(self, name, image):
        identity = backend(name).identity(image)
        handle = uuid.uuid4().hex
        root = self.root / handle
        root.mkdir(mode=0o700)
        (root / "work").mkdir(mode=0o700)
        atomic_json(root / "environment.json", identity)
        return {"environment_id": handle, **identity}

    def require_backend(self, handle, expected):
        config = json.loads((self.location(handle) / "config.json").read_text())
        choices = (expected,) if isinstance(expected, str) else expected
        if config["identity"]["backend"] not in choices:
            raise ValueError("Session belongs to a different execution backend")

    def start(self, environment_id, args, scope, job_id):
        PolicyEngine.verify_scope_window(scope)
        environment = self.location(environment_id)
        identity = json.loads((environment / "environment.json").read_text())
        work = environment / "work"
        if identity["backend"] == "host":
            cwd = str(Path(args["cwd"]).resolve(strict=True))
            if not Path(cwd).is_dir():
                raise ValueError("Host working directory is not a directory")
        else:
            relative = ConfinedWorkspace(work)._parse_relative_parts(args["cwd"], allow_root=True)
            cwd = "/".join(relative)
            check = ConfinedWorkspace(work).list_files(cwd or ".")
            if not check["success"]:
                raise ValueError("Working directory is missing or unsafe")
        if args["network"] == "outbound":
            # A generic program cannot be made target-aware by inspecting its arguments.
            if not scope.allow_all_targets or scope.allowed_targets or scope.excluded_targets or scope.allowed_ports or scope.allowed_protocols or scope.block_metadata_endpoints:
                raise ValueError("Outbound arbitrary execution needs an unrestricted user-configured network scope; use typed scoped adapters otherwise")
        handle = uuid.uuid4().hex
        config = {"identity": identity, "environment_id": environment_id, "session_id": handle,
                  "engagement_id": self.engagement_id, "job_id": job_id, "state_root": str(self.state_root),
                  "work": str(work), "cwd": cwd, "argv": args["argv"], "network": args["network"],
                  "tty": args.get("tty", False), "env": args.get("env", {}),
                  "columns": args.get("columns", 120), "rows": args.get("rows", 30),
                  "timeout": min(args["timeout"], scope.max_timeout_seconds), "env_refs": args["env_refs"],
                  "limits": {"memory_mb": args["memory_mb"], "processes": args["processes"],
                             "cpus": args["cpus"], "file_mb": args["file_mb"]}}
        # This transaction reserves detached sessions across concurrent MCP processes.
        with database_connection(self.root / "sessions.db", timeout=10) as db:
            db.execute("CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY)")
            db.execute("BEGIN IMMEDIATE")
            active = sum(self.status(row[0])["state"] not in TERMINAL for row in db.execute("SELECT id FROM sessions"))
            if active >= scope.max_concurrency:
                raise ValueError("Engagement detached-session concurrency limit reached")
            session = self.root / handle
            session.mkdir(mode=0o700)
            with database_connection(session / "control.db") as control:
                control.execute("CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, data TEXT)")
                control.execute("CREATE TABLE input_state (closed INTEGER)")
            atomic_json(session / "config.json", config)
            atomic_json(session / "status.json", {"session_id": handle, "environment_id": environment_id,
                        "state": "starting", "created_at": time.time(), "output_truncated": False,
                        "backend": identity["backend"], "tty": config["tty"]})
            bootstrap = "import sys;sys.path.insert(0,sys.argv[1]);from hexstrike.execution.sandbox import supervise;supervise(sys.argv[2])"
            proc = subprocess.Popen([sys.executable, "-I", "-c", bootstrap, str(Path(__file__).resolve().parents[2]), str(session)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    start_new_session=True)
            atomic_json(session / "owner.json", {"pid": proc.pid, "created": get_process_create_time(proc.pid)})
            threading.Thread(target=proc.wait, daemon=True).start()
            db.execute("INSERT INTO sessions VALUES (?)", (handle,))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.status(handle)
            if result["state"] != "starting":
                return result
            time.sleep(0.05)
        return self.status(handle)

    def status(self, handle, offset=0, limit=4000):
        session = self.location(handle)
        result = json.loads((session / "status.json").read_text())
        owner_path = session / "owner.json"
        if result["state"] not in TERMINAL and owner_path.exists():
            owner = json.loads(owner_path.read_text())
            if not is_pid_alive(owner["pid"], owner["created"]):
                config = json.loads((session / "config.json").read_text())
                engine = backend(config["identity"]["backend"])
                if isinstance(engine, HostBackend):
                    engine.pid, engine.created = result.get("pid"), result.get("pid_create_time")
                engine.stop(handle)
                result.update(state="interrupted", error="Session supervisor exited", completed_at=time.time())
                atomic_json(session / "status.json", result)
        for stream in ("stdout", "stderr"):
            path = session / (stream + ".log")
            size = path.stat().st_size if path.exists() else 0
            with path.open("rb") if path.exists() else open(os.devnull, "rb") as output:
                output.seek(offset)
                content = output.read(limit)
            result[stream] = {"content": redact_secrets(content.decode("utf-8", "replace")),
                              "offset": offset, "next_offset": offset + len(content), "total_bytes": size,
                              "has_more": offset + len(content) < size}
        return result

    def control(self, handle, action, data=""):
        session = self.location(handle)
        current = self.status(handle)
        if current["state"] in TERMINAL:
            if action == "cancel":
                return {"session_id": handle, "accepted": True, "already_terminal": True, "state": current["state"]}
            raise ValueError("Session already terminated")
        if action == "resize" and not current.get("tty"):
            raise ValueError("Only PTY sessions can be resized")
        with database_connection(session / "control.db", timeout=5) as db:
            db.execute("CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, data TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS input_state (closed INTEGER)")
            db.execute("BEGIN IMMEDIATE")
            if action in ("stdin", "eof") and db.execute("SELECT closed FROM input_state WHERE closed=1").fetchone():
                raise ValueError("Session input is closed")
            if action == "cancel":
                db.execute("DELETE FROM requests")
            if action != "cancel" and db.execute("SELECT count(*) FROM requests").fetchone()[0] >= 32:
                raise ValueError("Session input queue is full; retry after it drains")
            if action == "eof":
                db.execute("INSERT INTO input_state VALUES (1)")
            request = db.execute("INSERT INTO requests(action,data) VALUES (?,?)", (action, data)).lastrowid
        return {"session_id": handle, "accepted": True, "request_id": request}

    def remove(self, handle):
        environment = self.location(handle)
        for path in self.root.glob("*/config.json"):
            config = json.loads(path.read_text())
            if config["environment_id"] == handle and self.status(path.parent.name)["state"] not in TERMINAL:
                raise ValueError("Cancel active sessions before removing their environment")
        if not (environment / "environment.json").exists():
            raise ValueError("Not an environment handle")
        shutil.rmtree(environment)
        return {"removed": handle}


def supervise(directory):
    """Own a process independently of MCP transports and bound every output stream."""
    os.umask(0o077)
    root = Path(directory)
    config = json.loads((root / "config.json").read_text())
    event_store = StateStore(Path(config["state_root"]) / "hexstrike.db")
    status = json.loads((root / "status.json").read_text())
    engine = backend(config["identity"]["backend"])
    secrets = {}
    if config.get("env_refs"):
        with database_connection(Path(config["state_root"]) / "http_auth.db") as db:
            for name, reference in config["env_refs"].items():
                row = db.execute("SELECT value FROM execution_secrets WHERE name=?", (reference,)).fetchone()
                if not row:
                    atomic_json(root / "status.json", {**status, "state": "failed", "error": "Execution secret reference not found"})
                    return
                secrets[name] = row[0]
    process = None
    container_env_file = None
    output_threads = []
    inputs = queue.Queue(maxsize=32)
    lock = threading.Lock()
    stop = threading.Event()
    def shutdown(*_):
        stop.set()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    def read_stream(pipe, name):
        with (root / (name + ".log")).open("wb") as output:
            size = 0
            pending = b""
            secret_bytes = [value.encode() for value in secrets.values() if value]
            keep = max([len(value) for value in secret_bytes] + [1])
            last_preview = 0.0
            while True:
                try:
                    chunk = pipe.read1(4096)
                except OSError as exc:
                    if config.get("tty") and exc.errno == errno.EIO:
                        chunk = b""
                    else:
                        raise
                pending += chunk
                cut = len(pending) if not chunk else max(0, len(pending) - keep)
                for value in secret_bytes:
                    found = pending.find(value)
                    if 0 <= found < cut < found + len(value):
                        cut = found
                data, pending = pending[:cut], pending[cut:]
                for value in secret_bytes:
                    data = data.replace(value, b"[REDACTED_SECRET]")
                remaining = max(0, MAX_OUTPUT - size)
                output.write(data[:remaining])
                output.flush()
                if data and remaining and time.monotonic() - last_preview >= .25:
                    last_preview = time.monotonic()
                    event_store.append_event(config["engagement_id"], "session_" + name,
                        f"[{config['session_id']}] {redact_secrets(data[:300].decode('utf-8', 'replace'))}",
                        job_id=config["job_id"], payload={"session_id": config["session_id"]})
                size += min(len(data), remaining)
                if len(data) > remaining:
                    with lock:
                        status["output_truncated"] = True
                if not chunk:
                    break
        pipe.close()
    def write_input():
        while True:
            data = inputs.get()
            try:
                if data is None:
                    if config.get("tty"):
                        process.stdin.write(b"\x04")
                        process.stdin.flush()
                    process.stdin.close()
                    return
                process.stdin.write(data.encode())
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                return
    try:
        argv = engine.argv(config, Path(config["work"]), config["session_id"])
        inherited = (build_minimal_env(config.get("env"), host_execution=True)
                     if isinstance(engine, HostBackend) else os.environ.copy())
        options = {}
        if isinstance(engine, HostBackend):
            options["cwd"] = config["cwd"]
        secret_args = None
        if isinstance(engine, HostBackend):
            inherited.update(secrets)
        elif secrets and isinstance(engine, BubblewrapBackend):
            boundary = argv.index(engine.executable)
            inner = argv[boundary + 1:]
            separator = inner.index("--")
            secret_options = [item for name, value in secrets.items() for item in ("--setenv", name, value)]
            secret_args = tempfile.TemporaryFile()
            secret_args.write(b"\0".join(item.encode() for item in secret_options) + b"\0")
            secret_args.seek(0)
            argv = argv[:boundary + 1] + inner[:separator] + ["--args", str(secret_args.fileno())] + inner[separator:]
            options["pass_fds"] = (secret_args.fileno(),)
        elif secrets:
            if any("\n" in value or "\r" in value for value in secrets.values()):
                raise ValueError("Container environment secrets must be single-line values")
            container_env_file = tempfile.NamedTemporaryFile(mode="w", prefix="hexstrike-env-", encoding="utf-8")
            for name, value in secrets.items():
                container_env_file.write(f"{name}={value}\n")
            container_env_file.flush()
            index = argv.index("--entrypoint")
            argv[index:index] = ["--env-file", container_env_file.name]
        try:
            if isinstance(engine, HostBackend) and config.get("tty"):
                import termios
                master, slave = os.openpty()
                bootstrap = "import os,sys,fcntl,termios;fcntl.ioctl(0,termios.TIOCSCTTY,0);os.execvpe(sys.argv[1],sys.argv[1:],os.environ)"
                try:
                    termios.tcsetwinsize(slave, (config["rows"], config["columns"]))
                    process = subprocess.Popen([sys.executable, "-I", "-c", bootstrap, *argv], env=inherited,
                        stdin=slave, stdout=slave, stderr=slave, start_new_session=True, **options)
                    process.stdin = os.fdopen(os.dup(master), "wb", buffering=0)
                    process.stdout = os.fdopen(os.dup(master), "rb")
                    process.stderr = open(os.devnull, "rb")
                finally:
                    os.close(master)
                    os.close(slave)
            else:
                process = subprocess.Popen(argv, env=inherited, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, start_new_session=True, **options)
        finally:
            if secret_args:
                secret_args.close()
        created = get_process_create_time(process.pid)
        if isinstance(engine, HostBackend):
            engine.pid, engine.created = process.pid, created
        status.update(state="running", started_at=time.time(), pid=process.pid, pid_create_time=created)
        for name in ("stdout", "stderr"):
            thread = threading.Thread(target=read_stream, args=(getattr(process, name), name), daemon=True)
            thread.start()
            output_threads.append(thread)
        threading.Thread(target=write_input, daemon=True).start()
        deadline = time.monotonic() + config["timeout"]
        next_policy_check = 0.0
        while process.poll() is None:
            if time.monotonic() >= next_policy_check:
                with database_connection(Path(config["state_root"]) / "hexstrike.db") as db:
                    row = db.execute("SELECT status,scope_json FROM engagements WHERE engagement_id=?", (config["engagement_id"],)).fetchone()
                if not row or row[0] == "revoked":
                    stop.set()
                else:
                    try:
                        PolicyEngine.verify_scope_window(ScopePolicy.from_dict(json.loads(row[1])))
                    except PermissionError:
                        stop.set()
                if row and config["network"] == "outbound":
                    latest = json.loads(row[1])
                    if (not latest["allow_all_targets"] or latest["allowed_targets"] or latest["excluded_targets"]
                            or latest["allowed_ports"] or latest["allowed_protocols"] or latest["block_metadata_endpoints"]):
                        stop.set()
                next_policy_check = time.monotonic() + 0.5
            if (root / "control.db").exists():
                with database_connection(root / "control.db", timeout=5) as db:
                    db.execute("BEGIN IMMEDIATE")
                    for request_id, action, data in db.execute("SELECT id,action,data FROM requests ORDER BY id LIMIT 32").fetchall():
                        if action == "cancel":
                            stop.set()
                        elif action == "resize":
                            import termios
                            dimensions = json.loads(data)
                            termios.tcsetwinsize(process.stdin.fileno(), (dimensions["rows"], dimensions["columns"]))
                        elif not inputs.full():
                            inputs.put_nowait(None if action == "eof" else data)
                        else:
                            break
                        db.execute("DELETE FROM requests WHERE id=?", (request_id,))
            if stop.is_set() or time.monotonic() >= deadline:
                status["state"] = "cancelled" if stop.is_set() else "timed_out"
                engine.stop(config["session_id"])
                process.kill()
                break
            with lock:
                atomic_json(root / "status.json", status)
            time.sleep(0.1)
        process.wait(timeout=10)
        if isinstance(engine, HostBackend):
            engine.stop(config["session_id"])
        for thread in output_threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in output_threads):
            raise RuntimeError("Output streams did not close")
        if status["state"] == "running":
            status["state"] = "completed" if process.returncode == 0 else "failed"
        status["exit_code"] = process.returncode
    except Exception as exc:
        status.update(state="failed", error=redact_secrets(str(exc)))
    finally:
        try:
            engine.stop(config["session_id"])
        except Exception as exc:
            status.update(state="failed", cleanup_error=redact_secrets(str(exc)))
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if process and process.stdin and not process.stdin.closed:
            process.stdin.close()
        if container_env_file:
            container_env_file.close()
        status["evidence_ids"] = []
        try:
            workspace = ConfinedWorkspace(Path(config["state_root"]) / "workspace")
            engagement = event_store.get_engagement(config["engagement_id"])
            for stream in ("stdout", "stderr"):
                log = root / (stream + ".log")
                if not log.exists() or not log.stat().st_size:
                    continue
                content = redact_secrets(log.read_text(errors="replace")).encode()
                if len(content) > engagement.scope.max_artifact_bytes:
                    raise ValueError("Session output exceeds engagement evidence budget")
                saved = workspace.save_artifact(config["engagement_id"], new_id("art_session"), content, extension="log")
                if not saved["success"]:
                    raise ValueError(saved.get("error", "Session evidence write failed"))
                capability_id = "execution.host" if isinstance(engine, HostBackend) else "execution.sandbox"
                evidence = Evidence(new_id("ev"), config["engagement_id"], config["job_id"], capability_id,
                    "session_" + stream, "Execution session " + stream, saved["path"], hashlib.sha256(content).hexdigest(), len(content),
                    content[:1000].decode("utf-8", "replace"), provenance={"session_id": config["session_id"],
                    "environment_id": config["environment_id"], "backend_identity": config["identity"],
                    "exit_code": status.get("exit_code"), "truncated": status["output_truncated"]})
                event_store.save_evidence(evidence)
                status["evidence_ids"].append(evidence.evidence_id)
        except Exception as exc:
            status.update(state="failed", evidence_error=redact_secrets(str(exc)))
        status["completed_at"] = time.time()
        atomic_json(root / "status.json", status)
        event_store.append_event(config["engagement_id"], "session_finished",
            f"Session {config['session_id']} {status['state']} (exit {status.get('exit_code')})",
            job_id=config["job_id"], payload={"session_id": config["session_id"], "state": status["state"]})
