"""
Safe subprocess runner and constrained SSH remote worker bridge.

- Enforces `shell=False` with immutable `argv` tuples
- Validates executable path existence and rejects null/control bytes
- Runs processes in dedicated process groups (`start_new_session=True`) for reliable cancellation
- Supports cross-runtime process-group cancellation via persisted OS PID/PGID (`terminate_pid_group`)
- Streams redacted stdout/stderr lines in real time to callbacks / telemetry store
- Supports incremental line-by-line streaming and cancellation on remote Linux workers over SSH
"""

from __future__ import annotations

import base64
import errno
import json
import os
import shlex
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import psutil

from hexstrike.workspace.confined_fs import redact_secrets


SAFE_ENV_KEYS = (
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TERM",
    "TMPDIR",
    "SYSTEMROOT",
)


@dataclass
class ExecutionResult:
    success: bool
    return_code: int
    stdout: str
    stderr: str
    execution_time: float
    timed_out: bool = False
    cancelled: bool = False
    truncated: bool = False
    pid: Optional[int] = None
    worker_target: str = "local"
    argv: List[str] = field(default_factory=list)
    input_files: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "execution_time": self.execution_time,
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "truncated": self.truncated,
            "pid": self.pid,
            "worker_target": self.worker_target,
            "argv": list(self.argv),
            "input_files": self.input_files,
        }


class ExecutionSecurityError(PermissionError):
    """Raised when an execution request violates argv or binary safety rules."""


def build_minimal_env(extra_env: Optional[Dict[str, str]] = None, *, host_execution: bool = False) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for key in SAFE_ENV_KEYS:
        val = os.environ.get(key)
        if val is not None:
            env[key] = val
    default_path = os.defpath
    env["PATH"] = env.get("PATH", default_path)
    env["NO_COLOR"] = "1"
    if host_execution:
        for key in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                    "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"):
            if key in os.environ:
                env[key] = os.environ[key]
    if extra_env:
        for k, v in extra_env.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            if not host_execution and k.upper().startswith(("LD_", "DYLD_", "PYTHONINSPECT", "BASH_ENV", "ENV")):
                raise ExecutionSecurityError(f"Dangerous environment variable override blocked: {k}")
            env[k] = v
    return env


def validate_argv(argv: Sequence[str], require_absolute_binary: bool = False) -> Tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise ExecutionSecurityError("Raw command string is forbidden; pass an immutable argv sequence")
    if not argv:
        raise ExecutionSecurityError("argv cannot be empty")

    cleaned: List[str] = []
    for idx, arg in enumerate(argv):
        if not isinstance(arg, str):
            raise ExecutionSecurityError(f"argv[{idx}] must be a string")
        if "\x00" in arg:
            raise ExecutionSecurityError(f"Null byte forbidden in argv[{idx}]")
        cleaned.append(arg)

    binary = cleaned[0]
    if require_absolute_binary and not os.path.isabs(binary):
        resolved = shutil.which(binary)
        if not resolved:
            raise ExecutionSecurityError(f"Executable not found in trusted PATH: {binary}")
        cleaned[0] = os.path.abspath(resolved)

    return tuple(cleaned)


def get_process_create_time(pid: int) -> Optional[float]:
    if pid <= 0:
        return None
    try:
        return round(float(psutil.Process(pid).create_time()), 3)
    except Exception:
        return None


def is_pid_alive(pid: int, expected_create_time: Optional[float] = None) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        if exc.errno != errno.EPERM:
            return False
    if expected_create_time is not None:
        actual = get_process_create_time(pid)
        if actual is not None and abs(actual - expected_create_time) > 1.0:
            # PID was reused by a newer OS process!
            return False
    return True


def terminate_pid_group(
    pid: int,
    grace_seconds: float = 1.5,
    expected_create_time: Optional[float] = None,
) -> bool:
    """
    Terminate a process group or process by PID across runtime instances and verify
    that the target process (matching `expected_create_time` when recorded) is no longer alive.
    """
    if not is_pid_alive(pid, expected_create_time=expected_create_time):
        return False

    try:
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGTERM)
            except OSError:
                os.kill(pid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
    except OSError:
        pass

    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        if not is_pid_alive(pid, expected_create_time=expected_create_time):
            return True
        time.sleep(0.03)

    try:
        if os.name != "nt":
            try:
                pgid = os.getpgid(pid)
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                os.kill(pid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass

    kill_deadline = time.monotonic() + 0.5
    while time.monotonic() < kill_deadline:
        if not is_pid_alive(pid, expected_create_time=expected_create_time):
            return True
        time.sleep(0.02)

    return not is_pid_alive(pid, expected_create_time=expected_create_time)


class SafeSubprocessRunner:
    """
    Executes commands using `subprocess.Popen(..., shell=False)` with process-group
    management, bounded output buffers, cross-runtime PID registration, and real-time
    output callbacks.
    """

    def __init__(self, max_output_bytes: int = 8 * 1024 * 1024) -> None:
        self.max_output_bytes = max_output_bytes
        self._active_lock = threading.Lock()
        self._active_processes: Dict[str, subprocess.Popen[str]] = {}
        self._cancel_flags: set[str] = set()

    def cancel(
        self,
        job_id: str,
        persisted_pid: Optional[int] = None,
        expected_create_time: Optional[float] = None,
        grace_seconds: float = 1.5,
    ) -> bool:
        with self._active_lock:
            self._cancel_flags.add(job_id)
            proc = self._active_processes.get(job_id)

        if proc is not None and hasattr(proc, "poll") and proc.poll() is None:
            if getattr(proc, "stdin", None) is not None:
                try:
                    proc.stdin.write("cancel\n")
                    proc.stdin.flush()
                    proc.stdin.close()
                except Exception:
                    pass
            self._terminate_process_tree(proc, grace_seconds=grace_seconds)
            return True

        if persisted_pid is not None and persisted_pid > 0:
            return terminate_pid_group(
                persisted_pid,
                grace_seconds=grace_seconds,
                expected_create_time=expected_create_time,
            )

        return False

    def cancel_jobs(
        self,
        job_specs: Sequence[Tuple[str, Optional[int], Optional[float]]],
        grace_seconds: float = 1.5,
    ) -> int:
        """Cancel only the explicitly authorized `(job_id, pid, create_time)` entries."""
        cancelled = 0
        for jid, pid, ctime in job_specs:
            if self.cancel(jid, persisted_pid=pid, expected_create_time=ctime, grace_seconds=grace_seconds):
                cancelled += 1
        return cancelled

    def cancel_all(
        self,
        extra_pids: Optional[Sequence[int]] = None,
        authorized_job_ids: Optional[Sequence[str]] = None,
        grace_seconds: float = 1.5,
    ) -> int:
        if authorized_job_ids is not None:
            target_ids = list(authorized_job_ids)
        else:
            with self._active_lock:
                target_ids = list(self._active_processes.keys())
        cancelled = 0
        for jid in target_ids:
            if self.cancel(jid, grace_seconds=grace_seconds):
                cancelled += 1
        for pid in extra_pids or []:
            if terminate_pid_group(pid, grace_seconds=grace_seconds):
                cancelled += 1
        return cancelled

    @staticmethod
    def _terminate_process_tree(proc: subprocess.Popen[str], grace_seconds: float = 1.5) -> None:
        if proc.poll() is not None:
            return
        try:
            if os.name != "nt":
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGTERM)
            else:
                proc.terminate()
        except OSError:
            pass

        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return
            time.sleep(0.04)

        try:
            if os.name != "nt":
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except OSError:
            pass

    def run(
        self,
        argv: Sequence[str],
        job_id: Optional[str] = None,
        cwd: Optional[str | Path] = None,
        timeout: float = 300,
        env: Optional[Dict[str, str]] = None,
        stdin_data: Optional[str] = None,
        keep_stdin_open: bool = False,
        secrets_to_redact: Optional[List[str]] = None,
        on_start: Optional[Callable[[int], None]] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
        is_cancelled_fn: Optional[Callable[[], bool]] = None,
        require_absolute_binary: bool = False,
        host_execution: bool = False,
    ) -> ExecutionResult:
        validated_argv = validate_argv(argv, require_absolute_binary=require_absolute_binary)
        safe_env = build_minimal_env(env, host_execution=host_execution)
        start_time = time.monotonic()

        popen_kwargs: Dict[str, Any] = {
            "shell": False,
            "stdin": (
                subprocess.PIPE
                if (stdin_data is not None or keep_stdin_open)
                else subprocess.DEVNULL
            ),
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "env": safe_env,
            "cwd": str(cwd) if cwd else None,
        }
        if os.name != "nt":
            popen_kwargs["start_new_session"] = True

        try:
            proc = subprocess.Popen(list(validated_argv), **popen_kwargs)
        except FileNotFoundError:
            return ExecutionResult(
                success=False,
                return_code=127,
                stdout="",
                stderr=f"Executable not found: {validated_argv[0]}",
                execution_time=time.monotonic() - start_time,
                argv=list(validated_argv),
            )
        except Exception as exc:
            return ExecutionResult(
                success=False,
                return_code=-1,
                stdout="",
                stderr=f"Failed to start process: {exc}",
                execution_time=time.monotonic() - start_time,
                argv=list(validated_argv),
            )

        if on_start is not None:
            try:
                on_start(proc.pid)
            except Exception:
                pass

        if job_id:
            with self._active_lock:
                self._active_processes[job_id] = proc
                if job_id in self._cancel_flags:
                    self._terminate_process_tree(proc, grace_seconds=0.2)

        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []
        stdout_bytes = 0
        stderr_bytes = 0
        truncated = False

        def _drain(stream: Any, target_list: List[str], stream_name: str) -> None:
            nonlocal stdout_bytes, stderr_bytes, truncated
            if stream is None:
                return
            try:
                for line in iter(lambda: stream.readline(self.max_output_bytes + 1), ""):
                    if not line:
                        break
                    used_bytes = stdout_bytes if stream_name == "stdout" else stderr_bytes
                    remaining = max(0, self.max_output_bytes - used_bytes)
                    if not remaining:
                        truncated = True
                        continue
                    if len(line) > remaining:
                        truncated = True
                    redacted_line = redact_secrets(line, secrets_to_redact)
                    encoded = redacted_line.encode("utf-8", errors="replace")
                    if len(encoded) > remaining:
                        truncated = True
                    retained = encoded[:remaining].decode("utf-8", errors="ignore")
                    target_list.append(retained)
                    encoded_len = len(retained.encode("utf-8"))
                    if stream_name == "stdout":
                        stdout_bytes += encoded_len
                    else:
                        stderr_bytes += encoded_len
                    if on_output:
                        try:
                            on_output(stream_name, retained.rstrip("\r\n"))
                        except Exception:
                            pass
            except Exception:
                pass
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        if stdin_data is not None and proc.stdin is not None:
            try:
                proc.stdin.write(stdin_data)
            except Exception:
                pass
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

        t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_chunks, "stdout"), daemon=True)
        t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_chunks, "stderr"), daemon=True)
        t_out.start()
        t_err.start()

        timed_out = False
        cancelled = False
        deadline = start_time + max(0.001, timeout)

        while proc.poll() is None:
            ext_cancelled = bool(is_cancelled_fn and is_cancelled_fn())
            if (job_id and job_id in self._cancel_flags) or ext_cancelled:
                cancelled = True
                if keep_stdin_open and proc.stdin is not None:
                    try:
                        proc.stdin.write("cancel\n")
                        proc.stdin.flush()
                        proc.stdin.close()
                    except Exception:
                        pass
                self._terminate_process_tree(proc, grace_seconds=1.0)
                break
            if time.monotonic() >= deadline:
                timed_out = True
                if keep_stdin_open and proc.stdin is not None:
                    try:
                        proc.stdin.write("cancel\n")
                        proc.stdin.flush()
                        proc.stdin.close()
                    except Exception:
                        pass
                self._terminate_process_tree(proc, grace_seconds=1.0)
                break
            time.sleep(0.03)

        if keep_stdin_open and proc.stdin is not None:
            try:
                proc.stdin.close()
            except Exception:
                pass

        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)
        drain_incomplete = t_out.is_alive() or t_err.is_alive()
        truncated = truncated or drain_incomplete

        if job_id:
            with self._active_lock:
                self._active_processes.pop(job_id, None)
                self._cancel_flags.discard(job_id)

        rc = proc.returncode if proc.returncode is not None else -1
        if rc < 0 and not timed_out:
            cancelled = True
        elapsed = time.monotonic() - start_time
        return ExecutionResult(
            success=(rc == 0 and not timed_out and not cancelled and not drain_incomplete),
            return_code=rc,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks) + ("\nOutput collection did not finish" if drain_incomplete else ""),
            execution_time=elapsed,
            timed_out=timed_out,
            cancelled=cancelled,
            truncated=truncated,
            pid=proc.pid,
            worker_target="local",
            argv=list(validated_argv),
        )


REMOTE_WORKER_HARNESS = r"""
import base64, json, os, select, shutil, signal, subprocess, sys, threading, time

def _run_worker():
    payload = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
    argv = list(payload["argv"])
    timeout = float(payload.get("timeout", 300))
    cwd = payload.get("cwd")
    container = payload.get("container")
    max_output_bytes = int(payload.get("max_output_bytes", 8 * 1024 * 1024))
    max_line_chars = 65536

    worker_path = os.environ.get("PATH") or os.defpath
    child_env = {"PATH": worker_path, "LANG": "C.UTF-8", "NO_COLOR": "1"}
    for name in ("HOME", "USER", "LOGNAME", "TMPDIR"):
        if name in os.environ:
            child_env[name] = os.environ[name]
    # Container selection is explicit. Docker supplies the image's own environment.
    exec_argv = ["docker", "exec", "-i", container] + argv if container else argv

    emit_lock = threading.Lock()
    def emit_frame(obj):
        with emit_lock:
            sys.stdout.write(json.dumps(obj) + "\n")
            sys.stdout.flush()

    start = time.monotonic()
    proc = None
    def _kill_child(*_a):
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    for _sig in (signal.SIGTERM, signal.SIGINT, getattr(signal, "SIGHUP", signal.SIGTERM)):
        try:
            signal.signal(_sig, _kill_child)
        except Exception:
            pass

    try:
        proc = subprocess.Popen(
            exec_argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            env=child_env,
            start_new_session=True,
        )
        emit_frame({"type": "started", "pid": proc.pid})

        stdout_lines = []
        stderr_lines = []
        out_bytes = 0
        err_bytes = 0
        truncated = False

        def reader(stream, name, acc):
            nonlocal out_bytes, err_bytes, truncated
            while True:
                line = stream.readline(max_line_chars)
                if not line:
                    break
                b_len = len(line.encode("utf-8", errors="replace"))
                if name == "stdout":
                    if out_bytes + b_len <= max_output_bytes:
                        acc.append(line)
                        out_bytes += b_len
                        emit_frame({"type": "stream", "stream": name, "line": line.rstrip("\r\n")})
                    else:
                        truncated = True
                else:
                    if err_bytes + b_len <= max_output_bytes:
                        acc.append(line)
                        err_bytes += b_len
                        emit_frame({"type": "stream", "stream": name, "line": line.rstrip("\r\n")})
                    else:
                        truncated = True

        t1 = threading.Thread(target=reader, args=(proc.stdout, "stdout", stdout_lines), daemon=True)
        t2 = threading.Thread(target=reader, args=(proc.stderr, "stderr", stderr_lines), daemon=True)
        t1.start()
        t2.start()

        timed_out = False
        cancelled = False
        stdin_watch = True
        deadline = start + max(0.001, timeout)
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                timed_out = True
                _kill_child()
                break
            if stdin_watch:
                try:
                    rlist, _, _ = select.select([sys.stdin], [], [], 0.04)
                    if rlist:
                        cmd_line = sys.stdin.readline()
                        if not cmd_line or "cancel" in cmd_line.lower():
                            # Controller closed stdin pipe (disconnect/cancel) or sent explicit cancel
                            cancelled = True
                            _kill_child()
                            break
                except Exception:
                    stdin_watch = False
                    time.sleep(0.04)
            else:
                time.sleep(0.04)

        _kill_child()
        t1.join(timeout=2.0)
        t2.join(timeout=2.0)
        emit_frame({
            "type": "result",
            "success": proc.returncode == 0 and not timed_out and not cancelled,
            "return_code": proc.returncode if proc.returncode is not None else -1,
            "stdout": "".join(stdout_lines),
            "stderr": "".join(stderr_lines),
            "timed_out": timed_out,
            "cancelled": cancelled,
            "truncated": truncated,
            "execution_time": time.monotonic() - start,
            "pid": proc.pid,
        })
    except FileNotFoundError:
        emit_frame({
            "type": "result",
            "success": False,
            "return_code": 127,
            "stdout": "",
            "stderr": f"Executable not found on remote worker: {exec_argv[0]}",
            "timed_out": False,
            "execution_time": time.monotonic() - start,
            "pid": None,
        })
    except Exception as exc:
        emit_frame({
            "type": "result",
            "success": False,
            "return_code": -1,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
            "execution_time": time.monotonic() - start,
            "pid": None,
        })

_run_worker()
"""


class SshWorkerBridge:
    """
    Constrained SSH bridge to a remote Linux/Kali/container worker.

    Uses `ssh -T -o BatchMode=yes` with no PTY allocation, a sanitized remote child
    environment, incremental JSON-line streaming, and remote process-group cleanup.
    """

    def __init__(
        self,
        ssh_target: str,
        runner: Optional[SafeSubprocessRunner] = None,
        strict_host_key_checking: str = "accept-new",
        container: Optional[str] = None,
    ) -> None:
        if not ssh_target or ssh_target.startswith("-") or any(c in ssh_target for c in (";", "|", "&", "`", " ")):
            raise ExecutionSecurityError(f"Invalid SSH target: {ssh_target}")
        self.ssh_target = ssh_target
        self.runner = runner or SafeSubprocessRunner()
        self.strict_host_key_checking = strict_host_key_checking
        self.container = container

    def _build_ssh_argv(self, remote_python_cmd: List[str]) -> List[str]:
        return [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            f"StrictHostKeyChecking={self.strict_host_key_checking}",
            "-o",
            "ConnectTimeout=10",
            "--",
            self.ssh_target,
            *remote_python_cmd,
        ]

    def execute_argv(
        self,
        argv: Sequence[str],
        job_id: Optional[str] = None,
        timeout: float = 300,
        container: Optional[str] = None,
        on_start: Optional[Callable[[int], None]] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
        is_cancelled_fn: Optional[Callable[[], bool]] = None,
    ) -> ExecutionResult:
        validated = validate_argv(argv, require_absolute_binary=False)
        payload = {
            "argv": list(validated),
            "timeout": timeout,
            "container": container if container is not None else self.container,
        }
        b64_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        remote_cmd = [
            "python3",
            "-c",
            shlex.quote(REMOTE_WORKER_HARNESS),
            shlex.quote(b64_payload),
        ]
        ssh_argv = self._build_ssh_argv(remote_cmd)
        final_frame: Optional[Dict[str, Any]] = None

        def _handle_ssh_line(stream_name: str, raw_line: str) -> None:
            nonlocal final_frame
            if stream_name == "stdout" and raw_line.strip().startswith("{"):
                try:
                    frame = json.loads(raw_line.strip())
                    ftype = frame.get("type")
                    if ftype == "stream" and on_output:
                        on_output(
                            str(frame.get("stream", "stdout")),
                            redact_secrets(str(frame.get("line", ""))),
                        )
                    elif ftype == "result":
                        final_frame = frame
                    return
                except Exception:
                    pass
            if on_output and stream_name == "stderr":
                on_output("stderr", redact_secrets(raw_line))

        raw_res = self.runner.run(
            ssh_argv,
            job_id=job_id,
            timeout=timeout + 15,
            keep_stdin_open=True,
            on_start=on_start,
            on_output=_handle_ssh_line,
            is_cancelled_fn=is_cancelled_fn,
        )

        if final_frame is None and raw_res.stdout.strip():
            for ln in reversed(raw_res.stdout.strip().splitlines()):
                if ln.strip().startswith("{"):
                    try:
                        cand = json.loads(ln.strip())
                        if cand.get("type") == "result" or "return_code" in cand:
                            final_frame = cand
                            break
                    except Exception:
                        continue

        if final_frame is None:
            return ExecutionResult(
                success=False,
                return_code=raw_res.return_code,
                stdout="",
                stderr=raw_res.stderr or "Empty or interrupted response from SSH worker bridge",
                execution_time=raw_res.execution_time,
                timed_out=raw_res.timed_out,
                cancelled=raw_res.cancelled,
                worker_target=self.ssh_target,
                argv=list(validated),
            )

        stdout_str = redact_secrets(str(final_frame.get("stdout", "")))
        stderr_str = redact_secrets(str(final_frame.get("stderr", "")))
        return ExecutionResult(
            success=bool(final_frame.get("success", False)) and not raw_res.cancelled,
            return_code=int(final_frame.get("return_code", -1)),
            stdout=stdout_str,
            stderr=stderr_str,
            execution_time=float(final_frame.get("execution_time", raw_res.execution_time)),
            timed_out=bool(final_frame.get("timed_out", raw_res.timed_out)),
            cancelled=raw_res.cancelled,
            pid=final_frame.get("pid"),
            worker_target=self.ssh_target,
            argv=list(validated),
        )

    def probe_worker(self, tool_names: Optional[List[str]] = None) -> Dict[str, Any]:
        probe_script = r"""
import json, os, platform, shutil, subprocess
tools = %s
found = {}
worker_path = os.environ.get("PATH") or os.defpath
for t in tools:
    p = shutil.which(t, path=worker_path)
    if p:
        found[t] = p
containers = []
active_container = %s
if shutil.which("docker"):
    try:
        cp = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}:{{.Status}}:{{.Image}}"], capture_output=True, text=True, timeout=5)
        if cp.returncode == 0:
            containers = [line for line in cp.stdout.strip().splitlines() if line]
        if active_container:
            py_check = (
                "import json, shutil; "
                f"t={json.dumps(tools)}; "
                "print(json.dumps({k: shutil.which(k) for k in t if shutil.which(k)}))"
            )
            c_res = subprocess.run(
                ["docker", "exec", "-i", active_container, "python3", "-c", py_check],
                capture_output=True, text=True, timeout=8
            )
            if c_res.returncode == 0 and c_res.stdout.strip():
                c_tools = json.loads(c_res.stdout.strip().splitlines()[-1])
                for k, v in c_tools.items():
                    if k not in found:
                        found[k] = f"{active_container}:{v}"
    except Exception:
        pass
print(json.dumps({
    "hostname": platform.node(),
    "system": platform.system(),
    "release": platform.release(),
    "machine": platform.machine(),
    "python": platform.python_version(),
    "active_container": active_container,
    "tools": found,
    "containers": containers,
}))
""" % (json.dumps(
            tool_names
            or [
                "nmap",
                "httpx",
                "nuclei",
                "gobuster",
                "ffuf",
                "sqlmap",
                "subfinder",
                "feroxbuster",
                "checksec",
                "strings",
                "exiftool",
                "python3",
                "docker",
            ]
        ), repr(self.container))

        ssh_argv = self._build_ssh_argv(["python3", "-c", shlex.quote(probe_script)])
        res = self.runner.run(ssh_argv, timeout=15)
        if not res.success or not res.stdout.strip():
            return {
                "reachable": False,
                "ssh_target": self.ssh_target,
                "error": res.stderr.strip() or "SSH probe failed",
            }
        try:
            info = json.loads(res.stdout.strip().splitlines()[-1])
            info["reachable"] = True
            info["ssh_target"] = self.ssh_target
            return info
        except Exception as exc:
            return {
                "reachable": False,
                "ssh_target": self.ssh_target,
                "error": str(exc),
            }
