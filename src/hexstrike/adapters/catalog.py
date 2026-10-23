"""
Typed tool adapters, structured output parsers, and custom adapter SDK.

Every adapter builds an immutable `argv` list (`shell=False`), validates schema
parameters, blocks dangerous flag injection and unvalidated positional targets,
enforces user-configured engagement scope (including on redirects), and parses
tool output into structured observations and candidate/validated findings.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from jsonschema import Draft202012Validator


from hexstrike.domain.models import (
    CapabilityDescriptor,
    Finding,
    FindingState,
    RiskLevel,
    ScopePolicy,
    Severity,
    SideEffectClass,
    ToolStatus,
    new_id,
)
from hexstrike.execution.runner import ExecutionResult, SafeSubprocessRunner
from hexstrike.policy.engine import PolicyEngine, PolicyViolationError, canonicalize_target, parse_port_spec


DANGEROUS_FLAG_PREFIXES = (
    "--script",
    "--datadir",
    "--servicedb",
    "--versiondb",
    "-il",
    "-on",
    "-ox",
    "-og",
    "-oa",
    "-os",
    "--resume",
    "--stylesheet",
    "--os-shell",
    "--os-pwn",
    "--os-cmd",
    "--sql-shell",
    "--file-read",
    "--file-write",
    "--file-dest",
    "--eval",
    "--exec",
    "-e",
    "--command",
    "--config",
    "--resolvers",
    "--interactsh-url",
    "--headless-options",
    "--request-filename",
    "--proxy",
    "--proxies",
)


SAFE_VALUE_TAKING_FLAGS = frozenset(
    {
        "--top-ports",
        "--max-retries",
        "--min-rate",
        "--max-rate",
        "--host-timeout",
        "--scan-delay",
        "--max-scan-delay",
        "--version-intensity",
        "-t",
        "--threads",
        "-c",
        "--concurrency",
        "-rl",
        "--rate-limit",
        "-timeout",
        "--timeout",
        "-mc",
        "-fc",
        "-ms",
        "-fs",
        "-fw",
        "-fl",
    }
)


def validate_safe_extra_flags(
    extra_flags: Optional[Sequence[str] | str],
    allowed_prefixes: Optional[Tuple[str, ...]] = None,
    scalar_value_flags: Sequence[str] = (),
) -> List[str]:
    if not extra_flags:
        return []
    if isinstance(extra_flags, str):
        if any(ch in extra_flags for ch in (";", "|", "&", "`", "$", "\n", "\r", "\x00", ">", "<")):
            raise PolicyViolationError(
                f"Shell metacharacters forbidden in extra flags: {extra_flags}",
                code="ARGUMENT_INJECTION_BLOCKED",
            )
        tokens = shlex.split(extra_flags)
    elif isinstance(extra_flags, (list, tuple)):
        tokens = []
        for item in extra_flags:
            if not isinstance(item, str):
                raise PolicyViolationError("Extra flag items must be strings", code="INVALID_ARGUMENT")
            if any(ch in item for ch in (";", "|", "&", "`", "$", "\n", "\r", "\x00", ">", "<")):
                raise PolicyViolationError(
                    f"Shell metacharacters forbidden in flag token: {item}",
                    code="ARGUMENT_INJECTION_BLOCKED",
                )
            tokens.append(item)
    else:
        raise PolicyViolationError("extra_flags must be a list of strings", code="INVALID_ARGUMENT")

    expecting_scalar_value = False
    for tok in tokens:
        low = tok.strip().lower()
        if not low:
            continue
        if expecting_scalar_value:
            expecting_scalar_value = False
            # Value following a known scalar flag must be numeric/duration/status-list, never a hostname/IP/path
            if not re.match(r"^[0-9,]+(?:ms|s|m|h)?$", low):
                raise PolicyViolationError(
                    f"Invalid scalar value '{tok}' for option flag in extra_flags",
                    code="INVALID_FLAG_VALUE",
                )
            continue

        for bad in DANGEROUS_FLAG_PREFIXES:
            b_low = bad.lower().strip()
            if low == b_low or low.startswith(b_low + "="):
                raise PolicyViolationError(
                    f"Dangerous tool flag blocked by adapter policy: {tok}",
                    code="DANGEROUS_FLAG_BLOCKED",
                )
        if not tok.startswith("-") or tok == "--":
            raise PolicyViolationError(
                f"Positional target or non-flag argument '{tok}' is forbidden in extra_flags; "
                "specify targets through the structured 'target' field.",
                code="UNVALIDATED_EXTRA_TARGET",
            )
        if low in SAFE_VALUE_TAKING_FLAGS or low in scalar_value_flags:
            expecting_scalar_value = True
        if allowed_prefixes is not None:
            if not any(tok == ap or tok.startswith(ap + "=") for ap in allowed_prefixes):
                raise PolicyViolationError(
                    f"Flag '{tok}' is not in adapter allowlist {allowed_prefixes}",
                    code="UNSUPPORTED_FLAG",
                )
    if expecting_scalar_value:
        raise PolicyViolationError("Option flag in extra_flags is missing its value", code="MISSING_FLAG_VALUE")
    return tokens


def read_bounded_http_body(response: Any, limit: int = 65536, method: str = "GET") -> Tuple[bytes, Dict[str, Any]]:
    declared = response.headers.get("Content-Length")
    declared_length = int(declared) if declared is not None else None
    if declared_length is not None and declared_length < 0:
        raise ValueError("Negative HTTP Content-Length")
    body = response.read(limit + 1) if method != "HEAD" else b""
    if (method != "HEAD" and declared_length is not None
            and not response.headers.get("Transfer-Encoding")
            and len(body) < min(declared_length, limit + 1)):
        raise ValueError(f"Incomplete HTTP body: received {len(body)} of {declared_length} declared bytes")
    return body[:limit], {"body_truncated": len(body) > limit, "declared_body_length": declared_length}


class ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Validates every HTTP redirect destination against the engagement `ScopePolicy`
    before following the redirect. Prevents redirect-based port/host scope bypasses.
    """

    def __init__(self, scope: Optional[ScopePolicy] = None, policy: Optional[PolicyEngine] = None, follow_redirects: bool = True) -> None:
        super().__init__()
        self.scope = scope
        self.policy = policy or PolicyEngine()
        self.follow_redirects = follow_redirects

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        if not self.follow_redirects:
            return None
        resolved_url = urllib.parse.urljoin(req.full_url, newurl)
        if self.scope is not None:
            self.policy.evaluate_target(resolved_url, self.scope)
        return super().redirect_request(req, fp, code, msg, headers, resolved_url)


@dataclass
class BinaryIdentity:
    binary_name: str
    executable_path: Optional[str]
    sha256: str
    version: str
    vendor_flavor: str
    status: ToolStatus
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binary_name": self.binary_name,
            "executable_path": self.executable_path,
            "sha256": self.sha256,
            "version": self.version,
            "vendor_flavor": self.vendor_flavor,
            "status": self.status.value,
            "notes": self.notes,
        }


def compute_file_sha256(path: str | Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "unavailable"


def resolve_binary_path(binary_name: str, search_path: Optional[str] = None) -> Optional[str]:
    """Resolve distribution aliases without replacing unrelated commands on PATH."""
    names = ("httpx-toolkit", "httpx") if binary_name == "httpx" else (binary_name,)
    return next((path for name in names if (path := shutil.which(name, path=search_path))), None)


def inspect_binary_identity(
    binary_name: str,
    search_paths: Optional[Sequence[str]] = None,
    probe_version: bool = False,
    runner: Optional[SafeSubprocessRunner] = None,
) -> BinaryIdentity:
    if not binary_name:
        return BinaryIdentity(
            binary_name="builtin",
            executable_path="builtin",
            sha256="builtin",
            version="builtin",
            vendor_flavor="builtin",
            status=ToolStatus.ENABLED,
        )

    path_env = os.pathsep.join(search_paths) if search_paths else os.environ.get(
        "PATH", os.defpath
    )
    resolved = resolve_binary_path(binary_name, search_path=path_env)
    if not resolved:
        return BinaryIdentity(
            binary_name=binary_name,
            executable_path=None,
            sha256="missing",
            version="missing",
            vendor_flavor="missing",
            status=ToolStatus.MISSING,
            notes=f"Executable '{binary_name}' not found in search paths",
        )

    abs_path = os.path.abspath(resolved)
    digest = compute_file_sha256(abs_path)

    vendor_flavor = "standard"
    version_str = "detected"
    status = ToolStatus.ENABLED
    notes = ""

    if binary_name == "masscan" and hasattr(socket, "AF_PACKET"):
        try:
            # Opening a raw socket checks access without transmitting packets.
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0):
                pass
        except PermissionError:
            status = ToolStatus.RESTRICTED
            notes = "The server account cannot open raw sockets. Use a separately configured privileged worker for Masscan."

    if binary_name == "httpx":
        try:
            with open(abs_path, "rb") as f:
                head = f.read(4096)
            if head.startswith(b"#!") and b"python" in head.lower():
                vendor_flavor = "python_httpx"
                status = ToolStatus.INCOMPATIBLE
                notes = (
                    "Detected Python HTTPX CLI script instead of ProjectDiscovery httpx scanner. "
                    "Use 'web.http_inspect' built-in capability or install ProjectDiscovery httpx."
                )
            elif b"projectdiscovery" in head.lower() or b"go.buildid" in head.lower():
                vendor_flavor = "projectdiscovery_httpx"
        except OSError:
            pass

    if probe_version and runner is not None:
        v_flag = "--version" if binary_name not in ("gobuster", "ffuf") else "-V"
        res = runner.run([abs_path, v_flag], timeout=4)
        combined = (res.stdout + "\n" + res.stderr).strip()
        if combined:
            first_line = combined.splitlines()[0][:120]
            version_str = first_line
            if binary_name == "httpx":
                if "projectdiscovery" in combined.lower() or "-silent" in combined.lower():
                    vendor_flavor = "projectdiscovery_httpx"
                    status = ToolStatus.ENABLED
                elif "usage: httpx" in combined.lower() or "python" in combined.lower():
                    vendor_flavor = "python_httpx"
                    status = ToolStatus.INCOMPATIBLE
                    notes = "Python HTTPX CLI detected; incompatible with ProjectDiscovery httpx flags."

    return BinaryIdentity(
        binary_name=binary_name,
        executable_path=abs_path,
        sha256=digest,
        version=version_str,
        vendor_flavor=vendor_flavor,
        status=status,
        notes=notes,
    )


class ToolAdapter(ABC):
    """Base contract for all typed HexStrike tool adapters."""

    descriptor: CapabilityDescriptor
    input_file_parameters: tuple[str, ...] = ()

    def validate_arguments(self, operation: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if operation not in self.descriptor.operations:
            raise PolicyViolationError(
                f"Operation '{operation}' not supported by '{self.descriptor.capability_id}'",
                code="UNKNOWN_OPERATION",
            )
        op_spec = self.descriptor.operations[operation]
        schema_props: Dict[str, Any] = op_spec.get("parameters", {})
        required: List[str] = op_spec.get("required", [])
        schema = {"type": "object", "properties": schema_props, "additionalProperties": False}
        errors = list(Draft202012Validator(schema).iter_errors(arguments))
        if errors:
            error = errors[0]
            field = ".".join(str(part) for part in error.absolute_path) or "arguments"
            raise PolicyViolationError(f"Invalid {field}: {error.validator} constraint failed", code="SCHEMA_VALIDATION_ERROR")

        unknown = set(arguments.keys()) - set(schema_props.keys())
        if unknown:
            raise PolicyViolationError(
                f"Unknown arguments for {self.descriptor.capability_id}.{operation}: {sorted(unknown)}. "
                f"Allowed fields: {sorted(schema_props.keys())}",
                code="SCHEMA_VALIDATION_ERROR",
            )

        for req in required:
            if req not in arguments or arguments[req] is None or (arguments[req] == "" and schema_props.get(req, {}).get("minLength", 1) > 0):
                raise PolicyViolationError(
                    f"Missing required argument '{req}' for {self.descriptor.capability_id}.{operation}",
                    code="MISSING_REQUIRED_FIELD",
                )

        validated: Dict[str, Any] = {}
        for k, spec in schema_props.items():
            if k in arguments and arguments[k] is not None:
                val = arguments[k]
                expected_type = spec.get("type")
                if expected_type == "string" and not isinstance(val, str):
                    raise PolicyViolationError(f"Field '{k}' must be a string", code="SCHEMA_VALIDATION_ERROR")
                if expected_type == "integer" and (not isinstance(val, int) or isinstance(val, bool)):
                    raise PolicyViolationError(f"Field '{k}' must be an integer", code="SCHEMA_VALIDATION_ERROR")
                if expected_type == "boolean" and not isinstance(val, bool):
                    raise PolicyViolationError(f"Field '{k}' must be a boolean", code="SCHEMA_VALIDATION_ERROR")
                if expected_type == "array" and not isinstance(val, list):
                    raise PolicyViolationError(f"Field '{k}' must be an array", code="SCHEMA_VALIDATION_ERROR")
                if expected_type == "integer":
                    if "minimum" in spec and val < spec["minimum"] or "maximum" in spec and val > spec["maximum"]:
                        raise PolicyViolationError(f"Field '{k}' is outside its allowed range", code="SCHEMA_VALIDATION_ERROR")
                if "enum" in spec and val not in spec["enum"]:
                    raise PolicyViolationError(
                        f"Field '{k}' must be one of {spec['enum']}, got '{val}'",
                        code="SCHEMA_VALIDATION_ERROR",
                    )
                validated[k] = val
            elif "default" in spec:
                validated[k] = spec["default"]

        return validated

    @abstractmethod
    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        """Return target strings subject to engagement scope validation."""

    @abstractmethod
    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        """Build an immutable argv list for subprocess execution (or preview for built-in adapters)."""

    @abstractmethod
    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        """Parse raw execution output into structured JSON data and normalized Findings."""

    def execute_direct(
        self,
        operation: str,
        arguments: Dict[str, Any],
        timeout: int = 60,
        scope: Optional[ScopePolicy] = None,
        policy: Optional[PolicyEngine] = None,
    ) -> Optional[ExecutionResult]:
        """Optional hook for built-in pure-Python adapters."""
        return None

    def execution_succeeded(self, result: ExecutionResult) -> bool:
        """Interpret process completion without changing the recorded exit code."""
        return result.success


# ============================================================================
# 1. NMAP ADAPTER (WITH XML PARSER & PORT VALIDATION)
# ============================================================================

PORT_SPEC_RE = re.compile(r"^[0-9,\-TUVS:]+$")

NMAP_PROFILE_FLAGS: Dict[str, List[str]] = {
    "quick": ["-sT", "-T4", "-F", "--open"],
    "service_version": ["-sV", "-T4", "--version-light"],
    "default_syn": ["-sS", "-sV", "-T4"],
    "tcp_connect": ["-sT", "-sV", "-T4"],
    "ping_sweep": ["-sn"],
    "udp_top": ["-sU", "--top-ports", "50"],
}


def parse_nmap_xml(xml_text: str) -> Dict[str, Any]:
    hosts: List[Dict[str, Any]] = []
    if not xml_text or "<nmaprun" not in xml_text:
        return {"hosts": hosts, "parsed_xml": False}

    try:
        start_idx = xml_text.find("<nmaprun")
        end_idx = xml_text.rfind("</nmaprun>")
        if end_idx != -1:
            xml_slice = xml_text[start_idx : end_idx + len("</nmaprun>")]
        else:
            xml_slice = xml_text[start_idx:]
        root = ET.fromstring(xml_slice)
        for host_el in root.findall("host"):
            status_el = host_el.find("status")
            state = status_el.attrib.get("state", "unknown") if status_el is not None else "unknown"
            addrs = [a.attrib.get("addr", "") for a in host_el.findall("address") if a.attrib.get("addr")]
            hostnames = [
                hn.attrib.get("name", "")
                for hn in host_el.findall("./hostnames/hostname")
                if hn.attrib.get("name")
            ]
            open_ports: List[Dict[str, Any]] = []
            for port_el in host_el.findall("./ports/port"):
                p_state_el = port_el.find("state")
                p_state = p_state_el.attrib.get("state", "") if p_state_el is not None else ""
                svc_el = port_el.find("service")
                open_ports.append(
                    {
                        "port": int(port_el.attrib.get("portid", "0")),
                        "protocol": port_el.attrib.get("protocol", "tcp"),
                        "state": p_state,
                        "service": svc_el.attrib.get("name", "") if svc_el is not None else "",
                        "product": svc_el.attrib.get("product", "") if svc_el is not None else "",
                        "version": svc_el.attrib.get("version", "") if svc_el is not None else "",
                    }
                )
            hosts.append(
                {
                    "state": state,
                    "addresses": addrs,
                    "hostnames": hostnames,
                    "ports": open_ports,
                }
            )
        return {"hosts": hosts, "parsed_xml": True}
    except ET.ParseError as exc:
        return {"hosts": hosts, "parsed_xml": False, "parse_error": str(exc)}


class NmapAdapter(ToolAdapter):
    descriptor = CapabilityDescriptor(
        capability_id="network.nmap",
        name="Nmap Network Scanner",
        category="network",
        pack="network",
        description="Structured Nmap port and service discovery with XML output parsing.",
        binary_name="nmap",
        risk_level=RiskLevel.MEDIUM,
        side_effects=SideEffectClass.ACTIVE_SCAN,
        operations={
            "scan": {
                "description": "Run a structured Nmap port/service scan against an authorized host or CIDR.",
                "required": ["target"],
                "parameters": {
                    "target": {"type": "string", "description": "Target hostname, IP, or CIDR"},
                    "profile": {
                        "type": "string",
                        "enum": list(NMAP_PROFILE_FLAGS.keys()),
                        "default": "quick",
                        "description": "Scan profile",
                    },
                    "ports": {
                        "type": "string",
                        "default": "",
                        "description": "Port specification e.g. '80,443,8000-8100'",
                    },
                    "skip_host_discovery": {
                        "type": "boolean",
                        "default": True,
                        "description": "Pass -Pn to treat host as online",
                    },
                    "extra_flags": {
                        "type": "array",
                        "default": [],
                        "description": "Optional safe Nmap option flags",
                    },
                },
            }
        },
        examples=[
            {"operation": "scan", "arguments": {"target": "127.0.0.1", "profile": "quick", "ports": "22,80,443"}}
        ],
    )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        return [arguments["target"]]

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        validated = self.validate_arguments(operation, arguments)
        target = canonicalize_target(validated["target"])
        exe = binary_path or "nmap"
        profile = validated.get("profile", "quick")
        ports = validated.get("ports", "").strip()
        profile_flags = list(NMAP_PROFILE_FLAGS[profile])
        if ports:
            profile_flags = [f for f in profile_flags if f not in ("-F", "--top-ports", "50")]
        argv: List[str] = [exe, *profile_flags]

        if validated.get("skip_host_discovery", True) and "-sn" not in argv:
            argv.append("-Pn")

        if ports:
            if not PORT_SPEC_RE.match(ports):
                raise PolicyViolationError(f"Invalid Nmap port specification: {ports}", code="INVALID_PORT_SPEC")
            parse_port_spec(ports)
            argv.extend(["-p", ports])

        extra = validate_safe_extra_flags(validated.get("extra_flags"))
        argv.extend(extra)
        argv.extend(["-oX", "-", "--", target.host])
        return argv

    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        parsed = parse_nmap_xml(result.stdout)
        findings: List[Finding] = []
        for host in parsed.get("hosts", []):
            addr = (host.get("addresses") or [arguments.get("target", "unknown")])[0]
            for port_info in host.get("ports", []):
                if port_info.get("state") == "open":
                    svc_desc = " ".join(
                        p for p in (port_info.get("service"), port_info.get("product"), port_info.get("version")) if p
                    ).strip()
                    findings.append(
                        Finding(
                            finding_id=new_id("find"),
                            engagement_id=engagement_id,
                            job_id=job_id,
                            title=f"Open Port {port_info['port']}/{port_info['protocol']} ({svc_desc or 'unknown'})",
                            severity=Severity.INFO,
                            state=FindingState.OBSERVATION,
                            target=f"{addr}:{port_info['port']}",
                            capability_id=self.descriptor.capability_id,
                            description=(
                                f"Nmap observed open port {port_info['port']}/{port_info['protocol']} "
                                f"on {addr} running service '{svc_desc or 'unidentified'}'."
                            ),
                            wstg_id="WSTG-INFO-02",
                            confidence=0.95,
                        )
                    )
        return parsed, findings


# ============================================================================
# 2. BUILT-IN HTTP INSPECTION & SECURITY HEADER ADAPTER
# ============================================================================

SECURITY_HEADERS_CHECK = (
    ("Content-Security-Policy", Severity.LOW, "Missing Content-Security-Policy header"),
    ("Strict-Transport-Security", Severity.LOW, "Missing HSTS header on HTTPS endpoint"),
    ("X-Frame-Options", Severity.INFO, "Missing X-Frame-Options header"),
    ("X-Content-Type-Options", Severity.INFO, "Missing X-Content-Type-Options nosniff header"),
)


class HttpInspectAdapter(ToolAdapter):
    descriptor = CapabilityDescriptor(
        capability_id="web.http_inspect",
        name="HTTP Security Inspector & Repeater",
        category="web",
        pack="core",
        description=(
            "Built-in HTTP/HTTPS probe and repeater with security header analysis, "
            "scoped redirect tracking, and secret redaction."
        ),
        binary_name=None,
        risk_level=RiskLevel.LOW,
        side_effects=SideEffectClass.NETWORK_PROBE,
        operations={
            "probe": {
                "description": "Probe an HTTP/HTTPS URL and analyze headers, status, TLS, and response fingerprint.",
                "required": ["url"],
                "parameters": {
                    "url": {"type": "string", "description": "Target HTTP/HTTPS URL"},
                    "method": {
                        "type": "string",
                        "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
                        "default": "GET",
                    },
                    "follow_redirects": {"type": "boolean", "default": False},
                    "timeout": {"type": "integer", "default": 10, "minimum": 1, "maximum": 300},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "cookies": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string", "maxLength": 1048576, "minLength": 0},
                    "body_base64": {"type": "string", "maxLength": 1400000, "minLength": 0},
                    "json_body": {"type": "object"},
                    "multipart": {"type": "array", "maxItems": 100, "items": {"type": "object", "additionalProperties": False, "required": ["name"], "oneOf": [{"required": ["content"]}, {"required": ["content_base64"]}], "properties": {
                        "name": {"type": "string"}, "content": {"type": "string", "maxLength": 1048576}, "content_base64": {"type": "string", "maxLength": 1400000}, "filename": {"type": "string"}, "content_type": {"type": "string"}}}},
                    "credential_ref": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,80}$"},
                    "session": {"type": "string", "pattern": "^[A-Za-z0-9_.-]{1,80}$"},
                    "proxy": {"type": "string"},
                },
            }
        },
        examples=[{"operation": "probe", "arguments": {"url": "http://127.0.0.1:8000", "method": "GET"}}],
    )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        return [arguments["url"]]

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        validated = self.validate_arguments(operation, arguments)
        return ["builtin:http_inspect", validated.get("method", "GET"), validated["url"]]

    def execute_direct(self, operation, arguments, timeout=15, scope=None, policy=None, state_root=None, engagement_id="default"):
        import time
        from hexstrike.http.client import perform_request
        start = time.monotonic()
        args = self.validate_arguments(operation, arguments)
        try:
            output = perform_request(args, scope, policy or PolicyEngine(), timeout, state_root, engagement_id)
            return ExecutionResult(True, 0, json.dumps(output), "", time.monotonic() - start, argv=self.build_argv(operation, args))
        except Exception as exc:
            return ExecutionResult(False, 1, "", str(exc), time.monotonic() - start, argv=self.build_argv(operation, args))

    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        if not result.stdout.strip():
            return {"error": result.stderr}, []
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"raw": result.stdout[:2000]}, []

        headers_lower = {k.lower(): v for k, v in (data.get("headers") or {}).items()}
        findings: List[Finding] = []
        target_url = data.get("url", arguments.get("url", ""))

        for header_name, sev, title in SECURITY_HEADERS_CHECK:
            if header_name == "Strict-Transport-Security" and not target_url.lower().startswith("https://"):
                continue
            if header_name.lower() not in headers_lower:
                findings.append(
                    Finding(
                        finding_id=new_id("find"),
                        engagement_id=engagement_id,
                        job_id=job_id,
                        title=title,
                        severity=sev,
                        state=FindingState.OBSERVATION,
                        target=target_url,
                        capability_id=self.descriptor.capability_id,
                        description=f"HTTP response from {target_url} (status {data.get('status_code')}) omitted '{header_name}'.",
                        remediation=f"Configure the web server to return a strict '{header_name}' response header.",
                        wstg_id="WSTG-CONF-07",
                        confidence=0.9,
                    )
                )

        server_banner = headers_lower.get("server") or headers_lower.get("x-powered-by")
        if server_banner and any(ch.isdigit() for ch in server_banner):
            findings.append(
                Finding(
                    finding_id=new_id("find"),
                    engagement_id=engagement_id,
                    job_id=job_id,
                    title=f"Server Version Banner Disclosure: {server_banner[:60]}",
                    severity=Severity.INFO,
                    state=FindingState.OBSERVATION,
                    target=target_url,
                    capability_id=self.descriptor.capability_id,
                    description=f"Response headers disclosed versioned technology banner: '{server_banner}'.",
                    remediation="Suppress verbose version numbers in Server and X-Powered-By headers.",
                    wstg_id="WSTG-INFO-02",
                    confidence=0.95,
                )
            )
        return data, findings


# ============================================================================
# 3. PROJECTDISCOVERY HTTPX ADAPTER (WITH BINARY DISAMBIGUATION)
# ============================================================================


class HttpxProbeAdapter(ToolAdapter):
    descriptor = CapabilityDescriptor(
        capability_id="web.httpx_probe",
        name="ProjectDiscovery httpx Probe",
        category="web",
        pack="web",
        description="Fast HTTP/HTTPS technology and status prober (requires ProjectDiscovery httpx binary, not Python httpx).",
        binary_name="httpx",
        risk_level=RiskLevel.LOW,
        side_effects=SideEffectClass.NETWORK_PROBE,
        operations={
            "probe": {
                "description": "Probe a target URL or host using ProjectDiscovery httpx with JSON output.",
                "required": ["target"],
                "parameters": {
                    "target": {"type": "string", "description": "Target host or URL"},
                    "status_code": {"type": "boolean", "default": True},
                    "tech_detect": {"type": "boolean", "default": True},
                    "title": {"type": "boolean", "default": True},
                    "follow_redirects": {"type": "boolean", "default": False},
                },
            }
        },
        examples=[{"operation": "probe", "arguments": {"target": "https://example.com"}}],
    )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        return [arguments["target"]]

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        validated = self.validate_arguments(operation, arguments)
        target = canonicalize_target(validated["target"])
        exe = binary_path or "httpx"
        argv = [exe, "-u", target.raw, "-json", "-silent", "-no-color"]
        if validated.get("status_code", True):
            argv.append("-sc")
        if validated.get("tech_detect", True):
            argv.append("-td")
        if validated.get("title", True):
            argv.append("-title")
        if validated.get("follow_redirects", False):
            argv.append("-fr")
        return argv

    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        records: List[Dict[str, Any]] = []
        findings: List[Finding] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
                records.append(rec)
                url = rec.get("url", arguments.get("target", ""))
                techs = rec.get("tech", [])
                if techs:
                    findings.append(
                        Finding(
                            finding_id=new_id("find"),
                            engagement_id=engagement_id,
                            job_id=job_id,
                            title=f"Detected Web Technologies on {url}",
                            severity=Severity.INFO,
                            state=FindingState.OBSERVATION,
                            target=url,
                            capability_id=self.descriptor.capability_id,
                            description=f"httpx fingerprinted technologies: {', '.join(techs)}",
                            wstg_id="WSTG-INFO-08",
                            confidence=0.9,
                        )
                    )
            except json.JSONDecodeError:
                continue
        return {"probes": records, "count": len(records)}, findings


# ============================================================================
# 4. NUCLEI ADAPTER (WITH TEMPLATE PROVENANCE & JSONL PARSER)
# ============================================================================

SAFE_TEMPLATE_TAG_RE = re.compile(r"^[a-zA-Z0-9_,\-]+$")


class NucleiAdapter(ToolAdapter):
    descriptor = CapabilityDescriptor(
        capability_id="web.nuclei",
        name="Nuclei Template Scanner",
        category="web",
        pack="web",
        description="Template-driven vulnerability scanner with severity filtering and JSONL evidence extraction.",
        binary_name="nuclei",
        risk_level=RiskLevel.HIGH,
        side_effects=SideEffectClass.ACTIVE_SCAN,
        operations={
            "scan": {
                "description": "Execute Nuclei against a target URL with bounded severity/tag filters.",
                "required": ["target"],
                "parameters": {
                    "target": {"type": "string", "description": "Target URL or host"},
                    "severity": {
                        "type": "string",
                        "default": "critical,high,medium,low,info",
                        "description": "Comma-separated severities",
                    },
                    "tags": {
                        "type": "string",
                        "default": "",
                        "description": "Comma-separated template tags (e.g. 'cve,misconfig,exposure')",
                    },
                    "rate_limit": {"type": "integer", "default": 50},
                },
            }
        },
        examples=[{"operation": "scan", "arguments": {"target": "http://127.0.0.1:8080", "tags": "misconfig"}}],
    )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        return [arguments["target"]]

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        validated = self.validate_arguments(operation, arguments)
        target = canonicalize_target(validated["target"])
        exe = binary_path or "nuclei"
        severity = validated.get("severity", "critical,high,medium,low,info")
        if not SAFE_TEMPLATE_TAG_RE.match(severity):
            raise PolicyViolationError(f"Invalid severity filter: {severity}", code="INVALID_ARGUMENT")

        argv = [
            exe,
            "-u",
            target.raw,
            "-severity",
            severity,
            "-jsonl",
            "-silent",
            "-nc",
            "-rl",
            str(max(1, min(int(validated.get("rate_limit", 50)), 500))),
        ]
        tags = validated.get("tags", "").strip()
        if tags:
            if not SAFE_TEMPLATE_TAG_RE.match(tags):
                raise PolicyViolationError(f"Invalid Nuclei tag filter: {tags}", code="INVALID_ARGUMENT")
            argv.extend(["-tags", tags])
        return argv

    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        matches: List[Dict[str, Any]] = []
        findings: List[Finding] = []
        sev_map = {
            "info": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
                matches.append(item)
                info = item.get("info", {})
                raw_sev = str(info.get("severity", "info")).lower()
                sev = sev_map.get(raw_sev, Severity.INFO)
                template_id = item.get("template-id", "unknown-template")
                matched_at = item.get("matched-at", arguments.get("target", ""))
                findings.append(
                    Finding(
                        finding_id=new_id("find"),
                        engagement_id=engagement_id,
                        job_id=job_id,
                        title=f"[{template_id}] {info.get('name', template_id)}",
                        severity=sev,
                        state=FindingState.CANDIDATE,
                        target=matched_at,
                        capability_id=self.descriptor.capability_id,
                        description=info.get("description") or f"Nuclei template '{template_id}' matched at {matched_at}.",
                        remediation=info.get("remediation", ""),
                        confidence=0.85,
                    )
                )
            except json.JSONDecodeError:
                continue
        return {"matches": matches, "count": len(matches)}, findings


# ============================================================================
# 5. BUILT-IN JWT & API SCHEMA SECURITY ANALYZERS
# ============================================================================


class JwtAnalyzerAdapter(ToolAdapter):
    descriptor = CapabilityDescriptor(
        capability_id="api.jwt_analyzer",
        name="JWT Security Analyzer",
        category="api",
        pack="core",
        description="Inspects JWT header/claims for alg:none, weak algorithms, missing expiry, and sensitive claim exposure.",
        binary_name=None,
        risk_level=RiskLevel.PASSIVE,
        side_effects=SideEffectClass.LOCAL_COMPUTE,
        requires_network=False,
        operations={
            "analyze": {
                "description": "Decode and audit a JWT token without leaking secrets externally.",
                "required": ["token"],
                "parameters": {
                    "token": {"type": "string", "description": "Encoded JWT string (header.payload.signature)"},
                    "target": {"type": "string", "default": "jwt-token", "description": "Logical asset identifier"},
                },
            }
        },
        examples=[{"operation": "analyze", "arguments": {"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}}],
    )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        t = arguments.get("target", "jwt-token")
        return [t] if t and t != "jwt-token" else []

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        return ["builtin:jwt_analyzer", "analyze"]

    def execute_direct(
        self,
        operation: str,
        arguments: Dict[str, Any],
        timeout: int = 10,
        scope: Optional[ScopePolicy] = None,
        policy: Optional[PolicyEngine] = None,
    ) -> Optional[ExecutionResult]:
        import base64 as _b64

        validated = self.validate_arguments(operation, arguments)
        tok = validated["token"].strip()
        parts = tok.split(".")
        if len(parts) < 2:
            return ExecutionResult(
                success=False,
                return_code=1,
                stdout="",
                stderr="Malformed JWT: expected at least header.payload",
                execution_time=0.001,
                argv=["builtin:jwt_analyzer"],
            )

        def _b64_json(segment: str) -> Dict[str, Any]:
            padded = segment + "=" * (-len(segment) % 4)
            raw = _b64.urlsafe_b64decode(padded.encode("ascii"))
            return json.loads(raw.decode("utf-8", errors="replace"))

        try:
            header = _b64_json(parts[0])
            claims = _b64_json(parts[1])
            signature_present = len(parts) >= 3 and bool(parts[2])
            issues: List[Dict[str, str]] = []
            alg = str(header.get("alg", "")).lower()
            if alg == "none" or not signature_present:
                issues.append(
                    {
                        "id": "JWT_ALG_NONE",
                        "severity": "critical",
                        "title": "JWT allows unsigned tokens (alg: none or missing signature)",
                    }
                )
            elif alg in ("hs256", "hs384", "hs512"):
                issues.append(
                    {
                        "id": "JWT_SYMMETRIC_ALG",
                        "severity": "info",
                        "title": f"Symmetric HMAC algorithm ({alg.upper()}) in use; verify key entropy",
                    }
                )
            if "exp" not in claims:
                issues.append(
                    {
                        "id": "JWT_MISSING_EXP",
                        "severity": "medium",
                        "title": "JWT payload omits expiration ('exp') claim",
                    }
                )
            if "jku" in header or "x5u" in header:
                issues.append(
                    {
                        "id": "JWT_EXTERNAL_KEY_URL",
                        "severity": "high",
                        "title": "JWT header specifies external key URL (jku/x5u) susceptible to SSRF/key spoofing",
                    }
                )
            out = {
                "header": header,
                "claims": claims,
                "signature_present": signature_present,
                "issues": issues,
            }
            return ExecutionResult(
                success=True,
                return_code=0,
                stdout=json.dumps(out),
                stderr="",
                execution_time=0.002,
                argv=["builtin:jwt_analyzer"],
            )
        except Exception as exc:
            return ExecutionResult(
                success=False,
                return_code=1,
                stdout="",
                stderr=f"Failed to decode JWT: {exc}",
                execution_time=0.001,
                argv=["builtin:jwt_analyzer"],
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
        findings: List[Finding] = []
        sev_map = {
            "info": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        for issue in data.get("issues", []):
            sev = sev_map.get(issue["severity"], Severity.INFO)
            findings.append(
                Finding(
                    finding_id=new_id("find"),
                    engagement_id=engagement_id,
                    job_id=job_id,
                    title=issue["title"],
                    severity=sev,
                    state=(
                        FindingState.VALIDATED
                        if issue["id"] in ("JWT_ALG_NONE", "JWT_MISSING_EXP", "JWT_EXTERNAL_KEY_URL")
                        else FindingState.OBSERVATION
                    ),
                    target=arguments.get("target", "jwt-token"),
                    capability_id=self.descriptor.capability_id,
                    description=f"JWT static audit identified {issue['id']}: {issue['title']}.",
                    remediation="Enforce strong asymmetric or high-entropy algorithms, reject 'alg: none', and require 'exp' claims.",
                    wstg_id="WSTG-SESS-10",
                    confidence=0.98,
                    negative_control_verified=True,
                )
            )
        return data, findings


# ============================================================================
# 6. DEEP STRUCTURED PARSERS FOR CLI ADAPTERS
# ============================================================================

GOBUSTER_LINE_RE = re.compile(r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)(?:\s+\[Size:\s*(?P<size>\d+)\])?")


def parse_structured_cli_output(
    capability_id: str,
    stdout: str,
    target_str: str,
    engagement_id: str,
    job_id: str,
    wstg_id: str,
) -> Tuple[Dict[str, Any], List[Finding]]:
    findings: List[Finding] = []
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]

    # JSON output tools (trivy, checkov, exiftool, ffuf json)
    if capability_id not in ("web.ffuf", "web.feroxbuster") and stdout.lstrip().startswith(("{", "[")):
        try:
            parsed_json = json.loads(stdout)
            if capability_id == "cloud.trivy" and isinstance(parsed_json, dict):
                vulns = []
                misconfigurations = []
                for res_block in parsed_json.get("Results", []):
                    for v in res_block.get("Vulnerabilities", []) or []:
                        vulns.append(v)
                        vid = v.get("VulnerabilityID", "UNKNOWN")
                        sev_str = str(v.get("Severity", "LOW")).lower()
                        sev = Severity(sev_str) if sev_str in {"info", "low", "medium", "high", "critical"} else Severity.LOW
                        findings.append(
                            Finding(
                                finding_id=new_id("find"),
                                engagement_id=engagement_id,
                                job_id=job_id,
                                title=f"Trivy {vid} in {v.get('PkgName', 'package')}",
                                severity=sev,
                                state=FindingState.CANDIDATE,
                                target=target_str,
                                capability_id=capability_id,
                                description=v.get("Title") or v.get("Description", f"Detected {vid}"),
                                cve_id=vid if vid.startswith("CVE-") else None,
                                remediation=f"Upgrade to {v.get('FixedVersion', 'patched version')}",
                                wstg_id=wstg_id,
                            )
                        )
                    for issue in res_block.get("Misconfigurations", []) or []:
                        if not isinstance(issue, dict) or issue.get("Status") != "FAIL":
                            continue
                        misconfigurations.append(issue)
                        severity = str(issue.get("Severity", "LOW")).lower()
                        findings.append(Finding(
                            finding_id=new_id("find"), engagement_id=engagement_id, job_id=job_id,
                            title=f"Trivy {issue.get('ID', 'UNKNOWN')}: {issue.get('Title', 'Misconfiguration')}",
                            severity=Severity(severity) if severity in {"info", "low", "medium", "high", "critical"} else Severity.LOW,
                            state=FindingState.CANDIDATE,
                            target=str(res_block.get("Target") or target_str), capability_id=capability_id,
                            description=str(issue.get("Message") or issue.get("Description") or "Failed configuration check"),
                            remediation=str(issue.get("Resolution") or ""), wstg_id=wstg_id,
                        ))
                return {"results": parsed_json.get("Results", []), "vulnerability_count": len(vulns),
                        "misconfiguration_count": len(misconfigurations)}, findings
            if capability_id == "binary.checksec" and isinstance(parsed_json, dict):
                for bin_name, props in parsed_json.items():
                    if isinstance(props, dict):
                        missing_mitigations = [
                            k for k in ("relro", "canary", "nx", "pie")
                            if str(props.get(k, "")).lower() in ("no", "false", "disabled", "none")
                        ]
                        if missing_mitigations:
                            findings.append(
                                Finding(
                                    finding_id=new_id("find"),
                                    engagement_id=engagement_id,
                                    job_id=job_id,
                                    title=f"Missing Binary Mitigations ({', '.join(missing_mitigations)}) in {bin_name}",
                                    severity=Severity.LOW,
                                    state=FindingState.OBSERVATION,
                                    target=target_str,
                                    capability_id=capability_id,
                                    description=f"Checksec reported disabled hardening mitigations: {missing_mitigations}",
                                    remediation="Compile with full RELRO (-Wl,-z,relro,-z,now), stack protector (-fstack-protector-strong), NX, and PIE.",
                                    wstg_id=wstg_id,
                                )
                            )
                return {"checksec": parsed_json}, findings
            if capability_id == "cloud.checkov" and isinstance(parsed_json, (dict, list)):
                reports = parsed_json if isinstance(parsed_json, list) else [parsed_json]
                failed_checks = []
                for report in reports:
                    if isinstance(report, dict) and isinstance(report.get("results"), dict):
                        checks = report["results"].get("failed_checks")
                        if isinstance(checks, list):
                            failed_checks.extend(checks)
                for chk in failed_checks:
                    if isinstance(chk, dict):
                        cid = chk.get("check_id", "CKV_UNKNOWN")
                        cname = chk.get("check_name", "IaC Misconfiguration")
                        findings.append(
                            Finding(
                                finding_id=new_id("find"),
                                engagement_id=engagement_id,
                                job_id=job_id,
                                title=f"Checkov {cid}: {cname}",
                                severity=Severity.MEDIUM,
                                state=FindingState.CANDIDATE,
                                target=str(chk.get("file_path") or target_str),
                                capability_id=capability_id,
                                description=f"IaC check {cid} ({cname}) failed on resource {chk.get('resource', 'unknown')}.",
                                wstg_id=wstg_id,
                            )
                        )
                return {"failed_checks": failed_checks, "failed_count": len(failed_checks)}, findings
            if capability_id == "forensics.exiftool" and isinstance(parsed_json, list):
                sensitive_keys = {"GPSLatitude", "GPSLongitude", "Author", "Creator", "Producer", "SerialNumber"}
                exposed_meta: Dict[str, Any] = {}
                for item in parsed_json:
                    if isinstance(item, dict):
                        for sk in sensitive_keys:
                            if sk in item and item[sk]:
                                exposed_meta[sk] = item[sk]
                if exposed_meta:
                    findings.append(
                        Finding(
                            finding_id=new_id("find"),
                            engagement_id=engagement_id,
                            job_id=job_id,
                            title=f"Metadata Exposure in {target_str} ({', '.join(sorted(exposed_meta.keys()))})",
                            severity=Severity.LOW if "GPSLatitude" in exposed_meta else Severity.INFO,
                            state=FindingState.OBSERVATION,
                            target=target_str,
                            capability_id=capability_id,
                            description=f"ExifTool extracted sensitive metadata fields: {sorted(exposed_meta.keys())}",
                            wstg_id=wstg_id,
                        )
                    )
                return {"metadata": parsed_json, "exposed_fields": exposed_meta}, findings
            return {"data": parsed_json, "line_count": len(lines)}, findings
        except json.JSONDecodeError:
            pass

    # Gobuster / Feroxbuster directory discovery parsing
    if capability_id in ("web.gobuster", "web.feroxbuster", "web.ffuf"):
        discovered_paths: List[Dict[str, Any]] = []
        for ln in lines:
            m = GOBUSTER_LINE_RE.match(ln)
            entry = None
            if m:
                entry = {
                    "path": "/" + m.group("path").lstrip("/"),
                    "status": int(m.group("status")),
                    "size": int(m.group("size") or 0),
                }
            elif capability_id in ("web.ffuf", "web.feroxbuster"):
                try:
                    record = json.loads(ln)
                    if capability_id == "web.feroxbuster" and record.get("type") != "response":
                        continue
                    endpoint = urllib.parse.urlsplit(record["url"])
                    entry = {"path": endpoint.path or "/", "url": record["url"],
                             "status": int(record["status"]),
                             "size": int(record.get("length", record.get("content_length", 0)))}
                except (ValueError, KeyError, TypeError):
                    continue
            if entry is not None:
                discovered_paths.append(entry)
                if entry["status"] in (200, 204, 301, 302, 401, 403):
                    findings.append(
                        Finding(
                            finding_id=new_id("find"),
                            engagement_id=engagement_id,
                            job_id=job_id,
                            title=f"Discovered Endpoint {entry['path']} (HTTP {entry['status']})",
                            severity=Severity.LOW if entry["path"] in ("/.env", "/admin", "/.git") else Severity.INFO,
                            state=FindingState.CANDIDATE if entry["path"] in ("/.env", "/.git") else FindingState.OBSERVATION,
                            target=entry.get("url") or urllib.parse.urljoin(target_str.rstrip('/') + '/', entry['path']),
                            capability_id=capability_id,
                            description=f"Content discovery identified {entry['path']} returning status {entry['status']}.",
                            wstg_id="WSTG-CONFIG-04",
                        )
                    )
        return {"discovered_endpoints": discovered_paths, "line_count": len(lines)}, findings

    # Subfinder / DNS enumeration parsing
    if capability_id in ("network.subfinder", "network.dnsenum"):
        hosts = [ln for ln in lines if "." in ln and " " not in ln]
        for h in hosts[:50]:
            findings.append(
                Finding(
                    finding_id=new_id("find"),
                    engagement_id=engagement_id,
                    job_id=job_id,
                    title=f"Discovered Subdomain: {h}",
                    severity=Severity.INFO,
                    state=FindingState.OBSERVATION,
                    target=h,
                    capability_id=capability_id,
                    description=f"Subdomain enumeration discovered host '{h}'.",
                    wstg_id="WSTG-INFO-04",
                )
            )
        return {"subdomains": hosts, "count": len(hosts)}, findings

    # SQLMap injection confirmation parser
    if capability_id == "web.sqlmap":
        injectable_params = re.findall(
            r"(?m)^Parameter: [^\n]+\n(?:[ \t]+[^\n]*\n?)+", stdout
        )
        injectable_params = [block.strip() for block in injectable_params if re.search(r"(?m)^\s+Type:", block)]
        if injectable_params:
            findings.append(
                Finding(
                    finding_id=new_id("find"),
                    engagement_id=engagement_id,
                    job_id=job_id,
                    title=f"SQL Injection Candidate on {target_str}",
                    severity=Severity.HIGH,
                    state=FindingState.CANDIDATE,
                    target=target_str,
                    capability_id=capability_id,
                    description="\n".join(injectable_params[:10]),
                    remediation="Use parameterized queries / prepared statements.",
                    wstg_id="WSTG-INPV-05",
                )
            )
        return {"injectable_indicators": injectable_params, "line_count": len(lines)}, findings

    # Nikto web server findings parser
    if capability_id == "web.nikto":
        reported = [ln[2:].strip() for ln in lines if ln.startswith("+ ")]
        nikto_items = [item for item in reported if re.match(r"^(?:\[\d+\]|OSVDB-\d+|/)", item)]
        notes = [item for item in reported if item not in nikto_items]
        for item in nikto_items[:25]:
            findings.append(
                Finding(
                    finding_id=new_id("find"),
                    engagement_id=engagement_id,
                    job_id=job_id,
                    title=f"Nikto Observation: {item[:80]}",
                    severity=Severity.LOW,
                    state=FindingState.OBSERVATION,
                    target=target_str,
                    capability_id=capability_id,
                    description=item,
                    wstg_id="WSTG-CONF-04",
                )
            )
        return {"nikto_observations": nikto_items[:100], "count": len(nikto_items), "scanner_notes": notes[:25]}, findings

    # WAFW00F firewall detection parser
    if capability_id == "web.wafw00f":
        waf_name: Optional[str] = None
        for ln in lines:
            m_waf = re.search(r"is behind\s+(.+?)(?:\s+WAF|\s*$)", ln, re.IGNORECASE)
            if m_waf:
                waf_name = m_waf.group(1).strip()
                break
        if waf_name:
            findings.append(
                Finding(
                    finding_id=new_id("find"),
                    engagement_id=engagement_id,
                    job_id=job_id,
                    title=f"WAF Detected: {waf_name}",
                    severity=Severity.INFO,
                    state=FindingState.OBSERVATION,
                    target=target_str,
                    capability_id=capability_id,
                    description=f"WAFW00F identified Web Application Firewall: {waf_name}",
                    wstg_id="WSTG-INFO-08",
                )
            )
        return {"waf_detected": waf_name is not None, "waf_name": waf_name, "line_count": len(lines)}, findings

    # Katana crawler URL extraction
    if capability_id == "web.katana":
        urls = [ln for ln in lines if ln.startswith(("http://", "https://"))]
        return {"endpoints": urls, "count": len(urls)}, findings

    # Masscan / RustScan open port parsing
    if capability_id in ("network.masscan", "network.rustscan"):
        open_ports: List[Dict[str, Any]] = []
        for ln in lines:
            m_mass = re.search(r"Discovered open port\s+(\d+)/(tcp|udp)\s+on\s+(\S+)", ln, re.IGNORECASE)
            if m_mass:
                p_num = int(m_mass.group(1))
                proto = m_mass.group(2).lower()
                host_ip = m_mass.group(3)
                open_ports.append({"host": host_ip, "port": p_num, "protocol": proto})
            m_rust = re.search(r"(\S+)\s*->\s*\[([0-9,\s]+)\]", ln)
            if m_rust:
                host_ip = m_rust.group(1)
                for p_tok in m_rust.group(2).split(","):
                    if p_tok.strip().isdigit():
                        open_ports.append({"host": host_ip, "port": int(p_tok.strip()), "protocol": "tcp"})
        for op in open_ports[:50]:
            findings.append(
                Finding(
                    finding_id=new_id("find"),
                    engagement_id=engagement_id,
                    job_id=job_id,
                    title=f"Open Port {op['port']}/{op['protocol']} on {op['host']}",
                    severity=Severity.INFO,
                    state=FindingState.OBSERVATION,
                    target=f"{op['host']}:{op['port']}",
                    capability_id=capability_id,
                    description=f"Fast port discovery observed open port {op['port']}/{op['protocol']}.",
                    wstg_id="WSTG-INFO-02",
                )
            )
        return {"open_ports": open_ports, "count": len(open_ports)}, findings

    # Binary strings extraction
    if capability_id == "binary.strings":
        urls_found = [ln for ln in lines if "http://" in ln or "https://" in ln]
        return {"strings_count": len(lines), "urls_found": urls_found[:50], "sample_strings": lines[:100]}, findings

    return {
        "line_count": len(lines),
        "sample_lines": lines[:50],
    }, findings


class StandardCliScannerAdapter(ToolAdapter):
    """
    Parameterized, schema-validated CLI adapter for recognized security binaries
    with structured output parsing.
    """

    def __init__(
        self,
        capability_id: str,
        name: str,
        category: str,
        pack: str,
        binary_name: str,
        description: str,
        argv_builder_fn: Any,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        side_effects: SideEffectClass = SideEffectClass.ACTIVE_SCAN,
        parameters: Optional[Dict[str, Any]] = None,
        required: Optional[List[str]] = None,
        requires_network: bool = True,
        wstg_id: str = "WSTG-INFO-01",
        scalar_value_flags: Sequence[str] = (),
    ) -> None:
        self.input_file_parameters = ("target",) if category in ("binary", "forensics") else ()
        self._argv_builder_fn = argv_builder_fn
        self._wstg_id = wstg_id
        self._scalar_value_flags = tuple(scalar_value_flags)
        params = parameters or {
            "target": {"type": "string", "description": "Target host, URL, or workspace artifact"},
            "extra_flags": {"type": "array", "default": [], "description": "Safe additional CLI option flags"},
        }
        reqs = required or ["target"]
        self.descriptor = CapabilityDescriptor(
            capability_id=capability_id,
            name=name,
            category=category,
            pack=pack,
            description=description,
            binary_name=binary_name,
            risk_level=risk_level,
            side_effects=side_effects,
            requires_network=requires_network,
            requires_root=binary_name == "masscan",
            operations={
                "run": {
                    "description": description,
                    "required": reqs,
                    "parameters": params,
                }
            },
            examples=[{"operation": "run", "arguments": {reqs[0]: "samples/input.bin" if self.input_file_parameters else "127.0.0.1"}}],
        )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        if not self.descriptor.requires_network:
            return []
        for k in ("target", "url", "domain"):
            if k in arguments and arguments[k]:
                return [str(arguments[k])]
        return []

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        validated = self.validate_arguments(operation, arguments)
        exe = binary_path or self.descriptor.binary_name or "tool"
        extra = validate_safe_extra_flags(validated.get("extra_flags"), scalar_value_flags=self._scalar_value_flags)
        return self._argv_builder_fn(exe, validated, extra)

    def execution_succeeded(self, result: ExecutionResult) -> bool:
        if result.success or self.descriptor.capability_id != "cloud.checkov":
            return result.success
        if result.return_code != 1 or result.timed_out or result.cancelled or result.truncated:
            return False
        # Checkov uses exit code 1 for completed scans containing failed checks.
        # Only accept that contract when every framework has a complete, error-free report.
        try:
            payload = json.loads(result.stdout)
        except (ValueError, TypeError):
            return False
        reports = payload if isinstance(payload, list) else [payload]
        if not reports:
            return False
        failed_count = 0
        for report in reports:
            if not isinstance(report, dict):
                return False
            summary, results = report.get("summary"), report.get("results")
            if not isinstance(summary, dict) or not isinstance(results, dict):
                return False
            checks = results.get("failed_checks")
            if (not isinstance(checks, list) or summary.get("parsing_errors") != 0
                    or summary.get("failed") != len(checks)):
                return False
            if any(not isinstance(check, dict) or not check.get("check_id")
                   or not isinstance(check.get("check_result"), dict)
                   or check["check_result"].get("result") != "FAILED" for check in checks):
                return False
            failed_count += len(checks)
        return failed_count > 0

    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        target_str = str(
            arguments.get("target") or arguments.get("url") or arguments.get("domain") or "workspace"
        )
        structured, findings = parse_structured_cli_output(
            capability_id=self.descriptor.capability_id,
            stdout=result.stdout,
            target_str=target_str,
            engagement_id=engagement_id,
            job_id=job_id,
            wstg_id=self._wstg_id,
        )
        structured["return_code"] = result.return_code
        return structured, findings


# ============================================================================
# 7. CUSTOM DECLARATIVE ADAPTER MANIFEST SDK
# ============================================================================


@dataclass
class CustomAdapterManifest:
    capability_id: str
    name: str
    category: str
    binary_name: str
    description: str
    arg_template: List[str]
    parameters: Dict[str, Dict[str, Any]]
    required: List[str] = field(default_factory=lambda: ["target"])
    risk_level: str = "medium"
    requires_network: bool = True
    version: str = "1.0.0"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CustomAdapterManifest":
        if not isinstance(data, dict):
            raise ValueError("Custom adapter manifest must be a JSON object")
        allowed_keys = {
            "capability_id",
            "name",
            "category",
            "binary_name",
            "description",
            "arg_template",
            "parameters",
            "required",
            "risk_level",
            "requires_network",
            "version",
        }
        unknown_keys = set(data.keys()) - allowed_keys
        if unknown_keys:
            raise ValueError(f"Unknown fields in custom adapter manifest: {sorted(unknown_keys)}")

        required_keys = {"capability_id", "name", "category", "binary_name", "description", "arg_template", "parameters"}
        missing = required_keys - set(data.keys())
        if missing:
            raise ValueError(f"Custom adapter manifest missing fields: {sorted(missing)}")
        if not re.match(r"^[a-z0-9_]+\.[a-z0-9_]+$", str(data["capability_id"])):
            raise ValueError("capability_id must follow '<pack>.<name>' lowercase format")
        if not isinstance(data["arg_template"], list) or not all(isinstance(x, str) for x in data["arg_template"]):
            raise ValueError("arg_template must be a list of strings")
        for token in data["arg_template"]:
            if any(ch in token for ch in (";", "|", "&", "`", "$(")):
                raise ValueError(f"Unsafe shell token in arg_template: {token}")
        if not isinstance(data["parameters"], dict):
            raise ValueError("parameters must be a dictionary of parameter schemas")
        for key in ("capability_id", "name", "category", "binary_name", "description"):
            if not isinstance(data[key], str) or not data[key].strip() or any(ord(c) < 32 for c in data[key]):
                raise ValueError(f"Manifest {key} must be a nonempty string without control characters")
        if "requires_network" in data and not isinstance(data["requires_network"], bool):
            raise ValueError("requires_network must be a boolean")
        required = data.get("required", ["target"])
        if not isinstance(required, list) or not all(isinstance(k, str) and k in data["parameters"] for k in required):
            raise ValueError("required must name declared parameters")
        for name, spec in data["parameters"].items():
            if not isinstance(name, str) or not isinstance(spec, dict) or spec.get("type") not in ("string", "integer", "boolean", "array"):
                raise ValueError("Each parameter needs a supported typed schema")
        for token in data["arg_template"]:
            if any(ord(c) < 32 for c in token):
                raise ValueError("Control characters are forbidden in arg_template")
            for name in re.findall(r"\{([a-zA-Z_][a-zA-Z_0-9]*)\}", token):
                if name not in data["parameters"]:
                    raise ValueError(f"Undeclared template parameter: {name}")
                if name not in required and "default" not in data["parameters"][name]:
                    raise ValueError(f"Template parameter {name} must be required or have a default")
        RiskLevel(str(data.get("risk_level", "medium")).lower())
        return cls(
            capability_id=data["capability_id"],
            name=data["name"],
            category=data["category"],
            binary_name=data["binary_name"],
            description=data["description"],
            arg_template=list(data["arg_template"]),
            parameters=dict(data["parameters"]),
            required=list(data.get("required", ["target"])),
            risk_level=str(data.get("risk_level", "medium")),
            requires_network=bool(data.get("requires_network", True)),
            version=str(data.get("version", "1.0.0")),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "name": self.name,
            "category": self.category,
            "binary_name": self.binary_name,
            "description": self.description,
            "arg_template": self.arg_template,
            "parameters": self.parameters,
            "required": self.required,
            "risk_level": self.risk_level,
            "requires_network": self.requires_network,
            "version": self.version,
        }


class DeclarativeCustomAdapter(ToolAdapter):
    """Safe declarative custom adapter with zero arbitrary code evaluation."""

    def __init__(self, manifest: CustomAdapterManifest) -> None:
        self.manifest = manifest
        self.descriptor = CapabilityDescriptor(
            capability_id=manifest.capability_id,
            name=manifest.name,
            category=manifest.category,
            pack="custom",
            description=manifest.description,
            binary_name=manifest.binary_name,
            risk_level=RiskLevel(manifest.risk_level.lower()),
            side_effects=SideEffectClass.ACTIVE_SCAN if manifest.requires_network else SideEffectClass.LOCAL_COMPUTE,
            requires_network=manifest.requires_network,
            operations={
                "run": {
                    "description": manifest.description,
                    "required": manifest.required,
                    "parameters": manifest.parameters,
                }
            },
        )

    def extract_targets(self, operation: str, arguments: Dict[str, Any]) -> List[str]:
        if not self.manifest.requires_network:
            return []
        if "target" in arguments and arguments["target"]:
            return [str(arguments["target"])]
        return []

    def build_argv(self, operation: str, arguments: Dict[str, Any], binary_path: Optional[str] = None) -> List[str]:
        validated = self.validate_arguments(operation, arguments)
        if "target" in validated and self.manifest.requires_network:
            canonicalize_target(str(validated["target"]))
        exe = binary_path or self.manifest.binary_name
        argv = [exe]
        for tmpl in self.manifest.arg_template:
            rendered = tmpl
            for k, v in validated.items():
                placeholder = "{" + k + "}"
                if placeholder in rendered:
                    str_v = str(v)
                    if any(ch in str_v for ch in ("\x00", "\n", "\r", ";", "|", "&", "`")):
                        raise PolicyViolationError(f"Unsafe characters in parameter '{k}'", code="ARGUMENT_INJECTION_BLOCKED")
                    if str_v.startswith("-"):
                        raise PolicyViolationError(f"Option injection blocked in parameter '{k}'", code="OPTION_INJECTION_BLOCKED")
                    rendered = rendered.replace(placeholder, str_v)
            argv.append(rendered)
        return argv

    def parse_output(
        self,
        operation: str,
        arguments: Dict[str, Any],
        result: ExecutionResult,
        engagement_id: str,
        job_id: str,
    ) -> Tuple[Dict[str, Any], List[Finding]]:
        lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        return {"lines": lines[:100], "line_count": len(lines)}, []


def build_default_adapters() -> List[ToolAdapter]:
    adapters: List[ToolAdapter] = [
        NmapAdapter(),
        HttpInspectAdapter(),
        HttpxProbeAdapter(),
        NucleiAdapter(),
        JwtAnalyzerAdapter(),
    ]

    cli_specs = [
        (
            "web.gobuster",
            "Gobuster Directory & DNS Scanner",
            "web",
            "web",
            "gobuster",
            "Directory, vhost, and DNS enumeration with safe wordlist arguments.",
            lambda exe, args, extra: [
                exe,
                args.get("mode", "dir"),
                "-u",
                canonicalize_target(args["target"]).raw,
                "-w",
                args.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                "-q",
                "--no-progress",
                *extra,
            ],
            RiskLevel.MEDIUM,
            {
                "target": {"type": "string", "description": "Target URL or domain"},
                "mode": {"type": "string", "enum": ["dir", "dns", "vhost"], "default": "dir"},
                "wordlist": {"type": "string", "default": "/usr/share/wordlists/dirb/common.txt"},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "web.ffuf",
            "FFUF Web Fuzzer",
            "web",
            "web",
            "ffuf",
            "Fast web fuzzer for directories, parameters, and virtual hosts.",
            lambda exe, args, extra: [
                exe,
                "-u",
                canonicalize_target(args["target"]).raw,
                "-w",
                args.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                "-s",
                "-json",
                *extra,
            ],
            RiskLevel.MEDIUM,
            {
                "target": {"type": "string", "description": "Target URL (with FUZZ keyword if applicable)"},
                "wordlist": {"type": "string", "default": "/usr/share/wordlists/dirb/common.txt"},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "web.feroxbuster",
            "Feroxbuster Recursive Content Discovery",
            "web",
            "web",
            "feroxbuster",
            "Recursive web content discovery scanner.",
            lambda exe, args, extra: [
                exe,
                "-u",
                canonicalize_target(args["target"]).raw,
                "--silent",
                "--no-state",
                "--json",
                "--wordlist",
                args.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                *extra,
            ],
            RiskLevel.MEDIUM,
            {
                "target": {"type": "string", "description": "Target URL"},
                "wordlist": {"type": "string", "default": "/usr/share/wordlists/dirb/common.txt"},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "web.nikto",
            "Nikto Web Server Scanner",
            "web",
            "web",
            "nikto",
            "Web server misconfiguration and dangerous file scanner.",
            lambda exe, args, extra: [
                exe,
                "-h",
                canonicalize_target(args["target"]).raw,
                "-ask",
                "no",
                *(["-Tuning", args["tuning"]] if args.get("tuning", "all") != "all" else []),
                "-maxtime", str(args.get("max_time", 60)) + "s",
                "-timeout", str(args.get("request_timeout", 5)),
                *extra,
            ],
            RiskLevel.MEDIUM,
            {
                "target": {"type": "string", "description": "Target URL"},
                "tuning": {"type": "string", "enum": ["all","0","1","2","3","4","5","6","7","8","9","a","b","c","x"], "default": "all"},
                "max_time": {"type": "integer", "default": 60, "minimum": 1, "maximum": 3600},
                "request_timeout": {"type": "integer", "default": 5, "minimum": 1, "maximum": 60},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "web.sqlmap",
            "SQLMap Batch Parameter Auditor",
            "web",
            "web",
            "sqlmap",
            "Automated SQL injection detection in non-interactive batch mode (OS shell flags blocked).",
            lambda exe, args, extra: [
                exe,
                "-u",
                canonicalize_target(args["target"]).raw,
                "--batch",
                "--level",
                str(args.get("level", 1)),
                "--risk",
                str(args.get("risk", 1)),
                *extra,
            ],
            RiskLevel.HIGH,
            {
                "target": {"type": "string", "description": "Target URL with query parameters"},
                "level": {"type": "integer", "default": 1},
                "risk": {"type": "integer", "default": 1},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "web.wafw00f",
            "WAFW00F Firewall Fingerprinter",
            "web",
            "web",
            "wafw00f",
            "Web Application Firewall detection utility.",
            lambda exe, args, extra: [exe, canonicalize_target(args["target"]).raw, *extra],
            RiskLevel.LOW,
            None,
        ),
        (
            "web.katana",
            "Katana Web Crawler",
            "web",
            "web",
            "katana",
            "ProjectDiscovery crawling and endpoint discovery tool.",
            lambda exe, args, extra: [
                exe,
                "-u",
                canonicalize_target(args["target"]).raw,
                "-silent",
                "-nc",
                *extra,
            ],
            RiskLevel.LOW,
            None,
        ),
        (
            "network.subfinder",
            "Subfinder Subdomain Discovery",
            "network",
            "network",
            "subfinder",
            "Passive subdomain enumeration tool.",
            lambda exe, args, extra: [
                exe,
                "-d",
                canonicalize_target(args["target"]).host,
                "-silent",
                *extra,
            ],
            RiskLevel.PASSIVE,
            None,
        ),
        (
            "network.rustscan",
            "RustScan Fast Port Discovery",
            "network",
            "network",
            "rustscan",
            "High-speed port discovery tool.",
            lambda exe, args, extra: [
                exe,
                "-a",
                canonicalize_target(args["target"]).host,
                "-g",
                *extra,
            ],
            RiskLevel.MEDIUM,
            None,
        ),
        (
            "network.masscan",
            "Masscan Network Scanner",
            "network",
            "network",
            "masscan",
            "Asynchronous TCP port scanner.",
            lambda exe, args, extra: [
                exe,
                canonicalize_target(args["target"]).host,
                "-p",
                args.get("ports", "80,443"),
                "--rate",
                str(min(int(args.get("rate", 500)), 5000)),
                *extra,
            ],
            RiskLevel.HIGH,
            {
                "target": {"type": "string", "description": "Target IP or CIDR"},
                "ports": {"type": "string", "default": "80,443"},
                "rate": {"type": "integer", "default": 500},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "binary.checksec",
            "Checksec Binary Hardening Inspector",
            "binary",
            "binary",
            "checksec",
            "Inspects ELF/Mach-O binary mitigations (RELRO, Canary, NX, PIE).",
            lambda exe, args, extra: [exe, "--output=json", f"--file={args['target']}", *extra],
            RiskLevel.PASSIVE,
            {
                "target": {"type": "string", "description": "Workspace relative binary path"},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "binary.strings",
            "Strings Printable Sequence Extractor",
            "binary",
            "binary",
            "strings",
            "Extracts printable strings from a file inside the workspace.",
            lambda exe, args, extra: [exe, "-n", str(args.get("min_len", 6)), "--", args["target"]],
            RiskLevel.PASSIVE,
            {
                "target": {"type": "string", "description": "Workspace file path"},
                "min_len": {"type": "integer", "default": 6},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "forensics.exiftool",
            "ExifTool Metadata Inspector",
            "forensics",
            "forensics",
            "exiftool",
            "Extracts document and media metadata.",
            lambda exe, args, extra: [exe, "-j", "--", args["target"]],
            RiskLevel.PASSIVE,
            {
                "target": {"type": "string", "description": "Workspace file path"},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "cloud.trivy",
            "Trivy Container & Filesystem Scanner",
            "cloud",
            "cloud",
            "trivy",
            "Vulnerability and misconfiguration scanner for containers and IaC.",
            lambda exe, args, extra: [
                exe,
                args.get("scan_mode", "fs"),
                "--quiet",
                "--format",
                "json",
                args["target"],
            ],
            RiskLevel.LOW,
            {
                "target": {"type": "string", "description": "Target path or image reference"},
                "scan_mode": {"type": "string", "enum": ["fs", "config", "image"], "default": "fs"},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
        (
            "cloud.checkov",
            "Checkov IaC Static Analyzer",
            "cloud",
            "cloud",
            "checkov",
            "Static analysis for Terraform, Kubernetes, and CloudFormation manifests.",
            lambda exe, args, extra: [exe, "-d", args["target"], "--quiet", "--compact", "-o", "json"],
            RiskLevel.PASSIVE,
            {
                "target": {"type": "string", "description": "Target directory inside workspace"},
                "extra_flags": {"type": "array", "default": []},
            },
        ),
    ]

    for cid, name, cat, pack, bname, desc, fn, risk, params in cli_specs:
        requires_net = cat in ("web", "network")
        adapters.append(
            StandardCliScannerAdapter(
                capability_id=cid,
                name=name,
                category=cat,
                pack=pack,
                binary_name=bname,
                description=desc,
                argv_builder_fn=fn,
                risk_level=risk,
                side_effects=SideEffectClass.ACTIVE_SCAN if requires_net else SideEffectClass.LOCAL_COMPUTE,
                parameters=params,
                requires_network=requires_net,
                scalar_value_flags=("-d", "--depth") if cid == "web.feroxbuster" else (),
            )
        )

    return adapters
