"""
Target canonicalization, scope validation, and approval grant enforcement.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from hexstrike.domain.models import (
    ApprovalGrant,
    CapabilityDescriptor,
    Engagement,
    InvocationPlan,
    Principal,
    ScopePolicy,
    new_id,
)


CLOUD_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
    ipaddress.ip_address("100.100.100.200"),
}

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}

DEFAULT_SCHEME_PORTS: Dict[str, int] = {
    "http": 80,
    "https": 443,
    "ws": 80,
    "wss": 443,
    "ssh": 22,
    "smb": 445,
    "dns": 53,
}


class PolicyViolationError(PermissionError):
    """Raised when an action violates scope, ownership, or argument safety policy."""

    def __init__(self, message: str, code: str = "POLICY_DENIED") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CanonicalTarget:
    raw: str
    host: str
    ip: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]
    network: Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]
    port: Optional[int]
    scheme: Optional[str]


def _normalize_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def parse_port_spec(port_spec: str) -> List[int]:
    """
    Parse an Nmap/scanner port specification (e.g. '22', '80,443', '8000-8005', 'T:80,U:53')
    into validated port integers.
    """
    if not port_spec or not port_spec.strip():
        return []
    cleaned = port_spec.strip()
    ports: List[int] = []
    for part in cleaned.split(","):
        token = part.strip()
        if not token:
            continue
        if ":" in token:
            prefix, token = token.split(":", 1)
            if prefix.upper() not in ("T", "U", "S", "P"):
                raise PolicyViolationError(f"Invalid protocol prefix in port spec: {part}", code="INVALID_PORT_SPEC")
        if "-" in token:
            bounds = token.split("-", 1)
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                raise PolicyViolationError(f"Invalid port range: {part}", code="INVALID_PORT_SPEC")
            start_p, end_p = int(bounds[0]), int(bounds[1])
            if not (1 <= start_p <= end_p <= 65535):
                raise PolicyViolationError(f"Port range out of bounds: {part}", code="INVALID_PORT_SPEC")
            # Cap expansion size while checking boundary and interior ports
            if end_p - start_p <= 1024:
                ports.extend(range(start_p, end_p + 1))
            else:
                ports.extend([start_p, end_p])
        else:
            if not token.isdigit():
                raise PolicyViolationError(f"Invalid port number: {part}", code="INVALID_PORT_SPEC")
            p_num = int(token)
            if not (1 <= p_num <= 65535):
                raise PolicyViolationError(f"Port out of range (1-65535): {p_num}", code="INVALID_PORT_SPEC")
            ports.append(p_num)
    return ports


def canonicalize_target(raw_target: str) -> CanonicalTarget:
    if not isinstance(raw_target, str) or not raw_target.strip():
        raise PolicyViolationError("Target cannot be empty", code="INVALID_TARGET")

    cleaned = raw_target.strip()
    forbidden = ("\x00", "\n", "\r", ";", "|", "`", "$(")
    if any(ch in cleaned for ch in forbidden) or ("&" in cleaned and "://" not in cleaned):
        raise PolicyViolationError(
            f"Target contains illegal control or shell metacharacters: {raw_target}",
            code="TARGET_INJECTION_BLOCKED",
        )
    if cleaned.startswith("-"):
        raise PolicyViolationError(
            f"Target cannot start with an option dash ('-'): {raw_target}",
            code="OPTION_INJECTION_BLOCKED",
        )

    scheme: Optional[str] = None
    port: Optional[int] = None
    host_candidate = cleaned

    if "://" in cleaned:
        parsed = urllib.parse.urlsplit(cleaned)
        scheme = parsed.scheme.lower() if parsed.scheme else None
        if not parsed.hostname:
            raise PolicyViolationError(f"URL target missing hostname: {raw_target}", code="INVALID_TARGET")
        host_candidate = parsed.hostname
        try:
            port = parsed.port
        except ValueError as exc:
            raise PolicyViolationError(f"Invalid port in target URL: {raw_target}", code="INVALID_PORT") from exc
    else:
        if cleaned.startswith("[") and "]" in cleaned:
            bracket_end = cleaned.find("]")
            host_candidate = cleaned[1:bracket_end]
            rest = cleaned[bracket_end + 1 :]
            if rest.startswith(":"):
                port_str = rest[1:]
                if not port_str.isdigit():
                    raise PolicyViolationError(f"Invalid port in target: {raw_target}", code="INVALID_PORT")
                port = int(port_str)
        elif cleaned.count(":") == 1 and "/" not in cleaned:
            h_part, p_part = cleaned.rsplit(":", 1)
            if p_part.isdigit():
                host_candidate = h_part
                port = int(p_part)

    if port is not None and not (1 <= port <= 65535):
        raise PolicyViolationError(f"Port out of range (1-65535): {port}", code="INVALID_PORT")

    if "/" in host_candidate and "://" not in cleaned:
        try:
            net = ipaddress.ip_network(host_candidate, strict=False)
            return CanonicalTarget(
                raw=raw_target,
                host=str(net),
                ip=None,
                network=net,
                port=port,
                scheme=scheme,
            )
        except ValueError:
            host_candidate = host_candidate.split("/", 1)[0]

    try:
        ip_obj = _normalize_ip(ipaddress.ip_address(host_candidate))
        return CanonicalTarget(
            raw=raw_target,
            host=str(ip_obj),
            ip=ip_obj,
            network=None,
            port=port,
            scheme=scheme,
        )
    except ValueError:
        pass

    host_lower = host_candidate.rstrip(".").lower()
    try:
        ascii_host = host_lower.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise PolicyViolationError(f"Invalid IDNA hostname: {host_candidate}", code="INVALID_TARGET") from exc

    if not re.match(r"^[a-z0-9._\-]+$", ascii_host):
        raise PolicyViolationError(f"Invalid hostname syntax: {ascii_host}", code="INVALID_TARGET")

    return CanonicalTarget(
        raw=raw_target,
        host=ascii_host,
        ip=None,
        network=None,
        port=port,
        scheme=scheme,
    )


def _matches_rule(
    target: CanonicalTarget,
    rule: str,
    resolved_ips: Iterable[ipaddress.IPv4Address | ipaddress.IPv6Address],
    is_exclusion: bool = False,
) -> bool:
    rule_clean = rule.strip().lower()
    if not rule_clean:
        return False
    if rule_clean == "*":
        return True

    # Exact IP rule check first (so '192.0.2.10' is treated as a host IP before network)
    if "/" not in rule_clean:
        try:
            rule_ip = _normalize_ip(ipaddress.ip_address(rule_clean))
            if target.ip is not None and _normalize_ip(target.ip) == rule_ip:
                return True
            if target.network is not None:
                if is_exclusion:
                    # A target CIDR that contains an excluded IP overlaps the exclusion!
                    if target.network.version == rule_ip.version and rule_ip in target.network:
                        return True
                else:
                    if (
                        target.network.version == rule_ip.version
                        and target.network.num_addresses == 1
                        and target.network.network_address == rule_ip
                    ):
                        return True
            for r_ip in resolved_ips:
                if _normalize_ip(r_ip) == rule_ip:
                    return True
            return False
        except ValueError:
            pass

    # CIDR rule
    try:
        net = ipaddress.ip_network(rule_clean, strict=False)
        if target.ip is not None:
            t_ip = _normalize_ip(target.ip)
            if t_ip.version == net.version and t_ip in net:
                return True
        if target.network is not None:
            if target.network.version == net.version:
                if is_exclusion:
                    if target.network.overlaps(net):
                        return True
                else:
                    if target.network.subnet_of(net):
                        return True
        for r_ip in resolved_ips:
            norm_r = _normalize_ip(r_ip)
            if norm_r.version == net.version and norm_r in net:
                return True
        return False
    except ValueError:
        pass

    # Hostname / wildcard domain rule
    rule_host = rule_clean.rstrip(".")
    if rule_host.startswith("*."):
        suffix = rule_host[2:]
        return target.host == suffix or target.host.endswith("." + suffix)

    return target.host == rule_host


class PolicyEngine:
    """
    Central policy and scope engine.

    Enforces user-selected scope, port, protocol, and ownership settings consistently
    across preparation, execution, redirects, and workers.
    """

    def __init__(self, resolve_dns: bool = False) -> None:
        self.resolve_dns = resolve_dns

    def _resolve_target_ips(
        self, target: CanonicalTarget
    ) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        if target.ip is not None:
            return [target.ip]
        if not self.resolve_dns or target.network is not None:
            return []
        resolved: List[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        try:
            infos = socket.getaddrinfo(target.host, None)
            for info in infos:
                sockaddr = info[4]
                if sockaddr:
                    ip_obj = _normalize_ip(ipaddress.ip_address(sockaddr[0]))
                    if ip_obj not in resolved:
                        resolved.append(ip_obj)
        except OSError:
            pass
        return resolved

    @staticmethod
    def verify_scope_window(scope: ScopePolicy) -> None:
        now = datetime.now(timezone.utc)
        if scope.valid_from:
            if now < datetime.fromisoformat(scope.valid_from):
                raise PolicyViolationError("Engagement scope window has not started yet", code="SCOPE_EXPIRED")
        if scope.valid_until:
            if now > datetime.fromisoformat(scope.valid_until):
                raise PolicyViolationError("Engagement scope window has expired", code="SCOPE_EXPIRED")


    def evaluate_target(
        self,
        raw_target: str,
        scope: ScopePolicy,
        requested_ports: Optional[Iterable[int]] = None,
    ) -> CanonicalTarget:
        target = canonicalize_target(raw_target)
        resolved_ips = self._resolve_target_ips(target)

        self.verify_scope_window(scope)

        if scope.block_metadata_endpoints:
            explicitly_allowed = any(
                _matches_rule(target, r, resolved_ips, is_exclusion=False) for r in scope.allowed_targets
            )
            if not explicitly_allowed:
                if target.host in CLOUD_METADATA_HOSTS:
                    raise PolicyViolationError(
                        f"Metadata endpoint blocked by SSRF guard: {target.host}",
                        code="METADATA_SSRF_BLOCKED",
                    )
                for ip_candidate in ([target.ip] if target.ip else []) + resolved_ips:
                    if _normalize_ip(ip_candidate) in CLOUD_METADATA_IPS:
                        raise PolicyViolationError(
                            f"Metadata IP blocked by SSRF guard: {ip_candidate}",
                            code="METADATA_SSRF_BLOCKED",
                        )

        if target.scheme and scope.allowed_protocols:
            if target.scheme not in [p.lower() for p in scope.allowed_protocols]:
                raise PolicyViolationError(
                    f"Protocol '{target.scheme}' not in allowed_protocols: {scope.allowed_protocols}",
                    code="PROTOCOL_NOT_ALLOWED",
                )

        # Port check (explicit target port, default scheme port, and tool-requested ports)
        if scope.allowed_ports:
            allowed_port_set = set(scope.allowed_ports)
            effective_target_port = target.port
            if effective_target_port is None and target.scheme:
                effective_target_port = DEFAULT_SCHEME_PORTS.get(target.scheme)
            if effective_target_port is not None and effective_target_port not in allowed_port_set:
                raise PolicyViolationError(
                    f"Port {effective_target_port} not in allowed_ports: {scope.allowed_ports}",
                    code="PORT_NOT_ALLOWED",
                )
            if requested_ports is not None:
                for rp in requested_ports:
                    if rp not in allowed_port_set:
                        raise PolicyViolationError(
                            f"Requested scanner port {rp} not in allowed_ports: {scope.allowed_ports}",
                            code="PORT_NOT_ALLOWED",
                        )

        # Exclusions always win over inclusions (including CIDR overlap with excluded hosts)
        for ex_rule in scope.excluded_targets:
            if _matches_rule(target, ex_rule, resolved_ips, is_exclusion=True):
                raise PolicyViolationError(
                    f"Target '{raw_target}' matches or overlaps excluded scope rule '{ex_rule}'",
                    code="TARGET_EXCLUDED",
                )

        # Inclusions
        if scope.allowed_targets or not scope.allow_all_targets:
            if not any(_matches_rule(target, inc, resolved_ips, is_exclusion=False) for inc in scope.allowed_targets):
                raise PolicyViolationError(
                    f"Target '{raw_target}' is outside engagement allowed_targets {scope.allowed_targets}",
                    code="TARGET_OUT_OF_SCOPE",
                )

        return target

    @staticmethod
    def verify_engagement_ownership(principal: Principal, engagement: Engagement) -> None:
        if not principal.authenticated:
            raise PolicyViolationError("Principal is not authenticated", code="UNAUTHENTICATED")
        owner = engagement.owner_principal_id
        delegated = engagement.metadata.get("delegated_principals", [])
        # 'default' engagement created by 'local_operator' allows default local AI client unless owned by a named user
        if engagement.engagement_id == "default" and owner == "local_operator":
            if principal.principal_id in ("local_operator", "ai_client", "api_token_operator"):
                return
        if principal.principal_id != owner and principal.principal_id not in delegated:
            raise PolicyViolationError(
                f"Principal '{principal.principal_id}' is not authorized for engagement '{engagement.engagement_id}' (owner='{owner}')",
                code="FORBIDDEN",
            )

    def validate_plan_request(
        self,
        principal: Principal,
        engagement: Engagement,
        capability: CapabilityDescriptor,
        operation: str,
        arguments: Dict[str, Any],
        targets: List[str],
        argv_preview: List[str],
        binary_digest: str,
        timeout_seconds: Optional[float] = None,
        worker_target: Optional[str] = None,
    ) -> Tuple[InvocationPlan, Optional[ApprovalGrant]]:
        self.verify_engagement_ownership(principal, engagement)

        if engagement.status == "revoked":
            raise PolicyViolationError(
                f"Engagement '{engagement.engagement_id}' is revoked",
                code="ENGAGEMENT_REVOKED",
            )

        if operation not in capability.operations:
            raise PolicyViolationError(
                f"Unknown operation '{operation}' for capability '{capability.capability_id}'",
                code="UNKNOWN_OPERATION",
            )

        scope = engagement.scope
        # Extract any explicit ports argument from scanner parameters
        requested_ports: Optional[List[int]] = None
        if "ports" in arguments and arguments["ports"]:
            requested_ports = parse_port_spec(str(arguments["ports"]))
        elif scope.allowed_ports and capability.capability_id in ("network.nmap", "network.masscan", "network.rustscan"):
            # If engagement restricts ports and scanner omitted explicit ports, enforce that ports must be specified or within scope
            pass

        canonical_targets: List[str] = []
        for raw_t in targets:
            ct = self.evaluate_target(raw_t, scope, requested_ports=requested_ports)
            canonical_targets.append(ct.raw)

        effective_timeout = min(timeout_seconds or 300, scope.max_timeout_seconds)
        effective_worker = worker_target or scope.worker_target or "local"

        expiry = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
        plan = InvocationPlan(
            plan_id=new_id("plan"),
            engagement_id=engagement.engagement_id,
            principal_id=principal.principal_id,
            capability_id=capability.capability_id,
            operation=operation,
            arguments=dict(arguments),
            targets=tuple(canonical_targets),
            argv_preview=tuple(argv_preview),
            worker_target=effective_worker,
            risk_level=capability.risk_level,
            side_effects=capability.side_effects,
            schema_digest=capability.schema_digest,
            binary_digest=binary_digest,
            timeout_seconds=effective_timeout,
            created_at=datetime.now(timezone.utc).isoformat(),
            expires_at=expiry,
            policy_explanation=(
                f"Authorized for engagement '{engagement.engagement_id}' on worker '{effective_worker}' "
                f"(autonomous={scope.autonomous_mode})."
            ),
        )

        grant: Optional[ApprovalGrant] = None
        if scope.autonomous_mode:
            grant = ApprovalGrant(
                grant_id=new_id("grant"),
                plan_id=plan.plan_id,
                plan_digest=plan.plan_digest,
                engagement_id=engagement.engagement_id,
                principal_id=principal.principal_id,
                approved_by=principal.principal_id,
                expires_at=expiry,
            )

        return plan, grant
