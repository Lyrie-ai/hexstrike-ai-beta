"""DNS enumeration with explicit resolver and wordlist inputs."""

import re

from hexstrike.adapters.catalog import ToolAdapter
from hexstrike.domain.models import CapabilityDescriptor, RiskLevel, SideEffectClass
from hexstrike.policy.engine import canonicalize_target


class DnsEnumAdapter(ToolAdapter):
    input_file_parameters = ("wordlist",)
    descriptor = CapabilityDescriptor(
        capability_id="network.dnsenum",
        name="DNSenum Domain Enumerator",
        category="network",
        pack="network",
        description="Enumerate DNS records using an explicit resolver and workspace wordlist.",
        binary_name="dnsenum",
        requires_network=True,
        risk_level=RiskLevel.LOW,
        side_effects=SideEffectClass.NETWORK_PROBE,
        operations={
            "run": {
                "description": "Enumerate domain records and supplied candidate names",
                "required": ["target", "resolver", "wordlist"],
                "parameters": {
                    "target": {"type": "string", "description": "Domain to enumerate"},
                    "resolver": {
                        "type": "string",
                        "description": "Authorized DNS resolver IP or hostname",
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Workspace-relative candidate subdomain list",
                    },
                    "threads": {
                        "type": "integer",
                        "default": 1,
                        "minimum": 1,
                        "maximum": 20,
                    },
                    "query_timeout": {
                        "type": "integer",
                        "default": 3,
                        "minimum": 1,
                        "maximum": 30,
                    },
                },
            }
        },
    )

    def extract_targets(self, operation, arguments):
        return [arguments["target"], arguments["resolver"]]

    def build_argv(self, operation, arguments, binary_path=None):
        args = self.validate_arguments(operation, arguments)
        return [
            binary_path or "dnsenum",
            "--noreverse",
            "--nocolor",
            "--dnsserver",
            canonicalize_target(args["resolver"]).host,
            "--threads",
            str(args["threads"]),
            "--timeout",
            str(args["query_timeout"]),
            "--scrap",
            "0",
            "--file",
            args["wordlist"],
            canonicalize_target(args["target"]).host,
        ]

    def parse_output(self, operation, arguments, result, engagement_id, job_id):
        records = []
        for line in result.stdout.splitlines():
            match = re.match(
                r"^([\w.-]+)\s+(\d+)\s+IN\s+(A|AAAA|NS|MX|CNAME|TXT|SOA)\s+(.+?)\s*$",
                line,
            )
            if match:
                name, ttl, kind, value = match.groups()
                record = {
                    "name": name.rstrip("."),
                    "ttl": int(ttl),
                    "type": kind,
                    "value": value,
                }
                if record not in records:
                    records.append(record)
        domain = canonicalize_target(arguments["target"]).host.lower().rstrip(".")
        hosts = sorted({r["name"].lower() for r in records if r["type"] in ("A", "AAAA", "CNAME")})
        subdomains = [host for host in hosts if host.endswith("." + domain)]
        return {
            "records": records[:100],
            "record_count": len(records),
            "hosts": hosts[:100],
            "host_count": len(hosts),
            "subdomains": subdomains[:100],
            "count": len(subdomains),
            "has_more": len(records) > 100 or len(hosts) > 100,
            "return_code": result.return_code,
        }, []
