"""Measure MCP discovery and detection on local HTTP/JWT fixtures.

Token counts are byte-based estimates. Detection scores describe these fixtures,
not general vulnerability coverage or exploitability.
"""

from __future__ import annotations

import asyncio
import base64
import json
import platform
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Set

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from hexstrike import __version__
from hexstrike.application.services import HexStrikeRuntime
from hexstrike.domain.models import FindingState, utc_now_iso


def _make_jwt(header: Dict[str, Any], payload: Dict[str, Any], sig: str = "") -> str:
    def _enc(d: Dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode("utf-8")).decode("ascii").rstrip("=")

    return f"{_enc(header)}.{_enc(payload)}.{sig}"


def run_benchmark_suite() -> Dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[1]
    mcp_entry = repo_root / "hexstrike_mcp.py"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)

        # 1. Measure cold MCP stdio discovery latency & manifest size
        cold_latencies: List[float] = []
        manifest_bytes = 0
        manifest_tokens_estimate = 0
        discovered_tool_count = 0

        async def _measure_mcp_discovery() -> None:
            nonlocal manifest_bytes, manifest_tokens_estimate, discovered_tool_count
            for _ in range(3):
                t0 = time.monotonic()
                params = StdioServerParameters(
                    command=sys.executable,
                    args=[str(mcp_entry), "--state-dir", str(tmp_path)],
                )
                async with stdio_client(params) as (r_stream, w_stream):
                    async with ClientSession(r_stream, w_stream) as session:
                        await session.initialize()
                        res = await session.list_tools()
                        elapsed = time.monotonic() - t0
                        cold_latencies.append(elapsed)
                        discovered_tool_count = len(res.tools)
                        serialized = json.dumps(
                            [
                                {
                                    "name": t.name,
                                    "description": t.description,
                                    "inputSchema": getattr(t, "input_schema", getattr(t, "inputSchema", {})),
                                }
                                for t in res.tools
                            ]
                        )
                        manifest_bytes = len(serialized.encode("utf-8"))
                        manifest_tokens_estimate = manifest_bytes // 4

        asyncio.run(_measure_mcp_discovery())

        # 2. Ground-truth positive (vulnerable) and negative (hardened) HTTP + JWT fixtures
        excluded_hits: List[str] = []

        class _FastServer(HTTPServer):
            def server_bind(self) -> None:
                import socket as _s

                _s.socket.bind(self.socket, self.server_address)
                self.server_address = self.socket.getsockname()[:2]
                self.server_name = "127.0.0.1"
                self.server_port = self.server_address[1]

        class _ExcludedServerHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                excluded_hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"excluded")

            def log_message(self, *args: Any) -> None:
                pass

        excluded_srv = _FastServer(("127.0.0.1", 0), _ExcludedServerHandler)
        threading.Thread(target=excluded_srv.serve_forever, daemon=True).start()

        class _GroundTruthHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/vuln":
                    body = (
                        "<html><head><title>Vuln Page</title></head><body>"
                        "<form action='/transfer' method='POST'><input name='amount'/></form>"
                        "</body></html>"
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.send_header("Server", "Apache/2.4.49")
                    self.send_header("Set-Cookie", "sid=insecure_cookie; Path=/")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/hardened":
                    body = (
                        "<html><head><title>Hardened Page</title></head><body>"
                        "<form action='/transfer' method='POST'>"
                        "<input type='hidden' name='csrf_token' value='random123'/>"
                        "<input name='amount'/></form>"
                        "</body></html>"
                    ).encode("utf-8")
                    # BaseHTTPRequestHandler otherwise adds its Python version banner.
                    self.send_response_only(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.send_header("Content-Security-Policy", "default-src 'self'")
                    self.send_header("X-Frame-Options", "DENY")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Set-Cookie", "sid=secure_cookie; Path=/; HttpOnly; Secure")
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/redirect_to_excluded":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{excluded_srv.server_port}/escaped")
                    self.end_headers()

            def log_message(self, *args: Any) -> None:
                pass

            def address_string(self) -> str:
                return str(self.client_address[0])

        srv = _FastServer(("127.0.0.1", 0), _GroundTruthHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        rt = HexStrikeRuntime(state_dir=tmp_path)
        rt.engagement_manage(
            action="update",
            engagement_id="default",
            allow_all_targets=False,
            allowed_targets=["127.0.0.1", "vuln-jwt", "hardened-jwt"],
            allowed_ports=[srv.server_port],
        )

        vuln_url = f"http://127.0.0.1:{srv.server_port}/vuln"
        hardened_url = f"http://127.0.0.1:{srv.server_port}/hardened"
        redirect_url = f"http://127.0.0.1:{srv.server_port}/redirect_to_excluded"

        vuln_jwt = _make_jwt({"alg": "none"}, {"sub": "admin"}, sig="")
        hardened_jwt = _make_jwt(
            {"alg": "RS256"},
            {"sub": "user1", "exp": int(time.time()) + 3600},
            sig="valid_sig_placeholder",
        )

        # Seeded ground-truth positive instances: (target, wstg_id)
        expected_positives: Set[tuple[str, str]] = {
            (vuln_url, "WSTG-CONF-07"),
            (vuln_url, "WSTG-INFO-02"),
            (vuln_url, "WSTG-SESS-02"),
            (vuln_url, "WSTG-SESS-05"),
            ("vuln-jwt", "WSTG-SESS-10"),
        }

        # Seeded ground-truth negative instances (must produce 0 findings):
        negative_targets = {hardened_url, "hardened-jwt"}

        t_start = time.monotonic()
        try:
            # Positive runs
            rt.job_start(capability_id="web.http_inspect", operation="probe", arguments={"url": vuln_url})
            rt.job_start(capability_id="browser.inspect", operation="inspect", arguments={"url": vuln_url})
            rt.job_start(
                capability_id="api.jwt_analyzer",
                operation="analyze",
                arguments={"token": vuln_jwt, "target": "vuln-jwt"},
            )

            # Negative control runs (hardened targets)
            rt.job_start(capability_id="web.http_inspect", operation="probe", arguments={"url": hardened_url})
            rt.job_start(capability_id="browser.inspect", operation="inspect", arguments={"url": hardened_url})
            rt.job_start(
                capability_id="api.jwt_analyzer",
                operation="analyze",
                arguments={"token": hardened_jwt, "target": "hardened-jwt"},
            )

            # Execution-time redirect scope escape test
            rt.job_start(capability_id="browser.inspect", operation="inspect", arguments={"url": redirect_url})
            elapsed_eval = time.monotonic() - t_start
        finally:
            srv.shutdown()
            srv.server_close()
            excluded_srv.shutdown()
            excluded_srv.server_close()

        findings = rt.store.list_findings(engagement_id="default")
        observed_instances: Set[tuple[str, str]] = {
            (f.target, f.wstg_id or "") for f in findings
        }

        matched_tp = len(expected_positives.intersection(observed_instances))
        missed_fn = len(expected_positives - observed_instances)
        # Consistent instance-level false-positive rule: ANY observed (target, wstg_id)
        # instance not in expected_positives (whether on a hardened target OR an unexpected
        # category on a vulnerable target) is counted as a false positive.
        false_positive_instances = observed_instances - expected_positives
        false_positives = len(false_positive_instances)
        duplicate_findings_count = max(0, len(findings) - len(observed_instances))

        precision = (
            round(matched_tp / (matched_tp + false_positives), 4)
            if (matched_tp + false_positives) > 0
            else 0.0
        )
        recall = (
            round(matched_tp / len(expected_positives), 4)
            if expected_positives
            else 0.0
        )

        validated_count = sum(1 for f in findings if f.state == FindingState.VALIDATED)
        candidate_count = sum(1 for f in findings if f.state == FindingState.CANDIDATE)
        observation_count = sum(1 for f in findings if f.state == FindingState.OBSERVATION)

        return {
            "timestamp": utc_now_iso(),
            "version": __version__,
            "environment": {
                "os": platform.system(),
                "release": platform.release(),
                "arch": platform.machine(),
                "python": platform.python_version(),
            },
            "mcp_surface": {
                "current_default_tools": discovered_tool_count,
                "initial_manifest_bytes": manifest_bytes,
                "initial_manifest_token_estimate_bytes_div_4": manifest_tokens_estimate,
                "token_estimation_method": "utf8_bytes_divided_by_4_estimate",
                "token_budget_limit": 4000,
                "cold_discovery_latencies_sec": [round(x, 4) for x in cold_latencies],
                "cold_discovery_max_sec": round(max(cold_latencies), 4),
                "cold_discovery_budget_sec": 3.0,
            },
            "detection_quality": {
                "matching_unit": "unique_(target, wstg_id)_instance",
                "positive_ground_truth_instances": len(expected_positives),
                "negative_control_targets_tested": len(negative_targets),
                "unique_observed_instances": len(observed_instances),
                "duplicate_findings_count": duplicate_findings_count,
                "true_positive_instances_matched": matched_tp,
                "false_negative_instances_missed": missed_fn,
                "false_positive_instances": false_positives,
                "unexpected_instances": sorted(false_positive_instances),
                "missed_instances": sorted(expected_positives - observed_instances),
                "computed_precision": precision,
                "computed_recall": recall,
                "findings_by_state": {
                    "validated": validated_count,
                    "candidate": candidate_count,
                    "observation": observation_count,
                },
                "evaluation_runtime_sec": round(elapsed_eval, 4),
                "execution_time_redirect_escapes": len(excluded_hits),
            },
            "memory_subsystem": {
                "graphiti_core_integrated": rt.memory.graphiti_adapter.graphiti_available,
                "telemetry_enabled": rt.memory.telemetry_enabled,
                "local_only": not rt.memory.allow_external_inference,
            },
        }


if __name__ == "__main__":
    output = run_benchmark_suite()
    out_file = Path(__file__).resolve().parent / "latest_benchmark_results.json"
    out_file.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2))
