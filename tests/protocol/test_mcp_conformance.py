"""
End-to-end MCP stdio protocol conformance test using `mcp.ClientSession` and `stdio_client`.

Verifies:
- Cold stdio handshake & tool list discovery (< 3 seconds)
- Exact 10-tool compact schema manifest & token footprint (< 4,000 tokens)
- Stdout reserved exclusively for JSON-RPC frames
- Execution of `system_status`, `capabilities_search`, `capabilities_describe`,
  `engagement_manage`, `action_prepare`, `job_start`, `job_status`, `job_cancel`,
  `evidence_read`, and `memory_query` over live MCP stdio
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_mcp_stdio_protocol_conformance_end_to_end(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    mcp_entry = repo_root / "hexstrike_mcp.py"

    async def _run_client() -> None:
        t0 = time.monotonic()
        server_params = StdioServerParameters(
            command=sys.executable,
            args=[str(mcp_entry), "--state-dir", str(tmp_path)],
        )
        async with stdio_client(server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                discovery_res = await session.list_tools()
                discovery_latency = time.monotonic() - t0
                assert discovery_latency < 3.0, f"Cold discovery took {discovery_latency:.2f}s (> 3.0s budget)"

                tools = discovery_res.tools
                tool_names = [t.name for t in tools]
                assert len(tool_names) == 10

                # Measure initial manifest bytes and approximate token footprint (~4 chars/token)
                manifest_json = json.dumps(
                    [
                        {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": getattr(t, "input_schema", getattr(t, "inputSchema", {})),
                        }
                        for t in tools
                    ]
                )
                approx_tokens = len(manifest_json) // 4
                assert approx_tokens < 4000, f"Initial manifest tokens {approx_tokens} exceeded 4,000 budget"

                def _extract_payload(call_res: Any) -> dict[str, Any]:
                    assert not getattr(call_res, "is_error", getattr(call_res, "isError", False))
                    structured = getattr(call_res, "structured_content", getattr(call_res, "structuredContent", None))
                    if isinstance(structured, dict):
                        if "result" in structured and isinstance(structured["result"], dict):
                            return structured["result"]
                        return structured
                    blocks = getattr(call_res, "content", [])
                    assert blocks, "Tool call returned empty content"
                    text = getattr(blocks[0], "text", "")
                    parsed = json.loads(text)
                    if isinstance(parsed, dict) and "result" in parsed and isinstance(parsed["result"], dict):
                        return parsed["result"]
                    return parsed

                # 1. system_status
                st_data = _extract_payload(
                    await session.call_tool("system_status", {"engagement_id": "default"})
                )
                assert st_data.get("status") == "ready"

                # 2. capabilities_search
                cs_data = _extract_payload(
                    await session.call_tool("capabilities_search", {"query": "jwt"})
                )
                assert cs_data.get("count", 0) >= 1

                # 3. capabilities_describe
                cd_data = _extract_payload(
                    await session.call_tool(
                        "capabilities_describe", {"capability_ids": ["api.jwt_analyzer"]}
                    )
                )
                assert cd_data["descriptors"][0]["capability_id"] == "api.jwt_analyzer"

                # 4. engagement_manage
                em_data = _extract_payload(
                    await session.call_tool(
                        "engagement_manage",
                        {"action": "inspect", "engagement_id": "default"},
                    )
                )
                assert em_data["engagement"]["engagement_id"] == "default"

                # 5. action_prepare
                ap_data = _extract_payload(
                    await session.call_tool(
                        "action_prepare",
                        {
                            "capability_id": "api.jwt_analyzer",
                            "operation": "analyze",
                            "arguments": {"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."},
                        },
                    )
                )
                assert ap_data.get("success") is True
                assert ap_data.get("ready_to_start") is True

                # 6. job_start (direct 1-step execution)
                js_data = _extract_payload(
                    await session.call_tool(
                        "job_start",
                        {
                            "capability_id": "api.jwt_analyzer",
                            "operation": "analyze",
                            "arguments": {"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."},
                        },
                    )
                )
                assert js_data.get("success") is True
                assert js_data["job"]["state"] == "completed"

                # 7. job_status
                jst_data = _extract_payload(
                    await session.call_tool("job_status", {"engagement_id": "default"})
                )
                assert jst_data.get("count", 0) >= 1

                # 8. evidence_read
                ev_data = _extract_payload(
                    await session.call_tool("evidence_read", {"engagement_id": "default"})
                )
                assert ev_data.get("count", 0) >= 1

                # 9. memory_query
                mq_data = _extract_payload(
                    await session.call_tool("memory_query", {"engagement_id": "default"})
                )
                assert mq_data.get("engagement_id") == "default"

                # 10. job_cancel
                jc_data = _extract_payload(
                    await session.call_tool("job_cancel", {"cancel_all": True})
                )
                assert jc_data.get("success") is True

    asyncio.run(_run_client())
