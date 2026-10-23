"""Workspace, inventory, and custom-tool workflows through the runtime contract."""

import json
import os
import shutil
import sys

import pytest

from hexstrike.application.services import HexStrikeRuntime
from hexstrike.adapters.offline import run_workspace_tool
from hexstrike.execution.runner import SafeSubprocessRunner
from hexstrike.registry.catalog_registry import CapabilityRegistry
from hexstrike.policy.engine import PolicyViolationError


def run(rt, capability, arguments, operation="run"):
    return rt.job_start(
        capability_id=capability, operation=operation, arguments=arguments, wait=True
    )


def test_workspace_create_read_update_and_no_clobber(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    first = run(
        rt, "workspace.files", {"path": "case/notes.txt", "content": "first"}, "create"
    )
    assert first["job"]["state"] == "completed"
    duplicate = run(
        rt, "workspace.files", {"path": "case/notes.txt", "content": "wrong"}, "create"
    )
    assert duplicate["job"]["state"] == "failed"
    assert (rt.workspace.base_dir / "case/notes.txt").read_text() == "first"
    update = run(
        rt, "workspace.files", {"path": "case/notes.txt", "content": "second"}, "update"
    )
    assert update["job"]["state"] == "completed"
    read = run(rt, "workspace.files", {"path": "case/notes.txt", "limit": 3}, "read")
    output = read["job"]["structured_output"]
    assert output["content"] == "sec" and output["next_offset"] == 3
    assert (
        run(rt, "workspace.files", {"path": "case"}, "list")["job"][
            "structured_output"
        ]["total"]
        == 1
    )
    assert (
        run(rt, "workspace.files", {"path": "../escape", "content": "no"}, "create")[
            "job"
        ]["state"]
        == "failed"
    )
    rt.engagement_manage(action="update", max_artifact_bytes=4)
    assert (
        run(rt, "workspace.files", {"path": "oversize", "content": "12345"}, "create")[
            "job"
        ]["state"]
        == "failed"
    )
    assert not (rt.workspace.base_dir / "oversize").exists()


def test_inventory_lists_unbound_executables_without_running_them(tmp_path):
    tool = tmp_path / "custom-test-tool"
    tool.write_text("#!/bin/sh\nexit 99\n")
    tool.chmod(0o700)
    registry = CapabilityRegistry(search_paths=[str(tmp_path)])
    listing = registry.discover_installed(query="custom-test")
    assert listing["total"] == 1
    assert listing["executables"][0]["capability_ids"] == []
    second = tmp_path / "another-tool"
    second.write_text("")
    second.chmod(0o700)
    assert registry.discover_installed(limit=1)["next_offset"] == 1
    tool.unlink()
    assert registry.discover_installed(query="custom-test")["total"] == 0


def test_custom_program_created_installed_executed_and_removed(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    program = 'import json\nfrom pathlib import Path\nPath("case/result.json").write_text(json.dumps({"sum":sum(range(11))}))\nprint("analysis-created")\n'
    assert (
        run(
            rt,
            "workspace.files",
            {"path": "case/analyze.py", "content": program},
            "create",
        )["job"]["state"]
        == "completed"
    )
    manifest = {
        "capability_id": "custom.analysis",
        "name": "Case analysis",
        "category": "forensics",
        "binary_name": sys.executable,
        "description": "Trusted local case analysis",
        "parameters": {},
        "required": [],
        "arg_template": ["case/analyze.py"],
        "requires_network": False,
    }
    assert (
        run(rt, "tools.adapters", {"manifest": json.dumps(manifest)}, "install")["job"][
            "state"
        ]
        == "completed"
    )
    result = run(rt, "custom.analysis", {})
    assert result["job"]["state"] == "completed"
    assert json.loads((rt.workspace.base_dir / "case/result.json").read_text()) == {
        "sum": 55
    }
    assert (
        run(rt, "tools.adapters", {"capability_id": "custom.analysis"}, "remove")[
            "job"
        ]["state"]
        == "completed"
    )
    with pytest.raises(PolicyViolationError):
        rt.action_prepare("custom.analysis")


@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_offline_inputs_reject_links_and_dispatch_swap(tmp_path, link):
    rt = HexStrikeRuntime(state_dir=tmp_path / "state")
    outside = tmp_path / "outside"
    outside.write_text("outside-marker")
    target = rt.workspace.base_dir / "input"
    target.write_text("inside-marker")
    plan = rt.action_prepare("binary.strings", arguments={"target": "input"})
    target.unlink()
    (os.symlink if link == "symlink" else os.link)(outside, target)
    result = rt.job_start(plan_id=plan["plan"]["plan_id"], wait=True)
    assert result["job"]["state"] == "failed"
    assert not result["job"]["evidence_ids"]


def test_offline_snapshot_survives_input_swap(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.workspace.create_file("input", "inside-marker")
    adapter = rt.registry.get_adapter("binary.strings")
    delegate = SafeSubprocessRunner()

    class SwapRunner:
        def run(self, argv, **kwargs):
            (rt.workspace.base_dir / "input").unlink()
            (rt.workspace.base_dir / "input").symlink_to("/nonexistent")
            return delegate.run(argv, **kwargs)

    if not shutil.which("strings"):
        pytest.skip("strings unavailable")
    result = run_workspace_tool(
        adapter,
        "run",
        {"target": "input"},
        rt.workspace,
        SwapRunner(),
        shutil.which("strings"),
        timeout=5,
    )
    assert result.success and "inside-marker" in result.stdout


def test_workspace_fifo_does_not_block(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    rt = HexStrikeRuntime(state_dir=tmp_path)
    os.mkfifo(rt.workspace.base_dir / "pipe")
    assert rt.workspace.read_file("pipe")["success"] is False


def test_tshark_schema_and_argv_preserve_filter(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    adapter = rt.registry.get_adapter("forensics.tshark")
    argv = adapter.build_argv(
        "run",
        {
            "target": "capture.pcap",
            "display_filter": "tcp && http.response.code == 200",
        },
    )
    assert "tcp && http.response.code == 200" in argv
    with pytest.raises(PolicyViolationError):
        adapter.build_argv("run", {"target": "capture.pcap", "max_packets": 0})
    with pytest.raises(PolicyViolationError):
        rt.action_prepare("tools.inventory", arguments={"limit": -1})


def test_invalid_custom_manifest_is_a_clear_failure(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = run(rt, "tools.adapters", {"manifest": "[]"}, "install")
    assert result["job"]["state"] == "failed"
    assert "JSON object" in result["job"]["error_message"]
    base = {
        "capability_id": "custom.invalid",
        "name": "Invalid",
        "category": "custom",
        "binary_name": sys.executable,
        "description": "Invalid template",
        "parameters": {},
        "required": [],
        "arg_template": ["{undeclared}"],
        "requires_network": False,
    }
    result = run(rt, "tools.adapters", {"manifest": json.dumps(base)}, "install")
    assert result["job"]["state"] == "failed"
    assert "Undeclared" in result["job"]["error_message"]


def test_snapshot_metadata_identifies_original_file(tmp_path):
    from hexstrike.execution.runner import ExecutionResult

    rt = HexStrikeRuntime(state_dir=tmp_path)
    rt.workspace.create_file("original.bin", b"forensic-source")
    source = rt.workspace.base_dir / "original.bin"
    os.utime(source, ns=(123000000000, 123000000000))
    adapter = rt.registry.get_adapter("forensics.exiftool")

    class MetadataRunner:
        def run(self, argv, **kwargs):
            from pathlib import Path

            copy = Path(argv[-1])
            assert copy.name == source.name
            assert copy.stat().st_mtime_ns == source.stat().st_mtime_ns
            return ExecutionResult(
                True,
                0,
                json.dumps(
                    [
                        {
                            "SourceFile": str(copy),
                            "FileName": copy.name,
                            "Directory": str(copy.parent),
                            "FileInodeChangeDate": "copy-time",
                        }
                    ]
                ),
                "",
                0,
            )

    result = run_workspace_tool(
        adapter,
        "run",
        {"target": "original.bin"},
        rt.workspace,
        MetadataRunner(),
        "exiftool",
    )
    record = json.loads(result.stdout)[0]
    assert record == {"SourceFile": "original.bin", "FileName": "original.bin"}
    assert result.input_files["target"]["mtime_ns"] == 123000000000
    assert result.input_files["target"]["size"] == len(b"forensic-source")


def test_dns_records_parser_retains_native_rows(tmp_path):
    from hexstrike.execution.runner import ExecutionResult

    rt = HexStrikeRuntime(state_dir=tmp_path)
    adapter = rt.registry.get_adapter("network.dnsenum")
    output = "lab.test. 60 IN A 127.0.0.1\nns.lab.test. 60 IN A 127.0.0.1\nlab.test. 60 IN MX 10 mail.lab.test.\n"
    parsed, findings = adapter.parse_output(
        "run", {"target": "lab.test"}, ExecutionResult(True, 0, output, "", 0), "default", "test"
    )
    assert parsed["record_count"] == 3 and parsed["count"] == 1
    assert parsed["host_count"] == 2 and parsed["subdomains"] == ["ns.lab.test"]
    assert parsed["records"][2]["value"] == "10 mail.lab.test."
    assert not findings


def test_masscan_readiness_reports_missing_raw_socket_permission(tmp_path, monkeypatch):
    import socket
    from hexstrike.adapters.catalog import inspect_binary_identity
    from hexstrike.domain.models import ToolStatus

    fake = tmp_path / "masscan"
    fake.write_text("fixture")
    fake.chmod(0o700)
    monkeypatch.setattr(socket, "AF_PACKET", 17, raising=False)

    def denied(*args, **kwargs):
        raise PermissionError("not permitted")

    monkeypatch.setattr(socket, "socket", denied)
    identity = inspect_binary_identity("masscan", search_paths=[str(tmp_path)])
    assert identity.status == ToolStatus.RESTRICTED
    assert "raw sockets" in identity.notes


def test_nikto_typed_options_and_management_authority(tmp_path):
    from hexstrike.domain.models import Principal

    rt = HexStrikeRuntime(state_dir=tmp_path)
    adapter = rt.registry.get_adapter("web.nikto")
    argv = adapter.build_argv(
        "run",
        {
            "target": "http://127.0.0.1",
            "tuning": "2",
            "max_time": 20,
            "request_timeout": 2,
        },
    )
    assert argv[argv.index("-maxtime") + 1] == "20s"
    assert argv[argv.index("-Tuning") + 1] == "2"
    viewer = Principal(principal_id="reader", name="Reader", role="ai_agent")
    rt.engagement_manage(action="create", engagement_id="reader", principal=viewer)
    for capability, operation, args in [
        ("tools.adapters", "install", {"manifest": "{}"}),
        ("workspace.files", "read", {"path": "private.json"}),
    ]:
        with pytest.raises(PolicyViolationError, match="operator role"):
            rt.action_prepare(
                capability,
                operation=operation,
                arguments=args,
                engagement_id="reader",
                principal=viewer,
            )


def test_nikto_does_not_turn_run_metadata_into_findings():
    from hexstrike.adapters.catalog import parse_structured_cli_output

    text = "+ Start Time: today\n+ Server: fixture\n+ [013587] /: Header missing\n+ 12 requests: 0 errors and 1 items reported\n+ End Time: today\n+ 1 host(s) tested\n"
    output, findings = parse_structured_cli_output(
        "web.nikto", text, "http://fixture", "test", "job", "WSTG-CONF-04"
    )
    assert output["count"] == 1
    assert len(findings) == 1


def test_failed_custom_install_does_not_register_in_memory(tmp_path, monkeypatch):
    from hexstrike.adapters.catalog import CustomAdapterManifest

    rt = HexStrikeRuntime(state_dir=tmp_path)
    manifest = CustomAdapterManifest.from_dict(
        {
            "capability_id": "custom.failed",
            "name": "Failed",
            "category": "custom",
            "binary_name": sys.executable,
            "description": "I/O failure fixture",
            "arg_template": [],
            "parameters": {},
            "required": [],
            "requires_network": False,
        }
    )

    def denied(*args, **kwargs):
        raise OSError("write failure")

    monkeypatch.setattr(os, "replace", denied)
    with pytest.raises(OSError):
        rt.registry.register_custom_adapter(manifest)
    assert rt.registry.get_adapter("custom.failed") is None


def test_empty_workspace_file_creation(tmp_path):
    rt = HexStrikeRuntime(state_dir=tmp_path)
    result = run(rt, "workspace.files", {"path": "empty.txt", "content": ""}, "create")
    assert result["job"]["state"] == "completed"
    assert (rt.workspace.base_dir / "empty.txt").read_bytes() == b""


def test_httpx_resolves_kali_alias_and_refreshes_when_removed(tmp_path):
    primary = tmp_path / "httpx"
    primary.write_text("#!/usr/bin/python3\nimport httpx\n")
    primary.chmod(0o700)
    registry = CapabilityRegistry(search_paths=[str(tmp_path)])
    assert registry.get_binary_identity("httpx").status.value == "incompatible"
    alias = tmp_path / "httpx-toolkit"
    alias.write_text("#!/bin/sh\nexit 0\n")
    alias.chmod(0o700)
    assert registry.get_binary_identity("httpx").executable_path == str(alias)
    listing = registry.discover_installed(query="httpx-toolkit")
    assert listing["executables"][0]["capability_ids"] == ["web.httpx_probe"]
    alias.unlink()
    assert registry.get_binary_identity("httpx").status.value == "incompatible"
