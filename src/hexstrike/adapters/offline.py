"""Typed, offline inspection of workspace files with bounded parsed results."""

from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from pathlib import Path

from hexstrike.adapters.catalog import ToolAdapter
from hexstrike.domain.models import CapabilityDescriptor, RiskLevel, SideEffectClass
from hexstrike.policy.engine import PolicyViolationError


class OfflineFileAdapter(ToolAdapter):
    input_file_parameters = ("target",)

    def __init__(self, capability_id, binary, description, flags, parameters=None):
        self.flags = flags
        self.descriptor = CapabilityDescriptor(
            capability_id=capability_id,
            name=description,
            category=capability_id.split(".")[0],
            pack=capability_id.split(".")[0],
            description=description,
            binary_name=binary,
            requires_network=False,
            risk_level=RiskLevel.PASSIVE,
            side_effects=SideEffectClass.LOCAL_COMPUTE,
            operations={
                "run": {
                    "description": description,
                    "required": ["target"],
                    "parameters": {
                        "target": {
                            "type": "string",
                            "description": "Workspace-relative input file",
                        },
                        **(parameters or {}),
                    },
                }
            },
            examples=[
                {"operation": "run", "arguments": {"target": "samples/input.bin"}}
            ],
        )

    def extract_targets(self, operation, arguments):
        return []

    def build_argv(self, operation, arguments, binary_path=None):
        args = self.validate_arguments(operation, arguments)
        argv = [binary_path or self.descriptor.binary_name, *self.flags]
        if self.descriptor.binary_name == "tshark":
            count = args.get("max_packets", 100)
            if not 1 <= count <= 10000:
                raise PolicyViolationError(
                    "max_packets must be between 1 and 10000", code="INVALID_ARGUMENT"
                )
            argv += ["-c", str(count)]
            if args.get("display_filter"):
                argv += ["-Y", args["display_filter"]]
            argv += ["-r", args["target"]]
        else:
            argv += ["--", args["target"]]
        return argv

    def parse_output(self, operation, arguments, result, engagement_id, job_id):
        binary = self.descriptor.binary_name
        parsed = {"return_code": result.return_code, "target": arguments["target"]}
        if binary in ("tshark", "capinfos") and result.success:
            rows = list(
                csv.DictReader(
                    io.StringIO(result.stdout),
                    delimiter="\t" if binary == "tshark" else ",",
                )
            )
            parsed.update(
                rows=rows[:100], row_count=len(rows), has_more=len(rows) > 100
            )
            if binary == "tshark":
                parsed["packet_limit"] = arguments.get("max_packets", 100)
        elif binary == "file":
            parsed["media_type"] = result.stdout.strip()
        elif binary == "readelf":
            parsed["header"] = dict(
                line.strip().split(":", 1)
                for line in result.stdout.splitlines()
                if ":" in line
            )
            parsed["header"] = {k: v.strip() for k, v in parsed["header"].items()}
        else:
            lines = result.stdout.splitlines()
            parsed.update(
                lines=lines[:100], line_count=len(lines), has_more=len(lines) > 100
            )
        return parsed, []


def build_offline_adapters():
    fields = [
        "frame.number",
        "frame.time_relative",
        "ip.src",
        "ip.dst",
        "_ws.col.Protocol",
        "tcp.srcport",
        "tcp.dstport",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.response.code",
        "dns.qry.name",
    ]
    tshark_flags = ["-n", "-T", "fields", "-E", "header=y", "-E", "quote=d"]
    for field in fields:
        tshark_flags += ["-e", field]
    return [
        OfflineFileAdapter(
            "forensics.file", "file", "Identify file media type", ["-b", "--mime-type"]
        ),
        OfflineFileAdapter(
            "forensics.capinfos",
            "capinfos",
            "Summarize packet capture metadata",
            ["-T", "-m"],
        ),
        OfflineFileAdapter(
            "forensics.tshark",
            "tshark",
            "Inspect packet capture protocols and requests",
            tshark_flags,
            {
                "max_packets": {"type": "integer", "default": 100},
                "display_filter": {
                    "type": "string",
                    "default": "",
                    "description": "Wireshark display filter; no live capture",
                },
            },
        ),
        OfflineFileAdapter(
            "binary.readelf", "readelf", "Inspect ELF architecture and headers", ["-h"]
        ),
        OfflineFileAdapter(
            "binary.objdump", "objdump", "Inspect binary sections", ["-h"]
        ),
    ]


def validate_workspace_inputs(adapter, arguments, workspace):
    for key in adapter.input_file_parameters:
        result = workspace.read_file(
            arguments[key], max_bytes=1, binary=True, compute_full_sha256=False
        )
        if not result["success"]:
            raise PolicyViolationError(
                "Workspace input: " + result["error"],
                code=result.get("code", "INVALID_FILE"),
            )


def run_workspace_tool(
    adapter, operation, arguments, workspace, runner, binary_path, **run_options
):
    """Inspect private snapshots so later workspace symlink swaps cannot redirect a tool."""
    with tempfile.TemporaryDirectory(prefix="hexstrike-input-") as directory:
        copied = dict(arguments)
        replacements = {}
        inputs = {}
        for key in adapter.input_file_parameters:
            data = workspace.read_file(
                arguments[key],
                max_bytes=workspace.max_file_size + 1,
                binary=True,
                compute_full_sha256=False,
            )
            if (
                not data["success"]
                or data.get("has_more")
                or data.get("size", 0) > workspace.max_file_size
            ):
                raise PolicyViolationError(
                    "Workspace input: "
                    + data.get("error", "File exceeds input size limit"),
                    code="INVALID_FILE",
                )
            inputs[key] = {
                "path": arguments[key],
                "sha256": data["chunk_sha256"],
                **data["source_stat"],
            }
            parent = Path(directory) / key
            parent.mkdir(mode=0o700)
            path = parent / Path(arguments[key]).name
            path.write_bytes(data["raw_bytes"])
            path.chmod(0o600)
            os.utime(
                path,
                ns=(data["source_stat"]["mtime_ns"], data["source_stat"]["mtime_ns"]),
            )
            copied[key] = str(path)
            replacements[str(path)] = arguments[key]
        result = runner.run(
            adapter.build_argv(operation, copied, binary_path=binary_path),
            **run_options,
        )
        for source, original in replacements.items():
            # JSON tools escape some platform path separators.
            result.stdout = result.stdout.replace(
                json.dumps(source)[1:-1], json.dumps(original)[1:-1]
            ).replace(source, original)
            result.stderr = result.stderr.replace(source, original)
        if adapter.descriptor.binary_name == "exiftool" and result.success:
            records = json.loads(result.stdout)
            for record in records:
                # These describe the inspection copy, not the acquired source.
                for key in (
                    "Directory",
                    "FileAccessDate",
                    "FileInodeChangeDate",
                    "FilePermissions",
                ):
                    record.pop(key, None)
            result.stdout = json.dumps(records)
        result.input_files = inputs
        result.argv = adapter.build_argv(operation, arguments, binary_path=binary_path)
        return result
