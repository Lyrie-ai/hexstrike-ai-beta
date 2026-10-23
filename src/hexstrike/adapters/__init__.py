"""Tool adapters package."""

from hexstrike.adapters.catalog import (
    BinaryIdentity,
    CustomAdapterManifest,
    DeclarativeCustomAdapter,
    HttpInspectAdapter,
    HttpxProbeAdapter,
    JwtAnalyzerAdapter,
    NmapAdapter,
    NucleiAdapter,
    StandardCliScannerAdapter,
    ToolAdapter,
    build_default_adapters,
    compute_file_sha256,
    inspect_binary_identity,
    parse_nmap_xml,
    validate_safe_extra_flags,
)

__all__ = [
    "BinaryIdentity",
    "CustomAdapterManifest",
    "DeclarativeCustomAdapter",
    "HttpInspectAdapter",
    "HttpxProbeAdapter",
    "JwtAnalyzerAdapter",
    "NmapAdapter",
    "NucleiAdapter",
    "StandardCliScannerAdapter",
    "ToolAdapter",
    "build_default_adapters",
    "compute_file_sha256",
    "inspect_binary_identity",
    "parse_nmap_xml",
    "validate_safe_extra_flags",
]
