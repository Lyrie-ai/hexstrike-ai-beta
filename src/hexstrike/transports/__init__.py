"""Transports package."""

from importlib import import_module

__all__ = [
    "MCP_TOOL_NAMES",
    "TokenAuthenticator",
    "create_hexstrike_mcp_server",
    "create_http_app",
]


def __getattr__(name):
    # Keep module entry points unloaded until selected by the caller.
    if name in ("TokenAuthenticator", "create_http_app"):
        return getattr(import_module(".http_server", __name__), name)
    if name in ("MCP_TOOL_NAMES", "create_hexstrike_mcp_server"):
        return getattr(import_module(".mcp_stdio", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
