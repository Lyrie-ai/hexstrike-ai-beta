#!/usr/bin/env python3
"""Compatibility entry point for the MCP transport."""

from __future__ import annotations

import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent / "src"
if _SRC_DIR.exists() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from hexstrike import __version__
from hexstrike.transports.mcp_stdio import (
    MCP_TOOL_NAMES,
    create_hexstrike_mcp_server,
    main,
)

__all__ = ["__version__", "MCP_TOOL_NAMES", "create_hexstrike_mcp_server", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
