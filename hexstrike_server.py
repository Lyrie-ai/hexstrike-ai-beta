#!/usr/bin/env python3
"""Compatibility HTTP entry point and Python API aliases."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

_SRC_DIR = Path(__file__).resolve().parent / "src"
if _SRC_DIR.exists() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from hexstrike import __version__
from hexstrike.application.services import HexStrikeRuntime
from hexstrike.browser.inspector import BrowserInspectionAdapter
from hexstrike.cli.main import CRIMSON_BANNER_ASCII
from hexstrike.execution.runner import ExecutionResult, SafeSubprocessRunner
from hexstrike.transports.http_server import TokenAuthenticator, create_http_app, main
from hexstrike.workflows.engine import correlate_threat_indicators
from hexstrike.workspace.confined_fs import ConfinedWorkspace, WorkspaceSecurityError

# Compatibility alias for existing callers referencing FileOperationsManager
FileOperationsManager = ConfinedWorkspace


class ModernVisualEngine:
    """Terminal palette retained for compatibility."""

    COLORS = {
        "MATRIX_GREEN": "\033[38;5;46m",
        "NEON_BLUE": "\033[38;5;51m",
        "ELECTRIC_PURPLE": "\033[38;5;129m",
        "CYBER_ORANGE": "\033[38;5;208m",
        "HACKER_RED": "\033[38;5;196m",
        "TERMINAL_GRAY": "\033[38;5;240m",
        "BRIGHT_WHITE": "\033[97m",
        "RESET": "\033[0m",
        "BOLD": "\033[1m",
        "DIM": "\033[2m",
        "BLOOD_RED": "\033[38;5;124m",
        "CRIMSON": "\033[38;5;160m",
        "DARK_RED": "\033[38;5;88m",
        "PRIMARY_BORDER": "\033[38;5;160m",
        "ACCENT_LINE": "\033[38;5;196m",
        "ACCENT_GRADIENT": "\033[38;5;124m",
    }

    @staticmethod
    def create_banner() -> str:
        return CRIMSON_BANNER_ASCII


class EnhancedCommandExecutor:
    """
    Argument-vector executor retained for legacy Python callers.
    Rejects raw shell strings and executes only validated `argv` sequences with `shell=False`.
    """

    def __init__(self, argv: Sequence[str], timeout: int = 300, cwd: Optional[str | Path] = None) -> None:
        self.argv = argv
        self.timeout = timeout
        self.cwd = cwd
        self._runner = SafeSubprocessRunner()

    def execute(self) -> Dict[str, Any]:
        res: ExecutionResult = self._runner.run(
            self.argv,
            cwd=self.cwd,
            timeout=self.timeout,
        )
        return res.to_dict()


__all__ = [
    "__version__",
    "BrowserInspectionAdapter",
    "ConfinedWorkspace",
    "EnhancedCommandExecutor",
    "FileOperationsManager",
    "HexStrikeRuntime",
    "ModernVisualEngine",
    "SafeSubprocessRunner",
    "TokenAuthenticator",
    "WorkspaceSecurityError",
    "correlate_threat_indicators",
    "create_http_app",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
