"""Browser capability package."""

from hexstrike.browser.inspector import (
    BrowserInspectionAdapter,
    DEFAULT_SECURE_CHROMIUM_ARGS,
    FORBIDDEN_DEFAULT_BROWSER_FLAGS,
    redact_cookies_list,
    sanitize_dom_preview,
)

__all__ = [
    "BrowserInspectionAdapter",
    "DEFAULT_SECURE_CHROMIUM_ARGS",
    "FORBIDDEN_DEFAULT_BROWSER_FLAGS",
    "redact_cookies_list",
    "sanitize_dom_preview",
]
