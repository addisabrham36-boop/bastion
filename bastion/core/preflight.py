"""
Preflight protocol checks: method validation, URI/header/body size limits,
and structural protocol violations.
"""

from typing import Optional, Tuple
from fastapi import Request
from .enums import DecisionAction
from ..proxy.router import SiteConfig


class PreflightViolation(Exception):
    def __init__(self, status_code: int, error: str, message: str):
        self.status_code = status_code
        self.error = error
        self.message = message


def validate_preflight(
    method: str,
    raw_path: str,
    raw_query: str,
    headers: dict,
    site: SiteConfig,
) -> None:
    """Run cheap preflight validation checks before expensive rule evaluations."""
    # 1. Path length limit
    total_uri_len = len(raw_path) + (len(raw_query) + 1 if raw_query else 0)
    if total_uri_len > site.max_path_bytes:
        raise PreflightViolation(
            status_code=414,
            error="URI Too Long",
            message=f"Request URI length {total_uri_len} exceeds limit of {site.max_path_bytes} bytes.",
        )

    # 2. Method check
    if method not in site.allowed_methods:
        raise PreflightViolation(
            status_code=405,
            error="Method Not Allowed",
            message=f"HTTP method '{method}' is not allowed for site '{site.id}'.",
        )

    # 3. Header size check
    total_header_bytes = sum(len(k) + len(v) for k, v in headers.items())
    if total_header_bytes > 32_768:
        raise PreflightViolation(
            status_code=431,
            error="Request Header Fields Too Large",
            message=f"Total header bytes {total_header_bytes} exceeds limit of 32768 bytes.",
        )
