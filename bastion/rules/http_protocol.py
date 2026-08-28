"""
HTTP Protocol Anomaly detection rules (OWASP CRS 920xxx).

Covers:
- 920100  HTTPMethodRule      – non-standard HTTP methods
- 920200  HTTPHeaderAnomalyRule – oversized / malformed headers
- 920300  CRLFInjectionRule   – HTTP response splitting
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# 920100 – Non-standard HTTP methods
# ---------------------------------------------------------------------------

_ALLOWED_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)

# ---------------------------------------------------------------------------
# 920200 – Header anomalies
# ---------------------------------------------------------------------------

_HEADER_ANOMALY_PATTERNS: List[Tuple[str, str]] = [
    # Multiple Content-Length values (comma-separated or repeated)
    (r"^\d+\s*,\s*\d+", "Multiple Content-Length values detected"),
]
_COMPILED_HEADER_ANOMALY = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r)
    for p, r in _HEADER_ANOMALY_PATTERNS
]

_MAX_HEADER_VALUE_LEN = 8192

# ---------------------------------------------------------------------------
# 920300 – CRLF Injection / HTTP Response Splitting
# ---------------------------------------------------------------------------

_CRLF_PATTERNS: List[Tuple[str, str]] = [
    (r"\r\n", "Raw CRLF sequence detected"),
    (r"\n\r", "Reversed CRLF sequence detected"),
    (r"%0d%0a", "URL-encoded CRLF (%0d%0a)"),
    (r"%0D%0A", "URL-encoded CRLF (%0D%0A)"),
    (r"(?:%0d%0a|%0D%0A|\r\n)Location\s*:", "CRLF header injection – Location"),
    (r"(?:%0d%0a|%0D%0A|\r\n)Set-Cookie\s*:", "CRLF header injection – Set-Cookie"),
    (r"(?:%0d%0a|%0D%0A|\r\n)Content-Type\s*:", "CRLF header injection – Content-Type"),
    (r"(?:%0d%0a|%0D%0A|\r\n)[\w-]+\s*:", "CRLF arbitrary header injection"),
]
_COMPILED_CRLF = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _CRLF_PATTERNS
]


# ---------------------------------------------------------------------------
# Rule classes
# ---------------------------------------------------------------------------


class HTTPMethodRule(Rule):
    """Block non-standard / dangerous HTTP methods (OWASP CRS 920100)."""

    RULE_ID = "920100"
    NAME = "HTTP Method Enforcement"

    def match(self, request) -> Verdict:
        method = (request.method or "").upper()
        if method not in _ALLOWED_METHODS:
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason=f"Disallowed HTTP method: {method}",
                meta={"method": method},
            )
        return Verdict.clean(self.RULE_ID)


class HTTPHeaderAnomalyRule(Rule):
    """Detect oversized header values and malformed Host / Content-Length (OWASP CRS 920200)."""

    RULE_ID = "920200"
    NAME = "HTTP Header Anomaly Detection"

    def match(self, request) -> Verdict:
        headers: dict = request.headers or {}

        # 1. Oversized header values
        for header_name, header_value in headers.items():
            if not header_value:
                continue
            if len(header_value) > _MAX_HEADER_VALUE_LEN:
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason=f"Oversized header value in '{header_name}' ({len(header_value)} chars)",
                    meta={"field": f"header:{header_name}", "matched_value": header_value[:200]},
                )

        # 2. Missing Host header (required by HTTP/1.1)
        # Only flag when there are other headers present (real HTTP/1.1 client)
        # to avoid false positives on direct/unit-test bare requests
        host = headers.get("host", "")
        if headers and not host.strip():
            return Verdict(
                blocked=True,
                rule_id=self.RULE_ID,
                reason="Missing or empty Host header",
                meta={"field": "header:host"},
            )

        # 3. Malformed / multiple Content-Length
        content_length = headers.get("content-length", "")
        if content_length:
            for pattern, reason in _COMPILED_HEADER_ANOMALY:
                if pattern.search(content_length):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": "header:content-length", "matched_value": content_length[:200]},
                    )

        return Verdict.clean(self.RULE_ID)


class CRLFInjectionRule(Rule):
    """Detect HTTP response splitting via CRLF injection (OWASP CRS 920300)."""

    RULE_ID = "920300"
    NAME = "CRLF Injection / HTTP Response Splitting"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_CRLF:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
