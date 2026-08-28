"""
Server-Side Request Forgery (SSRF) detection rule (OWASP CRS 934100).
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_SSRF_PATTERNS: List[Tuple[str, str]] = [
    (r"(?:https?://|//|@|^)\s*(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|0\.0\.0\.0|\[?::1\]?)(?::\d+|/|$)", "Loopback / Localhost address target"),
    (r"\b(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.internal|instance-data)\b", "Cloud provider metadata endpoint target"),
    (r"(?:https?://|//|@|^)\s*10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+|/|$)", "Private Class A (10.0.0.0/8) RFC 1918 target"),
    (r"(?:https?://|//|@|^)\s*172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}(?::\d+|/|$)", "Private Class B (172.16.0.0/12) RFC 1918 target"),
    (r"(?:https?://|//|@|^)\s*192\.168\.\d{1,3}\.\d{1,3}(?::\d+|/|$)", "Private Class C (192.168.0.0/16) RFC 1918 target"),
    (r"\b(?:file|gopher|dict|tftp|ldap|ldaps|netdoc)://", "Dangerous non-HTTP protocol URI scheme"),
]

_COMPILED_SSRF = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _SSRF_PATTERNS]


class SSRFRule(Rule):
    RULE_ID = "934100"
    NAME = "Server-Side Request Forgery (SSRF) Guard"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_SSRF:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
