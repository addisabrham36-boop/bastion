"""
Remote File Inclusion (RFI) detection rules (OWASP CRS 950xxx).

Covers:
- 950100  RemoteFileInclusionRule – direct RFI via URL in parameters
- 950110  RFIEvasionRule          – RFI with URL-encoding evasion
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# 950100 – Remote File Inclusion
# ---------------------------------------------------------------------------

_RFI_PATTERNS: List[Tuple[str, str]] = [
    # Query parameter containing remote URL pointing at a script extension
    (
        r"(?:https?|ftp)://(?!(?:127\.0\.0\.1|localhost))\S+\.(?:php|asp|aspx|jsp|pl|py|sh|bash|rb|txt)",
        "RFI: remote script URL in parameter",
    ),
    # Bare = followed by http/ftp scheme
    (r"=(?:https?|ftp)://", "RFI: URL-valued parameter"),
    # Common inclusion parameter names followed by remote URL
    (
        r"(?:file|page|path|include|require|template|doc|document|folder|url|redirect|load|fetch|resource)=(?:https?|ftp)://",
        "RFI: inclusion parameter with remote URL",
    ),
]
_COMPILED_RFI = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _RFI_PATTERNS
]

# ---------------------------------------------------------------------------
# 950110 – RFI with URL-encoding evasion
# ---------------------------------------------------------------------------

_RFI_EVASION_PATTERNS: List[Tuple[str, str]] = [
    (r"\b(?:php|data|expect|zip|phar|glob|gopher|dict)://", "RFI/LFI wrapper injection"),
    (r"\.\./.*(?:https?|ftp)://", "RFI evasion: directory traversal combined with remote URL"),
    (r"//(?:etc|windows|usr|var|tmp)/", "RFI evasion: double-slash in sensitive path"),
    (r"(?:https?|ftp)://[^/]+/[^?#]*\.\./", "RFI evasion: remote URL with path traversal"),
]
_COMPILED_RFI_EVASION = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _RFI_EVASION_PATTERNS
]


# ---------------------------------------------------------------------------
# Rule classes
# ---------------------------------------------------------------------------


class RemoteFileInclusionRule(Rule):
    """Detect Remote File Inclusion attacks (OWASP CRS 950100)."""

    RULE_ID = "950100"
    NAME = "Remote File Inclusion Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_RFI:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)


class RFIEvasionRule(Rule):
    """Detect RFI with URL-encoding evasion techniques (OWASP CRS 950110)."""

    RULE_ID = "950110"
    NAME = "Remote File Inclusion Evasion Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_RFI_EVASION:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
