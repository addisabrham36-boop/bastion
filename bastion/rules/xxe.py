"""
XML External Entity (XXE) injection detection rule (OWASP CRS 953100).

Covers:
- 953100  XXERule – DOCTYPE/ENTITY declarations, SYSTEM/PUBLIC identifiers,
          dangerous URI schemes, and URL-encoded variants.
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# 953100 – XXE patterns
# ---------------------------------------------------------------------------

_XXE_PATTERNS: List[Tuple[str, str]] = [
    # DOCTYPE / ENTITY declarations
    (r"<!DOCTYPE\s+[^>]*\[", "XXE: DOCTYPE with internal subset declaration"),
    (r"<!ENTITY\s+", "XXE: ENTITY declaration"),
    (r"<!ENTITY\s+\S+\s+SYSTEM\b", "XXE: ENTITY with SYSTEM identifier"),
    (r"<!ENTITY\s+\S+\s+PUBLIC\b", "XXE: ENTITY with PUBLIC identifier"),
    # SYSTEM URI with dangerous schemes
    (
        r"SYSTEM\s+['\"](?:file:|http:|ftp:|php:|expect:|data:|jar:)",
        "XXE: SYSTEM identifier with dangerous URI scheme",
    ),
    (r"SYSTEM\s+['\"]//", "XXE: SYSTEM identifier with protocol-relative URL"),
    # Entity references
    (r"%xxe;", "XXE: parameter entity reference %xxe;"),
    (r"&xxe;", "XXE: general entity reference &xxe;"),
    # DOCTYPE-context entity references (any 2-20 char entity name)
    (r"&[a-zA-Z]{2,20};", "XXE: XML entity reference"),
    # Namespace / schema attributes
    (r"xmlns:\w+\s*=\s*['\"]", "XXE: custom XML namespace declaration"),
    (r"\bxsi:schemaLocation\b", "XXE: xsi:schemaLocation – external schema injection"),
    (r"<!\[CDATA\[.*\]\]>", "XXE: CDATA section – possible content injection"),
    # URL-encoded variants
    (r"%3C%21DOCTYPE", "XXE evasion: URL-encoded <!DOCTYPE"),
    (r"%3C%21ENTITY", "XXE evasion: URL-encoded <!ENTITY"),
]
_COMPILED_XXE = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _XXE_PATTERNS
]


class XXERule(Rule):
    """Detect XML External Entity (XXE) injection attacks (OWASP CRS 953100)."""

    RULE_ID = "953100"
    NAME = "XML External Entity (XXE) Injection Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_XXE:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
