"""
HTTP Request Smuggling detection rule (OWASP CRS 921100).

Covers:
- 921100  HTTPSmugglingRule – conflicting Transfer-Encoding / Content-Length headers
  and obfuscated TE header values used in CL.TE / TE.CL / TE.TE attacks.
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# Obfuscated Transfer-Encoding value patterns (TE.TE variant)
# ---------------------------------------------------------------------------

_TE_OBFUSCATION_PATTERNS: List[Tuple[str, str]] = [
    (r"xchunked", "Obfuscated Transfer-Encoding: xchunked"),
    (r"chunked\s*,\s*identity", "Conflicting TE directive: chunked, identity"),
    (r"chunked\s+", "TE value with trailing whitespace before comma/end"),
]
_COMPILED_TE_OBF = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _TE_OBFUSCATION_PATTERNS
]


class HTTPSmugglingRule(Rule):
    """Detect HTTP request smuggling attacks (OWASP CRS 921100)."""

    RULE_ID = "921100"
    NAME = "HTTP Request Smuggling Detection"

    def match(self, request) -> Verdict:
        headers: dict = request.headers or {}

        # Detect header names with embedded spaces before colon (TE.TE smuggling evasion):
        # e.g. "Transfer-Encoding : chunked" – some backends strip the space,
        # others treat it as a different header name.
        raw_header_names = list(headers.keys())
        for name in raw_header_names:
            # normalizer already lower-cases, so check for trailing space
            if name.rstrip() in ("transfer-encoding",) and name != name.rstrip():
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason="Whitespace-padded Transfer-Encoding header name (TE.TE smuggling)",
                    meta={"field": f"header:{name}"},
                )

        te_value = headers.get("transfer-encoding", "")
        cl_value = headers.get("content-length", "")

        # CL.TE / TE.CL: both headers present simultaneously
        if te_value and cl_value:
            te_norm = te_value.strip().lower()
            if "chunked" in te_norm:
                return Verdict(
                    blocked=True,
                    rule_id=self.RULE_ID,
                    reason="Conflicting Transfer-Encoding: chunked and Content-Length headers (CL.TE / TE.CL smuggling)",
                    meta={
                        "field": "header:transfer-encoding",
                        "matched_value": f"TE={te_value!r} CL={cl_value!r}",
                    },
                )

        # TE.TE: obfuscated Transfer-Encoding values
        if te_value:
            for pattern, reason in _COMPILED_TE_OBF:
                if pattern.search(te_value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": "header:transfer-encoding", "matched_value": te_value[:200]},
                    )

        return Verdict.clean(self.RULE_ID)
