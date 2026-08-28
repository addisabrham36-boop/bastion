"""
Cross-Site Scripting (XSS) detection rule (OWASP CRS 941100).
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_XSS_PATTERNS: List[Tuple[str, str]] = [
    (r"<\s*script\b", "explicit <script> tag"),
    (r"<\s*/\s*script\s*>", "closing </script> tag"),
    (r"\bjavascript\s*:", "javascript: pseudo-protocol"),
    (r"\bvbscript\s*:", "vbscript: pseudo-protocol"),
    (r"\bdata\s*:\s*text/html", "data:text/html URI scheme"),
    (
        r"\b(?:on(?:load|error|click|dblclick|contextmenu|mouseover|mouseenter|mouseleave|mousemove|mouseout|mouseup|mousedown|focus|blur|change|submit|input|keydown|keyup|keypress|pointerdown|pointerup|pointermove|select|wheel|touchstart|touchend|touchmove|animationstart|animationend|toggle))\s*=",
        "HTML DOM event handler attribute",
    ),
    (r"<\s*(?:iframe|embed|object|base|applet)\b", "dangerous HTML embedding tag"),
    (r"<\s*svg\b[^>]*\bon[a-z]+\s*=", "SVG inline event handler execution"),
    (r"<\s*img\b[^>]*\bonerror\s*=", "Image onerror payload"),
    (r"\bdocument\.(?:cookie|domain|write|writeln|location)\b", "DOM document manipulation"),
    (r"\bwindow\.(?:location|navigate)\b", "DOM window navigation"),
    (r"\b(?:eval|alert|prompt|confirm)\s*\(\s*(?:['\"`\d]|document\.|window\.|location\.|cookie|this\b|\))", "dangerous JavaScript execution sink"),
]

_COMPILED_XSS = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _XSS_PATTERNS]


class XSSRule(Rule):
    RULE_ID = "941100"
    NAME = "Cross-Site Scripting (XSS) Filter"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_XSS:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
