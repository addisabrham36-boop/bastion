"""
Server-Side Template Injection (SSTI) detection rule (OWASP CRS 952100).

Covers:
- 952100  SSTIRule – multi-engine SSTI detection (Jinja2, Twig, FreeMarker,
          Smarty, Velocity, Handlebars, Pebble, and generic math probes).
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# 952100 – SSTI patterns across multiple template engines
# ---------------------------------------------------------------------------

_SSTI_PATTERNS: List[Tuple[str, str]] = [
    # ------------------------------------------------------------------
    # Jinja2 / Python
    # ------------------------------------------------------------------
    (
        r"\{\{\s*['\"]?\s*\d+\s*[*+\-/]\s*\d+",
        "SSTI probe: Jinja2 arithmetic expression in {{ }}",
    ),
    (
        r"\{\{\s*(?:config|request|self|g|namespace|lipsum|range|dict|joiner|cycler)\b",
        "SSTI: Jinja2 context variable access",
    ),
    (
        r"\{%\s*(?:for|if|macro|set|block|extends|import|include|from|do|call|filter|with|recursive|scoped|required|not\s+scoped)\b",
        "SSTI: Jinja2 / Twig template tag",
    ),
    # ------------------------------------------------------------------
    # Twig
    # ------------------------------------------------------------------
    (
        r"\{\{\s*\d+\s*[*+\-/]\s*\d+\s*\}\}",
        "SSTI probe: Twig arithmetic expression",
    ),
    (
        r"\{%\s*set\s+\w+\s*=.*%\}",
        "SSTI: Twig/Jinja2 variable assignment tag",
    ),
    # ------------------------------------------------------------------
    # FreeMarker
    # ------------------------------------------------------------------
    (r"<#assign\b", "SSTI: FreeMarker <#assign directive"),
    (r"<#if\b", "SSTI: FreeMarker <#if directive"),
    (r"\$\{.*?freemarker", "SSTI: FreeMarker expression with 'freemarker' keyword"),
    (r"\[=", "SSTI: FreeMarker alternative expression syntax [=...]"),
    (r"\[#", "SSTI: FreeMarker alternative directive syntax [#...]"),
    # ------------------------------------------------------------------
    # Smarty
    # ------------------------------------------------------------------
    (r"\{\$smarty\.", "SSTI: Smarty $smarty reserved variable"),
    (r"\{literal\}", "SSTI: Smarty {literal} block"),
    (r"\{php\}", "SSTI: Smarty {php} tag – code execution"),
    # ------------------------------------------------------------------
    # Velocity
    # ------------------------------------------------------------------
    (r"#set\s*\(", "SSTI: Velocity #set directive"),
    (r"#foreach\s*\(", "SSTI: Velocity #foreach directive"),
    (r"#include\s*\(", "SSTI: Velocity #include directive"),
    (r"\$\{.*class.*\}", "SSTI: Velocity class access expression"),
    # ------------------------------------------------------------------
    # Handlebars
    # ------------------------------------------------------------------
    (
        r"\{\{#(?:each|if|unless|with)\b",
        "SSTI: Handlebars block helper ({{#each}}, {{#if}}, etc.)",
    ),
    (
        r"\{\{[^}]+\.constructor\b",
        "SSTI: Handlebars .constructor access – prototype pollution",
    ),
    # ------------------------------------------------------------------
    # Pebble
    # ------------------------------------------------------------------
    (r"\{%\s*set\b", "SSTI: Pebble {% set %} tag"),
    # ------------------------------------------------------------------
    # Generic math / polyglot probes
    # ------------------------------------------------------------------
    (
        r"\{\{\s*['\"]?\d+\s*[*]\s*\d+['\"]?\s*\}\}",
        "SSTI probe: generic multiply expression {{ N*N }}",
    ),
    (
        r"\$\{['\"]?\d+\s*[*]\s*\d+['\"]?\}",
        "SSTI probe: generic EL multiply expression ${N*N}",
    ),
]
_COMPILED_SSTI = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _SSTI_PATTERNS
]


class SSTIRule(Rule):
    """Detect Server-Side Template Injection across multiple template engines (OWASP CRS 952100)."""

    RULE_ID = "952100"
    NAME = "Server-Side Template Injection (SSTI) Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_SSTI:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
