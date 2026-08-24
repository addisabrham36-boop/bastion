"""
SQL injection detection rule.

Signature-based (regex) detection across UNION-based, boolean-blind,
time-blind, and stacked-query injection. Strips comment sequences before
matching so obfuscated payloads like UNION/**/SELECT still hit the
UNION...SELECT pattern — comment injection between keywords is one of the
most common WAF-bypass techniques for naive regex matchers.

RULE_ID "942100" matches the dashboard's existing mock log row
("OWASP-942100 (SQLi)") so Phase 3/4 wiring doesn't need to touch the
dashboard's expected rule-ID format.
"""

import re

from .base import Rule, Verdict

# Matches /* ... */, -- to end of line, and # to end of line. Applied
# before pattern matching so "UNION/**/SELECT" and "UNION--\nSELECT"
# both normalize to "UNION SELECT" and still trip the UNION+SELECT rule.
_COMMENT_RE = re.compile(r"/\*.*?\*/|--[^\n]*|#[^\n]*", re.DOTALL)

# (pattern, human-readable reason). Order doesn't matter — first match
# wins and short-circuits, since any one hit is enough to block.
_SQLI_PATTERNS = [
    (r"\bunion\b[\s\S]{0,50}?\bselect\b", "UNION-based SQLi"),
    (r"\b(?:or|and)\b\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1['\"]?", "boolean-based tautology (X=X)"),
    (r"'\s*(?:or|and)\b\s*['\"]?(\w+)['\"]?\s*=\s*['\"]?\1", "quoted tautology payload (' OR '1'='1)"),
    (r"\b(?:or|and)\b\s+(?:true|1)\s*(?:--|#|/\*|$)", "boolean literal injection (OR true)"),
    (r"\bsleep\s*\(\s*\d+\s*\)", "time-based SQLi (SLEEP)"),
    (r"\bwaitfor\s+delay\b", "time-based SQLi (WAITFOR DELAY)"),
    (r"\bbenchmark\s*\(\s*\d+\s*,", "time-based SQLi (BENCHMARK)"),
    (r";\s*(?:drop|delete|insert|update|alter)\s+(?:table|database|from|into|user|view)\b", "stacked-query SQLi"),
    (r"\binformation_schema\b", "schema enumeration"),
    (r"\bxp_cmdshell\b", "SQL Server command execution attempt"),
]


_COMPILED = [(re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in _SQLI_PATTERNS]


class SQLiRule(Rule):
    RULE_ID = "942100"
    NAME = "SQL Injection (SQLi) Shield"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            cleaned = _COMMENT_RE.sub(" ", value)
            for pattern, reason in _COMPILED:
                if pattern.search(cleaned):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
