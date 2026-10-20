"""
HTTP Parameter Pollution (HPP) Detection Rules (OWASP CRS 971xxx).
Detects duplicate parameters, array-style injection, and WAF bypass via parameter duplication.
"""

import re
from typing import List
from urllib.parse import unquote_plus
from .base import Rule, Verdict

_MAX = 2048  # max query/body length for scanning


def _hpp_verdict(rule_id: str, reason: str, meta: dict) -> Verdict:
    return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta=meta)


def _clean(rule_id: str) -> Verdict:
    return Verdict.clean(rule_id)


# Detect array-notation keys that many frameworks expand automatically
_ARRAY_KEY = re.compile(r"\[\d*\]|\[\w+\]", re.ASCII)

# Detect PHP-style variable variable or class injection through parameter names
_PHP_PARAM_INJECTION = re.compile(r"\$\{|%24\{|\$\(", re.IGNORECASE)

# Detect Spring / Java EL injection via parameter names
_EL_PARAM = re.compile(r"\$\{.*?\}|#\{.*?\}", re.DOTALL)

# Separator confusion: multiple encodings of & or =
_SEPARATOR_CONFUSION = re.compile(r"%26|%3[Dd]|%00", re.IGNORECASE)


class DuplicateParameterRule(Rule):
    """Detect the same parameter submitted more than once in the query string."""

    RULE_ID = "971100"
    NAME = "HTTP Parameter Pollution — Duplicate Parameter"

    def match(self, request) -> Verdict:
        dupes = [k for k, v in request.query_params.items() if len(v) > 1]
        if dupes:
            return _hpp_verdict(
                self.RULE_ID,
                "Duplicate query parameters detected (potential HPP)",
                {"duplicated_keys": dupes[:10]},
            )
        return _clean(self.RULE_ID)


class ArrayNotationParameterRule(Rule):
    """Detect PHP/Rails array bracket notation used to inject multi-value parameters."""

    RULE_ID = "971110"
    NAME = "HTTP Parameter Pollution — Array Notation Injection"

    def match(self, request) -> Verdict:
        for key in request.query_params:
            if _ARRAY_KEY.search(key[:256]):
                return _hpp_verdict(
                    self.RULE_ID,
                    "Array-notation parameter key detected (potential HPP)",
                    {"key": key[:200]},
                )
        # Also check body
        body = request.body[:_MAX]
        if body and _ARRAY_KEY.search(body):
            return _hpp_verdict(
                self.RULE_ID,
                "Array-notation in request body (potential HPP)",
                {"body_snippet": body[:200]},
            )
        return _clean(self.RULE_ID)


class ParameterSeparatorConfusionRule(Rule):
    """Detect URL-encoded separators (%26, %3D) used to hide extra parameters."""

    RULE_ID = "971120"
    NAME = "HTTP Parameter Pollution — Separator Confusion"

    def match(self, request) -> Verdict:
        # Check raw path and body for encoded separators that bypass naive parsers
        for field_label, value in request.iter_values():
            if _SEPARATOR_CONFUSION.search(value[:_MAX]):
                return _hpp_verdict(
                    self.RULE_ID,
                    "URL-encoded parameter separator detected (potential HPP evasion)",
                    {"field": field_label, "snippet": value[:200]},
                )
        return _clean(self.RULE_ID)


class PHPParamInjectionRule(Rule):
    """Detect PHP expression syntax injected through parameter names or values."""

    RULE_ID = "971130"
    NAME = "HTTP Parameter Pollution — PHP Expression in Parameter"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if _PHP_PARAM_INJECTION.search(value[:_MAX]):
                return _hpp_verdict(
                    self.RULE_ID,
                    "PHP/Shell expression syntax in parameter (potential injection via HPP)",
                    {"field": field_label, "snippet": value[:200]},
                )
        return _clean(self.RULE_ID)
