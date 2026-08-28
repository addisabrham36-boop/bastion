"""
PHP injection detection rules (OWASP CRS 933xxx).

Covers:
- 933100  PHPCodeInjectionRule    – PHP code injection / eval chains
- 933110  PHPObjectInjectionRule  – PHP unserialize / object injection
- 933120  PHPFileInclusionRule    – PHP file inclusion (local & remote)
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# 933100 – PHP code injection
# ---------------------------------------------------------------------------

_PHP_CODE_PATTERNS: List[Tuple[str, str]] = [
    (
        r"\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress|strrev)\b",
        "PHP eval() with obfuscation function",
    ),
    (r"\bbase64_decode\s*\(", "PHP base64_decode() – possible payload decoding"),
    (
        r"\bpreg_replace\s*\(\s*['\"].*[eE]['\"]",
        "PHP preg_replace with /e modifier – code execution",
    ),
    (r"\bassert\s*\(\s*['\"]", "PHP assert() with string argument – code injection"),
    (r"\bcreate_function\s*\(", "PHP create_function() – dynamic code execution"),
    (r"\bpassthru\s*\(\s*['\"]", "PHP passthru() shell command execution"),
    (r"\bshell_exec\s*\(\s*['\"]", "PHP shell_exec() shell command execution"),
    (r"\bsystem\s*\(\s*['\"]", "PHP system() shell command execution"),
    (r"<\?php\b", "PHP opening tag injection (<?php)"),
    (r"<\?=", "PHP short echo tag injection (<?=)"),
]
_COMPILED_PHP_CODE = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _PHP_CODE_PATTERNS
]

# ---------------------------------------------------------------------------
# 933110 – PHP object injection (unserialize)
# ---------------------------------------------------------------------------

_PHP_OBJ_PATTERNS: List[Tuple[str, str]] = [
    (r"O:\d+:\"[A-Za-z]", "PHP serialized object (O:<len>:<classname>)"),
    (r"a:\d+:\{", "PHP serialized array"),
    (r"s:\d+:\"", "PHP serialized string"),
]
_COMPILED_PHP_OBJ = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _PHP_OBJ_PATTERNS
]

# ---------------------------------------------------------------------------
# 933120 – PHP file inclusion
# ---------------------------------------------------------------------------

_PHP_FI_PATTERNS: List[Tuple[str, str]] = [
    (
        r"\binclude\s*\(\s*['\"]?(?:https?://|ftp://)",
        "PHP include() with remote URL",
    ),
    (
        r"\brequire\s*\(\s*['\"]?(?:https?://|ftp://)",
        "PHP require() with remote URL",
    ),
    (r"\binclude_once\s*\(", "PHP include_once() – potential file inclusion"),
    (r"\brequire_once\s*\(", "PHP require_once() – potential file inclusion"),
    (
        r"\bfile_get_contents\s*\(\s*['\"]?(?:https?://|php://)",
        "PHP file_get_contents() with remote/stream URL",
    ),
    (r"php://filter/", "PHP stream wrapper php://filter – LFI evasion"),
    (r"php://input\b", "PHP stream wrapper php://input – RCE vector"),
    (r"data://text/plain", "PHP data:// stream wrapper injection"),
]
_COMPILED_PHP_FI = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _PHP_FI_PATTERNS
]


# ---------------------------------------------------------------------------
# Rule classes
# ---------------------------------------------------------------------------


class PHPCodeInjectionRule(Rule):
    """Detect PHP code injection and dangerous PHP function calls (OWASP CRS 933100)."""

    RULE_ID = "933100"
    NAME = "PHP Code Injection Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_PHP_CODE:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)


class PHPObjectInjectionRule(Rule):
    """Detect PHP object injection via unserialize() (OWASP CRS 933110)."""

    RULE_ID = "933110"
    NAME = "PHP Object Injection Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_PHP_OBJ:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)


class PHPFileInclusionRule(Rule):
    """Detect PHP file inclusion vulnerabilities (LFI/RFI via PHP wrappers) (OWASP CRS 933120)."""

    RULE_ID = "933120"
    NAME = "PHP File Inclusion Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_PHP_FI:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
