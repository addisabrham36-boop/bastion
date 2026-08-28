"""
Cross-Site Scripting (XSS) Detection Rules (OWASP CRS 941xxx).
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict


def _match_helper(rule_id: str, compiled_patterns, request) -> Verdict:
    for field_label, value in request.iter_values():
        if not value:
            continue
        for pattern, reason in compiled_patterns:
            if pattern.search(value):
                return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
    return Verdict.clean(rule_id)


_ALL_XSS_PATTERNS: List[Tuple[str, str]] = [
    (r"<\s*script\b", "HTML <script> opening tag injection"),
    (r"<\s*/\s*script\s*>", "HTML </script> closing tag injection"),
    (r"\b(?:onload|onerror|onclick|ondblclick|onmouseover|onfocus|onblur|onchange|onsubmit|onkeydown|onkeypress|onkeyup)\s*=", "HTML inline event handler attribute injection"),
    (r"(?:href|src|action|formaction|data)\s*=\s*['\"]?\s*javascript\s*:", "HTML attribute with javascript: pseudo-protocol"),
    (r"(?:href|src)\s*=\s*['\"]?\s*vbscript\s*:", "HTML attribute with vbscript: pseudo-protocol"),
    (r"data\s*:\s*text/html", "data:text/html MIME vector injection"),
    (r"<\s*svg[^>]*\bon[a-z]+\s*=", "SVG element with inline event handler"),
    (r"<\s*svg/onload\s*=", "Malformed SVG/onload attribute injection"),
    (r"<\s*img[^>]+onerror\s*=", "<img onerror=...> event handler injection"),
    (r"<\s*(?:iframe|embed|object|base|applet)\b", "Dangerous frame/embed/object tag injection"),
    (r"\b(?:eval|alert|prompt|confirm)\s*\(\s*(?:['\"`]|document\.|window\.|[0-9]+)", "JavaScript execution sink invocation"),
    (r"\bdocument\.cookie\b", "DOM document.cookie access attempt"),
    (r"\b(?:window|document)\.location\s*=\s*['\"`]", "DOM location property assignment"),
    (r"\bString\.fromCharCode\s*\(", "JavaScript String.fromCharCode() character obfuscation"),
    (r"\bdocument\.write(?:ln)?\s*\(", "Dangerous document.write() sink invocation"),
]
_COMPILED_ALL_XSS = [(re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _ALL_XSS_PATTERNS]


class XSSRule(Rule):
    RULE_ID = "941100"
    NAME = "Cross-Site Scripting (XSS) Comprehensive Filter"
    def match(self, request) -> Verdict: return _match_helper(self.RULE_ID, _COMPILED_ALL_XSS, request)


class XSSScriptTagRule(Rule):
    RULE_ID = "941101"
    NAME = "XSS HTML Script Tag Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"<\s*script\b|<\s*/\s*script\s*>", re.I), "Script tag injection")]
        return _match_helper(self.RULE_ID, p, request)


class XSSEventHandlerRule(Rule):
    RULE_ID = "941110"
    NAME = "XSS Inline Event Handler Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bon[a-z]+\s*=", re.I), "Event handler injection")]
        return _match_helper(self.RULE_ID, p, request)


class XSSPseudoProtocolRule(Rule):
    RULE_ID = "941120"
    NAME = "XSS JavaScript / VBScript Pseudo-Protocol"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"javascript:|vbscript:|data:text/html", re.I), "Pseudo-protocol URI injection")]
        return _match_helper(self.RULE_ID, p, request)


class XSSSVGVectorRule(Rule):
    RULE_ID = "941130"
    NAME = "XSS SVG Element Vector Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"<\s*svg", re.I), "SVG element vector")]
        return _match_helper(self.RULE_ID, p, request)


class XSSMediaVectorRule(Rule):
    RULE_ID = "941140"
    NAME = "XSS Media Tag Event Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"<\s*(?:img|video|audio)[^>]+onerror\s*=", re.I), "Media tag onerror injection")]
        return _match_helper(self.RULE_ID, p, request)


class XSSFrameObjectRule(Rule):
    RULE_ID = "941150"
    NAME = "XSS Iframe / Object / Embed Tag Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"<\s*(?:iframe|embed|object|base)\b", re.I), "Frame / Object injection")]
        return _match_helper(self.RULE_ID, p, request)


class XSSExecutionSinksRule(Rule):
    RULE_ID = "941160"
    NAME = "XSS JavaScript Execution Sinks"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:eval|alert|prompt|confirm)\s*\(", re.I), "JS execution sink")]
        return _match_helper(self.RULE_ID, p, request)


class XSSCookieStorageRule(Rule):
    RULE_ID = "941170"
    NAME = "XSS DOM Cookie & Storage Access"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bdocument\.cookie\b|\blocalStorage\b", re.I), "DOM cookie/storage access")]
        return _match_helper(self.RULE_ID, p, request)


class XSSRedirectionHijackingRule(Rule):
    RULE_ID = "941180"
    NAME = "XSS DOM Navigation / Location Hijacking"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:window|document)\.location\s*=", re.I), "DOM location hijacking")]
        return _match_helper(self.RULE_ID, p, request)


class XSSCharCodeObfuscationRule(Rule):
    RULE_ID = "941190"
    NAME = "XSS CharCode & Base64 Obfuscation"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bString\.fromCharCode\s*\(", re.I), "String.fromCharCode obfuscation")]
        return _match_helper(self.RULE_ID, p, request)


class XSSDOMSourceSinkRule(Rule):
    RULE_ID = "941200"
    NAME = "XSS DOM Sources & Sinks (document.write)"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\bdocument\.write(?:ln)?\s*\(", re.I), "document.write sink")]
        return _match_helper(self.RULE_ID, p, request)


class XSSCSSExpressionRule(Rule):
    RULE_ID = "941210"
    NAME = "XSS CSS Style Expression Injection"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"expression\s*\(|-moz-binding", re.I), "CSS dynamic expression")]
        return _match_helper(self.RULE_ID, p, request)
