"""
Security Header Audit Rules (OWASP CRS 976xxx).
Detects missing, forged, or dangerous response-influencing request headers.
Logs when clients send headers that signal weak security posture or attempt header injection.
"""

import re
from .base import Rule, Verdict

_MAX = 512


def _hdr_verdict(rule_id: str, reason: str, meta: dict) -> Verdict:
    return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta=meta)


def _clean(rule_id: str) -> Verdict:
    return Verdict.clean(rule_id)


# CRLF injection in arbitrary request headers
_CRLF_INJECTION = re.compile(r"[\r\n]", re.ASCII)

# Detect attempts to forge security headers that backends trust
_FORGED_INTERNAL_HEADERS = [
    "x-real-ip",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-cluster-client-ip",
    "x-client-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "x-original-forwarded-for",
]

# Private IP ranges in Forwarded/X-Forwarded-For for IP spoofing
_PRIVATE_IP = re.compile(
    r"(?:^|\s|,)(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|::1|localhost)",
    re.IGNORECASE,
)

# Detect Content-Security-Policy bypass attempt via meta-tag injection in body
_CSP_META_INJECT = re.compile(
    r"<meta[^>]+http-equiv\s*=\s*['\"]content-security-policy['\"]",
    re.IGNORECASE | re.DOTALL,
)

# Detect iframe/frame ancestor spoofing via Referer manipulation
_REFERER_INJECTION = re.compile(r"[\r\n<>\"']", re.ASCII)

# Accept-Language header injection (used in some log-injection attacks)
_ACCEPT_LANG_INJECTION = re.compile(r"[\r\n<>\"']|script|javascript", re.IGNORECASE)

# Detect X-Requested-With spoofing (CSRF bypass in older APIs)
_CSRF_BYPASS_HEADER = re.compile(r"XMLHttpRequest", re.IGNORECASE)


class CRLFHeaderInjectionRule(Rule):
    """Detect CRLF (\\r\\n) injection in arbitrary HTTP request headers."""

    RULE_ID = "976100"
    NAME = "Security Header Audit — CRLF Header Injection"

    def match(self, request) -> Verdict:
        for hdr_name, hdr_value in request.headers.items():
            if _CRLF_INJECTION.search(hdr_value[:_MAX]):
                return _hdr_verdict(
                    self.RULE_ID,
                    f"CRLF injection detected in request header '{hdr_name}'",
                    {"header": hdr_name, "value": hdr_value[:200]},
                )
        return _clean(self.RULE_ID)


class IPSpoofingForwardedHeaderRule(Rule):
    """Detect private/loopback IPs submitted in X-Forwarded-For to spoof source IP."""

    RULE_ID = "976105"
    NAME = "Security Header Audit — IP Spoofing via X-Forwarded-For"

    def match(self, request) -> Verdict:
        for hdr in _FORGED_INTERNAL_HEADERS:
            value = request.headers.get(hdr, "")[:_MAX]
            if value and _PRIVATE_IP.search(value):
                return _hdr_verdict(
                    self.RULE_ID,
                    f"Private/loopback IP in '{hdr}' header (IP spoofing attempt)",
                    {"header": hdr, "value": value[:200]},
                )
        return _clean(self.RULE_ID)


class CSPMetaTagInjectionRule(Rule):
    """Detect CSP meta-tag injection in request bodies that try to override server CSP."""

    RULE_ID = "976110"
    NAME = "Security Header Audit — CSP Meta-Tag Injection in Body"

    def match(self, request) -> Verdict:
        body = request.body[:16384]
        if body and _CSP_META_INJECT.search(body):
            return _hdr_verdict(
                self.RULE_ID,
                "CSP override meta-tag injection detected in request body",
                {"snippet": body[:200]},
            )
        return _clean(self.RULE_ID)


class RefererHeaderInjectionRule(Rule):
    """Detect control characters or script content injected in Referer header."""

    RULE_ID = "976115"
    NAME = "Security Header Audit — Referer Header Injection"

    def match(self, request) -> Verdict:
        referer = request.headers.get("referer", "")[:_MAX]
        if referer and _REFERER_INJECTION.search(referer):
            return _hdr_verdict(
                self.RULE_ID,
                "Injection characters detected in Referer header",
                {"referer": referer[:200]},
            )
        return _clean(self.RULE_ID)


class AcceptLanguageInjectionRule(Rule):
    """Detect script/injection content in Accept-Language header (log injection vector)."""

    RULE_ID = "976120"
    NAME = "Security Header Audit — Accept-Language Header Injection"

    def match(self, request) -> Verdict:
        lang = request.headers.get("accept-language", "")[:_MAX]
        if lang and _ACCEPT_LANG_INJECTION.search(lang):
            return _hdr_verdict(
                self.RULE_ID,
                "Injection content detected in Accept-Language header",
                {"accept_language": lang[:200]},
            )
        return _clean(self.RULE_ID)
