"""
Host Header Manipulation Rules (OWASP CRS 970xxx).
Detects Host header injection, routing confusion, cache poisoning, and password-reset poisoning.
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

# ── Helpers ───────────────────────────────────────────────────────────────────

_MAX = 512  # maximum host header length to scan


def _host_verdict(rule_id: str, reason: str, meta: dict) -> Verdict:
    return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta=meta)


def _clean(rule_id: str) -> Verdict:
    return Verdict.clean(rule_id)


# ── Compiled patterns ─────────────────────────────────────────────────────────

# Host header that contains an extra port injection or forged sub-hostname
_EXTRA_HOST_PORT = re.compile(r"[\x00-\x1f\x7f]", re.ASCII)

# Host contains whitespace (header injection / CRLF)
_HOST_WHITESPACE = re.compile(r"[\r\n\t ]", re.ASCII)

# Host contains @ (user-info injection)
_HOST_AT = re.compile(r"@")

# X-Forwarded-Host / X-Original-Host override injection
_FORWARDED_HOST_INJECTION = re.compile(
    r"(?:localhost|127\.|0\.0\.0\.0|::1|169\.254\.|10\.\d|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)",
    re.IGNORECASE,
)

# X-Host-Override header probing for cache poisoning
_CACHE_POISON_HEADERS: List[str] = [
    "x-forwarded-host",
    "x-original-host",
    "x-rewrite-url",
    "x-override-url",
    "x-host",
]

# Host header pointing to a different domain via subdomain takeover probes
_SUBDOMAIN_TAKEOVER = re.compile(
    r"\.(?:azurewebsites\.net|herokuapp\.com|github\.io|s3\.amazonaws\.com|"
    r"cloudfront\.net|unbouncepages\.com|myshopify\.com|netlify\.app|firebaseapp\.com)",
    re.IGNORECASE,
)

# Absolute URI in request-target (proxy SSRF)
_ABSOLUTE_URI = re.compile(r"^https?://", re.IGNORECASE)


# ── Rule classes ──────────────────────────────────────────────────────────────

class HostHeaderInjectionRule(Rule):
    """Detect control characters and whitespace in the Host header (CRLF injection)."""

    RULE_ID = "970100"
    NAME = "Host Header CRLF / Control Character Injection"

    def match(self, request) -> Verdict:
        host = request.headers.get("host", "")[:_MAX]
        if not host:
            return _clean(self.RULE_ID)
        if _EXTRA_HOST_PORT.search(host):
            return _host_verdict(
                self.RULE_ID,
                "Control character in Host header",
                {"host": host[:200]},
            )
        if _HOST_WHITESPACE.search(host):
            return _host_verdict(
                self.RULE_ID,
                "Whitespace / CRLF in Host header",
                {"host": host[:200]},
            )
        return _clean(self.RULE_ID)


class HostHeaderAtSignRule(Rule):
    """Detect user-info (@ sign) embedded in Host, used to confuse parsers."""

    RULE_ID = "970105"
    NAME = "Host Header User-Info @ Sign Injection"

    def match(self, request) -> Verdict:
        host = request.headers.get("host", "")[:_MAX]
        if host and _HOST_AT.search(host):
            return _host_verdict(
                self.RULE_ID,
                "At-sign (@) in Host header indicates user-info injection",
                {"host": host[:200]},
            )
        return _clean(self.RULE_ID)


class CachePoisonHostOverrideRule(Rule):
    """Detect X-Forwarded-Host / X-Host style cache-poisoning headers."""

    RULE_ID = "970110"
    NAME = "Cache-Poisoning via Host Override Header"

    def match(self, request) -> Verdict:
        for hdr in _CACHE_POISON_HEADERS:
            value = request.headers.get(hdr, "")[:_MAX]
            if value:
                return _host_verdict(
                    self.RULE_ID,
                    f"Cache-poisoning header present: {hdr}",
                    {"header": hdr, "value": value[:200]},
                )
        return _clean(self.RULE_ID)


class PasswordResetPoisoningRule(Rule):
    """Detect Host injection aimed at poisoning password-reset links."""

    RULE_ID = "970115"
    NAME = "Password-Reset Poisoning via Host Header"

    def match(self, request) -> Verdict:
        # Triggered when reset / forgot-password path is combined with X-Forwarded-Host
        path = request.path.lower()
        if not any(kw in path for kw in ("reset", "forgot", "password", "recover")):
            return _clean(self.RULE_ID)
        for hdr in ("x-forwarded-host", "x-host", "x-original-host"):
            value = request.headers.get(hdr, "")[:_MAX]
            if value:
                return _host_verdict(
                    self.RULE_ID,
                    "Potential password-reset link poisoning via override header",
                    {"header": hdr, "value": value[:200], "path": path[:200]},
                )
        return _clean(self.RULE_ID)


class InternalHostRoutingRule(Rule):
    """Detect private/loopback IP addresses in forwarding headers (SSRF via routing)."""

    RULE_ID = "970120"
    NAME = "Host Header Private-IP Routing Confusion"

    def match(self, request) -> Verdict:
        for hdr in ("x-forwarded-host", "x-original-host", "x-host", "host"):
            value = request.headers.get(hdr, "")[:_MAX]
            if value and _FORWARDED_HOST_INJECTION.search(value):
                return _host_verdict(
                    self.RULE_ID,
                    f"Private/loopback IP in {hdr} header (potential SSRF routing)",
                    {"header": hdr, "value": value[:200]},
                )
        return _clean(self.RULE_ID)


class AbsoluteURIRequestTargetRule(Rule):
    """Detect absolute-URI request target used to proxy-bypass or SSRF via Host."""

    RULE_ID = "970125"
    NAME = "Absolute URI in Request-Target (Proxy SSRF)"

    def match(self, request) -> Verdict:
        path = request.path[:_MAX]
        if _ABSOLUTE_URI.match(path):
            return _host_verdict(
                self.RULE_ID,
                "Absolute URI in request-line (proxy SSRF attempt)",
                {"path": path[:200]},
            )
        return _clean(self.RULE_ID)
