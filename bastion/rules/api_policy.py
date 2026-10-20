"""
API Method & Content-Type Policy Enforcement Rules (OWASP CRS 973xxx).
Detects method overriding, unexpected HTTP verbs, missing/forged Content-Type,
and attempts to bypass API policy via tunneling.
"""

import re
from .base import Rule, Verdict

_MAX = 256

# Allowed methods for typical REST APIs (add HEAD, OPTIONS only at framework level)
_STANDARD_METHODS = frozenset(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])

# Methods that should never reach the WAF from a browser/API consumer
_DANGEROUS_METHODS = frozenset(["TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
                                 "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH",
                                 "REPORT", "CHECKOUT", "CHECKIN", "UNCHECKOUT",
                                 "MKWORKSPACE", "UPDATE", "LABEL", "MERGE",
                                 "BASELINE-CONTROL", "MKACTIVITY"])

# Method-override headers
_METHOD_OVERRIDE_HEADERS = ["x-http-method-override", "x-http-method", "x-method-override"]

# Content-type values that indicate SSRF/deserialization risk
_DANGEROUS_CONTENT_TYPES = re.compile(
    r"(?:application/(?:x-java-serialized-object|x-java-applet|java-serialized-object)|"
    r"application/x-www-form-urlencoded.*json|"
    r"text/xml.*application/json)",
    re.IGNORECASE,
)

# JSON body with PHP or Java object injection markers
_OBJECT_INJECTION = re.compile(
    r'"__proto__"\s*:|"constructor"\s*:|"prototype"\s*:|'
    r'"@class"\s*:|"@type"\s*:',
    re.IGNORECASE,
)

# GraphQL introspection / mass data extraction
_GRAPHQL_INTROSPECTION = re.compile(
    r"__schema\s*\{|__type\s*\(|IntrospectionQuery",
    re.IGNORECASE,
)


def _api_verdict(rule_id: str, reason: str, meta: dict) -> Verdict:
    return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta=meta)


def _clean(rule_id: str) -> Verdict:
    return Verdict.clean(rule_id)


class DangerousHTTPMethodRule(Rule):
    """Block WebDAV and trace-level HTTP verbs that should never reach the application."""

    RULE_ID = "973100"
    NAME = "API Policy — Dangerous HTTP Method"

    def match(self, request) -> Verdict:
        method = request.method.upper()
        if method in _DANGEROUS_METHODS:
            return _api_verdict(
                self.RULE_ID,
                f"Dangerous HTTP method '{method}' is not allowed",
                {"method": method},
            )
        return _clean(self.RULE_ID)


class MethodOverrideHeaderRule(Rule):
    """Detect X-HTTP-Method-Override and similar tunneling headers."""

    RULE_ID = "973105"
    NAME = "API Policy — HTTP Method Override Header"

    def match(self, request) -> Verdict:
        for hdr in _METHOD_OVERRIDE_HEADERS:
            value = request.headers.get(hdr, "")[:_MAX]
            if value:
                return _api_verdict(
                    self.RULE_ID,
                    f"HTTP method-override header '{hdr}' detected (potential verb-tunneling)",
                    {"header": hdr, "value": value[:100]},
                )
        return _clean(self.RULE_ID)


class DangerousContentTypeRule(Rule):
    """Detect Content-Type values associated with Java serialization or mixed-type attacks."""

    RULE_ID = "973110"
    NAME = "API Policy — Dangerous Content-Type Header"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "")[:_MAX]
        if ct and _DANGEROUS_CONTENT_TYPES.search(ct):
            return _api_verdict(
                self.RULE_ID,
                "Dangerous Content-Type detected (potential deserialization risk)",
                {"content_type": ct[:200]},
            )
        return _clean(self.RULE_ID)


class JSONPrototypePollutionRule(Rule):
    """Detect prototype pollution and Java class injection in JSON request bodies."""

    RULE_ID = "973115"
    NAME = "API Policy — JSON Prototype / Class Injection"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "").lower()
        if "json" not in ct and "javascript" not in ct:
            return _clean(self.RULE_ID)
        body = request.body[:4096]
        if body and _OBJECT_INJECTION.search(body):
            return _api_verdict(
                self.RULE_ID,
                "JavaScript prototype pollution or Java class injection in JSON body",
                {"snippet": body[:200]},
            )
        return _clean(self.RULE_ID)


class GraphQLIntrospectionRule(Rule):
    """Detect GraphQL schema introspection queries that map the API surface."""

    RULE_ID = "973120"
    NAME = "API Policy — GraphQL Introspection Query"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if _GRAPHQL_INTROSPECTION.search(value[:4096]):
                return _api_verdict(
                    self.RULE_ID,
                    "GraphQL schema introspection detected (maps API surface)",
                    {"field": field_label, "snippet": value[:200]},
                )
        return _clean(self.RULE_ID)
