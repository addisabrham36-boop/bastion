"""
HTTP Protocol Anomaly detection rules (OWASP CRS 920xxx).
Covers:
- 920100  HTTPMethodRule              – non-standard HTTP methods (TRACE, TRACK, DEBUG)
- 920120  HTTPMissingHostRule         – missing Host header
- 920130  HTTPHostIPRule              – host header direct IP targeting
- 920200  HTTPHeaderAnomalyRule       – oversized / malformed headers (>8KB)
- 920250  HTTPRangeAttackRule         – Range header DoS attack
- 920270  HTTPMissingUserAgentRule    – missing User-Agent header (automated probe)
- 920300  CRLFInjectionRule           – HTTP response splitting (%0d%0a)
- 920310  CRLFHeaderInjectionRule     – CRLF targeting Set-Cookie / Location
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


class HTTPMethodRule(Rule):
    RULE_ID = "920100"
    NAME = "HTTP Method Enforcement"

    def match(self, request) -> Verdict:
        method = (request.method or "").upper()
        if method not in _ALLOWED_METHODS:
            return Verdict(blocked=True, rule_id=self.RULE_ID, reason=f"Disallowed HTTP method: {method}", meta={"method": method})
        return Verdict.clean(self.RULE_ID)


class HTTPMissingHostRule(Rule):
    RULE_ID = "920120"
    NAME = "HTTP Missing Host Header Detection"

    def match(self, request) -> Verdict:
        headers = request.headers or {}
        host = headers.get("host", "")
        if headers and not host.strip():
            return Verdict(blocked=True, rule_id=self.RULE_ID, reason="Missing or empty Host header (HTTP/1.1 violation)", meta={"field": "header:host"})
        return Verdict.clean(self.RULE_ID)


class HTTPHostIPRule(Rule):
    RULE_ID = "920130"
    NAME = "HTTP Host Header Direct IP Target Detection"

    def match(self, request) -> Verdict:
        host = (request.headers or {}).get("host", "").strip()
        host_ip = host.split(":")[0]
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host_ip):
            # Allow localhost, loopback, zero, and private RFC 1918 subnets
            if (
                host_ip.startswith("127.")
                or host_ip == "0.0.0.0"
                or host_ip.startswith("10.")
                or host_ip.startswith("192.168.")
                or re.match(r"^172\.(?:1[6-9]|2\d|3[01])\.", host_ip)
            ):
                return Verdict.clean(self.RULE_ID)
            return Verdict(blocked=True, rule_id=self.RULE_ID, reason="Direct public IP Host header probing", meta={"host": host})
        return Verdict.clean(self.RULE_ID)


_MAX_HEADER_VALUE_LEN = 8192
_HEADER_ANOMALY_PATTERNS = [(r"^\d+\s*,\s*\d+", "Multiple Content-Length values detected")]
_COMPILED_HEADER_ANOMALY = [(re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _HEADER_ANOMALY_PATTERNS]


class HTTPHeaderAnomalyRule(Rule):
    RULE_ID = "920200"
    NAME = "HTTP Header Anomaly & Oversized Length Detection"

    def match(self, request) -> Verdict:
        headers = request.headers or {}
        host = headers.get("host", "")
        if headers and not host.strip():
            return Verdict(blocked=True, rule_id=self.RULE_ID, reason="Missing or empty Host header", meta={"field": "header:host"})
        for header_name, header_value in headers.items():

            if not header_value:
                continue
            if len(header_value) > _MAX_HEADER_VALUE_LEN:
                return Verdict(blocked=True, rule_id=self.RULE_ID, reason=f"Oversized header value in '{header_name}' ({len(header_value)} chars)", meta={"field": f"header:{header_name}", "matched_value": header_value[:200]})
        content_length = headers.get("content-length", "")
        if content_length:
            for pattern, reason in _COMPILED_HEADER_ANOMALY:
                if pattern.search(content_length):
                    return Verdict(blocked=True, rule_id=self.RULE_ID, reason=reason, meta={"field": "header:content-length", "matched_value": content_length[:200]})
        return Verdict.clean(self.RULE_ID)


class HTTPRangeAttackRule(Rule):
    RULE_ID = "920250"
    NAME = "HTTP Range Header Denial of Service Shield"

    def match(self, request) -> Verdict:
        range_header = (request.headers or {}).get("range", "")
        if range_header and range_header.count(",") > 5:
            return Verdict(blocked=True, rule_id=self.RULE_ID, reason="Excessive byte-range overlapping segments (Range DoS attempt)", meta={"range": range_header})
        return Verdict.clean(self.RULE_ID)


class HTTPMissingUserAgentRule(Rule):
    RULE_ID = "920270"
    NAME = "HTTP Missing User-Agent Header Probe"

    def match(self, request) -> Verdict:
        headers = request.headers or {}
        if len(headers) > 3 and "user-agent" not in headers:
            return Verdict(blocked=True, rule_id=self.RULE_ID, reason="Automated request missing standard User-Agent header", meta={"headers": list(headers.keys())})
        return Verdict.clean(self.RULE_ID)


_CRLF_PATTERNS = [
    (r"\r\n", "Raw CRLF sequence detected"),
    (r"\n\r", "Reversed CRLF sequence detected"),
    (r"%0d%0a", "URL-encoded CRLF (%0d%0a)"),
    (r"%0D%0A", "URL-encoded CRLF (%0D%0A)"),
]
_COMPILED_CRLF = [(re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _CRLF_PATTERNS]


class CRLFInjectionRule(Rule):
    RULE_ID = "920300"
    NAME = "CRLF Injection / HTTP Response Splitting"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value or field_label == "body":
                continue
            for pattern, reason in _COMPILED_CRLF:
                if pattern.search(value):
                    return Verdict(blocked=True, rule_id=self.RULE_ID, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
        return Verdict.clean(self.RULE_ID)


_CRLF_HDR_PATTERNS = [
    (r"(?:%0d%0a|%0D%0A|\r\n)Set-Cookie\s*:", "CRLF header injection targeting Set-Cookie"),
    (r"(?:%0d%0a|%0D%0A|\r\n)Location\s*:", "CRLF header injection targeting Location"),
    (r"(?:%0d%0a|%0D%0A|\r\n)Content-Type\s*:", "CRLF header injection targeting Content-Type"),
]
_COMPILED_CRLF_HDR = [(re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _CRLF_HDR_PATTERNS]


class CRLFHeaderInjectionRule(Rule):
    RULE_ID = "920310"
    NAME = "CRLF Targeted Response Header Splitting"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value or field_label == "body":
                continue
            for pattern, reason in _COMPILED_CRLF_HDR:
                if pattern.search(value):
                    return Verdict(blocked=True, rule_id=self.RULE_ID, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
        return Verdict.clean(self.RULE_ID)
