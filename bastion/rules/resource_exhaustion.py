"""
Resource Exhaustion & DoS Detection Rules (OWASP CRS 975xxx).
Detects oversized payloads, deep nesting, header bombs, and slow-loris style indicators.
"""

import re
from .base import Rule, Verdict


def _dos_verdict(rule_id: str, reason: str, meta: dict) -> Verdict:
    return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta=meta)


def _clean(rule_id: str) -> Verdict:
    return Verdict.clean(rule_id)


# Limits (educational — production would tune these)
_MAX_BODY_BYTES = 10 * 1024 * 1024       # 10 MB
_MAX_HEADER_VALUE_LEN = 8192             # 8 KB per header
_MAX_QUERY_STRING_LEN = 8192            # 8 KB
_MAX_PATH_LEN = 2048
_MAX_QUERY_PARAMS = 100                  # >100 params is abnormal
_MAX_JSON_DEPTH_MARKER = 50             # count of { in JSON body
_MAX_COOKIE_LEN = 4096

# Detect JSON / XML bomb markers
_JSON_NESTING = re.compile(r"\{")
_XML_ENTITY_BOMB = re.compile(
    r"<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC|\"|\').*?>",
    re.IGNORECASE | re.DOTALL,
)

# Ranged byte requests that could be used for bandwidth amplification
_BYTE_RANGE_BOMB = re.compile(
    r"bytes=(?:\d+-\d+,\s*){10,}",
    re.IGNORECASE,
)


class OversizedRequestBodyRule(Rule):
    """Reject bodies larger than the configured maximum (default 10 MB)."""

    RULE_ID = "975100"
    NAME = "Resource Exhaustion — Oversized Request Body"

    def match(self, request) -> Verdict:
        body_len = len(request.body.encode("utf-8", errors="replace")) if isinstance(request.body, str) else len(request.body)
        if body_len > _MAX_BODY_BYTES:
            return _dos_verdict(
                self.RULE_ID,
                f"Request body exceeds maximum allowed size ({body_len} bytes)",
                {"body_size_bytes": body_len, "limit_bytes": _MAX_BODY_BYTES},
            )
        return _clean(self.RULE_ID)


class OversizedQueryStringRule(Rule):
    """Detect excessively long query strings that could exhaust parser memory."""

    RULE_ID = "975105"
    NAME = "Resource Exhaustion — Oversized Query String"

    def match(self, request) -> Verdict:
        qs_len = sum(len(k) + sum(len(v) for v in vals) for k, vals in request.query_params.items())
        if qs_len > _MAX_QUERY_STRING_LEN:
            return _dos_verdict(
                self.RULE_ID,
                f"Query string exceeds maximum allowed length ({qs_len} chars)",
                {"qs_length": qs_len, "limit": _MAX_QUERY_STRING_LEN},
            )
        return _clean(self.RULE_ID)


class TooManyQueryParametersRule(Rule):
    """Detect an abnormal number of query parameters (parser DoS, HPP staging)."""

    RULE_ID = "975110"
    NAME = "Resource Exhaustion — Too Many Query Parameters"

    def match(self, request) -> Verdict:
        total = sum(len(v) for v in request.query_params.values())
        if total > _MAX_QUERY_PARAMS:
            return _dos_verdict(
                self.RULE_ID,
                f"Excessive number of query parameters ({total})",
                {"param_count": total, "limit": _MAX_QUERY_PARAMS},
            )
        return _clean(self.RULE_ID)


class JSONBombRule(Rule):
    """Detect deeply-nested JSON structures that can exhaust recursive parsers."""

    RULE_ID = "975115"
    NAME = "Resource Exhaustion — JSON Nesting Bomb"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "").lower()
        if "json" not in ct and "javascript" not in ct:
            return _clean(self.RULE_ID)
        body = request.body[:65536]  # only scan first 64 KB
        depth = len(_JSON_NESTING.findall(body))
        if depth > _MAX_JSON_DEPTH_MARKER:
            return _dos_verdict(
                self.RULE_ID,
                f"JSON body has excessive nesting depth indicator ({depth} opening braces)",
                {"brace_count": depth, "limit": _MAX_JSON_DEPTH_MARKER},
            )
        return _clean(self.RULE_ID)


class XMLEntityBombRule(Rule):
    """Detect XML entity declaration bombs (billion-laughs pattern)."""

    RULE_ID = "975120"
    NAME = "Resource Exhaustion — XML Entity Bomb"

    def match(self, request) -> Verdict:
        ct = request.headers.get("content-type", "").lower()
        if "xml" not in ct and "text/plain" not in ct:
            # also check body for XML prologue in case CT is wrong
            body_start = request.body[:256]
            if "<?xml" not in body_start and "<!DOCTYPE" not in body_start:
                return _clean(self.RULE_ID)
        body = request.body[:65536]
        if _XML_ENTITY_BOMB.search(body):
            return _dos_verdict(
                self.RULE_ID,
                "XML entity declaration detected (potential billion-laughs bomb)",
                {"snippet": body[:200]},
            )
        return _clean(self.RULE_ID)


class RangeHeaderBombRule(Rule):
    """Detect HTTP Range headers requesting many ranges (bandwidth amplification)."""

    RULE_ID = "975125"
    NAME = "Resource Exhaustion — Range Header Bomb"

    def match(self, request) -> Verdict:
        range_hdr = request.headers.get("range", "")[:512]
        if range_hdr and _BYTE_RANGE_BOMB.search(range_hdr):
            return _dos_verdict(
                self.RULE_ID,
                "HTTP Range header contains excessive number of ranges (amplification attack)",
                {"range": range_hdr[:200]},
            )
        return _clean(self.RULE_ID)


class OversizedCookieRule(Rule):
    """Detect cookies that exceed a safe size limit."""

    RULE_ID = "975130"
    NAME = "Resource Exhaustion — Oversized Cookie Header"

    def match(self, request) -> Verdict:
        cookie = request.headers.get("cookie", "")
        if len(cookie) > _MAX_COOKIE_LEN:
            return _dos_verdict(
                self.RULE_ID,
                f"Cookie header exceeds maximum size ({len(cookie)} chars)",
                {"cookie_length": len(cookie), "limit": _MAX_COOKIE_LEN},
            )
        return _clean(self.RULE_ID)
