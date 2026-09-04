"""
Server-Side Request Forgery (SSRF) Detection Rules (OWASP CRS 934xxx).
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict


def _match_helper(rule_id: str, compiled_patterns, request) -> Verdict:
    for field_label, value in request.iter_values():
        if not value:
            continue
        # Referer and Origin headers naturally contain the site origin (e.g. localhost) in normal browsing
        if field_label in ("header:referer", "header:origin"):
            continue
        for pattern, reason in compiled_patterns:
            if pattern.search(value):
                return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
    return Verdict.clean(rule_id)


_ALL_SSRF_PATTERNS: List[Tuple[str, str]] = [
    (r"(?:https?|ftp)://(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|\[::1\])", "SSRF localhost / loopback destination"),
    (r"169\.254\.169\.254", "Cloud instance metadata IP access (AWS/OpenStack)"),
    (r"metadata\.google\.internal\b", "GCP Compute Engine metadata DNS lookup"),
    (r"(?:https?|ftp)://10\.\d+\.\d+\.\d+", "SSRF private Class A IPv4 subnet (10.0.0.0/8)"),
    (r"(?:https?|ftp)://172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+", "SSRF private Class B IPv4 subnet (172.16.0.0/12)"),
    (r"(?:https?|ftp)://192\.168\.\d+\.\d+", "SSRF private Class C IPv4 subnet (192.168.0.0/16)"),
    (r"\b(?:gopher|dict|ldap|ldaps|tftp|jar|file)://", "SSRF dangerous protocol handler invocation"),
]
_COMPILED_ALL_SSRF = [(re.compile(p, re.IGNORECASE), r) for p, r in _ALL_SSRF_PATTERNS]


class SSRFRule(Rule):
    RULE_ID = "934100"
    NAME = "Server-Side Request Forgery (SSRF) Comprehensive Guard"
    def match(self, request) -> Verdict: return _match_helper(self.RULE_ID, _COMPILED_ALL_SSRF, request)


class SSRFLocalhostRule(Rule):
    RULE_ID = "934101"
    NAME = "SSRF Localhost & Loopback Target"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"(?:https?|ftp)://(?:127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|\[::1\])", re.I), "SSRF localhost")]
        return _match_helper(self.RULE_ID, p, request)


class SSRFAWSMetadataRule(Rule):
    RULE_ID = "934110"
    NAME = "SSRF AWS & Cloud Metadata Service"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"169\.254\.169\.254|latest/meta-data\b", re.I), "AWS metadata probe")]
        return _match_helper(self.RULE_ID, p, request)


class SSRFGCPMetadataRule(Rule):
    RULE_ID = "934120"
    NAME = "SSRF GCP Cloud Metadata Endpoint"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"metadata\.google\.internal\b|computeMetadata", re.I), "GCP metadata probe")]
        return _match_helper(self.RULE_ID, p, request)


class SSRFAzureMetadataRule(Rule):
    RULE_ID = "934130"
    NAME = "SSRF Azure Instance Metadata Service"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"metadata/instance\?api-version\b", re.I), "Azure metadata probe")]
        return _match_helper(self.RULE_ID, p, request)


class SSRFKubernetesRule(Rule):
    RULE_ID = "934140"
    NAME = "SSRF Kubernetes In-Cluster API & Token Probe"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"kubernetes\.default\.svc|kubernetes\.io/serviceaccount", re.I), "Kubernetes API probe")]
        return _match_helper(self.RULE_ID, p, request)


class SSRFPrivateSubnetRule(Rule):
    RULE_ID = "934150"
    NAME = "SSRF RFC 1918 Private Network Targeting"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"(?:https?|ftp)://(?:10\.\d+|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+", re.I), "RFC 1918 probe")]
        return _match_helper(self.RULE_ID, p, request)


class SSRFProtocolHandlerRule(Rule):
    RULE_ID = "934160"
    NAME = "SSRF Dangerous Protocol Schemes"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"\b(?:gopher|dict|ldap|file)://", re.I), "Protocol handler SSRF")]
        return _match_helper(self.RULE_ID, p, request)


class SSRFObfuscatedIPRule(Rule):
    RULE_ID = "934170"
    NAME = "SSRF Decimal & Hex IP Obfuscation"
    def match(self, request) -> Verdict:
        p = [(re.compile(r"(?:https?|ftp)://(?:2130706433|0x7f000001|0177\.0\.0\.1)", re.I), "Obfuscated IP SSRF")]
        return _match_helper(self.RULE_ID, p, request)
