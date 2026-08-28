"""
Client-side, application logic, and protocol injection rules (OWASP CRS 960xxx).
Covers:
- 960100  PrototypePollutionRule – JavaScript prototype tampering (__proto__)
- 960110  OpenRedirectRule       – Unvalidated redirect / phishing
- 960120  CORSSpoofingRule       – Malicious origin header manipulation
- 960140  SessionFixationRule    – Session ID in URL parameters
- 960150  LDAPInjectionRule      – LDAP query syntax injection
- 960160  XPathInjectionRule     – XML XPath query injection
- 960170  FileUploadRule         – Dangerous executable file upload extensions
- 960180  GraphQLAbuseRule       – GraphQL introspection / circular recursion
- 960200  HPPParameterRule       – HTTP Parameter Pollution detection
"""

import re
from typing import List, Tuple
from .base import Rule, Verdict

# 960100 Prototype Pollution
_PROTOTYPE_PATTERNS: List[Tuple[str, str]] = [
    (r"__proto__", "Prototype pollution via __proto__ property"),
    (r"constructor\s*\[\s*['\"]prototype['\"]\s*\]", "Prototype pollution via constructor.prototype"),
    (r"Object\.prototype", "Direct Object.prototype manipulation attempt"),
    (r"prototype\s*\[\s*['\"][a-zA-Z0-9_$]+['\"]\s*\]\s*=", "Prototype property assignment"),
]
_COMPILED_PROTO = [(re.compile(p, re.IGNORECASE), r) for p, r in _PROTOTYPE_PATTERNS]


class PrototypePollutionRule(Rule):
    RULE_ID = "960100"
    NAME = "Prototype Pollution Defense"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_PROTO:
                if pattern.search(value):
                    return Verdict(blocked=True, rule_id=self.RULE_ID, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
        return Verdict.clean(self.RULE_ID)


# 960110 Open Redirect
_REDIRECT_PATTERNS: List[Tuple[str, str]] = [
    (r"^(?:https?:)?//(?!(?:127\.0\.0\.1|localhost|localhost:\d+))[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Unvalidated open redirect parameter URL"),
    (r"^/\\[a-zA-Z0-9]", "Open redirect with backslash evasion (/\\)"),
    (r"^javascript:", "Open redirect with javascript: URI"),
]
_COMPILED_REDIRECT = [(re.compile(p, re.IGNORECASE), r) for p, r in _REDIRECT_PATTERNS]


class OpenRedirectRule(Rule):
    RULE_ID = "960110"
    NAME = "Open Redirect / Phishing Protection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            is_redirect_param = any(field_label.startswith(f"query:{k}") for k in ("redirect", "url", "next", "return", "dest", "destination", "forward", "goto"))
            if is_redirect_param:
                for pattern, reason in _COMPILED_REDIRECT:
                    if pattern.search(value):
                        return Verdict(blocked=True, rule_id=self.RULE_ID, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
        return Verdict.clean(self.RULE_ID)


# 960120 CORS Abuse
class CORSSpoofingRule(Rule):
    RULE_ID = "960120"
    NAME = "CORS Origin Spoofing Shield"

    def match(self, request) -> Verdict:
        origin = (request.headers or {}).get("origin", "").lower()
        if origin == "null" or origin.startswith("null://") or "file://" in origin:
            return Verdict(blocked=True, rule_id=self.RULE_ID, reason="Suspicious or null CORS Origin header", meta={"origin": origin})
        return Verdict.clean(self.RULE_ID)


# 960140 Session Fixation
_SESSION_IN_URL_PATTERN = re.compile(r"(?:phpsessid|jsessionid|aspsessionid|sid|session_id|sessionid)=[a-zA-Z0-9]{16,}", re.IGNORECASE)


class SessionFixationRule(Rule):
    RULE_ID = "960140"
    NAME = "Session Fixation in URL Shield"

    def match(self, request) -> Verdict:
        if _SESSION_IN_URL_PATTERN.search(request.path):
            return Verdict(blocked=True, rule_id=self.RULE_ID, reason="Session token exposed in URL path (Session Fixation risk)", meta={"path": request.path})
        for key, values in request.query_params.items():
            if key.lower() in ("phpsessid", "jsessionid", "aspsessionid", "session_id"):
                return Verdict(blocked=True, rule_id=self.RULE_ID, reason="Session token passed in URL query parameter", meta={"query_key": key})
        return Verdict.clean(self.RULE_ID)


# 960150 LDAP Injection
_LDAP_PATTERNS: List[Tuple[str, str]] = [
    (r"\*\)", "LDAP filter closing wildcard escape (*))"),
    (r"\)\s*\(", "LDAP filter operator chaining )("),
    (r"\)\s*\(\s*uid\s*=\s*\*", "LDAP injection attribute wildcards"),
    (r"\)\s*\(\s*userPassword\s*=\s*\*", "LDAP injection password disclosure probe"),
]
_COMPILED_LDAP = [(re.compile(p, re.IGNORECASE), r) for p, r in _LDAP_PATTERNS]


class LDAPInjectionRule(Rule):
    RULE_ID = "960150"
    NAME = "LDAP Injection Defense"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_LDAP:
                if pattern.search(value):
                    return Verdict(blocked=True, rule_id=self.RULE_ID, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
        return Verdict.clean(self.RULE_ID)


# 960160 XPath Injection
_XPATH_PATTERNS: List[Tuple[str, str]] = [
    (r"'\s+or\s+count\s*\(\s*/", "XPath function injection count()"),
    (r"//[a-zA-Z0-9_-]+\[\s*@?[a-zA-Z0-9_-]+\s*=", "XPath node selection query syntax injection"),
    (r"substring\s*\(\s*name\s*\(", "XPath schema extraction substring(name())"),
    (r"string-length\s*\(\s*name\s*\(", "XPath schema length extraction"),
    (r"'\s+or\s+'1'\s*=\s*'1", "XPath tautology probe"),
]
_COMPILED_XPATH = [(re.compile(p, re.IGNORECASE), r) for p, r in _XPATH_PATTERNS]


class XPathInjectionRule(Rule):
    RULE_ID = "960160"
    NAME = "XPath Injection Shield"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_XPATH:
                if pattern.search(value):
                    return Verdict(blocked=True, rule_id=self.RULE_ID, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
        return Verdict.clean(self.RULE_ID)


# 960170 File Upload
_DANGEROUS_EXTENSIONS = re.compile(
    r"\.(?:php\d?|phtml|phar|inc|asp|aspx|cer|asa|jsp|jspx|war|cgi|pl|py|sh|bash|exe|dll|bat|cmd|vbs|hta|ps1)\b",
    re.IGNORECASE,
)
_CONTENT_DISP_FILENAME = re.compile(r'filename\s*=\s*["\']?([^"\'\r\n;]+)', re.IGNORECASE)


class FileUploadRule(Rule):
    RULE_ID = "960170"
    NAME = "Dangerous File Upload Extension Guard"

    def match(self, request) -> Verdict:
        body = request.body or ""
        if "content-disposition" in body.lower() or "filename=" in body.lower():
            for match in _CONTENT_DISP_FILENAME.finditer(body):
                fname = match.group(1).strip()
                if _DANGEROUS_EXTENSIONS.search(fname):
                    return Verdict(blocked=True, rule_id=self.RULE_ID, reason=f"Dangerous executable file upload extension detected: '{fname}'", meta={"filename": fname})
        return Verdict.clean(self.RULE_ID)


# 960180 GraphQL Abuse
_GRAPHQL_PATTERNS: List[Tuple[str, str]] = [
    (r"__schema\s*\{\s*types", "GraphQL schema introspection probe"),
    (r"__type\s*\(\s*name\s*:\s*['\"][A-Za-z0-9_]+['\"]\s*\)", "GraphQL type extraction probe"),
    (r"(?:[a-zA-Z0-9_]+\s*\{\s*){7,}", "GraphQL deep recursive nesting DoS vector"),
]
_COMPILED_GRAPHQL = [(re.compile(p, re.IGNORECASE), r) for p, r in _GRAPHQL_PATTERNS]


class GraphQLAbuseRule(Rule):
    RULE_ID = "960180"
    NAME = "GraphQL Abuse & Introspection Defense"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_GRAPHQL:
                if pattern.search(value):
                    return Verdict(blocked=True, rule_id=self.RULE_ID, reason=reason, meta={"field": field_label, "matched_value": value[:200]})
        return Verdict.clean(self.RULE_ID)


# 960200 HTTP Parameter Pollution
class HPPParameterRule(Rule):
    RULE_ID = "960200"
    NAME = "HTTP Parameter Pollution (HPP) Shield"

    def match(self, request) -> Verdict:
        for key, values in request.query_params.items():
            if len(values) > 3:
                return Verdict(blocked=True, rule_id=self.RULE_ID, reason=f"Excessive duplicate parameter occurrences for '{key}' ({len(values)} copies)", meta={"query_key": key, "count": len(values)})
        return Verdict.clean(self.RULE_ID)
