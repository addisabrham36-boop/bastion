"""
Authentication Endpoint Abuse Detection Rules (OWASP CRS 972xxx).
Detects brute-force path probing, credential stuffing indicators, and auth-bypass tricks.
"""

import re
from .base import Rule, Verdict

_MAX = 512


def _auth_verdict(rule_id: str, reason: str, meta: dict) -> Verdict:
    return Verdict(blocked=True, rule_id=rule_id, reason=reason, meta=meta)


def _clean(rule_id: str) -> Verdict:
    return Verdict.clean(rule_id)


# Common authentication path keywords
_AUTH_PATHS = re.compile(
    r"/(?:login|signin|sign-in|auth|oauth|token|sso|saml|oidc|session|account/login|"
    r"user/login|admin/login|wp-login\.php|wp-admin|xmlrpc\.php|"
    r"\.htaccess|\.env|web\.config|config\.php|configuration\.php)",
    re.IGNORECASE,
)

# Credential stuffing: very long or suspiciously formatted usernames / passwords
_LONG_CREDENTIAL = re.compile(r"(?:username|user|email|password|passwd|pass|pwd)=[^&]{128,}", re.IGNORECASE)

# SQL injection in auth forms — quick check (full SQLi rule may also fire)
_AUTH_SQLI_QUICK = re.compile(
    r"(?:['\"`])\s*(?:or|and|--|\|\||#)|admin\s*'\s*--",
    re.IGNORECASE,
)

# JWT none-algorithm bypass
_JWT_NONE = re.compile(
    r"eyJ[a-zA-Z0-9+/=]+\.eyJ[a-zA-Z0-9+/=]+\.[a-zA-Z0-9+/=]*",
    re.ASCII,
)

# Basic auth header containing suspicious characters
_BASIC_AUTH_INJECTION = re.compile(r"Basic\s+[A-Za-z0-9+/=]{0,512}", re.ASCII)

# Admin/superuser username probing
_ADMIN_PROBE = re.compile(
    r"\b(?:admin|administrator|root|superuser|su|superadmin|sa|sysadmin|webmaster)\b",
    re.IGNORECASE,
)

# Path traversal inside auth paths
_AUTH_PATH_TRAVERSAL = re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE)


class BruteForcePathProbeRule(Rule):
    """Detect requests to well-known authentication endpoints that signal scanning."""

    RULE_ID = "972100"
    NAME = "Authentication Endpoint Brute-Force Path Probe"

    def match(self, request) -> Verdict:
        path = request.path[:_MAX]
        if _AUTH_PATHS.search(path):
            # Log-level only for portfolio (detection mode); flag for banking demo
            return _auth_verdict(
                self.RULE_ID,
                "Request to known authentication/admin endpoint detected",
                {"path": path[:200], "method": request.method},
            )
        return _clean(self.RULE_ID)


class CredentialStuffingIndicatorRule(Rule):
    """Detect oversized credential parameters typical of automated stuffing tools."""

    RULE_ID = "972110"
    NAME = "Credential Stuffing — Oversized Credential Parameter"

    def match(self, request) -> Verdict:
        body = request.body[:2048]
        if body and _LONG_CREDENTIAL.search(body):
            return _auth_verdict(
                self.RULE_ID,
                "Abnormally long credential parameter (potential credential stuffing)",
                {"body_snippet": body[:200]},
            )
        return _clean(self.RULE_ID)


class AuthFormSQLiRule(Rule):
    """Detect SQL injection patterns specifically within auth form submissions."""

    RULE_ID = "972115"
    NAME = "Authentication Form SQL Injection Attempt"

    def match(self, request) -> Verdict:
        path = request.path[:_MAX]
        if not _AUTH_PATHS.search(path):
            return _clean(self.RULE_ID)
        body = request.body[:2048]
        if body and _AUTH_SQLI_QUICK.search(body):
            return _auth_verdict(
                self.RULE_ID,
                "SQL injection attempt in authentication form",
                {"body_snippet": body[:200], "path": path[:200]},
            )
        # Also check query params
        for key, values in request.query_params.items():
            for v in values:
                if _AUTH_SQLI_QUICK.search(v[:512]):
                    return _auth_verdict(
                        self.RULE_ID,
                        "SQL injection attempt in auth query parameter",
                        {"param": key, "value": v[:200]},
                    )
        return _clean(self.RULE_ID)


class JWTNoneAlgorithmBypassRule(Rule):
    """Detect JWT tokens with 'none' algorithm or alg:none bypass attempt in headers."""

    RULE_ID = "972120"
    NAME = "JWT None-Algorithm Auth Bypass"

    _NONE_HEADER = re.compile(
        r'"alg"\s*:\s*"(?:none|NONE|None)"',
        re.IGNORECASE,
    )

    def match(self, request) -> Verdict:
        import base64
        # Check Authorization header for bearer JWT with none algorithm
        auth = request.headers.get("authorization", "")[:512]
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
            parts = token.split(".")
            if len(parts) >= 2:
                # Pad and decode header
                header_b64 = parts[0] + "=="
                try:
                    header_json = base64.urlsafe_b64decode(header_b64).decode("utf-8", errors="replace")
                    if self._NONE_HEADER.search(header_json):
                        return _auth_verdict(
                            self.RULE_ID,
                            "JWT 'alg: none' algorithm bypass detected",
                            {"jwt_header": header_json[:200]},
                        )
                except Exception:
                    pass
        return _clean(self.RULE_ID)


class AdminUsernameProbeRule(Rule):
    """Detect submission of privileged usernames in login forms."""

    RULE_ID = "972125"
    NAME = "Authentication Probe — Privileged Username Submission"

    def match(self, request) -> Verdict:
        path = request.path[:_MAX]
        if not _AUTH_PATHS.search(path):
            return _clean(self.RULE_ID)
        body = request.body[:2048]
        if body and _ADMIN_PROBE.search(body):
            return _auth_verdict(
                self.RULE_ID,
                "Privileged username submitted to authentication endpoint",
                {"body_snippet": body[:200]},
            )
        return _clean(self.RULE_ID)
