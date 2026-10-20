"""
Tests for Authentication Endpoint Abuse rules (972xxx).
"""

import base64
import json
import pytest
from bastion.core.inspector import inspect_request
from bastion.rules.auth_abuse import (
    BruteForcePathProbeRule,
    CredentialStuffingIndicatorRule,
    AuthFormSQLiRule,
    JWTNoneAlgorithmBypassRule,
    AdminUsernameProbeRule,
)


def _req(path="/", method="GET", headers=None, query="", body=b""):
    return inspect_request(
        method=method, path=path, query_string=query, headers=headers or {}, body=body
    ).request


def _make_jwt(alg: str) -> str:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": alg, "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(b'{"sub":"1"}').rstrip(b"=").decode()
    return f"{header}.{payload}."


class TestBruteForcePathProbeRule:
    rule = BruteForcePathProbeRule()

    def test_flags_login_path(self):
        r = _req(path="/login")
        v = self.rule.match(r)
        assert v.blocked

    def test_flags_wp_login(self):
        r = _req(path="/wp-login.php")
        v = self.rule.match(r)
        assert v.blocked

    def test_flags_admin_path(self):
        r = _req(path="/wp-admin/index.php")
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_path(self):
        r = _req(path="/api/v1/users")
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_portfolio_root(self):
        r = _req(path="/")
        v = self.rule.match(r)
        assert not v.blocked


class TestCredentialStuffingIndicatorRule:
    rule = CredentialStuffingIndicatorRule()

    def test_blocks_oversized_password(self):
        long_pass = "x" * 200
        r = _req(
            method="POST",
            body=f"username=admin&password={long_pass}".encode(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_password(self):
        r = _req(
            method="POST",
            body=b"username=alice&password=S3cur3Pass!",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        v = self.rule.match(r)
        assert not v.blocked


class TestAuthFormSQLiRule:
    rule = AuthFormSQLiRule()

    def test_blocks_sqli_in_login_body(self):
        r = _req(
            path="/login",
            method="POST",
            body=b"username=admin'--&password=x",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_or_1_equals_1(self):
        r = _req(
            path="/signin",
            method="POST",
            body=b"username=alice&password=' or '1'='1",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_login(self):
        r = _req(
            path="/login",
            method="POST",
            body=b"username=alice&password=SafePass123",
        )
        v = self.rule.match(r)
        assert not v.blocked

    def test_ignores_sqli_on_non_auth_path(self):
        # SQLi on a non-auth path should not fire THIS rule (sqli.py handles it)
        r = _req(
            path="/products",
            method="GET",
            query="q=' OR 1=1--",
        )
        v = self.rule.match(r)
        assert not v.blocked


class TestJWTNoneAlgorithmBypassRule:
    rule = JWTNoneAlgorithmBypassRule()

    def test_blocks_jwt_none_algorithm(self):
        token = _make_jwt("none")
        r = _req(headers={"authorization": f"Bearer {token}"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_jwt_NONE_uppercase(self):
        token = _make_jwt("NONE")
        r = _req(headers={"authorization": f"Bearer {token}"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_valid_hs256_jwt(self):
        token = _make_jwt("HS256")
        r = _req(headers={"authorization": f"Bearer {token}"})
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_request_without_auth_header(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked


class TestAdminUsernameProbeRule:
    rule = AdminUsernameProbeRule()

    def test_blocks_admin_username_in_login(self):
        r = _req(
            path="/login",
            method="POST",
            body=b"username=admin&password=test",
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_root_username(self):
        r = _req(
            path="/auth",
            method="POST",
            body=b"username=root&password=toor",
        )
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_username(self):
        r = _req(
            path="/login",
            method="POST",
            body=b"username=abrham&password=MyPass123",
        )
        v = self.rule.match(r)
        assert not v.blocked

    def test_ignores_admin_on_non_auth_path(self):
        r = _req(path="/docs/admin-guide", method="GET")
        v = self.rule.match(r)
        assert not v.blocked
