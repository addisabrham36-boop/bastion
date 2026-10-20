"""
Tests for HTTP Parameter Pollution rules (971xxx).
"""

import pytest
from bastion.core.inspector import inspect_request
from bastion.rules.parameter_pollution import (
    DuplicateParameterRule,
    ArrayNotationParameterRule,
    ParameterSeparatorConfusionRule,
    PHPParamInjectionRule,
)


def _req(path="/", method="GET", headers=None, query="", body=b""):
    return inspect_request(
        method=method, path=path, query_string=query, headers=headers or {}, body=body
    ).request


class TestDuplicateParameterRule:
    rule = DuplicateParameterRule()

    def test_blocks_duplicate_param(self):
        # Inspector parses query string; duplicate keys produce list with >1 value
        r = _req(query="id=1&id=2")
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_single_param(self):
        r = _req(query="id=1&name=alice")
        v = self.rule.match(r)
        assert not v.blocked

    def test_allows_empty_query(self):
        r = _req()
        v = self.rule.match(r)
        assert not v.blocked


class TestArrayNotationParameterRule:
    rule = ArrayNotationParameterRule()

    def test_blocks_array_bracket_in_key(self):
        r = _req(query="items[]=a&items[]=b")
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_indexed_array(self):
        r = _req(query="user[0]=alice")
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_params(self):
        r = _req(query="name=alice&age=30")
        v = self.rule.match(r)
        assert not v.blocked

    def test_blocks_array_in_body(self):
        r = _req(
            method="POST",
            body=b"roles[]=admin&roles[]=user",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        v = self.rule.match(r)
        assert v.blocked


class TestParameterSeparatorConfusionRule:
    rule = ParameterSeparatorConfusionRule()

    def test_blocks_percent26_in_referer_header(self):
        # Headers are NOT URL-decoded by the normalizer — %26 in Referer reaches the rule
        r = _req(headers={"referer": "http://evil.com/?a=1%26b=injected"})
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_percent00_in_user_agent_header(self):
        # %00 literal in User-Agent header — not decoded (header values skip normalizer)
        r = _req(headers={"user-agent": "Mozilla%00evil_agent"})
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_normal_query(self):
        r = _req(query="search=hello+world")
        v = self.rule.match(r)
        assert not v.blocked


class TestPHPParamInjectionRule:
    rule = PHPParamInjectionRule()

    def test_blocks_shell_injection_via_param(self):
        r = _req(query="cmd=$(whoami)")
        v = self.rule.match(r)
        assert v.blocked

    def test_blocks_php_variable_in_body(self):
        r = _req(method="POST", body=b"x=${system(id)}")
        v = self.rule.match(r)
        assert v.blocked

    def test_allows_safe_param(self):
        r = _req(query="search=python+programming")
        v = self.rule.match(r)
        assert not v.blocked
