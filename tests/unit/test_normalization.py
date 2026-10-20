"""
Unit tests for Milestone 3: Normalization, RequestContext, and Preflight validation.
"""

import pytest
from bastion.core.context import RequestContext, EvaluationState, Detection
from bastion.core.normalization import (
    canonicalize_path,
    parse_bounded_query,
    parse_bounded_json,
    repeated_url_decode,
)
from bastion.core.preflight import validate_preflight, PreflightViolation
from bastion.proxy.router import SiteConfig


def test_repeated_url_decode():
    assert repeated_url_decode("%252e%252e%252f") == "../"
    assert repeated_url_decode("normal_text") == "normal_text"


def test_canonicalize_path():
    assert canonicalize_path("/app/..%2f..%2fetc/passwd") == "/etc/passwd"
    assert canonicalize_path("//admin///console") == "/admin/console"
    assert canonicalize_path("/foo/bar/./baz") == "/foo/bar/baz"


def test_parse_bounded_query():
    q = parse_bounded_query("tag=sec&tag=net&user=alice%20smith")
    assert q["tag"] == ["sec", "net"]
    assert q["user"] == ["alice smith"]


def test_parse_bounded_json():
    # Valid json
    valid = parse_bounded_json(b'{"key": "value", "list": [1, 2, 3]}')
    assert valid["key"] == "value"

    # Excessive depth
    deep_json = b'{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":1}}}}}}}}}}}'
    assert parse_bounded_json(deep_json, max_depth=5) is None


def test_preflight_validation():
    site = SiteConfig(
        id="demo",
        hostnames=["example.com"],
        upstream_origin="http://127.0.0.1:5000",
        max_path_bytes=50,
        allowed_methods=["GET", "POST"],
    )

    # Path too long
    with pytest.raises(PreflightViolation) as exc:
        validate_preflight("GET", "/a" * 60, "", {}, site)
    assert exc.value.status_code == 414

    # Disallowed method
    with pytest.raises(PreflightViolation) as exc:
        validate_preflight("DELETE", "/test", "", {}, site)
    assert exc.value.status_code == 405
