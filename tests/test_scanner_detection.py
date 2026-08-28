from bastion.core.normalizer import normalize_request
from bastion.rules.scanner_detection import (
    ScannerSignatureRule,
    MaliciousBotRule,
    AttackToolPathRule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(method="GET", path="/", query_string="", headers=None, body=b""):
    return normalize_request(
        method,
        path=path,
        query_string=query_string,
        headers=headers or {"host": "example.com"},
        body=body,
    )


def _scanner_ua_verdict(ua: str):
    request = _make_request(headers={"host": "example.com", "user-agent": ua})
    return ScannerSignatureRule().match(request)


def _bot_ua_verdict(ua: str):
    request = _make_request(headers={"host": "example.com", "user-agent": ua})
    return MaliciousBotRule().match(request)


def _path_verdict(path: str, query_string: str = ""):
    request = _make_request(path=path, query_string=query_string)
    return AttackToolPathRule().match(request)


# ---------------------------------------------------------------------------
# ScannerSignatureRule (913100)
# ---------------------------------------------------------------------------


def test_scanner_sqlmap_blocked():
    verdict = _scanner_ua_verdict("sqlmap/1.4#stable (https://sqlmap.org)")
    assert verdict.blocked
    assert verdict.rule_id == "913100"


def test_scanner_nikto_blocked():
    verdict = _scanner_ua_verdict("nikto/2.1.6 (Evasions:None) (Test:006660)")
    assert verdict.blocked
    assert verdict.rule_id == "913100"


def test_scanner_nessus_blocked():
    verdict = _scanner_ua_verdict("Nessus/10.0")
    assert verdict.blocked
    assert verdict.rule_id == "913100"


def test_scanner_openvas_blocked():
    verdict = _scanner_ua_verdict("OpenVAS/21.4")
    assert verdict.blocked
    assert verdict.rule_id == "913100"


def test_scanner_acunetix_blocked():
    verdict = _scanner_ua_verdict("acunetix-product/13.0")
    assert verdict.blocked
    assert verdict.rule_id == "913100"


def test_scanner_nuclei_blocked():
    verdict = _scanner_ua_verdict("nuclei/2.9.4")
    assert verdict.blocked
    assert verdict.rule_id == "913100"


def test_scanner_mozilla_allowed():
    verdict = _scanner_ua_verdict(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )
    assert not verdict.blocked


def test_scanner_googlebot_allowed():
    verdict = _scanner_ua_verdict(
        "Googlebot/2.1 (+http://www.google.com/bot.html)"
    )
    assert not verdict.blocked


# ---------------------------------------------------------------------------
# AttackToolPathRule (913120)
# ---------------------------------------------------------------------------


def test_path_git_config_blocked():
    verdict = _path_verdict("/.git/config")
    assert verdict.blocked
    assert verdict.rule_id == "913120"


def test_path_wp_login_blocked():
    verdict = _path_verdict("/wp-login.php")
    assert verdict.blocked
    assert verdict.rule_id == "913120"


def test_path_actuator_env_blocked():
    verdict = _path_verdict("/actuator/env")
    assert verdict.blocked
    assert verdict.rule_id == "913120"


def test_path_phpmyadmin_blocked():
    verdict = _path_verdict("/phpMyAdmin/index.php")
    assert verdict.blocked
    assert verdict.rule_id == "913120"


def test_path_env_file_blocked():
    verdict = _path_verdict("/.env")
    assert verdict.blocked
    assert verdict.rule_id == "913120"


def test_path_webshell_blocked():
    verdict = _path_verdict("/uploads/c99.php")
    assert verdict.blocked
    assert verdict.rule_id == "913120"


def test_path_clean_search_allowed():
    verdict = _path_verdict("/search", query_string="q=hello")
    assert not verdict.blocked


def test_path_normal_api_allowed():
    verdict = _path_verdict("/api/v2/users")
    assert not verdict.blocked
