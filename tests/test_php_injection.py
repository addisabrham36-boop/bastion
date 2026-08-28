from bastion.core.normalizer import normalize_request
from bastion.rules.php_injection import (
    PHPCodeInjectionRule,
    PHPObjectInjectionRule,
    PHPFileInclusionRule,
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


def _code_verdict(query_string="", body=b""):
    request = _make_request(query_string=query_string, body=body)
    return PHPCodeInjectionRule().match(request)


def _fi_verdict(query_string="", body=b"", path="/"):
    request = _make_request(query_string=query_string, body=body, path=path)
    return PHPFileInclusionRule().match(request)


# ---------------------------------------------------------------------------
# PHPCodeInjectionRule (933100)
# ---------------------------------------------------------------------------


def test_php_eval_base64_blocked():
    verdict = _code_verdict(
        query_string="input=eval(base64_decode('cGhwaW5mbygpOw=='))"
    )
    assert verdict.blocked
    assert verdict.rule_id == "933100"


def test_php_open_tag_blocked():
    verdict = _code_verdict(body=b"data=<?php system('id'); ?>")
    assert verdict.blocked
    assert verdict.rule_id == "933100"


def test_php_shell_exec_blocked():
    verdict = _code_verdict(query_string="cmd=shell_exec('ls -la')")
    assert verdict.blocked
    assert verdict.rule_id == "933100"


def test_php_create_function_blocked():
    verdict = _code_verdict(query_string="x=create_function('','phpinfo()')")
    assert verdict.blocked
    assert verdict.rule_id == "933100"


def test_php_short_echo_tag_blocked():
    verdict = _code_verdict(body=b"<?= system('id') ?>")
    assert verdict.blocked
    assert verdict.rule_id == "933100"


def test_php_clean_request_allowed():
    # Plain PHP-related words without actual function calls
    verdict = _code_verdict(query_string="lang=php&topic=arrays&version=8.1")
    assert not verdict.blocked


# ---------------------------------------------------------------------------
# PHPFileInclusionRule (933120)
# ---------------------------------------------------------------------------


def test_php_filter_wrapper_blocked():
    verdict = _fi_verdict(
        query_string="file=php://filter/convert.base64-encode/resource=index.php"
    )
    assert verdict.blocked
    assert verdict.rule_id == "933120"


def test_php_data_wrapper_blocked():
    verdict = _fi_verdict(query_string="page=data://text/plain,<?php phpinfo(); ?>")
    assert verdict.blocked
    assert verdict.rule_id == "933120"


def test_php_input_wrapper_blocked():
    verdict = _fi_verdict(query_string="source=php://input")
    assert verdict.blocked
    assert verdict.rule_id == "933120"


def test_php_fi_clean_request_allowed():
    verdict = _fi_verdict(query_string="template=default&theme=dark")
    assert not verdict.blocked
