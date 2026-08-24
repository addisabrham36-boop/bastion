from bastion.core.normalizer import normalize_request
from bastion.rules.sqli import SQLiRule


def _match(query_string="", body=b"", headers=None):
    request = normalize_request("GET", "/api/v1/user", query_string=query_string, headers=headers or {}, body=body)
    return SQLiRule().match(request)


def test_union_select_blocked():
    verdict = _match(query_string="id=1' UNION SELECT username,password FROM users--")
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_comment_obfuscated_union_blocked():
    # UNION/**/SELECT is a classic filter-bypass attempt against naive
    # regex matchers that only look for "UNION SELECT" with a literal space.
    verdict = _match(query_string="id=1/**/UNION/**/SELECT/**/1,2,3--")
    assert verdict.blocked


def test_classic_tautology_blocked():
    verdict = _match(query_string="user=admin' OR '1'='1")
    assert verdict.blocked


def test_numeric_tautology_blocked():
    verdict = _match(query_string="id=1 OR 1=1")
    assert verdict.blocked


def test_time_based_sleep_blocked():
    verdict = _match(query_string="id=1 AND SLEEP(5)")
    assert verdict.blocked


def test_time_based_waitfor_blocked():
    verdict = _match(query_string="id=1; WAITFOR DELAY '0:0:5'")
    assert verdict.blocked


def test_stacked_query_drop_blocked():
    verdict = _match(query_string="id=1; DROP TABLE users;")
    assert verdict.blocked


def test_information_schema_blocked():
    verdict = _match(query_string="id=1 UNION SELECT table_name FROM information_schema.tables")
    assert verdict.blocked


def test_double_encoded_payload_blocked():
    # %2520 -> %20 (pass 1) -> space (pass 2), reconstructing "1 UNION SELECT 1"
    verdict = _match(query_string="id=1%2520UNION%2520SELECT%25201")
    assert verdict.blocked


def test_sqli_in_body_blocked():
    verdict = _match(
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=b"username=admin&password=x' OR '1'='1",
    )
    assert verdict.blocked


def test_clean_request_not_blocked():
    verdict = _match(query_string="id=42&name=john")
    assert not verdict.blocked


def test_clean_body_not_blocked():
    verdict = _match(
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=b"username=john&password=hunter2",
    )
    assert not verdict.blocked


def test_sqli_no_false_positive_on_and_or_phrases():
    # Normal phrases containing and/or
    verdict = _match(query_string="flavor=cookies+and+cream&category=rock+or+pop")
    assert not verdict.blocked


def test_sqli_no_false_positive_on_digits_in_text():
    # Numbers in text descriptions
    verdict = _match(query_string="item=available+in+sizes+1+and+2+now")
    assert not verdict.blocked

