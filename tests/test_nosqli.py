from bastion.core.normalizer import normalize_request
from bastion.rules.nosqli import MongoDBInjectionRule, NoSQLGeneralRule


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


def _mongo_verdict(query_string="", body=b"", path="/"):
    request = _make_request(query_string=query_string, body=body, path=path)
    return MongoDBInjectionRule().match(request)


def _nosql_general_verdict(query_string="", body=b"", path="/"):
    request = _make_request(query_string=query_string, body=body, path=path)
    return NoSQLGeneralRule().match(request)


# ---------------------------------------------------------------------------
# MongoDBInjectionRule (951100)
# ---------------------------------------------------------------------------


def test_mongo_where_operator_blocked():
    verdict = _mongo_verdict(
        body=b'{"query": {"$where": "function(){return true}"}}'
    )
    assert verdict.blocked
    assert verdict.rule_id == "951100"


def test_mongo_ne_operator_blocked():
    verdict = _mongo_verdict(query_string="password[$ne]=null")
    assert verdict.blocked
    assert verdict.rule_id == "951100"


def test_mongo_gt_operator_blocked():
    verdict = _mongo_verdict(body=b'{"age": {"$gt": 0}}')
    assert verdict.blocked
    assert verdict.rule_id == "951100"


def test_mongo_return_true_injection_blocked():
    verdict = _mongo_verdict(query_string="username=admin'; return true")
    assert verdict.blocked
    assert verdict.rule_id == "951100"


def test_mongo_in_operator_blocked():
    verdict = _mongo_verdict(body=b'{"role": {"$in": ["admin", "superuser"]}}')
    assert verdict.blocked
    assert verdict.rule_id == "951100"


def test_mongo_clean_json_allowed():
    # Plain JSON without MongoDB operators
    verdict = _mongo_verdict(body=b'{"username": "alice", "age": 30}')
    assert not verdict.blocked


def test_mongo_clean_query_allowed():
    verdict = _mongo_verdict(query_string="q=hello+world&page=1")
    assert not verdict.blocked


# ---------------------------------------------------------------------------
# NoSQLGeneralRule (951200)
# ---------------------------------------------------------------------------


def test_nosql_redis_flushall_blocked():
    verdict = _nosql_general_verdict(body=b"FLUSHALL")
    assert verdict.blocked
    assert verdict.rule_id == "951200"


def test_nosql_redis_config_blocked():
    verdict = _nosql_general_verdict(query_string="cmd=CONFIG+SET+requirepass+hacked")
    assert verdict.blocked
    assert verdict.rule_id == "951200"


def test_nosql_couchdb_all_docs_blocked():
    verdict = _nosql_general_verdict(path="/_all_docs")
    assert verdict.blocked
    assert verdict.rule_id == "951200"


def test_nosql_couchdb_changes_blocked():
    verdict = _nosql_general_verdict(path="/_changes")
    assert verdict.blocked
    assert verdict.rule_id == "951200"


def test_nosql_es_match_all_blocked():
    verdict = _nosql_general_verdict(
        body=b'{"query": {"match_all": {}}}'
    )
    assert verdict.blocked
    assert verdict.rule_id == "951200"


def test_nosql_general_clean_allowed():
    verdict = _nosql_general_verdict(query_string="search=product&category=books")
    assert not verdict.blocked
