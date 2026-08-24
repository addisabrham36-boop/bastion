from bastion.core.engine import Engine, discover_rules
from bastion.core.normalizer import normalize_request
from bastion.rules.sqli import SQLiRule


def test_discover_rules_finds_all_rules():
    rule_ids = {rule.RULE_ID for rule in discover_rules()}
    assert "942100" in rule_ids  # SQLi
    assert "941100" in rule_ids  # XSS
    assert "930120" in rule_ids  # Traversal
    assert "932100" in rule_ids  # Command Injection
    assert "934100" in rule_ids  # SSRF


def test_engine_full_discovery_blocks_sqli():
    engine = Engine()
    request = normalize_request("GET", "/search", query_string="q=' OR '1'='1")
    verdict = engine.evaluate(request)
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_engine_full_discovery_clean_request():
    engine = Engine()
    request = normalize_request("GET", "/search", query_string="q=hello+world")
    verdict = engine.evaluate(request)
    assert not verdict.blocked
    assert verdict.rule_id == "CLEAN"


def test_engine_explicit_rule_list_isolates_evaluation():
    engine = Engine(rules=[SQLiRule()])
    request = normalize_request("GET", "/search", query_string="q=1 UNION SELECT 1")
    verdict = engine.evaluate(request)
    assert verdict.blocked
    assert verdict.rule_id == "942100"


def test_engine_enabled_rules_filtering():
    engine = Engine()
    # SQLi payload, but only XSS enabled
    request = normalize_request("GET", "/search", query_string="q=' OR '1'='1")
    verdict = engine.evaluate(request, enabled_rule_ids={"941100"})
    assert not verdict.blocked


def test_engine_blocklist_ip(tmp_path):
    blocklist_file = tmp_path / "blocklist.json"
    blocklist_file.write_text('{"ip_blocklist": ["198.51.100.4"], "user_agent_blocklist": ["BadBot"]}')
    engine = Engine(blocklist_path=str(blocklist_file))

    req = normalize_request("GET", "/", client_ip="198.51.100.4")
    verdict = engine.evaluate(req)
    assert verdict.blocked
    assert verdict.rule_id == "BLOCKLIST_IP"


def test_engine_blocklist_user_agent(tmp_path):
    blocklist_file = tmp_path / "blocklist.json"
    blocklist_file.write_text('{"ip_blocklist": [], "user_agent_blocklist": ["BadBot"]}')
    engine = Engine(blocklist_path=str(blocklist_file))

    req = normalize_request("GET", "/", headers={"User-Agent": "Mozilla/5.0 (compatible; BadBot/1.0)"})
    verdict = engine.evaluate(req)
    assert verdict.blocked
    assert verdict.rule_id == "BLOCKLIST_UA"

