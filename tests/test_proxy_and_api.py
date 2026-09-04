from fastapi.testclient import TestClient
import pytest

from api.server import app as api_app
from bastion.core.proxy import app as proxy_app
from database.db import (
    add_site,
    get_logs,
    get_recent_events,
    get_rules,
    get_sites,
    get_stats,
    init_db,
    log_event,
    set_rule_state,
    set_site_defense,
)


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_database_crud_and_queries():
    # Test log event
    log_event(
        client_ip="192.0.2.1",
        method="GET",
        path="/search?q=' OR 1=1",
        blocked=True,
        rule_id="942100",
        reason="SQLi attempt",
    )

    stats = get_stats()
    assert stats["total_requests"] >= 1
    assert stats["blocked_attacks"] >= 1

    events = get_recent_events(limit=5)
    assert len(events) >= 1
    assert events[0]["client_ip"] == "192.0.2.1"
    assert events[0]["action"] == "403 Blocked"

    logs = get_logs(query="192.0.2.1")
    assert len(logs) >= 1
    assert logs[0]["rule_id"] == "942100"

    # Rules
    rules = get_rules()
    assert len(rules) >= 5
    set_rule_state("942100", False)
    updated_rules = {r["rule_id"]: r["enabled"] for r in get_rules()}
    assert updated_rules["942100"] is False
    set_rule_state("942100", True)

    # Sites
    sites = get_sites()
    assert isinstance(sites, list)
    add_site("testbank.local", "127.0.0.1:9090")
    sites_after = {s["domain"] for s in get_sites()}
    assert "testbank.local" in sites_after


def test_api_server_endpoints():
    client = TestClient(api_app)

    # Stats
    resp = client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_requests" in data
    assert "blocked_attacks" in data
    assert "protected_domains" in data

    # Events
    resp = client.get("/api/events")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Logs
    resp = client.get("/api/logs?q=192&threat=All Threat Types")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Rules
    resp = client.get("/api/rules")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    resp = client.post("/api/rules", json={"rule_id": "941100", "enabled": False})
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"

    # Re-enable rule
    client.post("/api/rules", json={"rule_id": "941100", "enabled": True})

    # Sites
    resp = client.get("/api/sites")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    resp = client.post(
        "/api/sites",
        json={"domain": "secure.internal", "upstream": "127.0.0.1:5000"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"


def test_proxy_blocks_malicious_requests():
    client = TestClient(proxy_app)

    # SQLi attack
    resp = client.get("/login?user=admin' OR '1'='1")
    assert resp.status_code == 403
    data = resp.json()
    assert data["blocked"] is True
    assert data["rule"] == "942100"

    # XSS attack
    resp = client.get("/comment?text=<script>alert(1)</script>")
    assert resp.status_code == 403
    assert resp.json()["blocked"] is True
    assert resp.json()["rule"] == "941100"

    # Path Traversal attack
    resp = client.get("/files/../../../../etc/passwd")
    assert resp.status_code == 403
    assert resp.json()["blocked"] is True
    assert resp.json()["rule"] == "930120"

    # Command injection attack
    resp = client.post("/ping", data={"host": "127.0.0.1; whoami"})
    assert resp.status_code == 403
    assert resp.json()["blocked"] is True
    assert resp.json()["rule"] == "932100"

    # SSRF attack
    resp = client.get("/fetch?url=http://169.254.169.254/metadata")
    assert resp.status_code == 403
    assert resp.json()["blocked"] is True
    assert resp.json()["rule"] == "934100"


def test_proxy_passes_clean_request():
    client = TestClient(proxy_app)
    # When clean traffic is sent, proxy forwards to upstream; if upstream is offline, returns 502 Bad Gateway
    resp = client.get("/search?q=123")
    assert resp.status_code in (200, 502)

