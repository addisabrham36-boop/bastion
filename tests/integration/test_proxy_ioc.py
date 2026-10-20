"""
Integration tests for Phase 4: Threat Intelligence and Redis IOC integration in the live proxy.
Verifies that:
- IP IOC match is blocked with 403 (IOC_IP_THREAT) in prevention mode.
- Domain IOC match is blocked with 403 (IOC_DOMAIN_THREAT) in prevention mode.
- Path IOC match is blocked with 403 (IOC_PATH_THREAT) in prevention mode.
- Clean request is allowed through to upstream.
- Detection mode records IOC attack without blocking (status != 403).
- Low confidence IOC (<0.5) logs without blocking (proposed action LOG).
- Scoped exclusion suppresses IOC rule (request allowed).
- Disabled rule in DB suppresses IOC evaluation (request allowed).
- Redis failure triggers degraded mode and falls back safely to CRS inspection.
- Spoofed X-Forwarded-For from untrusted peer is ignored.
- Trusted proxy X-Forwarded-For is honored.
"""

import asyncio
import json
import pytest
import httpx
from unittest.mock import AsyncMock

from bastion.core.proxy import (
    app as proxy_app,
    ioc_repo,
    threat_intel_service,
    exclusion_manager,
)
from bastion.rules.exclusions import RuleExclusion
from bastion.storage.ioc_repository import RedisIOCRepository
from database.db import add_site, get_recent_events, get_sites, set_rule_state, set_site_defense


class FakeAsyncRedis:
    def __init__(self):
        self.store = {}
        self.ttls = {}

    async def get(self, key: str):
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int = None):
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def delete(self, *keys: str):
        count = 0
        for k in keys:
            if k in self.store:
                del self.store[k]
                self.ttls.pop(k, None)
                count += 1
        return count


@pytest.fixture
def fake_redis():
    f_redis = FakeAsyncRedis()
    orig_redis = ioc_repo.redis
    ioc_repo.redis = f_redis
    if hasattr(proxy_app.state, "ioc_repo") and proxy_app.state.ioc_repo:
        proxy_app.state.ioc_repo.redis = f_redis
    yield f_redis
    ioc_repo.redis = orig_redis
    if hasattr(proxy_app.state, "ioc_repo") and proxy_app.state.ioc_repo:
        proxy_app.state.ioc_repo.redis = orig_redis


@pytest.fixture(autouse=True)
def setup_teardown():
    for s in get_sites():
        set_site_defense(s["id"], True)
    exclusion_manager._exclusions.clear()
    set_rule_state("IOC_IP_THREAT", True)
    set_rule_state("IOC_DOMAIN_THREAT", True)
    set_rule_state("IOC_PATH_THREAT", True)
    yield
    for s in get_sites():
        set_site_defense(s["id"], True)
        if "malicious" in str(s.get("domain", "")):
            try:
                from database.db import delete_site
                delete_site(s["id"])
            except Exception:
                pass
    exclusion_manager._exclusions.clear()
    set_rule_state("IOC_IP_THREAT", True)
    set_rule_state("IOC_DOMAIN_THREAT", True)
    set_rule_state("IOC_PATH_THREAT", True)


@pytest.mark.asyncio
async def test_proxy_ip_ioc_blocked_in_prevention_mode(fake_redis):
    # Seed malicious IP with high confidence (0.9)
    await ioc_repo.add_ip_ioc(
        ip="198.51.100.50",
        source="AbuseIPDB",
        reason="Malicious port scanner",
        ttl_seconds=3600,
        confidence=0.9,
    )

    transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.50", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/search?q=normal")
        assert resp.status_code == 403
        data = resp.json()
        assert data["blocked"] is True
        assert data["rule"] == "IOC_IP_THREAT"
        assert "Malicious port scanner" in data["reason"]


@pytest.mark.asyncio
async def test_proxy_domain_ioc_blocked_in_prevention_mode(fake_redis):
    # Register test site in db to route through bastion with defense_mode=True
    add_site("c2.malicious-corp.net", "https://abrham-addis-portfolio.netlify.app", "Active", True)

    try:
        # Seed malicious domain with subdomain matching
        await ioc_repo.add_domain_ioc(
            domain="malicious-corp.net",
            source="ThreatFeedX",
            reason="Command and Control domain",
            confidence=0.95,
            allow_subdomains=True,
        )

        transport = httpx.ASGITransport(app=proxy_app, client=("192.0.2.10", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://c2.malicious-corp.net") as client:
            resp = await client.get("/api/data")
            assert resp.status_code == 403
            data = resp.json()
            assert data["blocked"] is True
            assert data["rule"] == "IOC_DOMAIN_THREAT"
    finally:
        for s in get_sites():
            if s.get("domain") == "c2.malicious-corp.net":
                from database.db import delete_site
                delete_site(s["id"])


@pytest.mark.asyncio
async def test_proxy_path_ioc_blocked_in_prevention_mode(fake_redis):
    # Seed path IOC with clean path (not triggering unrelated CRS rules)
    await ioc_repo.add_path_ioc(
        path="/threat-intel-target/beacon",
        source="Honeypot",
        reason="Known C2 beacon URI",
        confidence=0.85,
    )

    transport = httpx.ASGITransport(app=proxy_app, client=("192.0.2.10", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/threat-intel-target/beacon")
        assert resp.status_code == 403
        data = resp.json()
        assert data["blocked"] is True
        assert data["rule"] == "IOC_PATH_THREAT"


@pytest.mark.asyncio
async def test_proxy_clean_request_allowed(fake_redis):
    # Clean client, host, and path
    transport = httpx.ASGITransport(app=proxy_app, client=("192.0.2.10", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/welcome")
        # Passes through WAF (upstream returns 200, 404, or 502)
        assert resp.status_code != 403


@pytest.mark.asyncio
async def test_proxy_detection_mode_records_ioc_without_blocking(fake_redis):
    # Set site defense to False (detection mode)
    for s in get_sites():
        set_site_defense(s["id"], False)

    await ioc_repo.add_ip_ioc(
        ip="198.51.100.50",
        source="AbuseIPDB",
        reason="Malicious port scanner",
        confidence=0.9,
    )

    transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.50", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/search?q=normal")
        # In detection mode, MUST NOT block
        assert resp.status_code != 403

        # Verify audit log recorded event
        events = get_recent_events(limit=5)
        ioc_events = [e for e in events if e["rule_id"] == "IOC_IP_THREAT" and e["blocked"] == 0]
        assert len(ioc_events) >= 1
        assert "Detection Mode" in ioc_events[0]["action"]


@pytest.mark.asyncio
async def test_proxy_low_confidence_ioc_logs_without_blocking(fake_redis):
    # Low confidence (0.3 -> score 25, proposed action LOG)
    await ioc_repo.add_ip_ioc(
        ip="198.51.100.75",
        source="LowConfidenceFeed",
        reason="Suspicious IP",
        confidence=0.3,
    )

    transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.75", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/search?q=normal")
        # Proposed action is LOG, score is 25 (below 50 block threshold) -> allowed!
        assert resp.status_code != 403


@pytest.mark.asyncio
async def test_proxy_scoped_exclusion_suppresses_ioc(fake_redis):
    await ioc_repo.add_ip_ioc(
        ip="198.51.100.50",
        source="AbuseIPDB",
        reason="Malicious scanner",
        confidence=0.95,
    )

    # Exclude IOC_IP_THREAT for this IP
    exclusion_manager.add_exclusion(RuleExclusion(
        rule_id="IOC_IP_THREAT",
        client_ip="198.51.100.50",
        reason="False positive exemption",
    ))

    transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.50", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/search?q=normal")
        # Excluded -> not blocked
        assert resp.status_code != 403


@pytest.mark.asyncio
async def test_proxy_disabled_rule_suppresses_ioc(fake_redis):
    await ioc_repo.add_ip_ioc(
        ip="198.51.100.50",
        source="AbuseIPDB",
        reason="Malicious scanner",
        confidence=0.95,
    )

    # Disable rule in DB
    set_rule_state("IOC_IP_THREAT", False)

    transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.50", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/search?q=normal")
        assert resp.status_code != 403


@pytest.mark.asyncio
async def test_proxy_redis_failure_falls_back_safely():
    # Mock redis that raises ConnectionError
    failing_redis = AsyncMock()
    failing_redis.get.side_effect = ConnectionError("Redis unreachable")

    orig_redis = ioc_repo.redis
    ioc_repo.redis = failing_redis
    if hasattr(proxy_app.state, "ioc_repo") and proxy_app.state.ioc_repo:
        proxy_app.state.ioc_repo.redis = failing_redis

    try:
        transport = httpx.ASGITransport(app=proxy_app, client=("198.51.100.50", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. Clean request still passes without crashing the proxy (500)
            resp = await client.get("/search?q=hello")
            assert resp.status_code != 500
            assert resp.status_code != 403

            # 2. CRS rules still block attack even when threat intel is down
            sqli_resp = await client.get("/login?user=admin' OR '1'='1")
            assert sqli_resp.status_code == 403
            assert sqli_resp.json()["rule"] == "942100"
    finally:
        ioc_repo.redis = orig_redis
        if hasattr(proxy_app.state, "ioc_repo") and proxy_app.state.ioc_repo:
            proxy_app.state.ioc_repo.redis = orig_redis


@pytest.mark.asyncio
async def test_proxy_untrusted_peer_cannot_spoof_ip(fake_redis):
    # Malicious IP in Redis
    await ioc_repo.add_ip_ioc(
        ip="198.51.100.50",
        source="AbuseFeed",
        reason="Bad IP",
        confidence=0.9,
    )

    # Peer 192.0.2.55 is NOT in trusted_proxies_list
    transport = httpx.ASGITransport(app=proxy_app, client=("192.0.2.55", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Attacker tries to spoof X-Forwarded-For with malicious IP
        resp = await client.get(
            "/search?q=normal",
            headers={"x-forwarded-for": "198.51.100.50"},
        )
        # Because peer is untrusted, XFF is ignored, client IP is 192.0.2.55 (clean), not blocked!
        assert resp.status_code != 403


@pytest.mark.asyncio
async def test_proxy_trusted_proxy_forwarded_ip_is_blocked(fake_redis):
    # Malicious IP in Redis
    await ioc_repo.add_ip_ioc(
        ip="198.51.100.50",
        source="AbuseFeed",
        reason="Bad IP",
        confidence=0.9,
    )

    # Peer 127.0.0.1 IS in trusted_proxies_list ("127.0.0.1/32,::1/128")
    transport = httpx.ASGITransport(app=proxy_app, client=("127.0.0.1", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Trusted reverse proxy passes X-Forwarded-For
        resp = await client.get(
            "/search?q=normal",
            headers={"x-forwarded-for": "198.51.100.50"},
        )
        # Trusted proxy XFF is honored, authentic client IP is resolved as 198.51.100.50 -> blocked!
        assert resp.status_code == 403
        data = resp.json()
        assert data["blocked"] is True
        assert data["rule"] == "IOC_IP_THREAT"
