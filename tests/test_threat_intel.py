"""
Unit tests for Threat Intelligence and Redis IOC integration (Phase 4).
Covers:
- RedisIOCRepository (IP, Domain, Path canonicalization, subdomain boundary safety, TTLs, metrics, timeout degradation)
- ThreatFeedIngester (schema validation, boundary ranges, batch fault tolerance)
- ThreatIntelService (confidence-based scoring, rule enable/disable, exclusions, safe fallback)
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch

from bastion.core.context import RequestContext
from bastion.core.enums import RuleCategory, Severity
from bastion.rules.exclusions import ExclusionManager, RuleExclusion
from bastion.storage.ioc_repository import RedisIOCRepository
from bastion.threat_intel.feed_ingester import ThreatFeedIngester
from bastion.threat_intel.service import (
    ThreatIntelService,
    RULE_ID_IP,
    RULE_ID_DOMAIN,
    RULE_ID_PATH,
    compute_ioc_scoring,
)


class FakeAsyncRedis:
    """In-memory async Redis fake for deterministic IOC testing."""

    def __init__(self):
        self.store = {}
        self.ttls = {}
        self.calls = []

    async def get(self, key: str):
        self.calls.append(("get", key))
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int = None):
        self.calls.append(("set", key, value, ex))
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def delete(self, *keys: str):
        self.calls.append(("delete", keys))
        count = 0
        for k in keys:
            if k in self.store:
                del self.store[k]
                self.ttls.pop(k, None)
                count += 1
        return count


def make_context(
    site_id="site-1",
    site_host="example.com",
    client_ip="127.0.0.1",
    method="GET",
    path="/",
    headers=None,
):
    hdrs = headers or {"host": site_host}
    return RequestContext.create(
        site_id=site_id,
        site_host=site_host,
        client_ip=client_ip,
        client_ip_source="peer",
        method=method,
        raw_path=path,
        raw_query="",
        headers=hdrs,
        body_bytes=b"",
        canonical_path=path,
        query_params={},
        form_params={},
        json_body=None,
        text_body="",
    )


# =============================================================================
# 1. RedisIOCRepository Unit Tests
# =============================================================================

def test_canonicalize_ip_valid_and_invalid():
    assert RedisIOCRepository.canonicalize_ip("  192.168.1.1  ") == "192.168.1.1"
    assert RedisIOCRepository.canonicalize_ip("10.0.0.1") == "10.0.0.1"
    assert RedisIOCRepository.canonicalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
    assert RedisIOCRepository.canonicalize_ip("::1") == "::1"

    with pytest.raises(ValueError):
        RedisIOCRepository.canonicalize_ip("not-an-ip")
    with pytest.raises(ValueError):
        RedisIOCRepository.canonicalize_ip("999.999.999.999")
    with pytest.raises(ValueError):
        RedisIOCRepository.canonicalize_ip("")


def test_canonicalize_domain_valid_and_invalid():
    assert RedisIOCRepository.canonicalize_domain("  EXAMPLE.COM  ") == "example.com"
    assert RedisIOCRepository.canonicalize_domain("sub.domain.co.uk.") == "sub.domain.co.uk"
    assert RedisIOCRepository.canonicalize_domain("api.service.internal:8080") == "api.service.internal"
    assert RedisIOCRepository.canonicalize_domain("localhost:9000") == "localhost"

    # Internationalized Domain Name (IDNA punycode)
    assert RedisIOCRepository.canonicalize_domain("münchen.de") == "xn--mnchen-3ya.de"

    with pytest.raises(ValueError):
        RedisIOCRepository.canonicalize_domain("")
    with pytest.raises(ValueError):
        RedisIOCRepository.canonicalize_domain("   ")
    with pytest.raises(ValueError):
        RedisIOCRepository.canonicalize_domain("invalid_char$domain.com")


def test_canonicalize_path():
    assert RedisIOCRepository.canonicalize_path("wp-login.php") == "/wp-login.php"
    assert RedisIOCRepository.canonicalize_path("/api/v1/../v2/users") == "/api/v2/users"
    assert RedisIOCRepository.canonicalize_path("/admin/config.php?debug=1") == "/admin/config.php"
    assert RedisIOCRepository.canonicalize_path("   ") == "/"
    assert RedisIOCRepository.canonicalize_path("/") == "/"


@pytest.mark.asyncio
async def test_ioc_repository_domain_exact_and_subdomain_matching():
    fake_redis = FakeAsyncRedis()
    repo = RedisIOCRepository(fake_redis)

    # Add domain IOC with allow_subdomains=True
    added = await repo.add_domain_ioc(
        domain="malicious-site.com",
        source="AbuseFeed",
        reason="Command and Control server",
        ttl_seconds=7200,
        confidence=0.95,
        allow_subdomains=True,
    )
    assert added is True
    assert fake_redis.ttls["bastion:ioc:v1:domain:malicious-site.com"] == 7200

    # 1. Exact match hit
    hit = await repo.check_domain_ioc("malicious-site.com")
    assert hit is not None
    assert hit["domain"] == "malicious-site.com"
    assert hit["confidence"] == 0.95

    # 2. Subdomain match hit
    sub_hit = await repo.check_domain_ioc("botnet.malicious-site.com")
    assert sub_hit is not None
    assert sub_hit["domain"] == "malicious-site.com"

    nested_hit = await repo.check_domain_ioc("c2.sub.malicious-site.com")
    assert nested_hit is not None

    # 3. Boundary check: hyphenated or prefix domain MUST NOT match
    assert await repo.check_domain_ioc("other-malicious-site.com") is None
    assert await repo.check_domain_ioc("evilmalicious-site.com") is None

    # 4. Clean domain has no match
    assert await repo.check_domain_ioc("google.com") is None


@pytest.mark.asyncio
async def test_ioc_repository_path_indicator_matching():
    fake_redis = FakeAsyncRedis()
    repo = RedisIOCRepository(fake_redis)

    # Add path IOC
    added = await repo.add_path_ioc(
        path="/.env",
        source="ExploitWatch",
        reason="Environment file exposure attempt",
        ttl_seconds=3600,
        confidence=0.9,
    )
    assert added is True
    assert fake_redis.ttls["bastion:ioc:v1:path:/.env"] == 3600

    # Matching path
    hit = await repo.check_path_ioc("/.env")
    assert hit is not None
    assert hit["path"] == "/.env"

    # Traversal resolving to target path matches
    hit_traversal = await repo.check_path_ioc("/static/../.env")
    assert hit_traversal is not None

    # Clean path does not match
    assert await repo.check_path_ioc("/index.html") is None

    # Remove path IOC
    deleted = await repo.remove_path_ioc("/.env")
    assert deleted is True
    assert await repo.check_path_ioc("/.env") is None


@pytest.mark.asyncio
async def test_ioc_repository_metrics_and_timeout_degradation():
    mock_redis = AsyncMock()
    mock_redis.get.side_effect = asyncio.TimeoutError()

    repo = RedisIOCRepository(mock_redis, default_timeout=0.01)
    res = await repo.check_ip_ioc("1.2.3.4")
    assert res is None
    assert repo.lookup_count == 1
    assert repo.error_count == 1
    assert repo.is_degraded is True


# =============================================================================
# 2. ThreatFeedIngester Unit Tests
# =============================================================================

@pytest.mark.asyncio
async def test_threat_feed_ingester_single_and_batch():
    fake_redis = FakeAsyncRedis()
    repo = RedisIOCRepository(fake_redis)
    ingester = ThreatFeedIngester(repo)

    batch = [
        # Valid IP
        {
            "type": "ip",
            "value": "198.51.100.42",
            "source": "Spamhaus",
            "reason": "Known botnet drop host",
            "confidence": 0.85,
            "ttl_seconds": 1800,
        },
        # Valid Domain with subdomain matching
        {
            "type": "domain",
            "value": "phishing-bank.xyz",
            "source": "PhishTank",
            "reason": "Banking credential harvester",
            "confidence": 0.9,
            "ttl_seconds": 3600,
            "allow_subdomains": True,
        },
        # Valid Path
        {
            "type": "path",
            "value": "/admin/shell.php",
            "source": "WebHoneypot",
            "reason": "Webshell path probe",
            "confidence": 0.75,
            "ttl_seconds": 86400,
        },
        # Invalid: unsupported type
        {
            "type": "hash_md5",
            "value": "d41d8cd98f00b204e9800998ecf8427e",
        },
        # Invalid: malformed IP
        {
            "type": "ip",
            "value": "999.888.777.666",
        },
        # Invalid: TTL out of bounds
        {
            "type": "ip",
            "value": "203.0.113.5",
            "ttl_seconds": 9999999999,
        },
        # Invalid: confidence out of bounds
        {
            "type": "domain",
            "value": "example.com",
            "confidence": 1.5,
        },
    ]

    result = await ingester.ingest_batch(batch)
    assert result.ingested == 3
    assert result.rejected == 4
    assert result.total == 7
    assert len(result.errors) == 4

    # Verify ingested items are queryable in repo
    assert await repo.check_ip_ioc("198.51.100.42") is not None
    assert await repo.check_domain_ioc("login.phishing-bank.xyz") is not None
    assert await repo.check_path_ioc("/admin/shell.php") is not None


# =============================================================================
# 3. ThreatIntelService Unit Tests
# =============================================================================

def test_compute_ioc_scoring():
    # Critical confidence >= 0.8
    sev, score, act = compute_ioc_scoring(0.95)
    assert sev == Severity.CRITICAL
    assert score == 50
    assert act == "BLOCK"

    # High confidence 0.5 <= conf < 0.8
    sev, score, act = compute_ioc_scoring(0.65)
    assert sev == Severity.HIGH
    assert score == 40
    assert act == "BLOCK"

    # Medium confidence < 0.5
    sev, score, act = compute_ioc_scoring(0.3)
    assert sev == Severity.MEDIUM
    assert score == 25
    assert act == "LOG"


@pytest.mark.asyncio
async def test_threat_intel_service_evaluates_ip_domain_and_path():
    fake_redis = FakeAsyncRedis()
    repo = RedisIOCRepository(fake_redis)
    ex_mgr = ExclusionManager()
    service = ThreatIntelService(repo, ex_mgr)

    # Seed IOCs
    await repo.add_ip_ioc("198.51.100.1", "FeedA", "Scanner", confidence=0.85)
    await repo.add_domain_ioc("c2-evil.com", "FeedB", "Malicious C2", confidence=0.6)
    await repo.add_path_ioc("/etc/shadow", "FeedC", "LFI target", confidence=0.3)

    # Context with all three matches
    ctx = make_context(
        site_id="site-1",
        site_host="c2-evil.com",
        client_ip="198.51.100.1",
        method="GET",
        path="/etc/shadow",
        headers={"host": "c2-evil.com"},
    )

    detections = await service.evaluate_request(ctx)
    assert len(detections) == 3

    det_map = {d.rule_id: d for d in detections}
    assert RULE_ID_IP in det_map
    assert det_map[RULE_ID_IP].score == 50
    assert det_map[RULE_ID_IP].severity == "critical"
    assert det_map[RULE_ID_IP].proposed_action == "BLOCK"

    assert RULE_ID_DOMAIN in det_map
    assert det_map[RULE_ID_DOMAIN].score == 40
    assert det_map[RULE_ID_DOMAIN].severity == "high"

    assert RULE_ID_PATH in det_map
    assert det_map[RULE_ID_PATH].score == 25
    assert det_map[RULE_ID_PATH].severity == "medium"
    assert det_map[RULE_ID_PATH].proposed_action == "LOG"


@pytest.mark.asyncio
async def test_threat_intel_service_respects_exclusions():
    fake_redis = FakeAsyncRedis()
    repo = RedisIOCRepository(fake_redis)
    ex_mgr = ExclusionManager()
    service = ThreatIntelService(repo, ex_mgr)

    await repo.add_ip_ioc("198.51.100.99", "FeedA", "Scanner", confidence=0.9)

    # Add exclusion for site-1 and this IP
    ex_mgr.add_exclusion(RuleExclusion(
        rule_id=RULE_ID_IP,
        site_id="site-1",
        client_ip="198.51.100.99",
        reason="Exclude internal monitoring IP",
    ))

    ctx = make_context(
        site_id="site-1",
        site_host="example.com",
        client_ip="198.51.100.99",
        method="GET",
        path="/status",
    )

    detections = await service.evaluate_request(ctx)
    assert len(detections) == 0


@pytest.mark.asyncio
async def test_threat_intel_service_respects_enabled_rules():
    fake_redis = FakeAsyncRedis()
    repo = RedisIOCRepository(fake_redis)
    service = ThreatIntelService(repo)

    await repo.add_ip_ioc("198.51.100.5", "FeedA", "Scanner", confidence=0.9)

    ctx = make_context(
        site_id="site-1",
        site_host="example.com",
        client_ip="198.51.100.5",
        method="GET",
        path="/",
    )

    # If only 942100 is enabled (SQLi), IOC rule should not trigger
    detections = await service.evaluate_request(ctx, enabled_rule_ids={"942100"})
    assert len(detections) == 0

    # If numeric alias 977100 is enabled, canonical IOC_IP_THREAT should trigger
    detections = await service.evaluate_request(ctx, enabled_rule_ids={"977100"})
    assert len(detections) == 1
    assert detections[0].rule_id == RULE_ID_IP


@pytest.mark.asyncio
async def test_threat_intel_service_bounds_total_delay():
    fake_redis = FakeAsyncRedis()
    repo = RedisIOCRepository(fake_redis)
    # Configure a strict 0.04s total timeout
    service = ThreatIntelService(repo, timeout_seconds=0.04)

    # Mock IP check to hang
    async def slow_check(*args, **kwargs):
        await asyncio.sleep(0.1)
        return None

    repo.check_ip_ioc = slow_check

    ctx = make_context(
        site_id="site-1",
        site_host="example.com",
        client_ip="198.51.100.1",
        method="GET",
        path="/",
    )

    start = asyncio.get_event_loop().time()
    detections = await service.evaluate_request(ctx)
    elapsed = asyncio.get_event_loop().time() - start

    assert detections == []
    assert elapsed < 0.08  # Strictly bounded by timeout, not hanging
    assert repo.is_degraded is True
    assert repo.error_count >= 1


def test_threat_intel_confidence_score_40_compatibility_vs_scored():
    from bastion.core.context import Detection, EvaluationState
    from bastion.core.decision import DecisionEngine
    from bastion.core.enums import DecisionAction
    from bastion.proxy.router import ScoreThresholds, SiteConfig

    site = SiteConfig(
        id="test-site",
        hostnames=["example.com"],
        upstream_origin="http://127.0.0.1:8080",
        mode="prevention",
        score_thresholds=ScoreThresholds(log=20, block=50),
    )
    ctx = make_context()

    # Score 40 detection (confidence 0.65 -> High severity, proposed action BLOCK)
    sev, score, proposed_action = compute_ioc_scoring(0.65)
    assert score == 40
    assert proposed_action == "BLOCK"

    det40 = Detection(
        rule_id="IOC_IP_THREAT",
        category="network",
        severity=sev.value,
        confidence=0.65,
        score=score,
        message="Threat Intel High Confidence Match",
        location="client_ip",
        evidence="ip=1.2.3.4",
        proposed_action=proposed_action,
    )

    state = EvaluationState()
    state.add_detection(det40)
    assert state.score == 40

    # 1. Compatibility strategy: proposed_action == "BLOCK" triggers would_action = BLOCK
    decision_compat = DecisionEngine.decide(ctx, state, site, strategy="compatibility")
    assert decision_compat.would_action == DecisionAction.BLOCK
    assert decision_compat.action == DecisionAction.BLOCK

    # 2. Scored strategy: score 40 alone does NOT meet threshold 50 -> would_action = LOG
    decision_scored = DecisionEngine.decide(ctx, state, site, strategy="scored")
    assert decision_scored.would_action == DecisionAction.LOG
    assert decision_scored.action == DecisionAction.LOG

    # 3. Scored strategy with accumulated score (40 + 15 = 55 >= 50) -> triggers BLOCK
    state_accum = EvaluationState()
    state_accum.add_detection(det40)
    state_accum.add_detection(Detection(
        rule_id="920100",
        category="protocol",
        severity="medium",
        confidence=1.0,
        score=15,
        message="Protocol anomaly",
        location="header",
        evidence="bad header",
        proposed_action="LOG",
    ))
    assert state_accum.score == 55

    decision_accum = DecisionEngine.decide(ctx, state_accum, site, strategy="scored")
    assert decision_accum.would_action == DecisionAction.BLOCK
    assert decision_accum.action == DecisionAction.BLOCK
