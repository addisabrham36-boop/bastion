"""
Unit tests for OpenSearch event repository and API integration.
"""

from unittest.mock import MagicMock
import pytest
from bastion.storage.opensearch import OpenSearchEventRepository


def test_opensearch_repository_offline_fallback():
    # When OpenSearch is not running, repository reports unavailable without raising exceptions
    repo = OpenSearchEventRepository(url="http://127.0.0.1:9999")
    assert repo.is_available is False
    assert repo.get_stats() is None
    assert repo.get_recent_events() is None
    assert repo.search_logs() is None


def test_opensearch_repository_mock_queries():
    repo = OpenSearchEventRepository(url="http://127.0.0.1:9200")
    mock_client = MagicMock()
    mock_client.ping.return_value = True

    # Mock search aggregation response for get_stats
    mock_client.search.return_value = {
        "hits": {"total": {"value": 150}},
        "aggregations": {
            "by_action": {"buckets": [{"key": "BLOCK", "doc_count": 50}, {"key": "ALLOW", "doc_count": 100}]},
            "by_rule": {"buckets": [{"key": "sqli", "doc_count": 30}, {"key": "xss", "doc_count": 20}]},
            "avg_latency": {"value": 0.45},
        },
    }
    repo.client = mock_client

    stats = repo.get_stats()
    assert stats is not None
    assert stats["total_requests"] == 150
    assert stats["blocked_attacks"] == 50
    assert stats["clean_requests"] == 100
    assert stats["storage_backend"] == "OpenSearch"
    assert stats["threat_breakdown"]["sqli"] == 30
    assert stats["latency_ms"] == 0.45
