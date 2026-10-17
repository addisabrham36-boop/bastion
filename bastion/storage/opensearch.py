"""
OpenSearch client adapter and query engine for security telemetry events and analytics.
Allows querying events, aggregations, stats, and audit logs directly from OpenSearch,
with SQLite graceful fallback if OpenSearch is not running.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from opensearchpy import OpenSearch

logger = logging.getLogger("bastion.storage.opensearch")


class OpenSearchEventRepository:
    def __init__(
        self,
        url: str = "http://127.0.0.1:9200",
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_tls: bool = False,
        index_pattern: str = "bastion-events-v1-*",
    ):
        self.url = url
        self.index_pattern = index_pattern
        http_auth = (username, password) if username and password else None
        try:
            self.client: Optional[OpenSearch] = OpenSearch(
                hosts=[url],
                http_auth=http_auth,
                verify_certs=verify_tls,
                ssl_show_warn=False,
                timeout=2.0,
            )
            # Test ping
            if not self.client.ping():
                self.client = None
        except Exception:
            self.client = None

    @property
    def is_available(self) -> bool:
        if not self.client:
            return False
        try:
            return bool(self.client.ping())
        except Exception:
            return False

    def get_stats(self) -> Optional[Dict[str, Any]]:
        """Get telemetry aggregate statistics directly from OpenSearch."""
        if not self.is_available or not self.client:
            return None

        try:
            query = {
                "size": 0,
                "aggs": {
                    "by_action": {"terms": {"field": "decision.enforced_action"}},
                    "by_rule": {"terms": {"field": "detections.category"}},
                    "avg_latency": {"avg": {"field": "timing.total_ms"}},
                },
            }
            res = self.client.search(index=self.index_pattern, body=query)
            total = res["hits"]["total"]["value"]
            aggs = res.get("aggregations", {})

            action_counts = {b["key"]: b["doc_count"] for b in aggs.get("by_action", {}).get("buckets", [])}
            blocked = action_counts.get("BLOCK", 0)
            allowed = action_counts.get("ALLOW", 0)

            threat_breakdown = {b["key"]: b["doc_count"] for b in aggs.get("by_rule", {}).get("buckets", [])}
            avg_latency = aggs.get("avg_latency", {}).get("value") or 0.35

            return {
                "total_requests": total,
                "blocked_attacks": blocked,
                "clean_requests": allowed,
                "protected_domains": 1,
                "threat_breakdown": threat_breakdown,
                "latency_ms": round(avg_latency, 2),
                "storage_backend": "OpenSearch",
            }
        except Exception as e:
            logger.warning("OpenSearch get_stats query failed: %s", e)
            return None

    def get_recent_events(self, limit: int = 50) -> Optional[List[Dict[str, Any]]]:
        """Fetch recent events from OpenSearch formatted for dashboard consumption."""
        if not self.is_available or not self.client:
            return None

        try:
            query = {
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }
            res = self.client.search(index=self.index_pattern, body=query)
            hits = res.get("hits", {}).get("hits", [])
            events = []
            for h in hits:
                s = h["_source"]
                detections = s.get("detections", [])
                rule_id = detections[0].get("rule_id", "N/A") if detections else "N/A"
                reason = detections[0].get("category", "Clean") if detections else "Clean Request"

                events.append({
                    "id": h["_id"],
                    "timestamp": s.get("@timestamp"),
                    "client_ip": s.get("client", {}).get("ip", "127.0.0.1"),
                    "method": s.get("http", {}).get("method", "GET"),
                    "path": s.get("http", {}).get("path", "/"),
                    "blocked": bool(s.get("decision", {}).get("enforced_action") == "BLOCK"),
                    "rule_id": rule_id,
                    "reason": reason,
                    "action": f"{s.get('http', {}).get('status_code', 200)} {s.get('decision', {}).get('enforced_action', 'ALLOW')}",
                    "payload_snippet": "",
                })
            return events
        except Exception as e:
            logger.warning("OpenSearch get_recent_events failed: %s", e)
            return None

    def search_logs(self, query_str: str = "", threat_type: str = "") -> Optional[List[Dict[str, Any]]]:
        """Search security events with filters."""
        if not self.is_available or not self.client:
            return None

        try:
            must_clauses = []
            if query_str:
                must_clauses.append({
                    "multi_match": {
                        "query": query_str,
                        "fields": ["client.ip", "http.path", "request_id", "detections.rule_id"],
                    }
                })
            if threat_type and threat_type != "All Threat Types":
                must_clauses.append({"term": {"detections.category": threat_type.lower()}})

            query_body = {
                "size": 100,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }
            if must_clauses:
                query_body["query"] = {"bool": {"must": must_clauses}}

            res = self.client.search(index=self.index_pattern, body=query_body)
            hits = res.get("hits", {}).get("hits", [])
            logs = []
            for h in hits:
                s = h["_source"]
                detections = s.get("detections", [])
                rule_id = detections[0].get("rule_id", "N/A") if detections else "N/A"
                logs.append({
                    "id": h["_id"],
                    "timestamp": s.get("@timestamp"),
                    "client_ip": s.get("client", {}).get("ip", "127.0.0.1"),
                    "method": s.get("http", {}).get("method", "GET"),
                    "path": s.get("http", {}).get("path", "/"),
                    "blocked": bool(s.get("decision", {}).get("enforced_action") == "BLOCK"),
                    "rule_id": rule_id,
                    "action": f"{s.get('http', {}).get('status_code', 200)} {s.get('decision', {}).get('enforced_action')}",
                })
            return logs
        except Exception as e:
            logger.warning("OpenSearch search_logs failed: %s", e)
            return None
