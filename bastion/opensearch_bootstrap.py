"""
OpenSearch & OpenSearch Dashboards Bootstrap Orchestrator.
Idempotently configures:
1. OpenSearch index template `bastion-events-v1`
2. Dashboards index pattern `bastion-events-v1-*` with time field `@timestamp`
3. Dashboards default index setting
4. Saved visualizations and "Bastion Security Overview" dashboard
Supports both Global and Private security tenants.
"""

import base64
import json
import logging
import os
from pathlib import Path
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from opensearchpy import OpenSearch

logger = logging.getLogger("bastion.opensearch_bootstrap")


def get_env_credentials() -> Dict[str, str]:
    env: Dict[str, str] = {}
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip("\"'")
    return env


def bootstrap(
    opensearch_url: Optional[str] = None,
    dashboards_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    dashboards_username: Optional[str] = None,
    dashboards_password: Optional[str] = None,
    verify_tls: Optional[bool] = None,
    timeout_seconds: int = 45,
) -> bool:
    env_vals = get_env_credentials()

    opensearch_url = opensearch_url or os.getenv("OPENSEARCH_URL", env_vals.get("OPENSEARCH_URL", "https://localhost:9200"))
    dashboards_url = dashboards_url or os.getenv("OPENSEARCH_DASHBOARDS_URL", "http://localhost:5601")
    username = username or os.getenv("OPENSEARCH_USERNAME", env_vals.get("OPENSEARCH_USERNAME", "admin"))
    password = password or os.getenv("OPENSEARCH_PASSWORD", env_vals.get("OPENSEARCH_PASSWORD", ""))
    dashboards_username = dashboards_username or os.getenv("OPENSEARCH_DASHBOARDS_USERNAME", env_vals.get("OPENSEARCH_DASHBOARDS_USERNAME", username))
    dashboards_password = dashboards_password or os.getenv("OPENSEARCH_DASHBOARDS_PASSWORD", env_vals.get("OPENSEARCH_DASHBOARDS_PASSWORD", password))

    if verify_tls is None:
        vt_str = os.getenv("OPENSEARCH_VERIFY_TLS", env_vals.get("OPENSEARCH_VERIFY_TLS", "false")).lower()
        verify_tls = vt_str not in ("false", "0", "no")

    use_ssl = opensearch_url.startswith("https")

    # 1. Wait for OpenSearch
    logger.info("Waiting for OpenSearch at %s...", opensearch_url)
    start = time.time()
    os_client = None
    while time.time() - start < timeout_seconds:
        try:
            client = OpenSearch(
                hosts=[opensearch_url],
                http_auth=(username, password) if username and password else None,
                use_ssl=use_ssl,
                verify_certs=verify_tls,
                ssl_show_warn=False,
                timeout=5.0,
            )
            if client.ping():
                os_client = client
                break
        except Exception as e:
            logger.debug("OpenSearch ping waiting: %s", e)
        time.sleep(2)

    if not os_client:
        logger.error("Timed out waiting for OpenSearch cluster at %s", opensearch_url)
        return False

    # 2. Put Index Template
    template_path = Path(__file__).resolve().parent.parent / "opensearch" / "index-template.json"
    if template_path.exists():
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template_body = json.load(f)
            os_client.indices.put_index_template(name="bastion-events-v1", body=template_body)
            logger.info("OpenSearch index template 'bastion-events-v1' registered.")
        except Exception as e:
            logger.error("Failed to register index template: %s", e)

    # 3. Configure OpenSearch Dashboards (Saved Objects)
    tenants = ["global", "private"]
    dashboards_auth = base64.b64encode(f"{dashboards_username}:{dashboards_password}".encode()).decode()

    # Fetch dynamic field list from Dashboards API so Discover field catalog resolves properly
    fields_list: List[Dict[str, Any]] = []
    try:
        fields_url = f"{dashboards_url.rstrip('/')}/api/index_patterns/_fields_for_wildcard?pattern=bastion-events-v1-*"
        req = urllib.request.Request(fields_url)
        req.add_header("Authorization", f"Basic {dashboards_auth}")
        req.add_header("osd-xsrf", "true")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            fields_list = data.get("fields", [])
    except Exception as e:
        logger.debug("Could not fetch fields via _fields_for_wildcard: %s", e)

    # Canonical default fields derived from index-template.json
    canonical_fields = [
        {"name": "@timestamp", "type": "date", "esTypes": ["date"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "event_id", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "request_id", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "site.id", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "site.host", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "client.ip", "type": "ip", "esTypes": ["ip"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "client.ip_source", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "client.user_agent", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "http.method", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "http.path", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "http.status_code", "type": "number", "esTypes": ["integer"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "decision.mode", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "decision.would_action", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "decision.enforced_action", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "decision.threat_score", "type": "number", "esTypes": ["integer"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "decision.reason_codes", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "detections", "type": "nested", "esTypes": ["nested"], "searchable": False, "aggregatable": False},
        {"name": "detections.rule_id", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True, "subType": {"multi": {"parent": "detections"}}},
        {"name": "detections.category", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True, "subType": {"multi": {"parent": "detections"}}},
        {"name": "detections.severity", "type": "string", "esTypes": ["keyword"], "searchable": True, "aggregatable": True, "readFromDocValues": True, "subType": {"multi": {"parent": "detections"}}},
        {"name": "detections.confidence", "type": "number", "esTypes": ["float"], "searchable": True, "aggregatable": True, "readFromDocValues": True, "subType": {"multi": {"parent": "detections"}}},
        {"name": "detections.score", "type": "number", "esTypes": ["integer"], "searchable": True, "aggregatable": True, "readFromDocValues": True, "subType": {"multi": {"parent": "detections"}}},
        {"name": "timing.total_ms", "type": "number", "esTypes": ["float"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
        {"name": "timing.inspection_ms", "type": "number", "esTypes": ["float"], "searchable": True, "aggregatable": True, "readFromDocValues": True},
    ]

    existing_field_names = {f.get("name") for f in fields_list}
    for cf in canonical_fields:
        if cf["name"] not in existing_field_names:
            fields_list.append(cf)

    # Index Pattern payload with serialized fields
    index_pattern_payload = {
        "attributes": {
            "title": "bastion-events-v1-*",
            "timeFieldName": "@timestamp",
            "fields": json.dumps(fields_list),
        }
    }

    # Dashboard, Visualizations, and Saved Searches payload
    vis_and_dashboard_objects = [
        {
            "type": "search",
            "id": "bastion-search-security-detections",
            "attributes": {
                "title": "All Security Detections",
                "description": "All events with triggered rule detections (using DQL nested syntax)",
                "hits": 0,
                "columns": ["@timestamp", "client.ip", "http.method", "http.path", "decision.enforced_action", "decision.reason_codes"],
                "sort": ["@timestamp", "desc"],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "bastion-events-v1",
                        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "query": {"query": "detections: { rule_id: * }", "language": "kuery"},
                        "filter": [],
                    })
                },
            },
            "references": [
                {
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern",
                    "id": "bastion-events-v1",
                }
            ],
        },
        {
            "type": "search",
            "id": "bastion-search-blocked-attacks",
            "attributes": {
                "title": "Blocked Attack Events",
                "description": "Events blocked by Bastion WAF",
                "hits": 0,
                "columns": ["@timestamp", "client.ip", "http.method", "http.path", "decision.threat_score", "decision.reason_codes"],
                "sort": ["@timestamp", "desc"],
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "bastion-events-v1",
                        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "query": {"query": 'decision.enforced_action: "BLOCK"', "language": "kuery"},
                        "filter": [],
                    })
                },
            },
            "references": [
                {
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern",
                    "id": "bastion-events-v1",
                }
            ],
        },
        {
            "type": "visualization",
            "id": "bastion-vis-total-events",
            "attributes": {
                "title": "Total Security Events",
                "visState": json.dumps({
                    "title": "Total Security Events",
                    "type": "metric",
                    "params": {
                        "metric": {"colorSchema": "Green to Red", "metricColorMode": "None", "style": {"fontSize": 32}},
                        "addTooltip": True,
                        "addLegend": False,
                        "type": "metric",
                    },
                    "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}],
                }),
                "uiStateJSON": "{}",
                "description": "Total security events processed by Bastion WAF",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "bastion-events-v1",
                        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "query": {"query": "", "language": "kuery"},
                        "filter": [],
                    })
                },
            },
            "references": [
                {
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern",
                    "id": "bastion-events-v1",
                }
            ],
        },
        {
            "type": "visualization",
            "id": "bastion-vis-action-split",
            "attributes": {
                "title": "Enforced Action (Block vs Allow)",
                "visState": json.dumps({
                    "title": "Enforced Action",
                    "type": "pie",
                    "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True},
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                        {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "decision.enforced_action", "size": 5, "order": "desc", "orderBy": "1"}},
                    ],
                }),
                "uiStateJSON": "{}",
                "description": "Enforced action breakdown",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "bastion-events-v1",
                        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "query": {"query": "", "language": "kuery"},
                        "filter": [],
                    })
                },
            },
            "references": [
                {
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern",
                    "id": "bastion-events-v1",
                }
            ],
        },
        {
            "type": "visualization",
            "id": "bastion-vis-top-rules",
            "attributes": {
                "title": "Top Triggered Rules",
                "visState": json.dumps({
                    "title": "Top Triggered Rules",
                    "type": "table",
                    "params": {"perPage": 10, "showPartialRows": False, "showMeticsAtAllLevels": False},
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                        {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {"field": "decision.reason_codes", "size": 10, "order": "desc", "orderBy": "1"}},
                    ],
                }),
                "uiStateJSON": "{}",
                "description": "Rules triggering detections",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "bastion-events-v1",
                        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                        "query": {"query": "", "language": "kuery"},
                        "filter": [],
                    })
                },
            },
            "references": [
                {
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern",
                    "id": "bastion-events-v1",
                }
            ],
        },
        {
            "type": "dashboard",
            "id": "bastion-security-overview",
            "attributes": {
                "title": "Bastion Security Overview",
                "description": "Real-time WAF telemetry, threat analysis, and traffic inspection",
                "hits": 0,
                "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
                "panelsJSON": json.dumps([
                    {"version": "3.9.0", "gridData": {"x": 0, "y": 0, "w": 12, "h": 8, "i": "1"}, "panelIndex": "1", "embeddableConfig": {}, "panelRefName": "panel_1"},
                    {"version": "3.9.0", "gridData": {"x": 12, "y": 0, "w": 12, "h": 8, "i": "2"}, "panelIndex": "2", "embeddableConfig": {}, "panelRefName": "panel_2"},
                    {"version": "3.9.0", "gridData": {"x": 0, "y": 8, "w": 24, "h": 12, "i": "3"}, "panelIndex": "3", "embeddableConfig": {}, "panelRefName": "panel_3"},
                ]),
                "timeRestore": False,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
                },
            },
            "references": [
                {"name": "panel_1", "type": "visualization", "id": "bastion-vis-total-events"},
                {"name": "panel_2", "type": "visualization", "id": "bastion-vis-action-split"},
                {"name": "panel_3", "type": "visualization", "id": "bastion-vis-top-rules"},
            ],
        },
    ]

    for tenant in tenants:
        # Create Index Pattern
        try:
            ip_url = f"{dashboards_url.rstrip('/')}/api/saved_objects/index-pattern/bastion-events-v1?overwrite=true"
            req = urllib.request.Request(ip_url, data=json.dumps(index_pattern_payload).encode("utf-8"), method="POST")
            req.add_header("Authorization", f"Basic {dashboards_auth}")
            req.add_header("osd-xsrf", "true")
            req.add_header("Content-Type", "application/json")
            req.add_header("securitytenant", tenant)
            with urllib.request.urlopen(req) as resp:
                pass
            logger.info("Index pattern 'bastion-events-v1-*' created in tenant '%s'.", tenant)
        except Exception as e:
            logger.debug("Could not create index pattern in tenant %s: %s", tenant, e)

        # Set default index
        try:
            set_default_url = f"{dashboards_url.rstrip('/')}/api/opensearch-dashboards/settings/defaultIndex"
            req = urllib.request.Request(set_default_url, data=json.dumps({"value": "bastion-events-v1"}).encode("utf-8"), method="POST")
            req.add_header("Authorization", f"Basic {dashboards_auth}")
            req.add_header("osd-xsrf", "true")
            req.add_header("Content-Type", "application/json")
            req.add_header("securitytenant", tenant)
            with urllib.request.urlopen(req) as resp:
                pass
            logger.info("Default index set to 'bastion-events-v1' in tenant '%s'.", tenant)
        except Exception as e:
            logger.debug("Could not set default index in tenant %s: %s", tenant, e)

        # Create Dashboard and Visualizations
        try:
            bulk_url = f"{dashboards_url.rstrip('/')}/api/saved_objects/_bulk_create?overwrite=true"
            req = urllib.request.Request(bulk_url, data=json.dumps(vis_and_dashboard_objects).encode("utf-8"), method="POST")
            req.add_header("Authorization", f"Basic {dashboards_auth}")
            req.add_header("osd-xsrf", "true")
            req.add_header("Content-Type", "application/json")
            req.add_header("securitytenant", tenant)
            with urllib.request.urlopen(req) as resp:
                pass
            logger.info("Bastion Security Overview dashboard created in tenant '%s'.", tenant)
        except Exception as e:
            logger.debug("Could not bulk create dashboard in tenant %s: %s", tenant, e)

    return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    success = bootstrap()
    print("OpenSearch bootstrap complete:", success)
