"""
Adapter bridging legacy Rule subclasses into the modern BaseRule/RuleRegistry architecture.
Ensures 100% of existing CRS and custom detection rules participate in the scored pipeline.
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional, Tuple

from .base import BaseRule, Rule, Verdict
from ..core.context import Detection, EvaluationState, RequestContext
from ..core.enums import RuleCategory, Severity
from ..core.normalizer import normalize_request

logger = logging.getLogger(__name__)


def map_legacy_rule_metadata(rule_id: str, rule_name: str) -> Tuple[RuleCategory, Severity, int]:
    """
    Map a legacy rule ID and name to a typed category, severity level, and base threat score.
    """
    rid = str(rule_id).strip()

    # RCE / Critical Server-Side Exploitation
    if (
        rid.startswith("932")  # OS Command Injection
        or rid.startswith("944")  # Java Injection (OGNL/Log4j)
        or rid.startswith("933")  # PHP Code Injection
        or rid.startswith("953")  # XXE Entity Injection
        or rid.startswith("934")  # SSRF Cloud Metadata / Localhost
    ):
        return RuleCategory.PAYLOAD, Severity.CRITICAL, 50

    # High Impact Injections & Traversal
    elif (
        rid.startswith("942")  # SQL Injection
        or rid.startswith("941")  # XSS
        or rid.startswith("930")  # Path Traversal / LFI
        or rid.startswith("950")  # RFI
        or rid.startswith("951")  # NoSQLi
        or rid.startswith("952")  # SSTI
        or rid in ("974100", "974105", "974110")  # Dangerous Uploads, Null-byte, Traversal in filename
    ):
        return RuleCategory.PAYLOAD, Severity.HIGH, 40

    # Protocol Violations, Parameter Tampering, & Abuse
    elif (
        rid.startswith("970")  # Host Header Manipulation
        or rid.startswith("971")  # Parameter Pollution
        or rid.startswith("972")  # Auth Endpoint Abuse
        or rid.startswith("973")  # API Method & Content-Type Policy
        or rid.startswith("974")  # Other Multipart Upload Integrity
        or rid.startswith("975")  # Resource Exhaustion / DoS
        or rid.startswith("976")  # Security Header Audit
        or rid.startswith("920")  # HTTP Protocol Violations
        or rid.startswith("921")  # HTTP Request Smuggling
    ):
        return RuleCategory.PROTOCOL, Severity.MEDIUM, 30

    # Scanner / Probe Detection
    elif rid.startswith("913"):
        return RuleCategory.BEHAVIORAL, Severity.LOW, 20

    # Client-Side Defenses
    elif rid.startswith("960"):
        return RuleCategory.PROTOCOL, Severity.MEDIUM, 25

    # Default fallback
    return RuleCategory.PAYLOAD, Severity.MEDIUM, 25


class LegacyRuleAdapter(BaseRule):
    """
    Wraps an existing legacy Rule instance so it executes within the scored RuleEngine.
    Preserves all detection logic, bounded execution, and raw-body inspection.
    """

    def __init__(self, legacy_rule: Rule):
        self.legacy_rule = legacy_rule
        self.id = str(legacy_rule.RULE_ID)
        self.name = str(legacy_rule.NAME)

        category, severity, score = map_legacy_rule_metadata(self.id, self.name)
        self.category = category
        self.severity = severity
        self.score = score
        self.confidence = 0.90
        self.enabled = True
        self.tags = [self.category.value, self.id[:3]]
        self.description = self.name
        self.proposed_action = "BLOCK"

    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        if not self.enabled:
            return None

        # Re-use normalized representation if already attached to context
        norm_req = getattr(context, "normalized", None)
        if norm_req is None:
            norm_req = normalize_request(
                method=context.method,
                path=context.canonical_path,
                query_string=context.raw_query,
                headers=context.headers,
                body=context.body_bytes,
                client_ip=context.client_ip,
            )

        try:
            verdict: Verdict = self.legacy_rule.match(norm_req)
        except NotImplementedError:
            return None
        except Exception as err:
            logger.warning("Legacy rule %s (%s) raised during match: %s", self.id, self.name, err)
            return None

        if verdict and verdict.blocked:
            location = verdict.meta.get("field", "payload") if isinstance(verdict.meta, dict) else "payload"
            matched_val = verdict.meta.get("matched_value", "") if isinstance(verdict.meta, dict) else ""
            evidence = str(matched_val or verdict.reason)[:256]

            return self.build_detection(
                location=location,
                evidence=evidence,
                message=verdict.reason or self.name,
                severity=self.severity,
                confidence=self.confidence,
                score=self.score,
            )

        return None


class BlocklistIPRule(BaseRule):
    """Evaluates client IP against configured blocklist in blocklist.json."""

    id = "BLOCKLIST_IP"
    name = "Client IP Blocklist Shield"
    category = RuleCategory.NETWORK
    severity = Severity.CRITICAL
    confidence = 1.0
    score = 100
    enabled = True
    tags = ["blocklist", "ip"]
    description = "Blocks traffic from explicitly blocklisted client IP addresses."
    proposed_action = "BLOCK"

    def __init__(self, blocklist_path: Optional[str] = None):
        if blocklist_path:
            self.blocklist_path = blocklist_path
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.blocklist_path = str(base_dir / "config" / "blocklist.json")

    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        if not self.enabled or not os.path.exists(self.blocklist_path) or not context.client_ip:
            return None
        try:
            with open(self.blocklist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ip_blocklist = data.get("ip_blocklist", [])
            if context.client_ip in ip_blocklist:
                return self.build_detection(
                    location="client_ip",
                    evidence=context.client_ip,
                    message="Client IP is in blocklist",
                    severity=self.severity,
                    score=self.score,
                )
        except Exception as e:
            logger.debug("Failed checking IP blocklist: %s", e)
        return None


class BlocklistUARule(BaseRule):
    """Evaluates User-Agent header against configured blocklist in blocklist.json."""

    id = "BLOCKLIST_UA"
    name = "User-Agent Blocklist Shield"
    category = RuleCategory.BEHAVIORAL
    severity = Severity.CRITICAL
    confidence = 1.0
    score = 100
    enabled = True
    tags = ["blocklist", "user_agent"]
    description = "Blocks traffic with known malicious automated scanning user agents."
    proposed_action = "BLOCK"

    def __init__(self, blocklist_path: Optional[str] = None):
        if blocklist_path:
            self.blocklist_path = blocklist_path
        else:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.blocklist_path = str(base_dir / "config" / "blocklist.json")

    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        if not self.enabled or not os.path.exists(self.blocklist_path):
            return None
        ua = context.headers.get("user-agent", "")
        if not ua:
            return None
        try:
            with open(self.blocklist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ua_blocklist = data.get("user_agent_blocklist", [])
            ua_lower = ua.lower()
            if any(b.lower() in ua_lower for b in ua_blocklist):
                return self.build_detection(
                    location="header:user-agent",
                    evidence=ua[:128],
                    message="User-Agent is in blocklist",
                    severity=self.severity,
                    score=self.score,
                )
        except Exception as e:
            logger.debug("Failed checking UA blocklist: %s", e)
        return None
