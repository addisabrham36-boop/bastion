"""
NoSQL Injection detection rules (OWASP CRS 951xxx).

Covers:
- 951100  MongoDBInjectionRule – MongoDB / NoSQL operator injection
- 951200  NoSQLGeneralRule     – Redis, CouchDB, Elasticsearch injection
"""

import re
from typing import List, Tuple

from .base import Rule, Verdict

# ---------------------------------------------------------------------------
# 951100 – MongoDB / NoSQL injection
# ---------------------------------------------------------------------------

_MONGODB_PATTERNS: List[Tuple[str, str]] = [
    (
        r"\$(?:where|regex|ne|gt|lt|gte|lte|in|nin|exists|type|mod|text|search|expr|jsonSchema|all|size|elemMatch)\b",
        "MongoDB query operator injection ($where, $ne, $gt, etc.)",
    ),
    (r"\{\s*\$", "JSON/NoSQL object starting with MongoDB operator"),
    (r"\[\s*\{\s*\$", "Array of MongoDB operator objects"),
    (r"';\s*return\s+true", "NoSQL injection: '; return true"),
    (r"';\s*return\s+false", "NoSQL injection: '; return false"),
    (r'"\s*\}\s*,\s*"', "NoSQL injection: JSON structure manipulation"),
]
_COMPILED_MONGODB = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _MONGODB_PATTERNS
]

# ---------------------------------------------------------------------------
# 951200 – General NoSQL (Redis, CouchDB, Elasticsearch)
# ---------------------------------------------------------------------------

_NOSQL_GENERAL_PATTERNS: List[Tuple[str, str]] = [
    # Redis commands
    (
        r"\b(?:KEYS|FLUSHALL|FLUSHDB|CONFIG|SLAVEOF|DEBUG|MONITOR|SUBSCRIBE|PSUBSCRIBE)\b",
        "Redis command injection",
    ),
    # CouchDB special endpoints
    (r"_all_docs\b", "CouchDB _all_docs endpoint probe"),
    (r"_changes\b", "CouchDB _changes endpoint probe"),
    (r"_design\b", "CouchDB _design endpoint probe"),
    (r"_view\b", "CouchDB _view endpoint probe"),
    # Elasticsearch DSL injection
    (
        r'\{\s*"query"\s*:\s*\{\s*"match_all"',
        "Elasticsearch match_all query injection",
    ),
    (r"\bscript_fields\b", "Elasticsearch script_fields injection"),
    (r'\binline\b.*\bpainless\b', "Elasticsearch inline Painless script injection"),
]
_COMPILED_NOSQL_GENERAL = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), r) for p, r in _NOSQL_GENERAL_PATTERNS
]


# ---------------------------------------------------------------------------
# Rule classes
# ---------------------------------------------------------------------------


class MongoDBInjectionRule(Rule):
    """Detect MongoDB / NoSQL operator injection (OWASP CRS 951100)."""

    RULE_ID = "951100"
    NAME = "MongoDB / NoSQL Injection Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_MONGODB:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)


class NoSQLGeneralRule(Rule):
    """Detect general NoSQL injection across Redis, CouchDB, and Elasticsearch (OWASP CRS 951200)."""

    RULE_ID = "951200"
    NAME = "General NoSQL Injection Detection"

    def match(self, request) -> Verdict:
        for field_label, value in request.iter_values():
            if not value:
                continue
            for pattern, reason in _COMPILED_NOSQL_GENERAL:
                if pattern.search(value):
                    return Verdict(
                        blocked=True,
                        rule_id=self.RULE_ID,
                        reason=reason,
                        meta={"field": field_label, "matched_value": value[:200]},
                    )
        return Verdict.clean(self.RULE_ID)
