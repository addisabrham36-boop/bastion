"""
Explicit Rule Exclusion Architecture for Bastion-TIP.
Supports scoped, time-bound, auditable rule exemptions without modifying rule code.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid


@dataclass
class RuleExclusion:
    """
    Structured rule exclusion record defining exact scope and expiry.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = "*"                     # Specific rule ID (e.g., "942100") or "*" for all
    site_id: str = "*"                     # Specific site ID or "*" for all sites
    path_pattern: Optional[str] = None     # Optional regex for URL path matching
    param_name: Optional[str] = None       # Optional specific query/body parameter name
    client_ip: Optional[str] = None        # Optional client IP or CIDR range (e.g., "192.168.1.0/24")
    reason: str = "Administrative exemption"
    created_by: str = "admin"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None  # None indicates perpetual until revoked
    enabled: bool = True

    def __post_init__(self):
        if self.path_pattern:
            # Pre-compile regex pattern for efficiency and safety
            self._compiled_path = re.compile(self.path_pattern)
        else:
            self._compiled_path = None

        if self.client_ip:
            try:
                self._ip_network = ipaddress.ip_network(self.client_ip.strip(), strict=False)
            except ValueError:
                self._ip_network = None
        else:
            self._ip_network = None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        current = now or datetime.now(timezone.utc)
        return current > self.expires_at

    def matches(
        self,
        rule_id: str,
        site_id: str,
        path: str,
        param: Optional[str] = None,
        client_ip: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> bool:
        """Evaluate whether this exclusion matches the current execution context."""
        if not self.enabled:
            return False

        if self.is_expired(now):
            return False

        # 1. Rule match
        if self.rule_id != "*" and self.rule_id != rule_id:
            return False

        # 2. Site match
        if self.site_id != "*" and self.site_id != site_id:
            return False

        # 3. Path pattern match
        if self._compiled_path is not None and not self._compiled_path.search(path):
            return False

        # 4. Parameter name match
        if self.param_name is not None:
            if param is None or self.param_name.lower() != param.lower():
                return False

        # 5. Client IP / CIDR match
        if self._ip_network is not None and client_ip:
            try:
                addr = ipaddress.ip_address(client_ip.strip())
                if addr not in self._ip_network:
                    return False
            except ValueError:
                return False

        return True


class ExclusionManager:
    """Manages active exclusions and provides audit records."""

    def __init__(self):
        self._exclusions: Dict[str, RuleExclusion] = {}
        self._audit_records: List[Dict[str, Any]] = []

    def add_exclusion(self, exclusion: RuleExclusion) -> RuleExclusion:
        self._exclusions[exclusion.id] = exclusion
        self._audit_records.append({
            "action": "EXCLUSION_ADDED",
            "exclusion_id": exclusion.id,
            "rule_id": exclusion.rule_id,
            "site_id": exclusion.site_id,
            "reason": exclusion.reason,
            "created_by": exclusion.created_by,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return exclusion

    def remove_exclusion(self, exclusion_id: str, revoked_by: str = "admin") -> bool:
        if exclusion_id in self._exclusions:
            ex = self._exclusions.pop(exclusion_id)
            self._audit_records.append({
                "action": "EXCLUSION_REVOKED",
                "exclusion_id": exclusion_id,
                "rule_id": ex.rule_id,
                "revoked_by": revoked_by,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            return True
        return False

    def is_excluded(
        self,
        rule_id: str,
        site_id: str,
        path: str,
        param: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> Tuple[bool, Optional[RuleExclusion]]:
        """Check if any active exclusion applies to this detection context."""
        now = datetime.now(timezone.utc)
        for exclusion in self._exclusions.values():
            if exclusion.matches(
                rule_id=rule_id,
                site_id=site_id,
                path=path,
                param=param,
                client_ip=client_ip,
                now=now,
            ):
                return True, exclusion
        return False, None

    def list_exclusions(self, include_expired: bool = False) -> List[RuleExclusion]:
        now = datetime.now(timezone.utc)
        if include_expired:
            return list(self._exclusions.values())
        return [ex for ex in self._exclusions.values() if not ex.is_expired(now)]

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        return list(self._audit_records)
