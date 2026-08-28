"""
Base interface for all Bastion detection rules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Verdict:
    """Result of running a single rule against a normalized request."""

    blocked: bool
    rule_id: str
    reason: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def clean(cls, rule_id: str) -> "Verdict":
        """Shorthand for 'this rule found nothing.'"""
        return cls(blocked=False, rule_id=rule_id)


class Rule(ABC):
    """
    Every detection rule (SQLi, XSS, path traversal, RCE, SSRF) implements this.
    """

    RULE_ID: str = "UNSET"
    NAME: str = "Unnamed Rule"

    @abstractmethod
    def match(self, request: Any) -> Verdict:
        """
        Inspect a normalized request and return a Verdict.
        """
        raise NotImplementedError
