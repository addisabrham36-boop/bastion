"""
Base interface for all Bastion detection rules.

Every rule in bastion/rules/ (sqli.py, xss.py, traversal.py, ...) subclasses
Rule and implements match(). engine.py depends only on this interface, so
adding rule N+1 never requires touching engine.py or any existing rule.
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
    # Free-form extra context for logging/dashboard (e.g. matched substring,
    # offending parameter name). Kept generic so rules don't need new fields
    # on this class every time they want to log something specific.
    meta: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def clean(cls, rule_id: str) -> "Verdict":
        """Shorthand for 'this rule found nothing.'"""
        return cls(blocked=False, rule_id=rule_id)


class Rule(ABC):
    """
    Every detection rule (SQLi, XSS, path traversal, ...) implements this.

    Naming convention: RULE_ID should match the OWASP CRS-style scheme used
    elsewhere in the project (e.g. "942100" for SQLi) so dashboard log rows
    and engine output stay consistent — see dashboard's "Rule ID Triggered"
    column, which already expects this format.
    """

    #: Stable identifier for this rule. Override in every subclass.
    RULE_ID: str = "UNSET"

    #: Human-readable name shown in the dashboard's Rule Engine tab.
    NAME: str = "Unnamed Rule"

    @abstractmethod
    def match(self, request: "NormalizedRequest") -> Verdict:
        """
        Inspect a normalized request and return a Verdict.

        Implementations must not raise on malformed input — a rule that
        crashes takes down engine.py's whole evaluation loop for every
        other rule. Catch parsing errors internally and return a clean
        Verdict (fail open) or a blocked Verdict (fail closed) as
        appropriate for that rule's risk profile.
        """
        raise NotImplementedError


# Forward reference for type hints above; actual NormalizedRequest type
# is defined in bastion/core/normalizer.py (Phase 1). Importing it here
# would create a circular import (normalizer -> rules -> normalizer),
# so rules type-hint against the string name only for now.
NormalizedRequest = Any
