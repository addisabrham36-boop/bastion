"""
Base interface and data structures for Bastion-TIP detection rules.
Supports both legacy Rule/Verdict and new BaseRule/Detection architectures.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from ..core.context import Detection, EvaluationState, RequestContext
from ..core.enums import RuleCategory, Severity


# Legacy compatibility classes for existing 18 rule modules
@dataclass
class Verdict:
    blocked: bool
    rule_id: str
    reason: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def clean(cls, rule_id: str) -> "Verdict":
        return cls(blocked=False, rule_id=rule_id)


class Rule(ABC):
    RULE_ID: str = "UNSET"
    NAME: str = "Unnamed Rule"

    @abstractmethod
    def match(self, request: Any) -> Verdict:
        raise NotImplementedError


# Enhanced Master Spec BaseRule contract
class BaseRule(ABC):
    id: str
    name: str
    category: RuleCategory
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.8
    score: int = 25
    enabled: bool = True
    tags: List[str] = []
    description: str = ""
    version: int = 1
    owasp_category: str = "A03:2025-Injection"
    detects: str = ""
    does_not_detect: str = ""
    proposed_action: str = "BLOCK"
    max_input_length: int = 4096  # Bounded string length to protect against ReDoS

    @abstractmethod
    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        raise NotImplementedError

    def safe_text(self, text: str) -> str:
        """Truncate input string to max_input_length to prevent pathological regex backtracking."""
        if not text:
            return ""
        if len(text) > self.max_input_length:
            return text[:self.max_input_length]
        return text

    def build_detection(
        self,
        location: str,
        evidence: str,
        message: Optional[str] = None,
        severity: Optional[Severity] = None,
        confidence: Optional[float] = None,
        score: Optional[int] = None,
    ) -> Detection:
        """Construct a standardized Detection record from rule metadata."""
        sev = (severity or self.severity).value if isinstance(severity or self.severity, Severity) else str(severity or self.severity)
        # Redact/bound evidence to 256 characters max
        safe_evidence = evidence[:256] if evidence else ""
        return Detection(
            rule_id=self.id,
            category=self.category.value if isinstance(self.category, RuleCategory) else str(self.category),
            severity=sev,
            confidence=confidence if confidence is not None else self.confidence,
            score=score if score is not None else self.score,
            message=message or self.description or self.name,
            location=location,
            evidence=safe_evidence,
            proposed_action=self.proposed_action,
            version=self.version,
        )
