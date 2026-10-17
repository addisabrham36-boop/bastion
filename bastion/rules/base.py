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

    @abstractmethod
    def evaluate(self, context: RequestContext, state: EvaluationState) -> Optional[Detection]:
        raise NotImplementedError
