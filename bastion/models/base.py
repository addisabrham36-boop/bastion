"""
ThreatModel contract for optional machine learning and risk-scoring components.
Ensures ML never crashes the pipeline and runs within strict timeout bounds.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional
from ..core.context import EvaluationState, RequestContext


@dataclass
class ThreatModelResult:
    score: int
    confidence: float
    model_name: str
    model_version: str
    status: str  # "success" | "timeout" | "unavailable" | "disabled"
    explanation: Dict[str, Any]


class ThreatModel(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def version(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def enabled(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def predict(self, context: RequestContext, state: EvaluationState) -> ThreatModelResult:
        """Score request features asynchronously within execution budget."""
        raise NotImplementedError


class NullThreatModel(ThreatModel):
    """Default P0 implementation — no ML dependencies required."""

    @property
    def name(self) -> str:
        return "NullThreatModel"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def enabled(self) -> bool:
        return False

    async def predict(self, context: RequestContext, state: EvaluationState) -> ThreatModelResult:
        return ThreatModelResult(
            score=0,
            confidence=0.0,
            model_name=self.name,
            model_version=self.version,
            status="disabled",
            explanation={"info": "ML threat model disabled in baseline release."},
        )
