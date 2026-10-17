"""
Single authority for final policy decisions.
Combines rule detections, aggregate score, rate limits, and site mode.
"""

from typing import List, Optional
from pydantic import BaseModel
from .context import Detection, EvaluationState, RequestContext
from .enums import DecisionAction, Mode
from ..proxy.router import SiteConfig


class WAFDecision(BaseModel):
    action: DecisionAction
    would_action: DecisionAction
    threat_score: int
    mode: Mode
    reason_codes: List[str]
    explanation: str


class DecisionEngine:
    @staticmethod
    def decide(
        context: RequestContext,
        state: EvaluationState,
        site: SiteConfig,
    ) -> WAFDecision:
        mode = Mode(site.mode.lower())
        thresholds = site.score_thresholds
        reason_codes = list(state.matched_rule_ids)

        # 1. Determine would-action based on score and severe detections
        critical_hits = [d for d in state.detections if d.severity == "critical"]

        if critical_hits or state.score >= thresholds.block:
            would_action = DecisionAction.BLOCK
        elif state.score >= thresholds.log:
            would_action = DecisionAction.LOG
        else:
            would_action = DecisionAction.ALLOW

        # 2. In Detection Mode, never enforce ordinary BLOCK decisions
        if mode == Mode.DETECTION:
            enforced_action = DecisionAction.ALLOW if would_action == DecisionAction.BLOCK else would_action
        else:
            enforced_action = would_action

        explanation = (
            f"Evaluated {len(state.detections)} detection(s) with total threat score {state.score} "
            f"(block threshold={thresholds.block}, mode={mode.value})."
        )

        return WAFDecision(
            action=enforced_action,
            would_action=would_action,
            threat_score=state.score,
            mode=mode,
            reason_codes=reason_codes,
            explanation=explanation,
        )
