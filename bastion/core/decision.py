"""
Single authority for final policy decisions.
Combines rule detections, aggregate score, rate limits, and site mode.
Supports configurable decision strategies:
  - "compatibility": Preserves legacy blocking behavior for any matching rule with
    proposed_action == "BLOCK" or critical severity, while computing full
    threat scores, multi-rule detection lists, and reason codes for telemetry.
  - "scored": Pure threshold-based decision (threat_score >= site.score_thresholds.block
    or any critical severity detection).
"""

import os
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
        strategy: Optional[str] = None,
    ) -> WAFDecision:
        mode = Mode(site.mode.lower())
        thresholds = site.score_thresholds
        reason_codes = list(state.matched_rule_ids)

        # Strategy resolution: explicit parameter > environment > default "compatibility"
        decision_strategy = (
            strategy or os.environ.get("BASTION_DECISION_STRATEGY", "compatibility")
        ).lower().strip()

        critical_hits = [d for d in state.detections if d.severity == "critical"]
        blocking_detections = [d for d in state.detections if d.proposed_action == "BLOCK"]

        # 1. Determine would-action based on strategy
        if decision_strategy == "compatibility":
            # Guarded compatibility: block if any rule proposed BLOCK, or critical hit, or score threshold met
            if critical_hits or blocking_detections or state.score >= thresholds.block:
                would_action = DecisionAction.BLOCK
            elif state.score >= thresholds.log:
                would_action = DecisionAction.LOG
            else:
                would_action = DecisionAction.ALLOW
        else:
            # Pure scored mode
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
            f"Strategy={decision_strategy}, Evaluated {len(state.detections)} detection(s) "
            f"with total threat score {state.score} "
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
