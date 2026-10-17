"""
Registry and deterministic engine for loading and evaluating BaseRule collections.
"""

from typing import Dict, List, Optional
from .base import BaseRule
from ..core.context import EvaluationState, RequestContext


class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}

    def register(self, rule: BaseRule):
        if rule.id in self._rules:
            raise ValueError(f"Duplicate rule ID registered: '{rule.id}'")
        self._rules[rule.id] = rule

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        return self._rules.get(rule_id)

    def list_rules(self) -> List[BaseRule]:
        # Return sorted list for deterministic evaluation order
        return sorted(self._rules.values(), key=lambda r: (r.category.value, r.id))


class RuleEngine:
    def __init__(self, registry: RuleRegistry):
        self.registry = registry

    def evaluate(self, context: RequestContext) -> EvaluationState:
        state = EvaluationState()
        rules = self.registry.list_rules()

        for rule in rules:
            if not rule.enabled:
                continue
            try:
                detection = rule.evaluate(context, state)
                if detection:
                    state.add_detection(detection)
            except Exception as e:
                # Rule execution failure should never crash the proxy
                state.notes.append(f"Rule {rule.id} failed evaluation: {str(e)}")
        return state
