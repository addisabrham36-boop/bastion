import logging
import os
from typing import Dict, List, Optional, Set
from .base import BaseRule
from .exclusions import ExclusionManager
from ..core.context import EvaluationState, RequestContext
from ..core.enums import RuleCategory

logger = logging.getLogger(__name__)


class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}

    def register(self, rule: BaseRule):
        if rule.id in self._rules:
            raise ValueError(f"Duplicate rule ID registered: '{rule.id}'")
        self._rules[rule.id] = rule

    def unregister(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        return self._rules.get(rule_id)

    def set_rule_state(self, rule_id: str, enabled: bool) -> bool:
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = enabled
            return True
        return False

    def list_rules(self) -> List[BaseRule]:
        # Return sorted list for deterministic evaluation order
        return sorted(self._rules.values(), key=lambda r: (r.category.value, r.id))

    def list_by_category(self, category: RuleCategory) -> List[BaseRule]:
        return [r for r in self.list_rules() if r.category == category]

    def list_by_tag(self, tag: str) -> List[BaseRule]:
        return [r for r in self.list_rules() if tag in r.tags]

    @classmethod
    def create_default(cls, blocklist_path: Optional[str] = None) -> "RuleRegistry":
        """
        Build the standard production RuleRegistry containing:
        1. Explicit IP & User-Agent blocklist rules
        2. Native BaseRule implementations (e.g. payload high-precision rules)
        3. All legacy Rule subclasses adapted via LegacyRuleAdapter
        """
        registry = cls()

        # 1. Blocklist rules
        from .adapter import BlocklistIPRule, BlocklistUARule, LegacyRuleAdapter
        registry.register(BlocklistIPRule(blocklist_path=blocklist_path))
        registry.register(BlocklistUARule(blocklist_path=blocklist_path))

        # 2. Native BaseRule implementations
        try:
            from .categories.payload import (
                SQLiUnionSelectRule,
                XSSScriptTagRule,
                PathTraversalDotDotRule,
                CommandInjectionChainingRule,
            )
            for native_cls in (
                SQLiUnionSelectRule,
                XSSScriptTagRule,
                PathTraversalDotDotRule,
                CommandInjectionChainingRule,
            ):
                inst = native_cls()
                if inst.id not in registry._rules:
                    registry.register(inst)
        except Exception as e:
            logger.debug("Native BaseRules not registered: %s", e)

        # 3. Discover and adapt all legacy Rule subclasses
        try:
            from ..core.engine import discover_rules
            for legacy_rule in discover_rules():
                rid = str(legacy_rule.RULE_ID)
                if rid not in registry._rules:
                    registry.register(LegacyRuleAdapter(legacy_rule))
        except Exception as e:
            logger.warning("Error discovering legacy rules for registry: %s", e)

        return registry


class RuleEngine:
    def __init__(
        self,
        registry: RuleRegistry,
        exclusion_manager: Optional[ExclusionManager] = None,
    ):
        self.registry = registry
        self.exclusion_manager = exclusion_manager or ExclusionManager()

    def evaluate(
        self,
        context: RequestContext,
        enabled_rule_ids: Optional[Set[str]] = None,
    ) -> EvaluationState:
        state = EvaluationState()
        rules = self.registry.list_rules()

        for rule in rules:
            if not rule.enabled:
                continue

            # Respect database/caller enabled rule set
            if enabled_rule_ids is not None and rule.id not in enabled_rule_ids:
                continue

            # Check if entire rule is excluded for this site/path/IP
            is_excluded, exclusion = self.exclusion_manager.is_excluded(
                rule_id=rule.id,
                site_id=context.site_id,
                path=context.canonical_path,
                client_ip=context.client_ip,
            )
            if is_excluded and exclusion:
                state.notes.append(f"Rule {rule.id} skipped via exclusion {exclusion.id} ({exclusion.reason})")
                continue

            try:
                detection = rule.evaluate(context, state)
                if detection:
                    # Check if specific detection location/param is excluded
                    det_excluded, det_ex = self.exclusion_manager.is_excluded(
                        rule_id=detection.rule_id,
                        site_id=context.site_id,
                        path=context.canonical_path,
                        param=detection.location,
                        client_ip=context.client_ip,
                    )
                    if det_excluded and det_ex:
                        state.notes.append(
                            f"Detection {detection.rule_id} at {detection.location} suppressed via exclusion {det_ex.id}"
                        )
                    else:
                        state.add_detection(detection)
            except Exception as e:
                # Rule execution failure should never crash the proxy
                state.notes.append(f"Rule {rule.id} failed evaluation: {str(e)}")
        return state
