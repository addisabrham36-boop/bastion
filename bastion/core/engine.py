"""
Detection engine — discovers every Rule subclass under bastion/rules/,
runs each against a NormalizedRequest, and returns the first blocking
Verdict (or a clean verdict if none match).

Auto-discovery via pkgutil/inspect means adding rules/new_rule.py with a
Rule subclass is enough to activate it — nothing here needs editing, which
is the whole point of the Rule interface in base.py.
"""

import importlib
import inspect
import json
import logging
import os
import pkgutil
from pathlib import Path
from typing import List, Optional, Set

from .. import rules as rules_package
from ..rules.base import Rule, Verdict

logger = logging.getLogger(__name__)


def discover_rules() -> List[Rule]:
    """
    Import every module in bastion/rules/ (except base.py) and instantiate
    every Rule subclass defined directly in that module.
    """
    instances: List[Rule] = []
    for _, module_name, _ in pkgutil.iter_modules(rules_package.__path__):
        if module_name == "base":
            continue
        module = importlib.import_module(f"{rules_package.__name__}.{module_name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Rule) and obj is not Rule and obj.__module__ == module.__name__:
                instances.append(obj())
    return instances


class Engine:
    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        blocklist_path: Optional[str] = None,
    ):
        self.rules: List[Rule] = rules if rules is not None else discover_rules()
        self.blocklist_path = blocklist_path or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config", "blocklist.json"
        )

    def _check_blocklist(self, request) -> Optional[Verdict]:
        """Check if client IP or User-Agent is explicitly blocklisted."""
        if not os.path.exists(self.blocklist_path):
            return None
        try:
            with open(self.blocklist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ip_blocklist = data.get("ip_blocklist", [])
            ua_blocklist = data.get("user_agent_blocklist", [])

            if request.client_ip and request.client_ip in ip_blocklist:
                return Verdict(
                    blocked=True,
                    rule_id="BLOCKLIST_IP",
                    reason="Client IP is in blocklist",
                    meta={"client_ip": request.client_ip},
                )

            user_agent = request.headers.get("user-agent", "")
            if user_agent and any(ua.lower() in user_agent.lower() for ua in ua_blocklist):
                return Verdict(
                    blocked=True,
                    rule_id="BLOCKLIST_UA",
                    reason="User-Agent is in blocklist",
                    meta={"user_agent": user_agent},
                )
        except Exception as e:
            logger.warning("Failed to check blocklist: %s", e)
        return None

    def evaluate(self, request, enabled_rule_ids: Optional[Set[str]] = None) -> Verdict:
        # 1. Check IP and User-Agent blocklists
        blocklist_verdict = self._check_blocklist(request)
        if blocklist_verdict and blocklist_verdict.blocked:
            return blocklist_verdict

        # 2. Check active detection rules
        for rule in self.rules:
            if enabled_rule_ids is not None and rule.RULE_ID not in enabled_rule_ids:
                continue
            try:
                verdict = rule.match(request)
            except NotImplementedError:
                logger.debug("Skipping unimplemented rule: %s", rule.RULE_ID)
                continue
            if verdict.blocked:
                return verdict
        return Verdict.clean("CLEAN")

