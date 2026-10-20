"""
Threat Intelligence Service for Bastion-TIP.
Performs live IOC evaluation against the RedisIOCRepository with
strict latency bounding, confidence-weighted scoring, and safe degradation.
"""

import asyncio
import logging
from typing import List, Optional, Set
from ..core.context import Detection, RequestContext
from ..core.enums import RuleCategory, Severity
from ..rules.exclusions import ExclusionManager
from ..storage.ioc_repository import RedisIOCRepository

logger = logging.getLogger("bastion.threat_intel.service")

RULE_ID_IP = "IOC_IP_THREAT"
RULE_ID_DOMAIN = "IOC_DOMAIN_THREAT"
RULE_ID_PATH = "IOC_PATH_THREAT"

# Numeric CRS-style aliases for UI/API compatibility
RULE_ALIAS_MAP = {
    "977100": RULE_ID_IP,
    "977110": RULE_ID_DOMAIN,
    "977120": RULE_ID_PATH,
}


def compute_ioc_scoring(confidence: float) -> tuple[Severity, int, str]:
    """
    Map IOC confidence to severity, threat score, and proposed action.
    - Confidence >= 0.8 -> CRITICAL, 50 points, BLOCK
    - 0.5 <= Confidence < 0.8 -> HIGH, 40 points, BLOCK
    - Confidence < 0.5 -> MEDIUM, 25 points, LOG
    """
    if confidence >= 0.8:
        return Severity.CRITICAL, 50, "BLOCK"
    elif confidence >= 0.5:
        return Severity.HIGH, 40, "BLOCK"
    else:
        return Severity.MEDIUM, 25, "LOG"


class ThreatIntelService:
    """
    Asynchronously evaluates incoming requests against configured threat intelligence.
    Employs bounded timeouts and graceful degradation on Redis outages.
    """

    def __init__(
        self,
        repo: RedisIOCRepository,
        exclusion_manager: Optional[ExclusionManager] = None,
        timeout_seconds: Optional[float] = None,
    ):
        self.repo = repo
        self.exclusion_manager = exclusion_manager or ExclusionManager()
        if timeout_seconds is None:
            try:
                from ..settings import get_settings
                self.timeout_seconds = get_settings().bastion_ioc_timeout_seconds
            except Exception:
                self.timeout_seconds = 0.1
        else:
            self.timeout_seconds = timeout_seconds

    def _is_rule_enabled(self, rule_id: str, enabled_rule_ids: Optional[Set[str]]) -> bool:
        if enabled_rule_ids is None:
            return True
        # Check canonical ID or numeric alias
        if rule_id in enabled_rule_ids:
            return True
        for alias, canonical in RULE_ALIAS_MAP.items():
            if canonical == rule_id and alias in enabled_rule_ids:
                return True
        return False

    async def _evaluate_ip(
        self,
        context: RequestContext,
        enabled_rule_ids: Optional[Set[str]],
    ) -> Optional[Detection]:
        if not self._is_rule_enabled(RULE_ID_IP, enabled_rule_ids) or not context.client_ip:
            return None
        is_ex, _ = self.exclusion_manager.is_excluded(
            rule_id=RULE_ID_IP,
            site_id=context.site_id,
            path=context.canonical_path,
            client_ip=context.client_ip,
        )
        if is_ex:
            return None
        ip_record = await self.repo.check_ip_ioc(context.client_ip)
        if ip_record:
            conf = float(ip_record.get("confidence", 1.0))
            src = str(ip_record.get("source", "threat_feed"))
            rsn = str(ip_record.get("reason", "Malicious host indicator"))
            sev, score, action = compute_ioc_scoring(conf)
            return Detection(
                rule_id=RULE_ID_IP,
                category=RuleCategory.NETWORK.value,
                severity=sev.value,
                confidence=conf,
                score=score,
                message=f"Threat intelligence match: {rsn} (source: {src})",
                location="client_ip",
                evidence=f"ip={context.client_ip}, source={src}, confidence={conf}",
                proposed_action=action,
            )
        return None

    async def _evaluate_domain(
        self,
        context: RequestContext,
        enabled_rule_ids: Optional[Set[str]],
    ) -> Optional[Detection]:
        host_header = context.site_host or context.headers.get("host", "")
        if not self._is_rule_enabled(RULE_ID_DOMAIN, enabled_rule_ids) or not host_header:
            return None
        clean_host = host_header.split(":")[0].strip().lower()
        is_ex, _ = self.exclusion_manager.is_excluded(
            rule_id=RULE_ID_DOMAIN,
            site_id=context.site_id,
            path=context.canonical_path,
            client_ip=context.client_ip,
        )
        if is_ex:
            return None
        domain_record = await self.repo.check_domain_ioc(clean_host)
        if domain_record:
            conf = float(domain_record.get("confidence", 1.0))
            src = str(domain_record.get("source", "threat_feed"))
            rsn = str(domain_record.get("reason", "Malicious domain indicator"))
            sev, score, action = compute_ioc_scoring(conf)
            return Detection(
                rule_id=RULE_ID_DOMAIN,
                category=RuleCategory.NETWORK.value,
                severity=sev.value,
                confidence=conf,
                score=score,
                message=f"Threat intelligence domain match: {rsn} (source: {src})",
                location="header:host",
                evidence=f"domain={clean_host}, source={src}, confidence={conf}",
                proposed_action=action,
            )
        return None

    async def _evaluate_path(
        self,
        context: RequestContext,
        enabled_rule_ids: Optional[Set[str]],
    ) -> Optional[Detection]:
        if not self._is_rule_enabled(RULE_ID_PATH, enabled_rule_ids) or not context.canonical_path:
            return None
        is_ex, _ = self.exclusion_manager.is_excluded(
            rule_id=RULE_ID_PATH,
            site_id=context.site_id,
            path=context.canonical_path,
            client_ip=context.client_ip,
        )
        if is_ex:
            return None
        path_record = await self.repo.check_path_ioc(context.canonical_path)
        if path_record:
            conf = float(path_record.get("confidence", 1.0))
            src = str(path_record.get("source", "threat_feed"))
            rsn = str(path_record.get("reason", "Malicious URI path indicator"))
            sev, score, action = compute_ioc_scoring(conf)
            return Detection(
                rule_id=RULE_ID_PATH,
                category=RuleCategory.NETWORK.value,
                severity=sev.value,
                confidence=conf,
                score=score,
                message=f"Threat intelligence path match: {rsn} (source: {src})",
                location="path",
                evidence=f"path={context.canonical_path}, source={src}, confidence={conf}",
                proposed_action=action,
            )
        return None

    async def evaluate_request(
        self,
        context: RequestContext,
        enabled_rule_ids: Optional[Set[str]] = None,
    ) -> List[Detection]:
        """
        Evaluate context against IP, Domain, and Path IOCs in Redis concurrently.
        Guarantees that the total composite evaluation delay is strictly bounded
        by timeout_seconds, preventing serial latency accumulation.
        """
        if not self.repo or not self.repo.redis:
            return []

        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    self._evaluate_ip(context, enabled_rule_ids),
                    self._evaluate_domain(context, enabled_rule_ids),
                    self._evaluate_path(context, enabled_rule_ids),
                    return_exceptions=False,
                ),
                timeout=self.timeout_seconds,
            )
            return [d for d in results if d is not None]
        except asyncio.TimeoutError:
            self.repo.error_count += 1
            self.repo.is_degraded = True
            logger.warning(
                "Threat intelligence composite lookup exceeded timeout limit (%ss); operating in degraded mode",
                self.timeout_seconds,
            )
            return []
        except Exception as exc:
            self.repo.error_count += 1
            self.repo.is_degraded = True
            err_name = type(exc).__name__
            err_msg = str(exc) or "unknown error"
            logger.warning(
                "Threat intelligence lookup encountered %s (%s); operating in degraded mode",
                err_name,
                err_msg,
            )
            return []
