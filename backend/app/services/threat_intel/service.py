import logging
import ipaddress
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from app.core.config import settings
from app.db.repositories.threat_intel_repository import ThreatIntelRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.schemas.indicator import IndicatorType
from app.schemas.threat_intel import ThreatIntelligence
from app.services.threat_intel.base import ThreatIntelProvider, ThreatIntelResult
from app.services.threat_intel.virustotal import VirusTotalProvider
from app.services.threat_intel.urlhaus import URLhausProvider
from app.services.threat_intel.abuseipdb import AbuseIPDBProvider
from app.services.threat_intel.alienvault_otx import AlienVaultOTXProvider

logger = logging.getLogger("emit.threat_intel.service")

class ThreatIntelService:
    """
    Coordinates threat intelligence enrichment across pluggable providers.
    Enforces indicator relevance filtering, caching, graceful error handling,
    and strict separation between local observations and external threat intelligence.
    """

    def __init__(
        self,
        providers: Optional[List[ThreatIntelProvider]] = None,
        threat_repo: Optional[ThreatIntelRepository] = None,
        indicator_repo: Optional[IndicatorRepository] = None
    ):
        self.providers = providers or [
            VirusTotalProvider(),
            URLhausProvider(),
            AbuseIPDBProvider(),
            AlienVaultOTXProvider()
        ]
        self.threat_repo = threat_repo or ThreatIntelRepository()
        self.indicator_repo = indicator_repo or IndicatorRepository()

    def get_provider(self, name: str) -> Optional[ThreatIntelProvider]:
        for p in self.providers:
            if p.name.lower() == name.lower():
                return p
        return None

    def get_enabled_providers(self) -> List[ThreatIntelProvider]:
        return [p for p in self.providers if p.is_enabled()]

    @staticmethod
    def is_relevant_indicator(indicator_value: str, indicator_type: IndicatorType) -> bool:
        """
        Determines whether an indicator is relevant for external enrichment.
        Do NOT send every indicator automatically (e.g. system permissions, APIs, private IPs).
        """
        val = indicator_value.strip().lower()

        # Non-network or local system indicator types are never sent
        if indicator_type in [
            IndicatorType.PERMISSION,
            IndicatorType.API,
            IndicatorType.PACKAGE,
            IndicatorType.CAPABILITY,
            IndicatorType.PORT,
            IndicatorType.PROTOCOL
        ]:
            return False

        # IP validation: only public routable IPs
        if indicator_type == IndicatorType.IP:
            try:
                ip_obj = ipaddress.ip_address(val)
                if (
                    ip_obj.is_private or
                    ip_obj.is_loopback or
                    ip_obj.is_reserved or
                    ip_obj.is_link_local or
                    ip_obj.is_multicast or
                    val in ["0.0.0.0", "255.255.255.255"]
                ):
                    return False
                return True
            except ValueError:
                return False

        # DOMAIN validation: only valid external domains
        if indicator_type == IndicatorType.DOMAIN:
            if not val or "." not in val:
                return False
            # Filter internal/local test hostnames
            local_suffixes = [".local", ".internal", ".test", ".localhost", ".corp", ".lan"]
            if any(val.endswith(sfx) for sfx in local_suffixes) or val in ["localhost", "localhost.localdomain"]:
                return False
            # Filter Android framework packages
            if val.startswith("android.") or val.startswith("com.android."):
                return False
            return True

        # URL validation: must have valid web scheme
        if indicator_type == IndicatorType.URL:
            return val.startswith("http://") or val.startswith("https://")

        # HASH validation: must look like md5/sha1/sha256 hex string
        if indicator_type == IndicatorType.HASH:
            return len(val) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in val)

        return False

    def enrich_indicator(
        self,
        indicator_id: str,
        indicator_value: str,
        indicator_type_str: str,
        case_id: str,
        provider_name: Optional[str] = None
    ) -> List[ThreatIntelligence]:
        """
        Enriches a single indicator against enabled providers or a specific provider.
        Checks cache first before making external calls.
        """
        try:
            ind_type = IndicatorType(indicator_type_str.upper())
        except ValueError:
            logger.debug(f"Indicator type {indicator_type_str} not recognized for enrichment.")
            return []

        if not self.is_relevant_indicator(indicator_value, ind_type):
            logger.debug(f"Indicator '{indicator_value}' of type {indicator_type_str} is not relevant for threat intel.")
            return []

        target_providers = (
            [self.get_provider(provider_name)] if provider_name
            else self.get_enabled_providers()
        )
        target_providers = [p for p in target_providers if p and p.supports(ind_type)]

        results: List[ThreatIntelligence] = []
        now = datetime.utcnow()

        for provider in target_providers:
            # 1. Cache lookup: check for unexpired cached result
            cached = self.threat_repo.find_one({
                "provider": provider.name,
                "indicator": indicator_value,
                "expires_at": {"$gt": now}
            })
            if cached:
                logger.info(f"Using cached threat intel result for {indicator_value} from {provider.name}.")
                results.append(ThreatIntelligence(**cached))
                continue

            # 2. Query provider
            try:
                enrich_result = provider.enrich(indicator_value, ind_type)
                if not enrich_result:
                    continue

                intel = ThreatIntelligence(
                    case_id=case_id,
                    indicator_id=indicator_id,
                    indicator=indicator_value,
                    indicator_type=ind_type.value,
                    provider=provider.name,
                    verdict=enrich_result.verdict,
                    score=enrich_result.score,
                    categories=enrich_result.categories,
                    raw_result=enrich_result.raw_result,
                    checked_at=enrich_result.checked_at,
                    expires_at=enrich_result.expires_at or (now + timedelta(hours=settings.THREAT_INTEL_CACHE_HOURS)),
                    metadata={"source": "EXTERNAL_THREAT_INTELLIGENCE"}
                )

                # Persist to database
                self.threat_repo.insert_one(intel.model_dump())
                results.append(intel)

            except Exception as e:
                logger.error(f"Error enriching {indicator_value} with {provider.name}: {e}")

        return results

    def enrich_case(
        self,
        case_id: str,
        max_indicators: int = 20
    ) -> List[ThreatIntelligence]:
        """
        Enriches all relevant indicators for a case against all enabled providers.
        Operates gracefully if all providers are disabled.
        """
        enabled = self.get_enabled_providers()
        if not enabled:
            logger.info(f"No threat intelligence providers enabled. Skipping case {case_id} enrichment.")
            return []

        indicators = self.indicator_repo.find_all({"case_id": case_id})
        all_results: List[ThreatIntelligence] = []
        enriched_count = 0

        for ind in indicators:
            if enriched_count >= max_indicators:
                break

            ind_id = ind.get("indicator_id")
            val = ind.get("normalized_value") or ind.get("value", "")
            type_str = ind.get("type", "")

            try:
                ind_type = IndicatorType(type_str.upper())
            except ValueError:
                continue

            if not self.is_relevant_indicator(val, ind_type):
                continue

            res = self.enrich_indicator(
                indicator_id=ind_id,
                indicator_value=val,
                indicator_type_str=type_str,
                case_id=case_id
            )
            all_results.extend(res)
            enriched_count += 1

        logger.info(f"Case {case_id} threat intelligence enrichment completed: {len(all_results)} results.")
        return all_results
