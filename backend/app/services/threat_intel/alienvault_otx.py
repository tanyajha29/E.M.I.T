import logging
import httpx
from typing import Optional, List
from datetime import datetime, timedelta

from app.core.config import settings
from app.schemas.indicator import IndicatorType
from app.services.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger("emit.threat_intel.otx")

class AlienVaultOTXProvider(ThreatIntelProvider):
    """
    Threat Intelligence provider for AlienVault OTX API.
    """

    @property
    def name(self) -> str:
        return "AlienVault OTX"

    def is_enabled(self) -> bool:
        if settings.ENABLE_THREAT_INTEL_OTX is not None:
            return settings.ENABLE_THREAT_INTEL_OTX
        return self.is_configured()

    def is_configured(self) -> bool:
        return bool(settings.OTX_API_KEY and settings.OTX_API_KEY.strip())

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in [
            IndicatorType.DOMAIN,
            IndicatorType.IP,
            IndicatorType.HASH,
            IndicatorType.URL
        ]

    def enrich(self, indicator: str, indicator_type: IndicatorType) -> Optional[ThreatIntelResult]:
        if not self.is_enabled():
            logger.debug(f"AlienVault OTX provider is disabled. Skipping {indicator}.")
            return None

        if not self.is_configured():
            logger.warning("AlienVault OTX is enabled but OTX_API_KEY is missing. Skipping.")
            return None

        if not self.supports(indicator_type):
            return None

        type_path = ""
        if indicator_type == IndicatorType.DOMAIN:
            type_path = "domain"
        elif indicator_type == IndicatorType.IP:
            type_path = "IPv4"
        elif indicator_type == IndicatorType.HASH:
            type_path = "file"
        elif indicator_type == IndicatorType.URL:
            type_path = "url"

        api_url = f"https://otx.alienvault.com/api/v1/indicators/{type_path}/{indicator}/general"
        headers = {
            "X-OTX-API-KEY": settings.OTX_API_KEY,
            "Accept": "application/json"
        }

        try:
            with httpx.Client(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                response = client.get(api_url, headers=headers)

                if response.status_code == 404:
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=indicator,
                        indicator_type=indicator_type.value,
                        verdict="UNKNOWN",
                        score=0.0,
                        categories=["Not in OTX Pulses"],
                        raw_result={"status_code": 404},
                        expires_at=datetime.utcnow() + timedelta(hours=settings.THREAT_INTEL_CACHE_HOURS)
                    )

                if response.status_code == 429:
                    logger.warning(f"AlienVault OTX rate limit exceeded for {indicator}.")
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=indicator,
                        indicator_type=indicator_type.value,
                        verdict="UNKNOWN",
                        score=None,
                        categories=["Rate Limited"],
                        raw_result={"status_code": 429},
                        expires_at=datetime.utcnow() + timedelta(minutes=15)
                    )

                if response.status_code in [401, 403]:
                    logger.error(f"AlienVault OTX authentication failed (status {response.status_code}).")
                    return None

                response.raise_for_status()
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                pulse_count = pulse_info.get("count", 0)

                categories: List[str] = []
                for pulse in pulse_info.get("pulses", [])[:5]:
                    name = pulse.get("name")
                    if name and name not in categories:
                        categories.append(name)
                    for tag in pulse.get("tags", []):
                        if tag and tag not in categories:
                            categories.append(str(tag))

                if pulse_count >= 5:
                    verdict = "MALICIOUS"
                    score = 90.0
                elif pulse_count > 0:
                    verdict = "SUSPICIOUS"
                    score = 50.0
                else:
                    verdict = "BENIGN"
                    score = 0.0

                return ThreatIntelResult(
                    provider=self.name,
                    indicator=indicator,
                    indicator_type=indicator_type.value,
                    verdict=verdict,
                    score=score,
                    categories=categories[:10],
                    raw_result={"pulse_count": pulse_count},
                    expires_at=datetime.utcnow() + timedelta(hours=settings.THREAT_INTEL_CACHE_HOURS)
                )

        except httpx.TimeoutException:
            logger.warning(f"AlienVault OTX query timed out for {indicator}.")
            return None
        except Exception as e:
            logger.error(f"AlienVault OTX query failed for {indicator}: {e}")
            return None
