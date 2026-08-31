import logging
import ipaddress
import httpx
from typing import Optional
from datetime import datetime, timedelta

from app.core.config import settings
from app.schemas.indicator import IndicatorType
from app.services.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger("emit.threat_intel.abuseipdb")

class AbuseIPDBProvider(ThreatIntelProvider):
    """
    Threat Intelligence provider for AbuseIPDB v2 API.
    """

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def is_enabled(self) -> bool:
        if settings.ENABLE_THREAT_INTEL_ABUSEIPDB is not None:
            return settings.ENABLE_THREAT_INTEL_ABUSEIPDB
        return self.is_configured()

    def is_configured(self) -> bool:
        return bool(settings.ABUSEIPDB_API_KEY and settings.ABUSEIPDB_API_KEY.strip())

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type == IndicatorType.IP

    def enrich(self, indicator: str, indicator_type: IndicatorType) -> Optional[ThreatIntelResult]:
        if not self.is_enabled():
            logger.debug(f"AbuseIPDB provider is disabled. Skipping {indicator}.")
            return None

        if not self.is_configured():
            logger.warning("AbuseIPDB is enabled but ABUSEIPDB_API_KEY is missing. Skipping.")
            return None

        if not self.supports(indicator_type):
            return None

        # Ensure IP is a valid public IP
        try:
            ip_obj = ipaddress.ip_address(indicator)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                logger.debug(f"Skipping AbuseIPDB lookup for non-public IP {indicator}.")
                return None
        except ValueError:
            return None

        api_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": settings.ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": indicator,
            "maxAgeInDays": 90,
            "verbose": True
        }

        try:
            with httpx.Client(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                response = client.get(api_url, headers=headers, params=params)

                if response.status_code == 429:
                    logger.warning(f"AbuseIPDB rate limit exceeded for {indicator}.")
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
                    logger.error(f"AbuseIPDB authentication failed (status {response.status_code}).")
                    return None

                response.raise_for_status()
                data = response.json().get("data", {})

                score = float(data.get("abuseConfidenceScore", 0))
                total_reports = data.get("totalReports", 0)
                usage_type = data.get("usageType")
                isp = data.get("isp")

                if score >= 50:
                    verdict = "MALICIOUS"
                elif score > 0 or total_reports > 0:
                    verdict = "SUSPICIOUS"
                else:
                    verdict = "BENIGN"

                categories = []
                if usage_type:
                    categories.append(str(usage_type))
                if isp:
                    categories.append(f"ISP: {isp}")

                return ThreatIntelResult(
                    provider=self.name,
                    indicator=indicator,
                    indicator_type=indicator_type.value,
                    verdict=verdict,
                    score=score,
                    categories=categories,
                    raw_result=data,
                    expires_at=datetime.utcnow() + timedelta(hours=settings.THREAT_INTEL_CACHE_HOURS)
                )

        except httpx.TimeoutException:
            logger.warning(f"AbuseIPDB query timed out for IP {indicator}.")
            return None
        except Exception as e:
            logger.error(f"AbuseIPDB query failed for IP {indicator}: {e}")
            return None
