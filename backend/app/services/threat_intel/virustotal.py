import logging
import httpx
from typing import Optional, List
from datetime import datetime, timedelta

from app.core.config import settings
from app.schemas.indicator import IndicatorType
from app.services.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger("emit.threat_intel.virustotal")

class VirusTotalProvider(ThreatIntelProvider):
    """
    Threat Intelligence provider for VirusTotal v3 API.
    """

    @property
    def name(self) -> str:
        return "VirusTotal"

    def is_enabled(self) -> bool:
        if settings.ENABLE_THREAT_INTEL_VIRUSTOTAL is not None:
            return settings.ENABLE_THREAT_INTEL_VIRUSTOTAL
        return self.is_configured()

    def is_configured(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY and settings.VIRUSTOTAL_API_KEY.strip())

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in [
            IndicatorType.DOMAIN,
            IndicatorType.IP,
            IndicatorType.HASH,
            IndicatorType.URL
        ]

    def enrich(self, indicator: str, indicator_type: IndicatorType) -> Optional[ThreatIntelResult]:
        if not self.is_enabled():
            logger.debug(f"VirusTotal provider is disabled. Skipping {indicator}.")
            return None

        if not self.is_configured():
            logger.warning("VirusTotal is enabled but VIRUSTOTAL_API_KEY is missing. Skipping enrichment.")
            return None

        if not self.supports(indicator_type):
            logger.debug(f"VirusTotal does not support indicator type {indicator_type.value}.")
            return None

        url_path = ""
        if indicator_type == IndicatorType.DOMAIN:
            url_path = f"domains/{indicator}"
        elif indicator_type == IndicatorType.IP:
            url_path = f"ip_addresses/{indicator}"
        elif indicator_type == IndicatorType.HASH:
            url_path = f"files/{indicator}"
        elif indicator_type == IndicatorType.URL:
            # VT URL identifier is base64 without padding
            import base64
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            url_path = f"urls/{url_id}"

        api_url = f"https://www.virustotal.com/api/v3/{url_path}"
        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }

        try:
            with httpx.Client(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                response = client.get(api_url, headers=headers)

                if response.status_code == 404:
                    logger.info(f"VirusTotal has no record for indicator {indicator}.")
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=indicator,
                        indicator_type=indicator_type.value,
                        verdict="UNKNOWN",
                        score=0.0,
                        categories=["Not Found"],
                        raw_result={"status_code": 404, "detail": "Indicator not in VirusTotal database"},
                        expires_at=datetime.utcnow() + timedelta(hours=settings.THREAT_INTEL_CACHE_HOURS)
                    )

                if response.status_code == 429:
                    logger.warning(f"VirusTotal rate limit exceeded for indicator {indicator}.")
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=indicator,
                        indicator_type=indicator_type.value,
                        verdict="UNKNOWN",
                        score=None,
                        categories=["Rate Limited"],
                        raw_result={"status_code": 429, "detail": "Rate limit exceeded"},
                        expires_at=datetime.utcnow() + timedelta(minutes=15)
                    )

                if response.status_code in [401, 403]:
                    logger.error(f"VirusTotal authentication failed (status {response.status_code}).")
                    return None

                response.raise_for_status()
                data = response.json().get("data", {})
                attrs = data.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + suspicious + harmless + undetected

                score = float(malicious) / float(total) * 100.0 if total > 0 else 0.0

                if malicious >= 3:
                    verdict = "MALICIOUS"
                elif malicious > 0 or suspicious > 0:
                    verdict = "SUSPICIOUS"
                elif harmless > 0:
                    verdict = "BENIGN"
                else:
                    verdict = "UNKNOWN"

                categories: List[str] = []
                for cat in attrs.get("categories", {}).values():
                    if cat and cat not in categories:
                        categories.append(str(cat))

                return ThreatIntelResult(
                    provider=self.name,
                    indicator=indicator,
                    indicator_type=indicator_type.value,
                    verdict=verdict,
                    score=round(score, 2),
                    categories=categories,
                    raw_result=stats,
                    expires_at=datetime.utcnow() + timedelta(hours=settings.THREAT_INTEL_CACHE_HOURS)
                )

        except httpx.TimeoutException:
            logger.warning(f"VirusTotal query timed out for indicator {indicator}.")
            return None
        except Exception as e:
            logger.error(f"VirusTotal query failed for indicator {indicator}: {e}")
            return None
