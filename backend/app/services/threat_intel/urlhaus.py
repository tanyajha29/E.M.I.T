import logging
import httpx
from typing import Optional, List
from datetime import datetime, timedelta

from app.core.config import settings
from app.schemas.indicator import IndicatorType
from app.services.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger("emit.threat_intel.urlhaus")

class URLhausProvider(ThreatIntelProvider):
    """
    Threat Intelligence provider for URLhaus (abuse.ch).
    """

    @property
    def name(self) -> str:
        return "URLhaus"

    def is_enabled(self) -> bool:
        return settings.ENABLE_THREAT_INTEL_URLHAUS

    def is_configured(self) -> bool:
        # URLhaus allows public querying; key is optional
        return True

    def supports(self, indicator_type: IndicatorType) -> bool:
        return indicator_type in [
            IndicatorType.URL,
            IndicatorType.DOMAIN,
            IndicatorType.HASH
        ]

    def enrich(self, indicator: str, indicator_type: IndicatorType) -> Optional[ThreatIntelResult]:
        if not self.is_enabled():
            logger.debug(f"URLhaus provider is disabled. Skipping {indicator}.")
            return None

        if not self.supports(indicator_type):
            logger.debug(f"URLhaus does not support indicator type {indicator_type.value}.")
            return None

        headers = {}
        if settings.URLHAUS_API_KEY:
            headers["Auth-Key"] = settings.URLHAUS_API_KEY

        endpoint = ""
        payload = {}
        if indicator_type == IndicatorType.URL:
            endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
            payload = {"url": indicator}
        elif indicator_type == IndicatorType.DOMAIN:
            endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
            payload = {"host": indicator}
        elif indicator_type == IndicatorType.HASH:
            endpoint = "https://urlhaus-api.abuse.ch/v1/payload/"
            payload = {"sha256_hash": indicator}

        try:
            with httpx.Client(timeout=settings.THREAT_INTEL_TIMEOUT_SECONDS) as client:
                response = client.post(endpoint, data=payload, headers=headers)

                if response.status_code == 429:
                    logger.warning(f"URLhaus rate limit exceeded for {indicator}.")
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

                response.raise_for_status()
                data = response.json()
                status = data.get("query_status", "")

                if status == "no_results":
                    return ThreatIntelResult(
                        provider=self.name,
                        indicator=indicator,
                        indicator_type=indicator_type.value,
                        verdict="BENIGN",
                        score=0.0,
                        categories=["Not in URLhaus database"],
                        raw_result=data,
                        expires_at=datetime.utcnow() + timedelta(hours=settings.THREAT_INTEL_CACHE_HOURS)
                    )

                if status == "ok":
                    url_status = data.get("url_status", "")
                    threat = data.get("threat", "")
                    tags = data.get("tags") or []
                    if isinstance(tags, str):
                        tags = [tags]

                    verdict = "MALICIOUS" if url_status == "online" or threat else "SUSPICIOUS"
                    score = 100.0 if verdict == "MALICIOUS" else 50.0

                    categories = list(set([threat] + tags)) if threat else tags
                    categories = [str(c) for c in categories if c]

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

                return ThreatIntelResult(
                    provider=self.name,
                    indicator=indicator,
                    indicator_type=indicator_type.value,
                    verdict="UNKNOWN",
                    score=0.0,
                    categories=[],
                    raw_result=data,
                    expires_at=datetime.utcnow() + timedelta(hours=settings.THREAT_INTEL_CACHE_HOURS)
                )

        except httpx.TimeoutException:
            logger.warning(f"URLhaus query timed out for indicator {indicator}.")
            return None
        except Exception as e:
            logger.error(f"URLhaus query failed for indicator {indicator}: {e}")
            return None
