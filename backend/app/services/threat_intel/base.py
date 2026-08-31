from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field
from app.schemas.indicator import IndicatorType

class ThreatIntelResult(BaseModel):
    provider: str
    indicator: str
    indicator_type: str
    verdict: str  # "MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN"
    score: Optional[float] = None
    categories: List[str] = Field(default_factory=list)
    raw_result: Dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ThreatIntelProvider(ABC):
    """
    Common abstract interface for external threat intelligence providers.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name identifier."""
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        """Returns True if the provider is enabled via configuration."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if required credentials / keys are present."""
        pass

    @abstractmethod
    def supports(self, indicator_type: IndicatorType) -> bool:
        """Returns True if this provider can inspect the given indicator type."""
        pass

    @abstractmethod
    def enrich(self, indicator: str, indicator_type: IndicatorType) -> Optional[ThreatIntelResult]:
        """
        Enriches an indicator with external threat intelligence.
        Returns a ThreatIntelResult or None if unhandled/error.
        Must handle timeouts, rate limits, and errors gracefully.
        """
        pass
