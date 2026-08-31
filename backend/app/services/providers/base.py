from abc import ABC, abstractmethod
from app.models.analysis_run import ProviderExecutionRecord
import os

class AnalysisProvider(ABC):
    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @property
    @abstractmethod
    def provider_type(self) -> str:
        # "APK" or "PCAP"
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        pass

    @abstractmethod
    def is_enabled(self) -> bool:
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    def validate(self, evidence_path: str) -> bool:
        """Basic validation verifying if the evidence file exists and is readable."""
        if not evidence_path:
            return False
        return os.path.exists(evidence_path) and os.access(evidence_path, os.R_OK)

    def health_check(self) -> bool:
        return self.is_available()

class APKAnalysisProvider(AnalysisProvider, ABC):
    @property
    def provider_type(self) -> str:
        return "APK"

    @abstractmethod
    def analyze_apk(self, evidence_path: str) -> ProviderExecutionRecord:
        pass

class NetworkAnalysisProvider(AnalysisProvider, ABC):
    @property
    def provider_type(self) -> str:
        return "PCAP"

    @abstractmethod
    def analyze_pcap(self, evidence_path: str) -> ProviderExecutionRecord:
        pass
