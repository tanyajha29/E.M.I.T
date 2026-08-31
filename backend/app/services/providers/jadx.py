from app.services.providers.base import APKAnalysisProvider
from app.models.analysis_run import ProviderExecutionRecord, ProviderStatus
from app.core.config import settings
from datetime import datetime

class JADXProvider(APKAnalysisProvider):
    @property
    def provider_name(self) -> str:
        return "jadx"

    @property
    def version(self) -> str:
        return "1.5.0"

    def is_enabled(self) -> bool:
        return settings.ENABLE_PROVIDER_JADX

    def is_configured(self) -> bool:
        return True

    def is_available(self) -> bool:
        import shutil
        return bool(shutil.which("jadx") or shutil.which("jadx.bat"))

    def analyze_apk(self, evidence_path: str) -> ProviderExecutionRecord:
        started = datetime.utcnow()
        status = ProviderStatus.RUNNING
        
        if not self.is_enabled():
            status = ProviderStatus.DISABLED
        elif not self.is_configured():
            status = ProviderStatus.NOT_CONFIGURED
        elif not self.is_available():
            status = ProviderStatus.UNAVAILABLE

        return ProviderExecutionRecord(
            provider=self.provider_name,
            provider_version=self.version,
            started_at=started if status == ProviderStatus.RUNNING else None,
            completed_at=datetime.utcnow() if status == ProviderStatus.RUNNING else None,
            status=status,
            duration=0.0,
            error="JADX executable is not available on host system" if status == ProviderStatus.UNAVAILABLE else None,
            output_metadata={
                "tool_version": self.version,
                "execution_mode": "PLACEHOLDER"
            }
        )
