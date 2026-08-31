import os
import logging
from datetime import datetime
import httpx
from app.services.providers.base import APKAnalysisProvider
from app.models.analysis_run import ProviderExecutionRecord, ProviderStatus
from app.core.config import settings

logger = logging.getLogger("emit.providers.mobsf")

class MobSFProvider(APKAnalysisProvider):
    @property
    def provider_name(self) -> str:
        return "mobsf"

    @property
    def version(self) -> str:
        return "3.5"

    def is_enabled(self) -> bool:
        return settings.ENABLE_PROVIDER_MOBSF

    def is_configured(self) -> bool:
        return bool(settings.MOBSF_URL and settings.MOBSF_API_KEY)

    def is_available(self) -> bool:
        if not self.is_configured():
            return False
        try:
            # Check if MobSF container is up by pinging the root endpoint
            res = httpx.get(settings.MOBSF_URL, timeout=2.0)
            return res.status_code in [200, 302, 401, 403]
        except Exception:
            return False

    def analyze_apk(self, evidence_path: str) -> ProviderExecutionRecord:
        started = datetime.utcnow()
        if not self.is_enabled():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                status=ProviderStatus.DISABLED,
                output_metadata={"tool_version": self.version}
            )
        if not self.is_configured():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                status=ProviderStatus.NOT_CONFIGURED,
                error="MobSF settings (URL or API Key) are not configured",
                output_metadata={"tool_version": self.version}
            )
        if not self.is_available():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                status=ProviderStatus.UNAVAILABLE,
                error="MobSF analysis service is not online or reachable",
                output_metadata={"tool_version": self.version}
            )

        headers = {"Authorization": settings.MOBSF_API_KEY}
        try:
            # 1. Upload APK to MobSF
            file_name = os.path.basename(evidence_path)
            with open(evidence_path, "rb") as f:
                files = {"file": (file_name, f, "application/octet-stream")}
                logger.info(f"Uploading APK {file_name} to MobSF at {settings.MOBSF_URL}...")
                upload_res = httpx.post(
                    f"{settings.MOBSF_URL}/api/v1/upload",
                    headers=headers,
                    files=files,
                    timeout=30.0
                )

            if upload_res.status_code != 200:
                raise RuntimeError(f"Upload failed: status code {upload_res.status_code}, response: {upload_res.text}")

            upload_data = upload_res.json()
            mobsf_hash = upload_data.get("hash")
            temp_name = upload_data.get("temp_name")
            if not mobsf_hash or not temp_name:
                raise KeyError(f"Missing hash or temp_name in upload response: {upload_data}")

            # 2. Trigger Scan
            logger.info(f"Triggering MobSF Scan for hash {mobsf_hash}...")
            scan_payload = {"hash": mobsf_hash, "temp_name": temp_name}
            scan_res = httpx.post(
                f"{settings.MOBSF_URL}/api/v1/scan",
                headers=headers,
                data=scan_payload,
                timeout=60.0
            )

            if scan_res.status_code != 200:
                raise RuntimeError(f"Scan trigger failed: status code {scan_res.status_code}, response: {scan_res.text}")

            # 3. Request JSON Report
            logger.info(f"Retrieving MobSF JSON report for hash {mobsf_hash}...")
            report_payload = {"hash": mobsf_hash}
            report_res = httpx.post(
                f"{settings.MOBSF_URL}/api/v1/report_json",
                headers=headers,
                data=report_payload,
                timeout=30.0
            )

            if report_res.status_code != 200:
                raise RuntimeError(f"Failed to retrieve report: status {report_res.status_code}")

            report_data = report_res.json()

            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.COMPLETED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                output_metadata=report_data
            )

        except Exception as e:
            logger.error(f"MobSF analysis run failed: {e}", exc_info=True)
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"MobSF call failed: {str(e)}",
                output_metadata={"tool_version": self.version}
            )
