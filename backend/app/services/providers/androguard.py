import os
import re
import zipfile
import logging
from datetime import datetime
from app.services.providers.base import APKAnalysisProvider
from app.models.analysis_run import ProviderExecutionRecord, ProviderStatus
from app.core.config import settings

logger = logging.getLogger("emit.providers.androguard")

class AndroguardProvider(APKAnalysisProvider):
    @property
    def provider_name(self) -> str:
        return "androguard"

    @property
    def version(self) -> str:
        return "4.1.4"

    def is_enabled(self) -> bool:
        return settings.ENABLE_PROVIDER_ANDROGUARD

    def is_configured(self) -> bool:
        return True

    def is_available(self) -> bool:
        try:
            from androguard.core.apk import APK
            return True
        except ImportError:
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
        if not self.is_available():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                status=ProviderStatus.UNAVAILABLE,
                error="Androguard local dependencies are not available",
                output_metadata={"tool_version": self.version}
            )

        try:
            from androguard.core.apk import APK
            apk = APK(evidence_path)

            # Metadata extraction
            package_name = apk.get_package() or ""
            app_name = apk.get_app_name() or ""
            version_name = apk.get_androidversion_name() or ""
            version_code = apk.get_androidversion_code() or ""
            min_sdk = apk.get_min_sdk_version() or ""
            target_sdk = apk.get_target_sdk_version() or ""

            # Manifest components
            permissions = list(apk.get_permissions())
            activities = list(apk.get_activities())
            services = list(apk.get_services())
            receivers = list(apk.get_receivers())
            providers = list(apk.get_providers())

            # Certificate extraction
            certs = []
            try:
                for cert in apk.get_certificates():
                    certs.append({
                        "issuer": cert.issuer.human_friendly if hasattr(cert.issuer, 'human_friendly') else str(cert.issuer),
                        "subject": cert.subject.human_friendly if hasattr(cert.subject, 'human_friendly') else str(cert.subject),
                        "serial_number": str(cert.serial_number),
                        "sha256": cert.sha256.hex() if hasattr(cert, 'sha256') and hasattr(cert.sha256, 'hex') else getattr(cert, 'sha256', '')
                    })
            except Exception as cert_err:
                logger.warning(f"Failed to extract certificates: {cert_err}")

            # Safe DEX string scanner (extracting URLs, IPs, domains from strings)
            url_pattern = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(?:/[^\s]*)?')
            ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

            urls = set()
            ips = set()
            domains = set()

            # Zip Extraction fallback to read DEX files
            dex_files = []
            try:
                with zipfile.ZipFile(evidence_path, "r") as z:
                    for name in z.namelist():
                        if name.startswith("classes") and name.endswith(".dex"):
                            dex_files.append(z.read(name))
            except Exception as zip_err:
                logger.warning(f"Zip extraction fallback failed: {zip_err}")

            for dex_bytes in dex_files:
                # Scan for ASCII strings of length 4 to 256
                curr = []
                for b in dex_bytes:
                    if 32 <= b <= 126:
                        curr.append(chr(b))
                    else:
                        if len(curr) >= 4:
                            s = "".join(curr)
                            # Match patterns
                            for url in url_pattern.findall(s):
                                urls.add(url)
                                from urllib.parse import urlparse
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    domains.add(parsed.netloc)
                            for ip in ip_pattern.findall(s):
                                ips.add(ip)
                        curr = []
                if len(curr) >= 4:
                    s = "".join(curr)
                    for url in url_pattern.findall(s):
                        urls.add(url)
                    for ip in ip_pattern.findall(s):
                        ips.add(ip)

            metadata = {
                "package_name": package_name,
                "app_name": app_name,
                "version_name": version_name,
                "version_code": version_code,
                "min_sdk": min_sdk,
                "target_sdk": target_sdk,
                "permissions": permissions,
                "activities": activities,
                "services": services,
                "receivers": receivers,
                "providers": providers,
                "certificates": certs,
                "urls": list(urls)[:100],  # cap to prevent huge sizes
                "domains": list(domains)[:100],
                "ips": list(ips)[:100]
            }

            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.COMPLETED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                output_metadata=metadata
            )
        except Exception as e:
            logger.error(f"Androguard analysis failed: {e}", exc_info=True)
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"Androguard analysis failed: {str(e)}",
                output_metadata={"tool_version": self.version}
            )
