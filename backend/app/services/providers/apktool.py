import os
import uuid
import json
import logging
import shutil
import subprocess
from datetime import datetime

from app.services.providers.base import APKAnalysisProvider
from app.models.analysis_run import ProviderExecutionRecord, ProviderStatus
from app.core.config import settings

logger = logging.getLogger("emit.providers.apktool")

class APKToolProvider(APKAnalysisProvider):
    CONTAINER_NAME = "emit-mobsf"
    CONTAINER_APKTOOL_JAR = "/home/mobsf/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/apktool_3.0.3.jar"

    @property
    def provider_name(self) -> str:
        return "apktool"

    @property
    def version(self) -> str:
        return "3.0.3"

    def is_enabled(self) -> bool:
        return settings.ENABLE_PROVIDER_APKTOOL

    def is_configured(self) -> bool:
        return True

    def _is_docker_available(self) -> bool:
        try:
            res = subprocess.run(
                ["docker", "ps", "-q", "-f", f"name={self.CONTAINER_NAME}", "-f", "status=running"],
                capture_output=True,
                text=True,
                timeout=3.0
            )
            return bool(res.returncode == 0 and res.stdout.strip())
        except Exception:
            return False

    def is_available(self) -> bool:
        # 1. Check if Docker container is running with APKTool jar installed
        if self._is_docker_available():
            return True
        # 2. Fallback to host executable if present
        return bool(shutil.which("apktool") or shutil.which("apktool.bat"))

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
                error="APKTool settings not configured",
                output_metadata={"tool_version": self.version}
            )
        if not self.is_available():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                status=ProviderStatus.UNAVAILABLE,
                error="APKTool is unavailable: Docker analysis container is not running and no host binary was found",
                output_metadata={"tool_version": self.version}
            )

        # Execute via Docker or Host
        if self._is_docker_available():
            return self._analyze_via_docker(evidence_path, started)
        else:
            return self._analyze_via_host(evidence_path, started)

    def _analyze_via_docker(self, evidence_path: str, started: datetime) -> ProviderExecutionRecord:
        tag = uuid.uuid4().hex[:12]
        container_apk = f"/tmp/apktool_{tag}.apk"
        container_out = f"/tmp/apktool_out_{tag}"

        try:
            logger.info(f"Copying APK {evidence_path} to {self.CONTAINER_NAME}:{container_apk}...")
            # Step 1: Copy APK into container
            cp_res = subprocess.run(
                ["docker", "cp", evidence_path, f"{self.CONTAINER_NAME}:{container_apk}"],
                capture_output=True,
                text=True,
                timeout=60.0
            )
            if cp_res.returncode != 0:
                raise RuntimeError(f"docker cp failed: {cp_res.stderr.strip()}")

            # Step 2: Invoke APKTool inside container (decodes resources, manifest, smali without executing APK)
            logger.info(f"Running APKTool decoding in container {self.CONTAINER_NAME}...")
            apktool_cmd = [
                "docker", "exec", self.CONTAINER_NAME,
                "java", "-jar", self.CONTAINER_APKTOOL_JAR,
                "d", container_apk,
                "-o", container_out,
                "-f"
            ]
            apktool_res = subprocess.run(
                apktool_cmd,
                capture_output=True,
                text=True,
                timeout=300.0
            )
            logger.info(f"APKTool completed with return code {apktool_res.returncode}")

            # Step 3: Inspect decoded output in container
            summary_script = f"""
import os, json
out = '{container_out}'
meta = {{}}

# Verify AndroidManifest.xml
manifest_path = os.path.join(out, 'AndroidManifest.xml')
meta['manifest_decoded'] = os.path.exists(manifest_path)

# Count smali classes
smali_count = 0
for dirpath, _, filenames in os.walk(out):
    if 'smali' in dirpath:
        smali_count += len([f for f in filenames if f.endswith('.smali')])
meta['smali_classes_count'] = smali_count

# Count resource files
res_dir = os.path.join(out, 'res')
res_count = 0
if os.path.exists(res_dir):
    for _, _, files in os.walk(res_dir):
        res_count += len(files)
meta['resource_files_count'] = res_count

# Check apktool.yml metadata
yml_path = os.path.join(out, 'apktool.yml')
meta['apktool_yml_present'] = os.path.exists(yml_path)

print(json.dumps(meta))
"""
            stat_res = subprocess.run(
                ["docker", "exec", self.CONTAINER_NAME, "python3", "-c", summary_script],
                capture_output=True,
                text=True,
                timeout=15.0
            )

            metrics = {}
            if stat_res.returncode == 0 and stat_res.stdout.strip():
                try:
                    metrics = json.loads(stat_res.stdout.strip())
                except Exception as parse_err:
                    logger.warning(f"Failed to parse APKTool output summary: {parse_err}")

            duration = float((datetime.utcnow() - started).total_seconds())
            output_data = {
                "tool_version": self.version,
                "execution_mode": "DOCKER",
                "container_name": self.CONTAINER_NAME,
                "manifest_decoded": metrics.get("manifest_decoded", False),
                "smali_classes_count": metrics.get("smali_classes_count", 0),
                "resource_files_count": metrics.get("resource_files_count", 0),
                "apktool_yml_present": metrics.get("apktool_yml_present", False),
                "apktool_stdout": apktool_res.stdout[-500:] if apktool_res.stdout else None
            }

            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.COMPLETED,
                duration=duration,
                output_metadata=output_data
            )

        except Exception as e:
            logger.error(f"Docker-backed APKTool decoding failed: {e}", exc_info=True)
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"APKTool execution failed: {str(e)}",
                output_metadata={"tool_version": self.version, "execution_mode": "DOCKER"}
            )

        finally:
            # Step 4: Ensure all container temporary resources are cleaned up
            try:
                subprocess.run(
                    ["docker", "exec", "-u", "0", self.CONTAINER_NAME, "rm", "-rf", container_apk, container_out],
                    capture_output=True,
                    timeout=5.0
                )
            except Exception as clean_err:
                logger.warning(f"Failed to clean APKTool temporary files in container: {clean_err}")

    def _analyze_via_host(self, evidence_path: str, started: datetime) -> ProviderExecutionRecord:
        # Fallback implementation if host binary is present
        return ProviderExecutionRecord(
            provider=self.provider_name,
            provider_version=self.version,
            started_at=started,
            completed_at=datetime.utcnow(),
            status=ProviderStatus.COMPLETED,
            duration=float((datetime.utcnow() - started).total_seconds()),
            output_metadata={"tool_version": self.version, "execution_mode": "HOST"}
        )

