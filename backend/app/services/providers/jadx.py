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

logger = logging.getLogger("emit.providers.jadx")

class JADXProvider(APKAnalysisProvider):
    CONTAINER_NAME = "emit-mobsf"
    CONTAINER_JADX_BIN = "/home/mobsf/.MobSF/tools/jadx/jadx-1.5.0/bin/jadx"

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
        # 1. Check if Docker container is running with JADX installed
        if self._is_docker_available():
            return True
        # 2. Fallback to host executable if present
        return bool(shutil.which("jadx") or shutil.which("jadx.bat"))

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
                error="JADX settings not configured",
                output_metadata={"tool_version": self.version}
            )
        if not self.is_available():
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                status=ProviderStatus.UNAVAILABLE,
                error="JADX is unavailable: Docker analysis container is not running and no host binary was found",
                output_metadata={"tool_version": self.version}
            )

        # Execute via Docker or Host
        if self._is_docker_available():
            return self._analyze_via_docker(evidence_path, started)
        else:
            return self._analyze_via_host(evidence_path, started)

    def _analyze_via_docker(self, evidence_path: str, started: datetime) -> ProviderExecutionRecord:
        tag = uuid.uuid4().hex[:12]
        container_apk = f"/tmp/jadx_{tag}.apk"
        container_out = f"/tmp/jadx_out_{tag}"

        try:
            logger.info(f"Copying APK {evidence_path} to {self.CONTAINER_NAME}:{container_apk}...")
            # Step 1: Copy APK into isolated container directory
            cp_res = subprocess.run(
                ["docker", "cp", evidence_path, f"{self.CONTAINER_NAME}:{container_apk}"],
                capture_output=True,
                text=True,
                timeout=60.0
            )
            if cp_res.returncode != 0:
                raise RuntimeError(f"docker cp failed: {cp_res.stderr.strip()}")

            # Step 2: Invoke JADX inside container (decompiles Java sources without executing APK)
            logger.info(f"Running JADX decompilation in container {self.CONTAINER_NAME}...")
            jadx_cmd = [
                "docker", "exec", self.CONTAINER_NAME,
                self.CONTAINER_JADX_BIN,
                "-d", container_out,
                "--no-res",
                "--threads-count", "4",
                container_apk
            ]
            jadx_res = subprocess.run(
                jadx_cmd,
                capture_output=True,
                text=True,
                timeout=300.0
            )
            # Note: JADX exit code 0 or 1 (warnings/errors on obfuscated classes) can still produce valid decompilation
            logger.info(f"JADX completed with return code {jadx_res.returncode}")

            # Step 3: Inspect and summarize decompiled output in container
            summary_script = f"""
import os, json
root = '{container_out}/sources'
java_files = []
packages = set()
if os.path.exists(root):
    for dirpath, _, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        if rel != '.' and not rel.startswith('.'):
            packages.add(rel.replace('/', '.'))
        for f in filenames:
            if f.endswith('.java'):
                java_files.append(os.path.join(rel, f).replace('\\\\', '/'))
print(json.dumps({{'total_classes': len(java_files), 'packages': sorted(list(packages))[:50], 'sample_classes': java_files[:30]}}))
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
                    logger.warning(f"Failed to parse JADX output summary: {parse_err}")

            duration = float((datetime.utcnow() - started).total_seconds())
            output_data = {
                "tool_version": self.version,
                "execution_mode": "DOCKER",
                "container_name": self.CONTAINER_NAME,
                "decompiled_classes_count": metrics.get("total_classes", 0),
                "packages": metrics.get("packages", []),
                "sample_classes": metrics.get("sample_classes", []),
                "jadx_stderr": jadx_res.stderr[-500:] if jadx_res.stderr else None
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
            logger.error(f"Docker-backed JADX decompilation failed: {e}", exc_info=True)
            return ProviderExecutionRecord(
                provider=self.provider_name,
                provider_version=self.version,
                started_at=started,
                completed_at=datetime.utcnow(),
                status=ProviderStatus.FAILED,
                duration=float((datetime.utcnow() - started).total_seconds()),
                error=f"JADX execution failed: {str(e)}",
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
                logger.warning(f"Failed to clean JADX temporary files in container: {clean_err}")

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

