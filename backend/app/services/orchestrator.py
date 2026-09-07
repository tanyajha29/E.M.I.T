import logging
import time
import os
import concurrent.futures
from datetime import datetime, timedelta
from uuid import uuid4

from app.core.config import settings
from app.db.repositories.analysis_run_repository import AnalysisRunRepository
from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.evidence_repository import EvidenceRepository
from app.models.analysis_run import (
    AnalysisRun, AnalysisStatus, AnalysisStage,
    ProviderExecutionRecord, ProviderStatus, AnalysisType
)
from app.services.providers.registry import provider_registry
from app.services.normalizer import EvidenceNormalizer
from app.services.correlation_engine import CorrelationEngine
from app.services.attack_reconstructor import AttackChainReconstructor
from app.services.risk_engine import RiskEngine

logger = logging.getLogger("emit.orchestrator")

class DuplicateAnalysisError(Exception):
    pass

class AnalysisOrchestrator:
    def __init__(self):
        self.run_repo = AnalysisRunRepository()
        self.case_repo = CaseRepository()
        self.evidence_repo = EvidenceRepository()

    def _validate_evidence_file(self, evidence_path: str, expected_type: str) -> None:
        if not evidence_path:
            raise ValueError("Evidence path is empty")
        if not os.path.exists(evidence_path):
            raise FileNotFoundError(f"Evidence file not found: {evidence_path}")
        if not os.access(evidence_path, os.R_OK):
            raise PermissionError(f"Evidence file not readable: {evidence_path}")
        
        # Check file naming or format
        _, ext = os.path.splitext(evidence_path.lower())
        if expected_type == "APK":
            if ext != ".apk":
                raise ValueError(f"Expected .apk file, got {ext}")
            # Basic zip file signature verification
            import zipfile
            if not zipfile.is_zipfile(evidence_path):
                raise ValueError("Evidence is not a valid zip/apk structure")
        elif expected_type == "PCAP":
            if ext not in [".pcap", ".pcapng"]:
                raise ValueError(f"Expected .pcap or .pcapng file, got {ext}")
            # Check basic magic bytes for PCAP/PCAPNG
            with open(evidence_path, "rb") as f:
                header = f.read(4)
            if header not in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x0a\x0d\x0d\x0a']:
                raise ValueError("Evidence is not a valid PCAP/PCAPNG header format")

    def run_analysis(self, case_id: str, evidence_id: str, analysis_type: str) -> str:
        # 1. Verify case and evidence exist in MongoDB
        case_dict = self.case_repo.find_one({"case_id": case_id})
        if not case_dict:
            raise ValueError(f"Case {case_id} not found")

        evidence_dict = self.evidence_repo.find_one({"case_id": case_id, "evidence_id": evidence_id})
        if not evidence_dict:
            raise ValueError(f"Evidence {evidence_id} not found in case {case_id}")

        # 2. Prevent duplicate runs: check if same evidence is already actively running
        active_runs = self.run_repo.find_all({
            "case_id": case_id,
            "evidence_id": evidence_id,
            "analysis_type": analysis_type,
            "status": {"$in": ["PENDING", "RUNNING", "PARTIAL"]}  # Check active statuses
        })
        now = datetime.utcnow()
        for r in active_runs:
            if r["current_stage"] not in ["COMPLETED", "FAILED"]:
                # Check for stale orphaned runs from a previous server restart or crash
                started_at = r.get("started_at")
                if started_at:
                    if isinstance(started_at, str):
                        try:
                            started_at = datetime.fromisoformat(started_at)
                        except Exception:
                            started_at = None
                    elif isinstance(started_at, (int, float)):
                        started_at = datetime.utcfromtimestamp(started_at)

                timeout_limit = getattr(settings, "ANALYSIS_TIMEOUT_SECONDS", 180)
                if started_at and (now - started_at).total_seconds() > timeout_limit:
                    logger.warning(f"Reaping stale analysis run {r['analysis_id']} (started {started_at})")
                    self.run_repo.complete(
                        r["analysis_id"],
                        AnalysisStatus.FAILED.value,
                        now,
                        errors=["Analysis timed out or worker was interrupted by server restart"],
                        warnings=[]
                    )
                    continue

                raise DuplicateAnalysisError(f"Analysis run already in progress for evidence {evidence_id}")

        # 3. Create AnalysisRun record in MongoDB as PENDING with all providers pre-initialized in PENDING
        analysis_id = str(uuid4())
        
        all_types = {
            "APK": ["androguard", "mobsf", "jadx", "apktool"],
            "PCAP": ["tshark", "scapy"]
        }
        
        provider_defaults = {
            "androguard": {"message": "Queued: DEX & manifest structural analysis", "mode": "HOST", "container": None},
            "mobsf": {"message": "Queued: Containerized static security scanning", "mode": "CONTAINER", "container": "emit-mobsf"},
            "jadx": {"message": "Queued: Containerized Java decompilation", "mode": "CONTAINER", "container": "emit-mobsf"},
            "apktool": {"message": "Queued: Containerized resource decoding", "mode": "CONTAINER", "container": "emit-mobsf"},
            "tshark": {"message": "Queued: Containerized packet frame dissection", "mode": "CONTAINER", "container": "emit-mobsf"},
            "scapy": {"message": "Queued: Protocol header & stream parsing", "mode": "HOST", "container": None},
        }

        initial_providers = {}
        for p_name in all_types.get(analysis_type, []):
            prov = provider_registry.get_provider(p_name)
            ver = prov.version if prov else "1.0.0"
            meta = provider_defaults.get(p_name, {"message": "Queued for analysis", "mode": "HOST", "container": None})
            initial_providers[p_name] = ProviderExecutionRecord(
                provider=p_name,
                provider_version=ver,
                status=ProviderStatus.PENDING,
                message=meta["message"],
                execution_mode=meta["mode"],
                container_name=meta["container"]
            )

        run = AnalysisRun(
            analysis_id=analysis_id,
            case_id=case_id,
            evidence_id=evidence_id,
            analysis_type=AnalysisType(analysis_type),
            status=AnalysisStatus.STARTING,
            current_stage=AnalysisStage.STARTING,
            progress_percent=0,
            provider_results=initial_providers,
            providers=initial_providers
        )
        self.run_repo.create(run.model_dump())

        # 4. Process execution (caller can run this directly or in background)
        return analysis_id, run, evidence_dict["storage_path"]

    def _process_run(self, run: AnalysisRun, evidence_path: str):
        analysis_id = run.analysis_id
        errors = []
        warnings = []
        provider_records = dict(run.provider_results or {})

        provider_messages = {
            "androguard": "Extracting manifest, permissions, and DEX opcodes...",
            "mobsf": "Running containerized static security analysis...",
            "jadx": "Decompiling classes.dex to Java source...",
            "apktool": "Disassembling APK bytecode and decoding XML resources...",
            "tshark": "Dissecting packet frames, protocols, and conversations...",
            "scapy": "Analyzing protocol headers and payload streams...",
        }

        all_types = {
            "APK": ["androguard", "mobsf", "jadx", "apktool"],
            "PCAP": ["tshark", "scapy"]
        }
        target_provider_names = all_types.get(run.analysis_type.value, [])
        total_providers = max(1, len(target_provider_names))

        # Stage 1: VALIDATING
        self.run_repo.update_stage(analysis_id, "VALIDATING", "RUNNING", progress_percent=5)
        try:
            self._validate_evidence_file(evidence_path, run.analysis_type.value)
        except Exception as e:
            logger.error(f"Validation failed for run {analysis_id}: {e}")
            sanitized_err = f"Validation failed: {str(e)}"
            self.run_repo.complete(
                analysis_id, 
                "FAILED", 
                datetime.utcnow(), 
                [sanitized_err], 
                [],
                progress_percent=100
            )
            return

        # Stage 2: ANALYZING
        self.run_repo.update_stage(analysis_id, "ANALYZING", "RUNNING", progress_percent=10)

        for idx, name in enumerate(target_provider_names):
            provider = provider_registry.get_provider(name)
            started_time = datetime.utcnow()
            base_progress = 10 + int((idx / total_providers) * 65)

            if not provider:
                record = ProviderExecutionRecord(
                    provider=name,
                    status=ProviderStatus.UNAVAILABLE,
                    message="Provider plugin not registered in engine",
                    error="Provider not found in registry"
                )
                provider_records[name] = record
                self.run_repo.update_provider_result(analysis_id, name, record.model_dump(), progress_percent=base_progress)
                warnings.append(f"Provider {name} not found")
                continue

            # Evaluate provider state semantics
            if not provider.is_enabled():
                record = ProviderExecutionRecord(
                    provider=name,
                    provider_version=provider.version,
                    status=ProviderStatus.DISABLED,
                    message="Provider disabled in configuration",
                    output_metadata={"tool_version": provider.version}
                )
                provider_records[name] = record
                self.run_repo.update_provider_result(analysis_id, name, record.model_dump(), progress_percent=base_progress)
                warnings.append(f"Provider {name} is disabled")
                continue
            elif not provider.is_configured():
                record = ProviderExecutionRecord(
                    provider=name,
                    provider_version=provider.version,
                    status=ProviderStatus.NOT_CONFIGURED,
                    message="Provider missing configuration parameters",
                    error=f"Provider {name} is not configured",
                    output_metadata={"tool_version": provider.version}
                )
                provider_records[name] = record
                self.run_repo.update_provider_result(analysis_id, name, record.model_dump(), progress_percent=base_progress)
                warnings.append(f"Provider {name} is not configured")
                continue
            elif not provider.is_available():
                record = ProviderExecutionRecord(
                    provider=name,
                    provider_version=provider.version,
                    status=ProviderStatus.UNAVAILABLE,
                    message="Provider container/binary service unavailable",
                    error=f"Provider {name} is unavailable",
                    output_metadata={"tool_version": provider.version}
                )
                provider_records[name] = record
                self.run_repo.update_provider_result(analysis_id, name, record.model_dump(), progress_percent=base_progress)
                warnings.append(f"Provider {name} is unavailable")
                continue

            # -------------------------------------------------------------
            # Active Provider Execution: Transition STARTING -> EXECUTING -> COMPLETED
            # -------------------------------------------------------------
            # Transition 1: STARTING
            exec_mode = "CONTAINER" if name in ["mobsf", "jadx", "apktool", "tshark"] else "HOST"
            container_name = "emit-mobsf" if exec_mode == "CONTAINER" else None

            starting_record = ProviderExecutionRecord(
                provider=name,
                provider_version=provider.version,
                status=ProviderStatus.STARTING,
                started_at=started_time,
                message=f"Initializing {name.upper()} execution environment...",
                execution_mode=exec_mode,
                container_name=container_name,
                output_metadata={"tool_version": provider.version}
            )
            self.run_repo.update_provider_result(analysis_id, name, starting_record.model_dump(), progress_percent=base_progress + 2)

            # Transition 2: EXECUTING
            executing_msg = provider_messages.get(name, f"Executing {name.upper()} forensic analysis...")
            executing_record = ProviderExecutionRecord(
                provider=name,
                provider_version=provider.version,
                status=ProviderStatus.EXECUTING,
                started_at=started_time,
                message=executing_msg,
                execution_mode=exec_mode,
                container_name=container_name,
                output_metadata={"tool_version": provider.version}
            )
            self.run_repo.update_provider_result(analysis_id, name, executing_record.model_dump(), progress_percent=base_progress + 5)

            # Run with timeout protection
            record = None
            start_ticks = time.time()
            
            def run_func():
                if run.analysis_type == AnalysisType.APK:
                    return provider.analyze_apk(evidence_path)
                else:
                    return provider.analyze_pcap(evidence_path)

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_func)
                try:
                    record = future.result(timeout=settings.ANALYSIS_TIMEOUT_SECONDS)
                    # Normalize successful completion
                    if record and record.status in [ProviderStatus.COMPLETED, ProviderStatus.RUNNING]:
                        record.status = ProviderStatus.COMPLETED
                        if not record.message:
                            record.message = f"{name.upper()} analysis completed successfully"
                        if record.duration is None:
                            record.duration = float(time.time() - start_ticks)
                        record.duration_seconds = record.duration
                        record.execution_mode = exec_mode
                        record.container_name = container_name
                        if not record.started_at:
                            record.started_at = started_time
                        if not record.completed_at:
                            record.completed_at = datetime.utcnow()
                except concurrent.futures.TimeoutError:
                    logger.warning(f"Provider {name} timed out for run {analysis_id}")
                    record = ProviderExecutionRecord(
                        provider=name,
                        provider_version=provider.version,
                        started_at=started_time,
                        completed_at=datetime.utcnow(),
                        status=ProviderStatus.TIMEOUT,
                        duration=float(time.time() - start_ticks),
                        duration_seconds=float(time.time() - start_ticks),
                        message=f"Provider exceeded configured timeout ({settings.ANALYSIS_TIMEOUT_SECONDS}s)",
                        error=f"Timeout of {settings.ANALYSIS_TIMEOUT_SECONDS}s exceeded",
                        execution_mode=exec_mode,
                        container_name=container_name,
                        output_metadata={"tool_version": provider.version}
                    )
                except Exception as e:
                    logger.error(f"Provider {name} crashed: {e}", exc_info=True)
                    record = ProviderExecutionRecord(
                        provider=name,
                        provider_version=provider.version,
                        started_at=started_time,
                        completed_at=datetime.utcnow(),
                        status=ProviderStatus.FAILED,
                        duration=float(time.time() - start_ticks),
                        duration_seconds=float(time.time() - start_ticks),
                        message=f"{name.upper()} process exited with an error",
                        error=f"{provider.provider_name} execution error: {str(e)}",
                        execution_mode=exec_mode,
                        container_name=container_name,
                        output_metadata={"tool_version": provider.version}
                    )

            provider_records[name] = record
            finished_progress = 10 + int(((idx + 1) / total_providers) * 65)
            self.run_repo.update_provider_result(analysis_id, name, record.model_dump(), progress_percent=finished_progress)

            if record.status == ProviderStatus.COMPLETED:
                pass
            elif record.status in [ProviderStatus.FAILED, ProviderStatus.TIMEOUT]:
                errors.append(f"Provider {name} {record.status.value.lower()}: {record.error or record.message}")
            elif record.status in [ProviderStatus.UNAVAILABLE, ProviderStatus.NOT_CONFIGURED]:
                warnings.append(f"Provider {name} not run: status is {record.status.value}")

        # Stage 3: NORMALIZING
        self.run_repo.update_stage(analysis_id, "NORMALIZING", "RUNNING", progress_percent=80)
        try:
            provider_results_dict = {k: v.model_dump() for k, v in provider_records.items()}
            normalized = EvidenceNormalizer.normalize(provider_results_dict, run.case_id, run.evidence_id)
            
            # Stage 4: CORRELATING
            self.run_repo.update_stage(analysis_id, "CORRELATING", "RUNNING", progress_percent=90)
            correlations = CorrelationEngine.correlate(normalized)
            
            # Stage 5: BUILDING_GRAPH
            self.run_repo.update_stage(analysis_id, "BUILDING_GRAPH", "RUNNING", progress_percent=95)
            attack_chain = AttackChainReconstructor.reconstruct(normalized, correlations)
            RiskEngine.assess(normalized, correlations, attack_chain)
        except Exception as e:
            logger.error(f"Normalizer/Correlation pipeline failed: {e}", exc_info=True)
            errors.append(f"Normalization stage error: {str(e)}")

        # Complete execution run and map final status
        executable_providers = [p for p in provider_records.values() if p.status not in [ProviderStatus.DISABLED, ProviderStatus.NOT_CONFIGURED, ProviderStatus.UNAVAILABLE]]
        completed_providers = [p for p in executable_providers if p.status == ProviderStatus.COMPLETED]

        if not completed_providers:
            if not executable_providers:
                final_status = AnalysisStatus.FAILED
                errors.append("No enabled/available analysis provider configured")
            else:
                final_status = AnalysisStatus.FAILED
                errors.append("No enabled analysis provider completed execution successfully")
        elif len(completed_providers) == len(executable_providers):
            final_status = AnalysisStatus.COMPLETED
        else:
            final_status = AnalysisStatus.PARTIAL

        self.run_repo.complete(analysis_id, final_status.value, datetime.utcnow(), errors, warnings, progress_percent=100)
