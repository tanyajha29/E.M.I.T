import logging
import time
import os
import concurrent.futures
from datetime import datetime
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
        # If any run has incomplete stage, we block duplicate executions
        for r in active_runs:
            if r["current_stage"] not in ["COMPLETED", "FAILED"]:
                raise DuplicateAnalysisError(f"Analysis run already in progress for evidence {evidence_id}")

        # 3. Create AnalysisRun record in MongoDB as PENDING
        analysis_id = str(uuid4())
        run = AnalysisRun(
            analysis_id=analysis_id,
            case_id=case_id,
            evidence_id=evidence_id,
            analysis_type=AnalysisType(analysis_type),
            status=AnalysisStatus.PENDING,
            current_stage=AnalysisStage.PENDING
        )
        self.run_repo.create(run.model_dump())

        # 4. Start execution loop asynchronously or in blocking mode for sync test runs
        self._process_run(run, evidence_dict["storage_path"])
        return analysis_id

    def _process_run(self, run: AnalysisRun, evidence_path: str):
        analysis_id = run.analysis_id
        errors = []
        warnings = []
        provider_records = {}

        # Stage 1: VALIDATING
        self.run_repo.update_stage(analysis_id, "VALIDATING", "PENDING")
        try:
            self._validate_evidence_file(evidence_path, run.analysis_type.value)
        except Exception as e:
            logger.error(f"Validation failed for run {analysis_id}: {e}")
            # Ensure full trace is not written directly to user-facing database record
            sanitized_err = f"Validation failed: {str(e)}"
            self.run_repo.complete(
                analysis_id, 
                "FAILED", 
                datetime.utcnow(), 
                [sanitized_err], 
                []
            )
            return

        # Stage 2: ANALYZING
        self.run_repo.update_stage(analysis_id, "ANALYZING", "PENDING")
        
        all_types = {
            "APK": ["mobsf", "androguard", "jadx", "apktool"],
            "PCAP": ["tshark", "scapy"]
        }
        
        providers_to_evaluate = []
        for name in all_types[run.analysis_type.value]:
            p = provider_registry.get_provider(name)
            if p:
                providers_to_evaluate.append(p)

        for provider in providers_to_evaluate:
            name = provider.provider_name
            started_time = datetime.utcnow()
            
            # Evaluate provider state semantics
            if not provider.is_enabled():
                record = ProviderExecutionRecord(
                    provider=name,
                    status=ProviderStatus.DISABLED,
                    output_metadata={"tool_version": provider.version}
                )
            elif not provider.is_configured():
                record = ProviderExecutionRecord(
                    provider=name,
                    status=ProviderStatus.NOT_CONFIGURED,
                    error=f"Provider {name} is not configured",
                    output_metadata={"tool_version": provider.version}
                )
            elif not provider.is_available():
                record = ProviderExecutionRecord(
                    provider=name,
                    status=ProviderStatus.UNAVAILABLE,
                    error=f"Provider {name} is unavailable",
                    output_metadata={"tool_version": provider.version}
                )
            else:
                # Executable! Run under timeout protection
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
                    except concurrent.futures.TimeoutError:
                        logger.warning(f"Provider {name} timed out for run {analysis_id}")
                        record = ProviderExecutionRecord(
                            provider=name,
                            provider_version=provider.version,
                            started_at=started_time,
                            completed_at=datetime.utcnow(),
                            status=ProviderStatus.FAILED,
                            duration=float(time.time() - start_ticks),
                            error=f"Timeout of {settings.ANALYSIS_TIMEOUT_SECONDS}s exceeded",
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
                            error=f"{provider.provider_name} crashed: {str(e)}",
                            output_metadata={"tool_version": provider.version}
                        )

            # Persist provider-level result immediately
            provider_records[name] = record
            self.run_repo.update_provider_result(analysis_id, name, record.model_dump())

            if record.status == ProviderStatus.COMPLETED:
                pass
            elif record.status == ProviderStatus.FAILED:
                errors.append(f"Provider {name} failed: {record.error}")
            elif record.status in [ProviderStatus.UNAVAILABLE, ProviderStatus.NOT_CONFIGURED]:
                warnings.append(f"Provider {name} not run: status is {record.status.value}")

        # Stage 3: NORMALIZING
        self.run_repo.update_stage(analysis_id, "NORMALIZING", "PENDING")
        try:
            # Map provider results and invoke placeholder normalizer/correlation contracts
            provider_results_dict = {k: v.model_dump() for k, v in provider_records.items()}
            normalized = EvidenceNormalizer.normalize(provider_results_dict, run.case_id, run.evidence_id)
            
            # Invocation check of placeholders (produces zero db writes/findings)
            correlations = CorrelationEngine.correlate(normalized)
            attack_chain = AttackChainReconstructor.reconstruct(normalized, correlations)
            RiskEngine.assess(normalized, correlations, attack_chain)
        except Exception as e:
            logger.error(f"Normalizer/Correlation pipeline failed: {e}", exc_info=True)
            errors.append(f"Normalization stage error: {str(e)}")

        # Complete execution run and map final status
        executable_providers = [p for p in provider_records.values() if p.status not in [ProviderStatus.DISABLED]]
        completed_providers = [p for p in executable_providers if p.status == ProviderStatus.COMPLETED]

        if not completed_providers:
            # All executable providers failed, or none are configured/available
            final_status = AnalysisStatus.FAILED
            errors.append("No enabled/available analysis provider completed execution successfully")
        elif len(completed_providers) == len(executable_providers):
            # All ran successfully
            final_status = AnalysisStatus.COMPLETED
        else:
            # Some completed, others failed or were not available
            final_status = AnalysisStatus.PARTIAL

        self.run_repo.complete(analysis_id, final_status.value, datetime.utcnow(), errors, warnings)
