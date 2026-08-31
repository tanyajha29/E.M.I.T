from fastapi import FastAPI, HTTPException, UploadFile, File, Depends, BackgroundTasks, Query
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List

from app.core.config import settings
from app.db.mongodb import db_helper

# Services & Schemas
from app.services.case_service import CaseService
from app.services.evidence_service import EvidenceService, DuplicateEvidenceError, CaseNotFoundError
from app.services.orchestrator import AnalysisOrchestrator, DuplicateAnalysisError
from app.schemas.case import Case, CaseCreate, CaseUpdate
from app.schemas.evidence import EvidenceFile
from app.schemas.indicator import Indicator, IndicatorCreate

# Repositories (for Indicators, Runs, and Internal validation routes)
from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.attack_repository import AttackNodeRepository, AttackEdgeRepository
from app.db.repositories.analysis_repository import APKAnalysisRepository, NetworkAnalysisRepository
from app.db.repositories.threat_intel_repository import ThreatIntelRepository
from app.db.repositories.risk_repository import RiskRepository
from app.db.repositories.report_repository import ReportRepository
from app.db.repositories.analysis_run_repository import AnalysisRunRepository

# Models (AnalysisRun)
from app.models.analysis_run import AnalysisRun

# Schemas (for Internal validation routes)
from app.schemas.observation import Observation, ObservationCreate
from app.schemas.correlation import Correlation, CorrelationCreate
from app.schemas.attack_graph import AttackNode, AttackNodeCreate, AttackEdge, AttackEdgeCreate
from app.schemas.analysis import Analysis, AnalysisCreate
from app.schemas.threat_intel import ThreatIntelligence, ThreatIntelligenceCreate
from app.schemas.risk import RiskAssessment, RiskAssessmentCreate
from app.schemas.report import Report, ReportCreate

app = FastAPI(
    title="E.M.I.T. API",
    description="Evidence-backed Mobile Investigation Tool Backend",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Services & Repositories dynamically per route or dependency injection
def get_case_service():
    return CaseService()

def get_evidence_service():
    return EvidenceService()

def get_indicator_repo():
    return IndicatorRepository()

def get_orchestrator():
    return AnalysisOrchestrator()

def get_run_repo():
    return AnalysisRunRepository()

@app.get("/health")
def health_check():
    db_ok = db_helper.check_health()
    return {
        "status": "ok" if db_ok else "degraded",
        "service": "E.M.I.T. API",
        "database": {
            "status": "connected" if db_ok else "disconnected"
        }
    }

# =====================================================================
# CASES CRUD ENDPOINTS
# =====================================================================

@app.post("/cases", response_model=Case, status_code=201)
def create_case(case_in: CaseCreate, service: CaseService = Depends(get_case_service)):
    return service.create_case(case_in)

@app.get("/cases", response_model=List[Case])
def get_all_cases(service: CaseService = Depends(get_case_service)):
    return service.get_all_cases()

@app.get("/cases/{case_id}", response_model=Case)
def get_case(case_id: str, service: CaseService = Depends(get_case_service)):
    case_obj = service.get_case(case_id)
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")
    return case_obj

@app.put("/cases/{case_id}", response_model=Case)
def update_case(case_id: str, case_in: CaseUpdate, service: CaseService = Depends(get_case_service)):
    updated_case = service.update_case(case_id, case_in)
    if not updated_case:
        raise HTTPException(status_code=404, detail="Case not found")
    return updated_case

@app.delete("/cases/{case_id}")
def delete_case(case_id: str, service: CaseService = Depends(get_case_service)):
    success = service.delete_case(case_id)
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"message": "Case deleted successfully"}

# =====================================================================
# EVIDENCE METADATA & FILES ENDPOINTS
# =====================================================================

@app.post("/cases/{case_id}/evidence", response_model=EvidenceFile, status_code=201)
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...),
    service: EvidenceService = Depends(get_evidence_service)
):
    try:
        content = await file.read()
        evidence = service.upload_evidence(
            case_id=case_id,
            file_name=file.filename or "unknown",
            file_content=content,
            mime_type=file.content_type or "application/octet-stream"
        )
        return evidence
    except CaseNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except DuplicateEvidenceError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evidence upload failed: {e}")

@app.get("/cases/{case_id}/evidence", response_model=List[EvidenceFile])
def get_all_evidence_for_case(case_id: str, service: EvidenceService = Depends(get_evidence_service)):
    return service.get_all_evidence_for_case(case_id)

@app.get("/cases/{case_id}/evidence/{evidence_id}", response_model=EvidenceFile)
def get_evidence(case_id: str, evidence_id: str, service: EvidenceService = Depends(get_evidence_service)):
    evidence = service.get_evidence(case_id, evidence_id)
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence file metadata not found")
    return evidence

@app.delete("/cases/{case_id}/evidence/{evidence_id}")
def delete_evidence(case_id: str, evidence_id: str, service: EvidenceService = Depends(get_evidence_service)):
    success = service.delete_evidence(case_id, evidence_id)
    if not success:
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return {"message": "Evidence deleted successfully"}

# =====================================================================
# INDICATORS CRUD ENDPOINTS
# =====================================================================

@app.post("/cases/{case_id}/indicators", response_model=Indicator, status_code=201)
def create_indicator(
    case_id: str, 
    indicator_in: IndicatorCreate, 
    repo: IndicatorRepository = Depends(get_indicator_repo)
):
    duplicate = repo.find_one({
        "case_id": case_id, 
        "type": indicator_in.type, 
        "normalized_value": indicator_in.normalized_value
    })
    if duplicate:
        raise HTTPException(status_code=409, detail="Indicator already exists for this case")

    indicator_data = Indicator(
        case_id=case_id,
        type=indicator_in.type,
        value=indicator_in.value,
        normalized_value=indicator_in.normalized_value,
        metadata=indicator_in.metadata
    )
    inserted = repo.insert_one(indicator_data.model_dump())
    return Indicator(**inserted)

@app.get("/cases/{case_id}/indicators", response_model=List[Indicator])
def get_indicators_for_case(case_id: str, repo: IndicatorRepository = Depends(get_indicator_repo)):
    list_dicts = repo.find_all({"case_id": case_id})
    return [Indicator(**d) for d in list_dicts]

@app.get("/cases/{case_id}/observations", response_model=List[Observation])
def get_observations_for_case(case_id: str):
    repo = ObservationRepository()
    list_dicts = repo.find_all({"case_id": case_id})
    return [Observation(**d) for d in list_dicts]

@app.get("/cases/{case_id}/correlations", response_model=List[Correlation])
def get_correlations_for_case(case_id: str):
    repo = CorrelationRepository()
    list_dicts = repo.find_all({"case_id": case_id})
    return [Correlation(**d) for d in list_dicts]

@app.get("/cases/{case_id}/graph")
def get_attack_graph_for_case(case_id: str):
    from app.services.attack_reconstructor import AttackChainReconstructor
    return AttackChainReconstructor.reconstruct(case_id)

# =====================================================================
# ANALYSIS PIPELINE & ORCHESTRATOR ENDPOINTS
# =====================================================================

@app.post("/cases/{case_id}/evidence/{evidence_id}/analyze", response_model=AnalysisRun, status_code=201)
def trigger_analysis(
    case_id: str,
    evidence_id: str,
    analysis_type: str = Query(..., pattern="^(APK|PCAP)$"),
    orchestrator: AnalysisOrchestrator = Depends(get_orchestrator),
    run_repo: AnalysisRunRepository = Depends(get_run_repo)
):
    try:
        analysis_id = orchestrator.run_analysis(case_id, evidence_id, analysis_type)
        run_record = run_repo.get_by_id(analysis_id)
        if not run_record:
            raise HTTPException(status_code=500, detail="AnalysisRun record not created")
        return AnalysisRun(**run_record)
    except DuplicateAnalysisError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed to start: {e}")

@app.get("/cases/{case_id}/analyses", response_model=List[AnalysisRun])
def get_analyses_for_case(
    case_id: str,
    run_repo: AnalysisRunRepository = Depends(get_run_repo)
):
    runs_list = run_repo.list_by_case(case_id)
    return [AnalysisRun(**r) for r in runs_list]

@app.get("/cases/{case_id}/analyses/{analysis_id}", response_model=AnalysisRun)
def get_analysis_run(
    case_id: str,
    analysis_id: str,
    run_repo: AnalysisRunRepository = Depends(get_run_repo)
):
    run_record = run_repo.get_by_id(analysis_id)
    if not run_record or run_record["case_id"] != case_id:
        raise HTTPException(status_code=404, detail="Analysis run not found")
    return AnalysisRun(**run_record)

# =====================================================================
# INTERNAL / TESTING ENDPOINTS (For Phase 2/3 Verification Only)
# =====================================================================

@app.post("/api/v1/internal/observations", response_model=Observation, status_code=201)
def create_internal_observation(obs_in: ObservationCreate):
    repo = ObservationRepository()
    obs_data = Observation(
        case_id=obs_in.case_id,
        indicator_id=obs_in.indicator_id,
        evidence_id=obs_in.evidence_id,
        observation_type=obs_in.observation_type,
        source=obs_in.source,
        value=obs_in.value,
        timestamp=obs_in.timestamp,
        metadata=obs_in.metadata
    )
    inserted = repo.insert_one(obs_data.model_dump())
    return Observation(**inserted)

@app.post("/api/v1/internal/correlations", response_model=Correlation, status_code=201)
def create_internal_correlation(corr_in: CorrelationCreate):
    repo = CorrelationRepository()
    corr_data = Correlation(
        case_id=corr_in.case_id,
        source_observation_ids=corr_in.source_observation_ids,
        target_observation_ids=corr_in.target_observation_ids,
        relationship_type=corr_in.relationship_type,
        strength=corr_in.strength,
        reason=corr_in.reason,
        supporting_evidence_ids=corr_in.supporting_evidence_ids
    )
    inserted = repo.insert_one(corr_data.model_dump())
    return Correlation(**inserted)

@app.post("/api/v1/internal/attack-nodes", response_model=AttackNode, status_code=201)
def create_internal_node(node_in: AttackNodeCreate):
    repo = AttackNodeRepository()
    node_data = AttackNode(
        case_id=node_in.case_id,
        node_type=node_in.node_type,
        label=node_in.label,
        entity_reference=node_in.entity_reference,
        metadata=node_in.metadata
    )
    inserted = repo.insert_one(node_data.model_dump())
    return AttackNode(**inserted)

@app.post("/api/v1/internal/attack-edges", response_model=AttackEdge, status_code=201)
def create_internal_edge(edge_in: AttackEdgeCreate):
    if edge_in.relationship_class in ["INFERRED", "CORRELATED"]:
        if not edge_in.supporting_evidence_ids:
            raise HTTPException(
                status_code=400, 
                detail="Inferred or Correlated edges must reference supporting evidence IDs"
            )
    repo = AttackEdgeRepository()
    edge_data = AttackEdge(
        case_id=edge_in.case_id,
        source_node_id=edge_in.source_node_id,
        target_node_id=edge_in.target_node_id,
        relationship_type=edge_in.relationship_type,
        relationship_class=edge_in.relationship_class,
        strength=edge_in.strength,
        reason=edge_in.reason,
        supporting_observation_ids=edge_in.supporting_observation_ids,
        supporting_correlation_ids=edge_in.supporting_correlation_ids,
        supporting_evidence_ids=edge_in.supporting_evidence_ids
    )
    inserted = repo.insert_one(edge_data.model_dump())
    return AttackEdge(**inserted)

@app.post("/api/v1/internal/analyses", response_model=Analysis, status_code=201)
def create_internal_analysis(analysis_in: AnalysisCreate):
    repo = APKAnalysisRepository() if analysis_in.analysis_type == "APK_STATIC" else NetworkAnalysisRepository()
    analysis_data = Analysis(
        case_id=analysis_in.case_id,
        evidence_id=analysis_in.evidence_id,
        provider=analysis_in.provider,
        provider_version=analysis_in.provider_version,
        analysis_type=analysis_in.analysis_type,
        status=analysis_in.status,
        tool_results=analysis_in.tool_results,
        normalized_summary=analysis_in.normalized_summary,
        error=analysis_in.error
    )
    inserted = repo.insert_one(analysis_data.model_dump())
    return Analysis(**inserted)

@app.get("/cases/{case_id}/threat-intel", response_model=List[ThreatIntelligence])
def get_threat_intel_for_case(case_id: str):
    repo = ThreatIntelRepository()
    records = repo.find_all({"case_id": case_id})
    return [ThreatIntelligence(**r) for r in records]

@app.post("/cases/{case_id}/threat-intel/enrich", response_model=List[ThreatIntelligence])
def trigger_case_threat_intel_enrichment(case_id: str):
    from app.services.threat_intel import ThreatIntelService
    service = ThreatIntelService()
    return service.enrich_case(case_id)

@app.post("/api/v1/internal/threat-intel", response_model=ThreatIntelligence, status_code=201)
def create_internal_threat_intel(intel_in: ThreatIntelligenceCreate):
    repo = ThreatIntelRepository()
    intel_data = ThreatIntelligence(
        case_id=intel_in.case_id,
        indicator_id=intel_in.indicator_id,
        indicator=intel_in.indicator,
        indicator_type=intel_in.indicator_type,
        provider=intel_in.provider,
        verdict=intel_in.verdict,
        score=intel_in.score,
        categories=intel_in.categories,
        raw_result=intel_in.raw_result,
        checked_at=intel_in.checked_at,
        expires_at=intel_in.expires_at,
        metadata=intel_in.metadata
    )
    inserted = repo.insert_one(intel_data.model_dump())
    return ThreatIntelligence(**inserted)

@app.get("/cases/{case_id}/risk", response_model=RiskAssessment)
def get_risk_assessment_for_case(case_id: str):
    from app.services.risk_engine import RiskEngine
    repo = RiskRepository()
    existing = repo.find_one({"case_id": case_id})
    if existing:
        return RiskAssessment(**existing)
    # Generate on demand
    return RiskEngine.assess(case_id)

@app.post("/cases/{case_id}/risk/assess", response_model=RiskAssessment)
def trigger_case_risk_assessment(case_id: str):
    from app.services.risk_engine import RiskEngine
    return RiskEngine.assess(case_id)

@app.post("/api/v1/internal/risk-assessments", response_model=RiskAssessment, status_code=201)
def create_internal_risk_assessment(risk_in: RiskAssessmentCreate):
    repo = RiskRepository()
    risk_data = RiskAssessment(
        case_id=risk_in.case_id,
        risk_level=risk_in.risk_level,
        evidence_strength=risk_in.evidence_strength,
        confidence=risk_in.confidence,
        summary=risk_in.summary,
        observed_facts=risk_in.observed_facts,
        inferences=risk_in.inferences,
        possible_interpretations=risk_in.possible_interpretations,
        uncertainty=risk_in.uncertainty,
        limitations=risk_in.limitations,
        analyst_guidance=risk_in.analyst_guidance,
        supporting_observation_ids=risk_in.supporting_observation_ids,
        supporting_correlation_ids=risk_in.supporting_correlation_ids,
        supporting_evidence_ids=risk_in.supporting_evidence_ids,
        category_scores=risk_in.category_scores,
        metadata=risk_in.metadata
    )
    inserted = repo.insert_one(risk_data.model_dump())
    return RiskAssessment(**inserted)

@app.post("/cases/{case_id}/reports/generate", response_model=Report, status_code=201)
def generate_case_report(
    case_id: str,
    format: str = Query("BOTH", description="Report format: HTML, PDF, or BOTH"),
    title: str = Query("E.M.I.T. Forensic Investigation Report", description="Custom report title")
):
    from app.services.report_generator import ReportGeneratorService
    from app.schemas.report import ReportFormat
    try:
        rep_fmt = ReportFormat(format.upper())
    except ValueError:
        rep_fmt = ReportFormat.BOTH

    try:
        report = ReportGeneratorService.generate_report(case_id=case_id, report_format=rep_fmt, title=title)
        return report
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@app.get("/cases/{case_id}/reports", response_model=List[Report])
def list_case_reports(case_id: str):
    repo = ReportRepository()
    records = repo.find_all({"case_id": case_id})
    return [Report(**r) for r in records]

@app.get("/cases/{case_id}/reports/{report_id}", response_model=Report)
def get_case_report(case_id: str, report_id: str):
    repo = ReportRepository()
    record = repo.find_one({"case_id": case_id, "report_id": report_id})
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")
    return Report(**record)

@app.get("/cases/{case_id}/reports/{report_id}/download")
def download_case_report(case_id: str, report_id: str, format: str = Query("html")):
    import os
    repo = ReportRepository()
    record = repo.find_one({"case_id": case_id, "report_id": report_id})
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")

    fmt = format.lower()
    if fmt == "pdf":
        file_path = record.get("pdf_path")
        media_type = "application/pdf"
        filename = f"report_{case_id[:8]}_{report_id[:8]}.pdf"
    else:
        file_path = record.get("html_path")
        media_type = "text/html"
        filename = f"report_{case_id[:8]}_{report_id[:8]}.html"

    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Report file in {format.upper()} format not available on disk")

    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=filename
    )

@app.post("/api/v1/internal/reports", response_model=Report, status_code=201)
def create_internal_report(report_in: ReportCreate):
    repo = ReportRepository()
    report_data = Report(
        case_id=report_in.case_id,
        report_type=report_in.report_type,
        storage_path=report_in.storage_path,
        status=report_in.status
    )
    inserted = repo.insert_one(report_data.model_dump())
    return Report(**inserted)
