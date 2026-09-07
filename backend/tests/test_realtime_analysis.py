import io
import zipfile
import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.models.analysis_run import ProviderStatus, AnalysisStatus, AnalysisStage, ProviderExecutionRecord
from app.services.orchestrator import AnalysisOrchestrator
from app.db.repositories.analysis_run_repository import AnalysisRunRepository
from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.evidence_repository import EvidenceRepository
from app.schemas.user import UserOut, UserRole

client = TestClient(app)

def create_valid_apk_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.emit.test'></manifest>")
        zf.writestr("classes.dex", b"dex\n035\x00DummyDexBytes")
    return buf.getvalue()

@pytest.fixture
def auth_case_evidence():
    case_res = client.post("/cases", json={"name": "Realtime Pipeline Case", "description": "Testing live progress transitions"})
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]

    apk_bytes = create_valid_apk_zip()
    ev_res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("sample_app.apk", apk_bytes, "application/vnd.android.package-archive")}
    )
    assert ev_res.status_code == 201
    evidence_id = ev_res.json()["evidence_id"]
    return case_id, evidence_id

def test_initial_analysis_run_has_pending_providers(auth_case_evidence):
    case_id, evidence_id = auth_case_evidence
    orchestrator = AnalysisOrchestrator()

    # Step 1: Initialize run via orchestrator directly without executing _process_run yet
    analysis_id, run, storage_path = orchestrator.run_analysis(case_id, evidence_id, "APK")

    repo = AnalysisRunRepository()
    saved_run = repo.get_by_id(analysis_id)

    assert saved_run is not None
    assert saved_run["status"] in [AnalysisStatus.PENDING.value, AnalysisStatus.STARTING.value]
    assert saved_run["current_stage"] in [AnalysisStage.PENDING.value, AnalysisStage.STARTING.value]
    assert saved_run["progress_percent"] == 0

    providers = saved_run.get("provider_results", {})
    assert "androguard" in providers
    assert "mobsf" in providers
    assert "jadx" in providers
    assert "apktool" in providers

    for p_name, p_rec in providers.items():
        assert p_rec["status"] == ProviderStatus.PENDING.value
        assert p_rec["message"] is not None

def test_stage_and_provider_transitions(auth_case_evidence):
    case_id, evidence_id = auth_case_evidence
    orchestrator = AnalysisOrchestrator()

    mock_record = ProviderExecutionRecord(
        provider="androguard",
        provider_version="4.1.4",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        status=ProviderStatus.COMPLETED,
        duration=1.5,
        duration_seconds=1.5,
        message="DEX bytecode parsed successfully",
        output_metadata={"package": "com.emit.test"}
    )

    mock_andro = MagicMock()
    mock_andro.version = "4.1.4"
    mock_andro.is_enabled.return_value = True
    mock_andro.is_configured.return_value = True
    mock_andro.is_available.return_value = True
    mock_andro.analyze_apk.return_value = mock_record

    def get_prov(name):
        if name == "androguard":
            return mock_andro
        m = MagicMock()
        m.version = "1.0.0"
        m.is_enabled.return_value = False
        m.is_available.return_value = False
        return m

    with patch("app.services.orchestrator.provider_registry.get_provider", side_effect=get_prov):
        analysis_id, run, storage_path = orchestrator.run_analysis(case_id, evidence_id, "APK")
        orchestrator._process_run(run, storage_path)

        repo = AnalysisRunRepository()
        finished_run = repo.get_by_id(analysis_id)
        assert finished_run["status"] == AnalysisStatus.COMPLETED.value
        assert finished_run["progress_percent"] == 100
        assert finished_run["provider_results"]["androguard"]["status"] == ProviderStatus.COMPLETED.value

def test_partial_status_on_single_provider_failure(auth_case_evidence):
    case_id, evidence_id = auth_case_evidence
    orchestrator = AnalysisOrchestrator()

    andro_rec = ProviderExecutionRecord(
        provider="androguard",
        provider_version="4.1.4",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        status=ProviderStatus.COMPLETED,
        duration=1.2,
        message="Manifest and DEX parsed"
    )

    mock_andro = MagicMock()
    mock_andro.version = "4.1.4"
    mock_andro.is_enabled.return_value = True
    mock_andro.is_configured.return_value = True
    mock_andro.is_available.return_value = True
    mock_andro.analyze_apk.return_value = andro_rec

    mock_mobsf = MagicMock()
    mock_mobsf.version = "4.3.0"
    mock_mobsf.is_enabled.return_value = True
    mock_mobsf.is_configured.return_value = True
    mock_mobsf.is_available.return_value = True
    mock_mobsf.analyze_apk.side_effect = Exception("Docker socket disconnected")

    def get_prov_partial(name):
        if name == "androguard":
            return mock_andro
        if name == "mobsf":
            return mock_mobsf
        m = MagicMock()
        m.version = "1.0.0"
        m.is_enabled.return_value = False
        m.is_available.return_value = False
        return m

    with patch("app.services.orchestrator.provider_registry.get_provider", side_effect=get_prov_partial):
        analysis_id, run, storage_path = orchestrator.run_analysis(case_id, evidence_id, "APK")
        orchestrator._process_run(run, storage_path)

        repo = AnalysisRunRepository()
        run_record = repo.get_by_id(analysis_id)
        assert run_record["status"] == AnalysisStatus.PARTIAL.value
        assert run_record["provider_results"]["androguard"]["status"] == ProviderStatus.COMPLETED.value
        assert run_record["provider_results"]["mobsf"]["status"] == ProviderStatus.FAILED.value
        assert "Docker socket disconnected" in run_record["provider_results"]["mobsf"]["error"]

def test_realtime_analysis_status_endpoint_idor_protection(auth_case_evidence):
    case_id, evidence_id = auth_case_evidence

    with patch("app.services.orchestrator.AnalysisOrchestrator._process_run"):
        res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
        assert res.status_code == 201
        analysis_id = res.json()["analysis_id"]

        # Valid access with assigned investigator
        status_res = client.get(f"/cases/{case_id}/analyses/{analysis_id}/status")
    assert status_res.status_code == 200
    data = status_res.json()
    assert data["analysis_id"] == analysis_id
    assert "elapsed_seconds" in data
    assert "provider_results" in data

    # Access under another unauthorized user
    other_user = UserOut(
        user_id="unauthorized-intruder",
        email="intruder@test.local",
        full_name="Unauthorized Analyst",
        role=UserRole.INVESTIGATOR,
        badge_id="INTRUDER-999",
        is_active=True,
        created_at=datetime.utcnow()
    )

    from app.core.security import get_current_user
    app.dependency_overrides[get_current_user] = lambda: other_user
    try:
        denied_res = client.get(f"/cases/{case_id}/analyses/{analysis_id}/status")
        assert denied_res.status_code in [403, 404]
    finally:
        app.dependency_overrides.pop(get_current_user, None)
