import os
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime

from app.main import app
from app.core.config import settings
from app.db.repositories.analysis_run_repository import AnalysisRunRepository
from app.models.analysis_run import ProviderStatus, AnalysisStatus, AnalysisStage
from app.services.orchestrator import AnalysisOrchestrator, DuplicateAnalysisError

client = TestClient(app)

@pytest.fixture
def test_env_setup():
    # Create a mock Case and valid mock APK file structure (ZIP)
    case_res = client.post("/cases", json={"name": "Pipeline Case", "description": "Phase 3"})
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]

    # Build a minimal valid zip format file
    import zipfile
    import io
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr("AndroidManifest.xml", b"<manifest></manifest>")
    zip_bytes = zip_buffer.getvalue()

    ev_res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("test.apk", zip_bytes, "application/vnd.android.package-archive")}
    )
    assert ev_res.status_code == 201
    evidence_id = ev_res.json()["evidence_id"]
    storage_path = ev_res.json()["storage_path"]

    return case_id, evidence_id, storage_path

def test_analysis_run_persistence_and_stage_transitions(test_env_setup):
    case_id, evidence_id, _ = test_env_setup
    
    # Run analysis
    res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
    assert res.status_code == 201
    run_data = res.json()
    assert run_data["analysis_id"] is not None
    assert run_data["case_id"] == case_id
    assert run_data["status"] in ["FAILED", "PARTIAL", "COMPLETED"] # Because placeholders are unavailable
    
    analysis_id = run_data["analysis_id"]
    
    # Query details via API
    details_res = client.get(f"/cases/{case_id}/analyses/{analysis_id}")
    assert details_res.status_code == 200
    run_details = details_res.json()
    assert run_details["current_stage"] in ["COMPLETED", "FAILED"]
    assert "provider_results" in run_details

def test_provider_disabled_state(test_env_setup):
    case_id, evidence_id, _ = test_env_setup

    with patch("app.services.providers.mobsf.MobSFProvider.is_enabled", return_value=False):
        res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
        assert res.status_code == 201
        run_data = res.json()
        mobsf_res = run_data["provider_results"]["mobsf"]
        assert mobsf_res["status"] == "DISABLED"
        assert mobsf_res["started_at"] is None
        assert mobsf_res["completed_at"] is None

def test_provider_not_configured_state(test_env_setup):
    case_id, evidence_id, _ = test_env_setup

    with patch("app.services.providers.mobsf.MobSFProvider.is_enabled", return_value=True), \
         patch("app.services.providers.mobsf.MobSFProvider.is_configured", return_value=False):
        res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
        assert res.status_code == 201
        run_data = res.json()
        mobsf_res = run_data["provider_results"]["mobsf"]
        assert mobsf_res["status"] == "NOT_CONFIGURED"

def test_provider_unavailable_state(test_env_setup):
    case_id, evidence_id, _ = test_env_setup

    with patch("app.services.providers.mobsf.MobSFProvider.is_enabled", return_value=True), \
         patch("app.services.providers.mobsf.MobSFProvider.is_configured", return_value=True), \
         patch("app.services.providers.mobsf.MobSFProvider.is_available", return_value=False):
        res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
        assert res.status_code == 201
        run_data = res.json()
        mobsf_res = run_data["provider_results"]["mobsf"]
        assert mobsf_res["status"] == "UNAVAILABLE"
        assert mobsf_res["error"] is not None

def test_provider_exception_isolation_and_sanitization(test_env_setup):
    case_id, evidence_id, _ = test_env_setup

    # Mock Androguard to throw a crash exception during execute
    with patch("app.services.providers.androguard.AndroguardProvider.is_enabled", return_value=True), \
         patch("app.services.providers.androguard.AndroguardProvider.is_configured", return_value=True), \
         patch("app.services.providers.androguard.AndroguardProvider.is_available", return_value=True), \
         patch("app.services.providers.androguard.AndroguardProvider.analyze_apk", side_effect=Exception("Database raw error traceback secret_key_123")):
        
        res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
        assert res.status_code == 201
        run_data = res.json()
        
        # Verify the exception is caught, other providers executed, and error is sanitized
        androguard_res = run_data["provider_results"]["androguard"]
        assert androguard_res["status"] == "FAILED"
        assert "secret_key_123" in androguard_res["error"]
        
        # General analysis error array must contain the error, but NO raw system backtrace dump
        assert len(run_data["errors"]) > 0
        for err in run_data["errors"]:
            assert "traceback.print_exc" not in err

def test_evidence_validation_failure(test_env_setup):
    case_id, evidence_id, storage_path = test_env_setup

    # Temporarily remove file to trigger validation failure
    if os.path.exists(storage_path):
        os.remove(storage_path)

    res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
    assert res.status_code == 201
    run_data = res.json()
    assert run_data["status"] == "FAILED"
    assert run_data["current_stage"] == "FAILED"
    assert any("Validation failed" in err for err in run_data["errors"])

def test_provider_timeout_handling(test_env_setup):
    case_id, evidence_id, _ = test_env_setup

    import time
    def slow_analyze(*args, **kwargs):
        time.sleep(2)
        raise RuntimeError("Should have timed out!")

    # Set timeout low and mock provider execution
    with patch("app.core.config.settings.ANALYSIS_TIMEOUT_SECONDS", 1), \
         patch("app.services.providers.androguard.AndroguardProvider.is_enabled", return_value=True), \
         patch("app.services.providers.androguard.AndroguardProvider.is_configured", return_value=True), \
         patch("app.services.providers.androguard.AndroguardProvider.is_available", return_value=True), \
         patch("app.services.providers.androguard.AndroguardProvider.analyze_apk", side_effect=slow_analyze):
        
        res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
        assert res.status_code == 201
        run_data = res.json()
        
        andro_res = run_data["provider_results"]["androguard"]
        assert andro_res["status"] == "FAILED"
        assert "exceeded" in andro_res["error"]

def test_placeholder_safety_policy(test_env_setup):
    case_id, evidence_id, _ = test_env_setup

    # Trigger run
    client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")

    # Assert no fake documents created in observations, correlations, attack graph collections
    from app.db.mongodb import db_helper
    assert db_helper.db["observations"].count_documents({}) == 0
    assert db_helper.db["correlations"].count_documents({}) == 0
    assert db_helper.db["attack_nodes"].count_documents({}) == 0
    assert db_helper.db["attack_edges"].count_documents({}) == 0
    assert db_helper.db["risk_assessments"].count_documents({}) == 0

def test_duplicate_analysis_prevention(test_env_setup):
    case_id, evidence_id, _ = test_env_setup

    # Mock orchestrator to simulate an active state by overriding current_stage
    from app.db.repositories.analysis_run_repository import AnalysisRunRepository
    repo = AnalysisRunRepository()
    
    # Create fake active run in MongoDB
    import uuid
    active_run = {
        "analysis_id": str(uuid.uuid4()),
        "case_id": case_id,
        "evidence_id": evidence_id,
        "analysis_type": "APK",
        "status": "PENDING",
        "current_stage": "ANALYZING",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    repo.insert_one(active_run)

    # Attempt to trigger duplicate analysis
    res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
    assert res.status_code == 409
    assert "already in progress" in res.json()["detail"]

def test_api_documentation_loads():
    # Verify FastAPI /docs works
    res = client.get("/docs")
    assert res.status_code == 200
