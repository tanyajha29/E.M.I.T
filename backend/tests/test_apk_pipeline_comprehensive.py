import io
import zipfile
import pytest
from datetime import datetime
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.services.providers.androguard import AndroguardProvider
from app.models.analysis_run import ProviderStatus
from app.services.orchestrator import AnalysisOrchestrator
from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.evidence_repository import EvidenceRepository

client = TestClient(app)


def create_minimal_apk_bytes():
    """Generates a valid zip structure simulating an APK with AndroidManifest.xml and classes.dex."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00DummyBinaryXmlContent")
        zf.writestr("classes.dex", b"dex\n035\x00DummyDexBytes")
    return buf.getvalue()


@pytest.fixture
def temp_case():
    case_repo = CaseRepository()
    case_id = f"test-apk-pipe-{datetime.utcnow().timestamp()}"
    case_repo.insert_one({
        "case_id": case_id,
        "name": "APK Pipeline Test Case",
        "description": "Comprehensive APK pipeline test",
        "status": "OPEN",
        "created_at": datetime.utcnow()
    })
    yield case_id
    case_repo.collection.delete_many({"case_id": case_id})
    EvidenceRepository().collection.delete_many({"case_id": case_id})


def test_apk_pipeline_valid_upload(temp_case):
    """Test valid APK upload with PK\\x03\\x04 signature and metadata extraction."""
    apk_bytes = create_minimal_apk_bytes()
    res = client.post(
        f"/cases/{temp_case}/evidence",
        files={"file": ("sample.apk", apk_bytes, "application/vnd.android.package-archive")}
    )
    assert res.status_code == 201
    data = res.json()
    assert data["file_type"] == "APK"
    assert data["sha256"] is not None
    assert data["file_size"] == len(apk_bytes)


def test_apk_pipeline_invalid_magic_bytes_rejected(temp_case):
    """Test rejection of APK files with invalid magic bytes (e.g. text/exe masquerading as .apk)."""
    fake_apk = b"MZ\x90\x00This is an executable not an APK"
    res = client.post(
        f"/cases/{temp_case}/evidence",
        files={"file": ("malicious.apk", fake_apk, "application/vnd.android.package-archive")}
    )
    assert res.status_code == 400
    assert "Invalid APK file signature" in res.json()["detail"]


def test_apk_pipeline_corrupted_zip_graceful_handling(tmp_path):
    """Test that a valid PK\\x03\\x04 zip that is corrupted does not crash the analyzer."""
    corrupted_apk_path = tmp_path / "corrupted.apk"
    # Valid ZIP header bytes followed by corrupted payload
    corrupted_apk_path.write_bytes(b"PK\x03\x04\x00\x00\x00\x00CORRUPTED_ZIP_INTERNAL_DATA_STREAM")

    provider = AndroguardProvider()
    record = provider.analyze_apk(str(corrupted_apk_path))

    assert record.provider == "androguard"
    assert record.status == ProviderStatus.FAILED
    assert record.error is not None
    assert "failed" in record.error.lower()


def test_apk_pipeline_disabled_provider_handling(tmp_path):
    """Test graceful handling when an APK provider is disabled."""
    valid_apk_path = tmp_path / "test.apk"
    valid_apk_path.write_bytes(create_minimal_apk_bytes())

    provider = AndroguardProvider()
    with patch.object(provider, "is_enabled", return_value=False):
        record = provider.analyze_apk(str(valid_apk_path))
        assert record.status == ProviderStatus.DISABLED


def test_apk_pipeline_unavailable_provider_handling(tmp_path):
    """Test graceful handling when an APK provider dependencies are missing."""
    valid_apk_path = tmp_path / "test.apk"
    valid_apk_path.write_bytes(create_minimal_apk_bytes())

    provider = AndroguardProvider()
    with patch.object(provider, "is_available", return_value=False):
        record = provider.analyze_apk(str(valid_apk_path))
        assert record.status == ProviderStatus.UNAVAILABLE
        assert "not available" in record.error.lower()
