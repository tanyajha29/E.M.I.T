import os
import pytest
from datetime import datetime
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.repositories.case_repository import CaseRepository

client = TestClient(app)


@pytest.fixture
def clean_case():
    case_repo = CaseRepository()
    case_id = f"test-sec-{datetime.utcnow().timestamp()}"
    case_repo.insert_one({
        "case_id": case_id,
        "name": "Security Test Case",
        "description": "Validates boundary and security constraints",
        "status": "OPEN",
        "created_at": datetime.utcnow()
    })
    yield case_id
    case_repo.collection.delete_many({"case_id": case_id})


def test_security_unsupported_file_formats_rejected(clean_case):
    """Verifies that unsupported executable, script, or binary file formats are rejected with 400."""
    unsupported_files = [
        ("payload.exe", b"MZ\x90\x00DummyWindowsExecutable"),
        ("script.sh", b"#!/bin/bash\nrm -rf /"),
        ("exploit.bat", b"@echo off\necho pwned"),
        ("library.dll", b"MZ\x90\x00DummyDLL"),
        ("document.pdf", b"%PDF-1.4\n1 0 obj<<>>endobj")
    ]

    for filename, content in unsupported_files:
        res = client.post(
            f"/cases/{clean_case}/evidence",
            files={"file": (filename, content, "application/octet-stream")}
        )
        assert res.status_code == 400, f"Expected 400 for {filename}, got {res.status_code}"
        assert "Unsupported evidence file format" in res.json()["detail"]


def test_security_oversized_file_rejected(clean_case):
    """Verifies that uploaded files exceeding MAX_EVIDENCE_SIZE_BYTES are rejected with 400."""
    # Temporarily set max limit to 100 bytes for testing
    with patch.object(settings, "MAX_EVIDENCE_SIZE_BYTES", 100):
        oversized_content = b"PK\x03\x04" + (b"A" * 150)
        res = client.post(
            f"/cases/{clean_case}/evidence",
            files={"file": ("huge.apk", oversized_content, "application/vnd.android.package-archive")}
        )
        assert res.status_code == 400
        assert "exceeds maximum allowed limit" in res.json()["detail"]


def test_security_path_traversal_prevention(clean_case):
    """Verifies that path traversal sequences in filenames cannot escape the storage root."""
    traversal_names = [
        "../../etc/passwd.apk",
        "..\\..\\windows\\win.ini.apk",
        "nested/../../escape.apk",
        "/absolute/path/file.apk"
    ]

    for idx, bad_name in enumerate(traversal_names):
        apk_content = f"PK\x03\x04ValidHeaderWithSafeStorageContent_{idx}".encode()
        res = client.post(
            f"/cases/{clean_case}/evidence",
            files={"file": (bad_name, apk_content, "application/vnd.android.package-archive")}
        )
        assert res.status_code == 201
        data = res.json()
        storage_path = data["storage_path"]
        
        # Must not contain directory traversal sequences
        assert ".." not in storage_path
        # Must be located inside the storage directory
        assert os.path.exists(storage_path)
        assert os.path.abspath(storage_path).startswith(os.path.abspath("storage"))


def test_security_malformed_request_payload():
    """Verifies that invalid or malformed JSON payloads return 422 Unprocessable Entity."""
    # Empty case name / invalid payload
    res = client.post("/cases", json={"unknown_key": 12345})
    assert res.status_code == 422


def test_security_nonexistent_ids_return_404():
    """Verifies that requests for nonexistent case, evidence, run, or report IDs return 404."""
    nonexistent_id = "nonexistent-uuid-99999"

    # Nonexistent Case
    assert client.get(f"/cases/{nonexistent_id}").status_code == 404

    # Nonexistent Evidence
    assert client.get(f"/cases/{nonexistent_id}/evidence/nonexistent-ev-id").status_code == 404

    # Nonexistent Report Download
    assert client.get(f"/cases/{nonexistent_id}/reports/nonexistent-rep-id/download").status_code == 404


def test_security_filename_sanitization_and_relative_path_isolation(clean_case):
    """Verifies that dangerous characters in filenames are sanitized and internal host paths are not leaked."""
    dangerous_filename = 'malicious:payload*with?unsafe"chars<and>pipes|null\x00.apk'
    apk_content = b"PK\x03\x04ValidHeaderWithSafeStorageContent_DangerousName"

    res = client.post(
        f"/cases/{clean_case}/evidence",
        files={"file": (dangerous_filename, apk_content, "application/vnd.android.package-archive")}
    )
    assert res.status_code == 201
    data = res.json()
    storage_path = data["storage_path"]

    # 1. No illegal characters in storage path
    for illegal in [':', '*', '?', '"', '<', '>', '|', '\x00']:
        assert illegal not in storage_path

    # 2. Path is relative, preventing host directory leak
    assert not os.path.isabs(storage_path)
    assert "storage/" in storage_path or "storage\\" in storage_path
    assert not storage_path.startswith("C:")
    assert not storage_path.startswith("/Users")
    assert not storage_path.startswith("/home")


def test_security_api_keys_not_exposed_in_health_or_case_responses():
    """Verifies that external API keys and database credentials are never exposed via API endpoints."""
    # Health endpoint
    res_health = client.get("/health")
    assert res_health.status_code == 200
    health_text = res_health.text
    for secret_name in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "mongodb://"]:
        assert secret_name not in health_text

    # Cases endpoint
    res_cases = client.get("/cases")
    assert res_cases.status_code == 200
    cases_text = res_cases.text
    for secret_name in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY"]:
        assert secret_name not in cases_text


def test_security_tshark_uses_no_dns_resolution_flag():
    """Verifies that TsharkProvider uses the -n flag to prevent live external DNS leakage during PCAP parsing."""
    from app.services.providers.tshark import TsharkProvider
    import inspect

    source = inspect.getsource(TsharkProvider.analyze_pcap)
    assert '"-n"' in source, "Tshark command must include '-n' flag to prevent live network DNS resolution leakage"

