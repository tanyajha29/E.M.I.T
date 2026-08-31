import os
from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_evidence_upload_workflow():
    # 1. Create a case
    case_payload = {"name": "Case Target", "description": "Case description"}
    res = client.post("/cases", json=case_payload)
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # 2. Upload evidence file bytes
    file_content = b"PK\x03\x04Fake APK bytes payload"
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("malware.apk", file_content, "application/vnd.android.package-archive")}
    )
    assert res.status_code == 201
    evidence_data = res.json()
    assert "evidence_id" in evidence_data
    assert evidence_data["case_id"] == case_id
    assert evidence_data["file_name"] == "malware.apk"
    assert evidence_data["file_size"] == len(file_content)
    
    # Verify server calculated the hash correctly from bytes
    import hashlib
    expected_hash = hashlib.sha256(file_content).hexdigest()
    assert evidence_data["sha256"] == expected_hash
    assert os.path.exists(evidence_data["storage_path"])
    
    evidence_id = evidence_data["evidence_id"]

    # 3. Retrieve evidence using case_id
    res = client.get(f"/cases/{case_id}/evidence")
    assert res.status_code == 200
    evidence_list = res.json()
    assert len(evidence_list) == 1
    assert evidence_list[0]["evidence_id"] == evidence_id
    assert evidence_list[0]["sha256"] == expected_hash

    # 4. Try duplicate upload (must fail with HTTP 409)
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("malware.apk", file_content, "application/vnd.android.package-archive")}
    )
    assert res.status_code == 409

    # 5. Delete evidence and confirm storage cleanup
    storage_path = evidence_data["storage_path"]
    assert os.path.exists(storage_path)

    res = client.delete(f"/cases/{case_id}/evidence/{evidence_id}")
    assert res.status_code == 200
    # Check that storage file is deleted
    assert not os.path.exists(storage_path)

def test_evidence_consistency_rollback():
    # Verify that if MongoDB metadata write fails, the physical file is cleaned up
    case_payload = {"name": "Case Rollback", "description": "Case description"}
    res = client.post("/cases", json=case_payload)
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    file_content = b"PK\x03\x04Rollback file content"
    
    # Mock insert_one to fail
    with patch("app.db.repositories.evidence_repository.EvidenceRepository.insert_one", side_effect=Exception("Database write error")):
        res = client.post(
            f"/cases/{case_id}/evidence",
            files={"file": ("rollback.apk", file_content, "application/vnd.android.package-archive")}
        )
        assert res.status_code == 500
        
        # Verify that no file containing "rollback.apk" exists in the storage directory
        storage_dir = os.path.abspath("storage")
        if os.path.exists(storage_dir):
            files = os.listdir(storage_dir)
            for f in files:
                assert "rollback.apk" not in f

def test_evidence_path_traversal_safety():
    import pytest
    # Verify that a path traversal filename cannot escape the storage base directory
    case_payload = {"name": "Case Traversal", "description": "Case description"}
    res = client.post("/cases", json=case_payload)
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    file_content = b"PK\x03\x04Traversal safety content"
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("../../traversal_attempt.apk", file_content, "application/octet-stream")}
    )
    assert res.status_code == 201
    evidence_data = res.json()
    
    # Storage path should contain basename "traversal_attempt.apk", and not escape storage directory
    storage_path = evidence_data["storage_path"]
    assert "traversal_attempt.apk" in storage_path
    assert "../../" not in storage_path
    assert os.path.exists(storage_path)

    # Verify that attempting to read outside base directory throws permission error
    from app.services.storage import LocalStorageProvider
    provider = LocalStorageProvider(base_dir="storage")
    
    with pytest.raises(PermissionError):
        provider.read_file("storage/../../outside.txt")

def test_get_observations_for_case():
    case_payload = {"name": "Case Obs Test", "description": "Verify observations endpoint"}
    res = client.post("/cases", json=case_payload)
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # Insert an observation
    from app.db.repositories.observation_repository import ObservationRepository
    obs_repo = ObservationRepository()
    obs_repo.insert_one({
        "observation_id": f"obs-{case_id}-1",
        "case_id": case_id,
        "indicator_id": "ind-1",
        "evidence_id": "ev-1",
        "observation_type": "DNS_QUERY",
        "source": "PCAP",
        "value": "phish.example.com",
        "confidence": 1.0
    })

    res = client.get(f"/cases/{case_id}/observations")
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["value"] == "phish.example.com"
    assert data[0]["source"] == "PCAP"
    assert data[0]["observation_type"] == "DNS_QUERY"

    # Clean up
    obs_repo.collection.delete_many({"case_id": case_id})

