from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_case_crud_workflow():
    # 1. Create a case
    case_payload = {
        "name": "Case Trojan Zero",
        "description": "Static indicators of banking malware Trojan.APK"
    }
    response = client.post("/cases", json=case_payload)
    assert response.status_code == 201
    created_data = response.json()
    assert "case_id" in created_data
    assert created_data["name"] == "Case Trojan Zero"
    assert created_data["status"] == "OPEN"
    case_id = created_data["case_id"]

    # 2. Read the case
    response = client.get(f"/cases/{case_id}")
    assert response.status_code == 200
    read_data = response.json()
    assert read_data["case_id"] == case_id
    assert read_data["name"] == "Case Trojan Zero"

    # 3. Update the case
    update_payload = {
        "name": "Case Trojan Zero Revised",
        "status": "ANALYZING"
    }
    response = client.put(f"/cases/{case_id}", json=update_payload)
    assert response.status_code == 200
    updated_data = response.json()
    assert updated_data["name"] == "Case Trojan Zero Revised"
    assert updated_data["status"] == "ANALYZING"

    # 4. Confirm updated data by reading again
    response = client.get(f"/cases/{case_id}")
    assert response.status_code == 200
    confirmed_data = response.json()
    assert confirmed_data["name"] == "Case Trojan Zero Revised"
    assert confirmed_data["status"] == "ANALYZING"

    # 5. Delete the case
    response = client.delete(f"/cases/{case_id}")
    assert response.status_code == 200

    # 6. Confirm expected final state (404 Not Found)
    response = client.get(f"/cases/{case_id}")
    assert response.status_code == 404
