from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_androguard_analysis_success():
    # Create mock APK details
    mock_apk = MagicMock()
    mock_apk.get_package.return_value = "com.malicious.target"
    mock_apk.get_app_name.return_value = "MalwareTarget"
    mock_apk.get_androidversion_name.return_value = "1.0.0"
    mock_apk.get_androidversion_code.return_value = "1"
    mock_apk.get_min_sdk_version.return_value = "21"
    mock_apk.get_target_sdk_version.return_value = "33"
    mock_apk.get_permissions.return_value = ["android.permission.INTERNET", "android.permission.SEND_SMS"]
    mock_apk.get_activities.return_value = ["com.malicious.target.MainActivity"]
    mock_apk.get_services.return_value = []
    mock_apk.get_receivers.return_value = []
    mock_apk.get_providers.return_value = []
    mock_apk.get_certificates.return_value = []

    # Mock Androguard APK class and DEX string scanner
    with patch("androguard.core.apk.APK", return_value=mock_apk):
        # 1. Create Case
        res = client.post("/cases", json={"name": "APK Test Case", "description": "Verify static extraction"})
        assert res.status_code == 201
        case_id = res.json()["case_id"]

        # 2. Upload valid APK
        import zipfile
        import io
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
            zip_file.writestr("AndroidManifest.xml", b"<manifest></manifest>")
            zip_file.writestr("classes.dex", b"DEX\x035\x00\x00\x00SomeStringDataHere")
        file_content = zip_buffer.getvalue()

        res = client.post(
            f"/cases/{case_id}/evidence",
            files={"file": ("target.apk", file_content, "application/octet-stream")}
        )
        assert res.status_code == 201
        evidence_id = res.json()["evidence_id"]

        # Disable other providers (MobSF, JADX, APKTool) to focus purely on Androguard's completion status
        with patch("app.services.providers.mobsf.MobSFProvider.is_enabled", return_value=False):
            with patch("app.services.providers.jadx.JADXProvider.is_enabled", return_value=False):
                with patch("app.services.providers.apktool.APKToolProvider.is_enabled", return_value=False):
                    
                    # 3. Trigger Static Analysis
                    res = client.post(f"/cases/{case_id}/evidence/{evidence_id}/analyze?analysis_type=APK")
                    assert res.status_code == 201
                    analysis_id = res.json()["analysis_id"]

                    # 4. Check run status details
                    res = client.get(f"/cases/{case_id}/analyses/{analysis_id}")
                    assert res.status_code == 200
                    run_record = res.json()
                    
                    # Verify Androguard succeeded and completed
                    assert run_record["status"] == "COMPLETED"
                    assert run_record["current_stage"] == "COMPLETED"
                    assert "androguard" in run_record["provider_results"]
                    assert run_record["provider_results"]["androguard"]["status"] == "COMPLETED"

                    # 5. Verify database Indicator records were correctly written
                    res = client.get(f"/cases/{case_id}/indicators")
                    assert res.status_code == 200
                    indicators = res.json()
                    
                    types = [ind["type"] for ind in indicators]
                    values = [ind["value"] for ind in indicators]
                    
                    assert "PACKAGE" in types
                    assert "PERMISSION" in types
                    assert "com.malicious.target" in values
                    assert "android.permission.SEND_SMS" in values

        # Cleanup Case
        client.delete(f"/cases/{case_id}")
