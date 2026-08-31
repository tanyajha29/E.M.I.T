from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_evidence_signatures_validation():
    # 1. Create a case
    case_payload = {"name": "Signature Tests", "description": "Verification of magic-bytes content check"}
    res = client.post("/cases", json=case_payload)
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # 2. Try uploading invalid APK (text content renamed as .apk)
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("malicious.apk", b"This is a plain text file", "application/vnd.android.package-archive")}
    )
    assert res.status_code == 400
    assert "Invalid APK file signature" in res.json()["detail"]

    # 3. Try uploading valid APK (starts with zip PK\x03\x04)
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("legit.apk", b"PK\x03\x04Some APK Contents", "application/vnd.android.package-archive")}
    )
    assert res.status_code == 201
    legit_ev_id = res.json()["evidence_id"]

    # 4. Try uploading invalid PCAP
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("capture.pcap", b"Plain text masquerading as PCAP", "application/octet-stream")}
    )
    assert res.status_code == 400
    assert "Invalid PCAP file signature" in res.json()["detail"]

    # 5. Try uploading valid PCAP (microsecond magic bytes)
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("capture.pcap", b"\xd4\xc3\xb2\xa1Some PCAP Content", "application/octet-stream")}
    )
    assert res.status_code == 201

    # 6. Try uploading invalid PCAPNG
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("capture.pcapng", b"Plain text masquerading as PCAPNG", "application/octet-stream")}
    )
    assert res.status_code == 400
    assert "Invalid PCAPNG file signature" in res.json()["detail"]

    # 7. Try uploading valid PCAPNG (starts with b"\x0a\x0d\x0d\x0a")
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("capture.pcapng", b"\x0a\x0d\x0d\x0aSome PCAPNG Content", "application/octet-stream")}
    )
    assert res.status_code == 201

    # 8. Try uploading unsupported file type
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("image.png", b"\x89PNG\r\n\x1a\nPNG file", "image/png")}
    )
    assert res.status_code == 400
    assert "Unsupported evidence file format" in res.json()["detail"]

    # 9. Clean up database case and files
    client.delete(f"/cases/{case_id}")
