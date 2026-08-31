import os
import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.evidence_repository import EvidenceRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.threat_intel_repository import ThreatIntelRepository
from app.db.repositories.risk_repository import RiskRepository
from app.db.repositories.report_repository import ReportRepository
from app.schemas.report import ReportFormat, ReportStatus
from app.services.report_generator import ReportGeneratorService

client = TestClient(app)


@pytest.fixture
def populated_case():
    case_repo = CaseRepository()
    ev_repo = EvidenceRepository()
    obs_repo = ObservationRepository()
    ind_repo = IndicatorRepository()
    corr_repo = CorrelationRepository()
    threat_repo = ThreatIntelRepository()
    risk_repo = RiskRepository()
    rep_repo = ReportRepository()

    case_id = f"test-case-rep-{datetime.utcnow().timestamp()}"
    
    # 1. Case
    case_repo.insert_one({
        "case_id": case_id,
        "name": "Investigation Alpha",
        "description": "Suspicious Trojanized Banking APK",
        "status": "OPEN",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    })

    # 2. Evidence
    ev_repo.insert_one({
        "evidence_id": f"ev-apk-{case_id}",
        "case_id": case_id,
        "file_name": "trojan_bank.apk",
        "file_type": "APK",
        "mime_type": "application/vnd.android.package-archive",
        "file_size": 2048576,
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "storage_provider": "LOCAL",
        "storage_path": "storage/test.apk",
        "status": "STORED",
        "uploaded_at": datetime.utcnow(),
        "created_at": datetime.utcnow()
    })

    # 3. Observations
    obs_repo.insert_one({
        "observation_id": f"obs-perm-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-sms",
        "evidence_id": f"ev-apk-{case_id}",
        "observation_type": "SUSPICIOUS_PERMISSION",
        "source": "APK",
        "value": "android.permission.SEND_SMS",
        "confidence": 1.0,
        "timestamp": datetime.utcnow()
    })
    obs_repo.insert_one({
        "observation_id": f"obs-net-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-dom",
        "evidence_id": f"ev-apk-{case_id}",
        "observation_type": "DNS_QUERY",
        "source": "PCAP",
        "value": "c2-stealer.biz",
        "confidence": 1.0,
        "timestamp": datetime.utcnow()
    })

    # 4. Indicators
    ind_repo.insert_one({
        "indicator_id": f"ind-dom-{case_id}",
        "case_id": case_id,
        "type": "DOMAIN",
        "value": "c2-stealer.biz",
        "normalized_value": "c2-stealer.biz",
        "created_at": datetime.utcnow(),
        "metadata": {}
    })

    # 5. Correlations
    corr_repo.insert_one({
        "correlation_id": f"corr-{case_id}",
        "case_id": case_id,
        "source_observation_ids": [f"obs-perm-{case_id}"],
        "target_observation_ids": [f"obs-net-{case_id}"],
        "relationship_type": "DOMAIN_MATCH",
        "strength": "STRONG",
        "reason": "APK embedded domain matches active DNS traffic in PCAP",
        "evidence_class": "CORRELATED",
        "supporting_evidence_ids": [f"ev-apk-{case_id}"],
        "created_at": datetime.utcnow()
    })

    # 6. Threat Intel
    threat_repo.insert_one({
        "threat_intel_id": f"ti-{case_id}",
        "case_id": case_id,
        "indicator": "c2-stealer.biz",
        "indicator_type": "DOMAIN",
        "provider": "VirusTotal",
        "verdict": "MALICIOUS",
        "score": 92.0,
        "categories": ["Trojan-Banker"],
        "checked_at": datetime.utcnow(),
        "expires_at": datetime.utcnow()
    })

    yield case_id

    # Teardown
    case_repo.collection.delete_many({"case_id": case_id})
    ev_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    ind_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
    threat_repo.collection.delete_many({"case_id": case_id})
    risk_repo.collection.delete_many({"case_id": case_id})
    rep_repo.collection.delete_many({"case_id": case_id})


def test_html_report_generation_contains_all_13_sections(populated_case):
    """Verifies that generated HTML report contains all 13 required forensic sections."""
    case_id = populated_case
    report = ReportGeneratorService.generate_report(case_id, report_format=ReportFormat.HTML)
    
    assert report.status == ReportStatus.COMPLETED
    assert report.html_path is not None
    assert os.path.exists(report.html_path)

    with open(report.html_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 1. Investigation Summary
    assert "1. Investigation Summary" in content
    assert "Investigation Alpha" in content
    assert case_id in content

    # 2. Evidence Inventory
    assert "2. Evidence Inventory" in content
    assert "trojan_bank.apk" in content
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in content

    # 3. APK Analysis
    assert "3. Android APK Static Analysis Findings" in content
    assert "android.permission.SEND_SMS" in content

    # 4. Network Analysis
    assert "4. PCAP Network Traffic Analysis Findings" in content

    # 5. Indicators
    assert "5. Normalized Indicators of Compromise" in content
    assert "c2-stealer.biz" in content

    # 6. Correlations
    assert "6. Deterministic Evidence Correlations" in content
    assert "DOMAIN_MATCH" in content

    # 7. Threat Intelligence
    assert "7. External Threat Intelligence Enrichment" in content
    assert "VirusTotal" in content
    assert "MALICIOUS" in content

    # 8. Attack Chain
    assert "8. Attack Chain Reconstruction" in content

    # 9. Timeline
    assert "9. Forensic Chronological Timeline" in content

    # 10. Risk Assessment
    assert "10. Deterministic Risk Assessment" in content

    # 11. Supporting Evidence
    assert "11. Supporting Evidence Traceability" in content

    # 12. Uncertainty & Limitations
    assert "12. Technical Uncertainty & Operational Limitations" in content

    # 13. Analyst Guidance
    assert "13. Actionable Analyst Guidance" in content

    # Check forensic evidence layer separation badges
    assert "Observed Evidence" in content
    assert "Correlated Linkages" in content
    assert "External Intelligence" in content
    assert "Inferred Relationships" in content


def test_pdf_export_generation(populated_case):
    """Verifies that PDF export compiles cleanly and outputs a valid non-empty PDF file."""
    case_id = populated_case
    report = ReportGeneratorService.generate_report(case_id, report_format=ReportFormat.PDF)

    assert report.status == ReportStatus.COMPLETED
    assert report.pdf_path is not None
    assert os.path.exists(report.pdf_path)
    assert os.path.getsize(report.pdf_path) > 1000  # Non-trivial PDF size


def test_both_formats_generation(populated_case):
    """Verifies BOTH format option generates both HTML and PDF."""
    case_id = populated_case
    report = ReportGeneratorService.generate_report(case_id, report_format=ReportFormat.BOTH)

    assert os.path.exists(report.html_path)
    assert os.path.exists(report.pdf_path)


def test_report_api_endpoints(populated_case):
    """Verifies REST endpoints: generate, list, get, and download."""
    case_id = populated_case

    # POST /cases/{case_id}/reports/generate
    res = client.post(f"/cases/{case_id}/reports/generate?format=BOTH&title=Unit+Test+Report")
    assert res.status_code == 201
    data = res.json()
    assert "report_id" in data
    report_id = data["report_id"]
    assert data["status"] == "COMPLETED"

    # GET /cases/{case_id}/reports
    res = client.get(f"/cases/{case_id}/reports")
    assert res.status_code == 200
    reports_list = res.json()
    assert len(reports_list) >= 1

    # GET /cases/{case_id}/reports/{report_id}
    res = client.get(f"/cases/{case_id}/reports/{report_id}")
    assert res.status_code == 200
    assert res.json()["report_id"] == report_id

    # GET /cases/{case_id}/reports/{report_id}/download?format=html
    res = client.get(f"/cases/{case_id}/reports/{report_id}/download?format=html")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "E.M.I.T. FORENSIC INVESTIGATION REPORT" in res.text

    # GET /cases/{case_id}/reports/{report_id}/download?format=pdf
    res = client.get(f"/cases/{case_id}/reports/{report_id}/download?format=pdf")
    assert res.status_code == 200
    assert "application/pdf" in res.headers["content-type"]
    assert len(res.content) > 1000
