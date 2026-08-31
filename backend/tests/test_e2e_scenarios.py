import os
import io
import zipfile
import struct
import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.evidence_repository import EvidenceRepository
from app.db.repositories.analysis_run_repository import AnalysisRunRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.threat_intel_repository import ThreatIntelRepository
from app.db.repositories.risk_repository import RiskRepository
from app.db.repositories.report_repository import ReportRepository

from app.services.correlation_engine import CorrelationEngine
from app.services.attack_reconstructor import AttackChainReconstructor
from app.services.risk_engine import RiskEngine
from app.services.report_generator import ReportGeneratorService
from app.schemas.report import ReportFormat

client = TestClient(app)


def build_synthetic_apk_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00BinaryXmlSample")
        zf.writestr("classes.dex", b"dex\n035\x00DexSampleBytes")
    return buf.getvalue()


def build_synthetic_pcap_bytes():
    return struct.pack(
        "<IHHIIII",
        0xa1b2c3d4, 2, 4, 0, 0, 65535, 1
    )


@pytest.fixture
def e2e_cleanup():
    created_case_ids = []
    yield created_case_ids

    # Teardown all test cases and dependent artifacts
    case_repo = CaseRepository()
    ev_repo = EvidenceRepository()
    run_repo = AnalysisRunRepository()
    obs_repo = ObservationRepository()
    ind_repo = IndicatorRepository()
    corr_repo = CorrelationRepository()
    threat_repo = ThreatIntelRepository()
    risk_repo = RiskRepository()
    rep_repo = ReportRepository()

    for cid in created_case_ids:
        case_repo.collection.delete_many({"case_id": cid})
        ev_repo.collection.delete_many({"case_id": cid})
        run_repo.collection.delete_many({"case_id": cid})
        obs_repo.collection.delete_many({"case_id": cid})
        ind_repo.collection.delete_many({"case_id": cid})
        corr_repo.collection.delete_many({"case_id": cid})
        threat_repo.collection.delete_many({"case_id": cid})
        risk_repo.collection.delete_many({"case_id": cid})
        rep_repo.collection.delete_many({"case_id": cid})


def test_e2e_scenario_1_suspicious_app_and_matching_pcap(e2e_cleanup):
    """
    End-to-End Test Scenario 1:
    SuspiciousApp.apk + authorized_investigation.pcap
    Expected:
    APK evidence + PCAP evidence + normalized indicators + correlations + attack graph + risk assessment + report
    """
    # 1. Register Case
    case_res = client.post("/cases", json={
        "name": "Incident #402 - Mobile Trojan Investigation",
        "description": "Authorized forensic analysis of banking trojan and network capture"
    })
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]
    e2e_cleanup.append(case_id)

    # 2. Upload SuspiciousApp.apk
    apk_content = build_synthetic_apk_bytes()
    apk_res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("SuspiciousApp.apk", apk_content, "application/vnd.android.package-archive")}
    )
    assert apk_res.status_code == 201
    apk_evidence = apk_res.json()
    apk_ev_id = apk_evidence["evidence_id"]

    # 3. Upload authorized investigation.pcap
    pcap_content = build_synthetic_pcap_bytes()
    pcap_res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("investigation.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
    )
    assert pcap_res.status_code == 201
    pcap_evidence = pcap_res.json()
    pcap_ev_id = pcap_evidence["evidence_id"]

    # 4. Ingest Observed Evidence (APK & PCAP findings)
    now = datetime.utcnow()
    obs_repo = ObservationRepository()
    ind_repo = IndicatorRepository()

    # APK Findings: suspicious permission, embedded domain, embedded IP
    obs_repo.insert_one({
        "observation_id": f"obs-perm-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-sms",
        "evidence_id": apk_ev_id,
        "observation_type": "SUSPICIOUS_PERMISSION",
        "source": "APK",
        "value": "android.permission.SEND_SMS",
        "confidence": 1.0,
        "timestamp": now - timedelta(minutes=30)
    })
    obs_repo.insert_one({
        "observation_id": f"obs-apk-dom-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-c2-dom",
        "evidence_id": apk_ev_id,
        "observation_type": "EMBEDDED_DOMAIN",
        "source": "APK",
        "value": "c2.trojanstealer.org",
        "confidence": 1.0,
        "timestamp": now - timedelta(minutes=30)
    })
    obs_repo.insert_one({
        "observation_id": f"obs-apk-ip-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-c2-ip",
        "evidence_id": apk_ev_id,
        "observation_type": "EMBEDDED_IP",
        "source": "APK",
        "value": "198.51.100.77",
        "confidence": 1.0,
        "timestamp": now - timedelta(minutes=30)
    })

    # PCAP Findings: DNS query matching c2.trojanstealer.org, repeated communication to 198.51.100.77
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-dns-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-c2-dom",
        "evidence_id": pcap_ev_id,
        "observation_type": "DNS_QUERY",
        "source": "PCAP",
        "value": "c2.trojanstealer.org",
        "confidence": 1.0,
        "timestamp": now - timedelta(minutes=20)
    })
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-ip-net-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-c2-ip",
        "evidence_id": pcap_ev_id,
        "observation_type": "NETWORK_CONNECTION",
        "source": "PCAP",
        "value": "198.51.100.77",
        "confidence": 1.0,
        "timestamp": now - timedelta(minutes=15)
    })
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-conn-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-c2-ip",
        "evidence_id": pcap_ev_id,
        "observation_type": "REPEATED_COMMUNICATION",
        "source": "PCAP",
        "value": "198.51.100.77",
        "confidence": 1.0,
        "timestamp": now - timedelta(minutes=15),
        "metadata": {"packet_count": 48, "interval": 15.0}
    })

    # 5. Normalization: extract normalized indicators
    indicators = [
        {"type": "DOMAIN", "value": "c2.trojanstealer.org", "normalized_value": "c2.trojanstealer.org"},
        {"type": "IP", "value": "198.51.100.77", "normalized_value": "198.51.100.77"},
        {"type": "PERMISSION", "value": "android.permission.SEND_SMS", "normalized_value": "android.permission.SEND_SMS"}
    ]
    for ind in indicators:
        ind_repo.insert_one({
            "indicator_id": f"ind-{ind['type']}-{case_id}",
            "case_id": case_id,
            "type": ind["type"],
            "value": ind["value"],
            "normalized_value": ind["normalized_value"],
            "created_at": now
        })

    # 6. Execute Correlation Engine
    corr_repo = CorrelationRepository()
    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo)
    assert len(correlations) >= 2, "Expected multiple deterministic correlations between matching APK and PCAP"
    rel_types = [c.relationship_type for c in correlations]
    assert "DOMAIN_MATCH" in rel_types
    assert "IP_MATCH" in rel_types

    # 7. Reconstruct Attack Chain Graph
    graph = AttackChainReconstructor.reconstruct(case_id)
    nodes = graph["nodes"]
    edges = graph["edges"]
    assert len(nodes) >= 3, "Expected Application, Domain, and IP nodes"
    assert len(edges) >= 2, "Expected evidence-backed graph edges"
    edge_types = [e["relationship_type"] for e in edges]
    assert any("EMBEDS" in t or "CONNECTS_TO" in t or "CORRELATED_WITH" in t for t in edge_types)

    # 8. Run Risk Assessment
    risk_repo = RiskRepository()
    threat_repo = ThreatIntelRepository()
    assessment = RiskEngine.assess(case_id, risk_repo=risk_repo, obs_repo=obs_repo, corr_repo=corr_repo, threat_repo=threat_repo)
    assert assessment.risk_level in ("HIGH", "CRITICAL")
    assert assessment.confidence >= 0.70
    assert len(assessment.observed_facts) >= 3
    assert len(assessment.inferences) >= 1
    assert len(assessment.uncertainty) >= 1
    assert len(assessment.analyst_guidance) >= 1

    # 9. Generate Forensic Investigation Report (Both HTML & PDF)
    report = ReportGeneratorService.generate_report(case_id, report_format=ReportFormat.BOTH)
    assert report.status.value == "COMPLETED"
    assert os.path.exists(report.html_path)
    assert os.path.exists(report.pdf_path)
    assert os.path.getsize(report.pdf_path) > 1000

    with open(report.html_path, "r", encoding="utf-8") as f:
        html_doc = f.read()
    assert "Incident #402 - Mobile Trojan Investigation" in html_doc
    assert "c2.trojanstealer.org" in html_doc
    assert "198.51.100.77" in html_doc
    assert "Observed Evidence" in html_doc
    assert "Correlated Linkages" in html_doc


def test_e2e_scenario_2_non_matching_app_and_unrelated_pcap(e2e_cleanup):
    """
    End-to-End Test Scenario 2:
    NonMatchingApp.apk + unrelated.pcap
    Expected:
    No fabricated correlation, disconnected attack graph, LOW risk level.
    """
    # 1. Register Case
    case_res = client.post("/cases", json={
        "name": "Incident #403 - Benign Unrelated Activity",
        "description": "Case with non-matching benign app and unrelated network traffic"
    })
    assert case_res.status_code == 201
    case_id = case_res.json()["case_id"]
    e2e_cleanup.append(case_id)

    # 2. Upload NonMatchingApp.apk
    apk_content = build_synthetic_apk_bytes()
    apk_res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("NonMatchingApp.apk", apk_content, "application/vnd.android.package-archive")}
    )
    assert apk_res.status_code == 201
    apk_ev_id = apk_res.json()["evidence_id"]

    # 3. Upload unrelated.pcap
    pcap_content = build_synthetic_pcap_bytes()
    pcap_res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("unrelated.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
    )
    assert pcap_res.status_code == 201
    pcap_ev_id = pcap_res.json()["evidence_id"]

    # 4. Ingest Unrelated Observations
    now = datetime.utcnow()
    obs_repo = ObservationRepository()
    ind_repo = IndicatorRepository()

    # APK Findings: Benign calculator domain and internal IP
    obs_repo.insert_one({
        "observation_id": f"obs-benign-dom-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-calc-dom",
        "evidence_id": apk_ev_id,
        "observation_type": "EMBEDDED_DOMAIN",
        "source": "APK",
        "value": "calc.internal.local",
        "confidence": 1.0,
        "timestamp": now - timedelta(days=2)
    })
    obs_repo.insert_one({
        "observation_id": f"obs-benign-ip-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-calc-ip",
        "evidence_id": apk_ev_id,
        "observation_type": "EMBEDDED_IP",
        "source": "APK",
        "value": "10.0.0.5",
        "confidence": 1.0,
        "timestamp": now - timedelta(days=2)
    })

    # PCAP Findings: Completely unrelated public weather domain and public IP
    obs_repo.insert_one({
        "observation_id": f"obs-unrelated-dom-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-weather-dom",
        "evidence_id": pcap_ev_id,
        "observation_type": "DNS_QUERY",
        "source": "PCAP",
        "value": "weather.nationalgov.example",
        "confidence": 1.0,
        "timestamp": now - timedelta(minutes=5)
    })
    obs_repo.insert_one({
        "observation_id": f"obs-unrelated-ip-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-weather-ip",
        "evidence_id": pcap_ev_id,
        "observation_type": "NETWORK_CONNECTION",
        "source": "PCAP",
        "value": "203.0.113.88",
        "confidence": 1.0,
        "timestamp": now - timedelta(minutes=5)
    })

    # 5. Execute Correlation Engine
    corr_repo = CorrelationRepository()
    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo)
    
    # CRITICAL ACCEPTANCE CRITERIA: NO FABRICATED CORRELATION
    assert len(correlations) == 0, (
        f"Expected EXACTLY ZERO correlations for unrelated APK and PCAP, but got: "
        f"{[c.relationship_type for c in correlations]}"
    )

    # 6. Reconstruct Attack Chain
    graph = AttackChainReconstructor.reconstruct(case_id)
    edges = graph["edges"]
    # Verify no cross-evidence edges link APK domain/IP to PCAP network activity
    cross_evidence_edges = [
        e for e in edges if e.get("relationship_class") in ("CORRELATED", "INFERRED")
    ]
    assert len(cross_evidence_edges) == 0, "No cross-evidence edges should exist in unrelated scenario"

    # 7. Risk Assessment must remain LOW
    risk_repo = RiskRepository()
    threat_repo = ThreatIntelRepository()
    assessment = RiskEngine.assess(case_id, risk_repo=risk_repo, obs_repo=obs_repo, corr_repo=corr_repo, threat_repo=threat_repo)
    assert assessment.risk_level == "LOW", f"Expected LOW risk for benign unrelated activity, got {assessment.risk_level}"
    assert len(assessment.inferences) == 0, "Expected zero inferences for non-correlated benign findings"

    # 8. Report Generation
    report = ReportGeneratorService.generate_report(case_id, report_format=ReportFormat.BOTH)
    assert report.status.value == "COMPLETED"
    with open(report.html_path, "r", encoding="utf-8") as f:
        html_doc = f.read()
    assert "No cross-evidence correlations established." in html_doc
    assert "LOW RISK" in html_doc
