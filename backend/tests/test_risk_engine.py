import pytest
from datetime import datetime
from fastapi.testclient import TestClient

from app.main import app
from app.db.repositories.risk_repository import RiskRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.threat_intel_repository import ThreatIntelRepository
from app.schemas.risk import RiskLevel
from app.schemas.normalized import ObservationType
from app.schemas.correlation import CorrelationStrength
from app.services.risk_engine import RiskEngine

client = TestClient(app)

def test_risk_engine_low_tier_benign_case():
    """Verify clean or minimal observation case deterministically results in LOW risk."""
    risk_repo = RiskRepository()
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    threat_repo = ThreatIntelRepository()

    case_id = "test-case-risk-low-001"
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
    threat_repo.collection.delete_many({"case_id": case_id})

    # Only ordinary benign package and single permission
    obs_repo.insert_one({
        "observation_id": "obs-pkg-low",
        "case_id": case_id,
        "indicator_id": "ind-pkg-low",
        "evidence_id": "ev-apk-low",
        "observation_type": ObservationType.PACKAGE_NAME.value,
        "source": "APK",
        "value": "com.simple.calculator"
    })

    assessment = RiskEngine.assess(
        case_id,
        risk_repo=risk_repo,
        obs_repo=obs_repo,
        corr_repo=corr_repo,
        threat_repo=threat_repo
    )

    assert assessment.risk_level == RiskLevel.LOW
    assert assessment.evidence_strength == "MODERATE" or assessment.evidence_strength == "WEAK"
    assert assessment.confidence <= 0.70
    assert "LOW Risk" in assessment.summary
    assert len(assessment.possible_interpretations) > 0
    assert len(assessment.uncertainty) > 0

    # Cleanup
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})


def test_risk_engine_medium_tier_static_anomalies():
    """Verify static suspicious permissions + APIs elevate score into MEDIUM risk without network corroboration."""
    risk_repo = RiskRepository()
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    threat_repo = ThreatIntelRepository()

    case_id = "test-case-risk-med-002"
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
    threat_repo.collection.delete_many({"case_id": case_id})

    ev_id = "ev-apk-med"

    # Privileged permissions (5 pts each, cap 15)
    for perm in ["android.permission.SEND_SMS", "android.permission.RECORD_AUDIO", "android.permission.RECEIVE_BOOT_COMPLETED"]:
        obs_repo.insert_one({
            "observation_id": f"obs-perm-{perm}",
            "case_id": case_id,
            "indicator_id": f"ind-{perm}",
            "evidence_id": ev_id,
            "observation_type": ObservationType.SUSPICIOUS_PERMISSION.value,
            "source": "APK",
            "value": perm
        })

    # Sensitive APIs (5 pts each, cap 15)
    for api in ["dalvik/system/DexClassLoader;->loadClass", "javax/crypto/Cipher;->getInstance"]:
        obs_repo.insert_one({
            "observation_id": f"obs-api-{api}",
            "case_id": case_id,
            "indicator_id": f"ind-{api}",
            "evidence_id": ev_id,
            "observation_type": ObservationType.SUSPICIOUS_API.value,
            "source": "APK",
            "value": api
        })

    assessment = RiskEngine.assess(
        case_id,
        risk_repo=risk_repo,
        obs_repo=obs_repo,
        corr_repo=corr_repo,
        threat_repo=threat_repo
    )

    assert assessment.risk_level == RiskLevel.MEDIUM
    assert len(assessment.observed_facts) >= 5
    assert any("SEND_SMS" in fact for fact in assessment.observed_facts)
    assert any("DexClassLoader" in fact for fact in assessment.observed_facts)
    # Check that guidance is provided
    assert len(assessment.analyst_guidance) > 0

    # Cleanup
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})


def test_risk_engine_high_tier_cross_evidence_correlation():
    """Verify matching APK domain and PCAP traffic elevates score to HIGH risk."""
    risk_repo = RiskRepository()
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    threat_repo = ThreatIntelRepository()

    case_id = "test-case-risk-high-003"
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
    threat_repo.collection.delete_many({"case_id": case_id})

    # Embedded domain in APK
    obs_repo.insert_one({
        "observation_id": "obs-dom-high",
        "case_id": case_id,
        "indicator_id": "ind-dom-high",
        "evidence_id": "ev-apk-high",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "phish-portal.biz"
    })

    # DNS query in PCAP
    obs_repo.insert_one({
        "observation_id": "obs-dns-high",
        "case_id": case_id,
        "indicator_id": "ind-dom-high",
        "evidence_id": "ev-pcap-high",
        "observation_type": ObservationType.DNS_QUERY.value,
        "source": "PCAP",
        "value": "phish-portal.biz"
    })

    # Sensitive API
    obs_repo.insert_one({
        "observation_id": "obs-api-high",
        "case_id": case_id,
        "indicator_id": "ind-api-high",
        "evidence_id": "ev-apk-high",
        "observation_type": ObservationType.SUSPICIOUS_API.value,
        "source": "APK",
        "value": "Ljava/net/Socket;->connect"
    })

    # Privileged permissions
    for perm in ["android.permission.INTERNET", "android.permission.ACCESS_FINE_LOCATION"]:
        obs_repo.insert_one({
            "observation_id": f"obs-perm-{perm}",
            "case_id": case_id,
            "indicator_id": f"ind-{perm}",
            "evidence_id": "ev-apk-high",
            "observation_type": ObservationType.DECLARED_PERMISSION.value,
            "source": "APK",
            "value": perm
        })

    # Correlations: DOMAIN_MATCH (15 pts) + CAPABILITY_ACTIVITY_ALIGNMENT
    corr_repo.insert_one({
        "correlation_id": "corr-domain-high",
        "case_id": case_id,
        "source_observation_ids": ["obs-dom-high"],
        "target_observation_ids": ["obs-dns-high"],
        "relationship_type": "DOMAIN_MATCH",
        "strength": CorrelationStrength.STRONG.value,
        "reason": "Domain phish-portal.biz matches across APK and PCAP",
        "evidence_class": "CORRELATED",
        "supporting_evidence_ids": ["ev-apk-high", "ev-pcap-high"]
    })

    # Resolved IP match (20 pts)
    corr_repo.insert_one({
        "correlation_id": "corr-resolved-high",
        "case_id": case_id,
        "source_observation_ids": ["obs-dom-high"],
        "target_observation_ids": ["obs-dns-high"],
        "relationship_type": "RESOLVED_IP_MATCH",
        "strength": CorrelationStrength.STRONG.value,
        "reason": "Domain resolved to active IP in PCAP",
        "evidence_class": "CORRELATED",
        "supporting_evidence_ids": ["ev-apk-high", "ev-pcap-high"]
    })

    assessment = RiskEngine.assess(
        case_id,
        risk_repo=risk_repo,
        obs_repo=obs_repo,
        corr_repo=corr_repo,
        threat_repo=threat_repo
    )

    assert assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
    assert assessment.evidence_strength == "STRONG"
    assert assessment.confidence >= 0.85
    assert len(assessment.supporting_observation_ids) > 0
    assert len(assessment.supporting_correlation_ids) > 0
    assert len(assessment.supporting_evidence_ids) > 0

    # Cleanup
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_risk_engine_critical_tier_multi_factor_convergence():
    """Verify multi-factor convergence (resolved IP + repeated beaconing + malicious threat intel) produces CRITICAL risk."""
    risk_repo = RiskRepository()
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    threat_repo = ThreatIntelRepository()

    case_id = "test-case-risk-crit-004"
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
    threat_repo.collection.delete_many({"case_id": case_id})

    # Observations
    obs_repo.insert_one({
        "observation_id": "obs-dom-crit",
        "case_id": case_id,
        "indicator_id": "ind-dom-crit",
        "evidence_id": "ev-apk-crit",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "c2-stealer.net"
    })
    obs_repo.insert_one({
        "observation_id": "obs-rep-crit",
        "case_id": case_id,
        "indicator_id": "ind-ip-crit",
        "evidence_id": "ev-pcap-crit",
        "observation_type": ObservationType.REPEATED_COMMUNICATION.value,
        "source": "PCAP",
        "value": "185.220.101.5",
        "metadata": {"packet_count": 50, "pattern_classification": "periodic communication pattern"}
    })

    # Correlations: DOMAIN_MATCH (15) + RESOLVED_IP_MATCH (20) + PERIODIC_COMMUNICATION_MATCH (20)
    for rtype in ["DOMAIN_MATCH", "RESOLVED_IP_MATCH", "PERIODIC_COMMUNICATION_MATCH"]:
        corr_repo.insert_one({
            "correlation_id": f"corr-{rtype}",
            "case_id": case_id,
            "source_observation_ids": ["obs-dom-crit"],
            "target_observation_ids": ["obs-rep-crit"],
            "relationship_type": rtype,
            "strength": CorrelationStrength.STRONG.value,
            "reason": f"Correlation for {rtype}",
            "evidence_class": "CORRELATED",
            "supporting_evidence_ids": ["ev-apk-crit", "ev-pcap-crit"]
        })

    # Threat Intel: MALICIOUS (25 pts)
    threat_repo.insert_one({
        "threat_intel_id": "ti-crit-1",
        "case_id": case_id,
        "indicator_id": "ind-dom-crit",
        "indicator": "c2-stealer.net",
        "provider": "VirusTotal",
        "verdict": "MALICIOUS",
        "score": 98.0,
        "categories": ["Trojan-Spy"],
        "checked_at": datetime.utcnow()
    })

    assessment = RiskEngine.assess(
        case_id,
        risk_repo=risk_repo,
        obs_repo=obs_repo,
        corr_repo=corr_repo,
        threat_repo=threat_repo
    )

    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.evidence_strength == "STRONG"
    assert assessment.confidence >= 0.90
    assert "CRITICAL Risk" in assessment.summary

    # Acceptance Criteria Check: Observed evidence explicitly separated from inference
    assert len(assessment.observed_facts) > 0
    assert len(assessment.inferences) > 0
    assert len(assessment.possible_interpretations) > 0

    # Acceptance Criteria Check: Do not claim C2 as proven fact without evidence qualification
    has_qualified_c2 = any(
        "Do not claim" in interp or "consistent with" in interp or "may represent" in interp
        for interp in assessment.possible_interpretations
    )
    assert has_qualified_c2

    # Cleanup
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
    threat_repo.collection.delete_many({"case_id": case_id})


def test_determinism_of_risk_assessment():
    """Verify that multiple evaluations of identical evidence produce 100% identical risk metrics."""
    risk_repo = RiskRepository()
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    threat_repo = ThreatIntelRepository()

    case_id = "test-case-risk-det-005"
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    obs_repo.insert_one({
        "observation_id": "obs-det-1",
        "case_id": case_id,
        "indicator_id": "ind-det-1",
        "evidence_id": "ev-det-1",
        "observation_type": ObservationType.SUSPICIOUS_PERMISSION.value,
        "source": "APK",
        "value": "android.permission.RECORD_AUDIO"
    })

    a1 = RiskEngine.assess(case_id, risk_repo=risk_repo, obs_repo=obs_repo, corr_repo=corr_repo, threat_repo=threat_repo)
    a2 = RiskEngine.assess(case_id, risk_repo=risk_repo, obs_repo=obs_repo, corr_repo=corr_repo, threat_repo=threat_repo)

    assert a1.risk_level == a2.risk_level
    assert a1.confidence == a2.confidence
    assert a1.evidence_strength == a2.evidence_strength
    assert a1.category_scores == a2.category_scores

    # Cleanup
    risk_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})


def test_api_risk_endpoints():
    """Verify GET /cases/{case_id}/risk and POST /cases/{case_id}/risk/assess endpoints."""
    res = client.post("/cases", json={"name": "Risk API Case", "description": "Verify risk endpoints"})
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # Trigger assessment via POST
    res = client.post(f"/cases/{case_id}/risk/assess")
    assert res.status_code == 200
    data = res.json()
    assert "risk_level" in data
    assert "evidence_strength" in data
    assert "confidence" in data
    assert "summary" in data
    assert "observed_facts" in data
    assert "inferences" in data
    assert "possible_interpretations" in data
    assert "uncertainty" in data
    assert "analyst_guidance" in data

    # Retrieve via GET
    res = client.get(f"/cases/{case_id}/risk")
    assert res.status_code == 200
    assert res.json()["risk_level"] == data["risk_level"]
