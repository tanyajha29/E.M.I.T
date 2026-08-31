import pytest
from datetime import datetime, timedelta

from app.services.correlation_engine import CorrelationEngine
from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.threat_intel_repository import ThreatIntelRepository


@pytest.fixture
def clean_case():
    case_repo = CaseRepository()
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    threat_repo = ThreatIntelRepository()

    case_id = f"test-corr-comp-{datetime.utcnow().timestamp()}"
    case_repo.insert_one({
        "case_id": case_id,
        "name": "Correlation Comprehensive Test",
        "description": "Validates correlation rules 1-7, negative cases, and evidence strength",
        "status": "OPEN",
        "created_at": datetime.utcnow()
    })

    yield case_id, obs_repo, corr_repo, threat_repo

    case_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
    threat_repo.collection.delete_many({"case_id": case_id})


def test_correlation_matching_and_non_matching_domain(clean_case):
    """Verifies that matching domains trigger RULE 1, while non-matching domains produce zero correlations."""
    case_id, obs_repo, corr_repo, _ = clean_case

    # 1. Non-matching domain
    obs_repo.insert_one({
        "observation_id": f"obs-apk-1-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-1",
        "evidence_id": "ev-apk-1",
        "observation_type": "EMBEDDED_DOMAIN",
        "source": "APK",
        "value": "bank-legit-app.com",
        "confidence": 1.0
    })
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-1-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-2",
        "evidence_id": "ev-pcap-1",
        "observation_type": "DNS_QUERY",
        "source": "PCAP",
        "value": "unrelated-weather-api.org",
        "confidence": 1.0
    })

    results_empty = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo)
    assert len(results_empty) == 0, "Non-matching domains must not produce correlations"

    # 2. Insert matching domain
    obs_repo.insert_one({
        "observation_id": f"obs-apk-match-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-match",
        "evidence_id": "ev-apk-1",
        "observation_type": "EMBEDDED_DOMAIN",
        "source": "APK",
        "value": "c2-stealer.biz",
        "confidence": 1.0
    })
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-match-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-match",
        "evidence_id": "ev-pcap-1",
        "observation_type": "DNS_QUERY",
        "source": "PCAP",
        "value": "c2-stealer.biz",
        "confidence": 1.0
    })

    results = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo)
    assert len(results) >= 1
    domain_corrs = [c for c in results if c.relationship_type == "DOMAIN_MATCH"]
    assert len(domain_corrs) == 1
    assert domain_corrs[0].evidence_class == "CORRELATED"
    assert "c2-stealer.biz" in domain_corrs[0].reason


def test_correlation_matching_and_non_matching_ip(clean_case):
    """Verifies that matching IPs trigger RULE 2, while non-matching IPs produce zero correlations."""
    case_id, obs_repo, corr_repo, _ = clean_case

    # Non-matching IP
    obs_repo.insert_one({
        "observation_id": f"obs-apk-ip-1-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-ip-1",
        "evidence_id": "ev-apk-1",
        "observation_type": "EMBEDDED_IP",
        "source": "APK",
        "value": "198.51.100.10",
        "confidence": 1.0
    })
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-ip-2-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-ip-2",
        "evidence_id": "ev-pcap-1",
        "observation_type": "NETWORK_CONNECTION",
        "source": "PCAP",
        "value": "203.0.113.55",
        "confidence": 1.0
    })

    res_empty = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo)
    assert len(res_empty) == 0

    # Matching IP
    obs_repo.insert_one({
        "observation_id": f"obs-apk-ip-match-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-ip-match",
        "evidence_id": "ev-apk-1",
        "observation_type": "EMBEDDED_IP",
        "source": "APK",
        "value": "185.220.101.5",
        "confidence": 1.0
    })
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-ip-match-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-ip-match",
        "evidence_id": "ev-pcap-1",
        "observation_type": "NETWORK_CONNECTION",
        "source": "PCAP",
        "value": "185.220.101.5",
        "confidence": 1.0
    })

    results = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo)
    ip_corrs = [c for c in results if c.relationship_type == "IP_MATCH"]
    assert len(ip_corrs) == 1
    assert "185.220.101.5" in ip_corrs[0].reason


def test_correlation_repeated_communication_and_temporal_alignment(clean_case):
    """Verifies that repeated communications trigger RULE 5, and timestamps within 1 hour trigger RULE 6."""
    case_id, obs_repo, corr_repo, _ = clean_case

    now = datetime.utcnow()
    t_apk = now - timedelta(minutes=15)
    t_pcap = now - timedelta(minutes=10)

    # 1. Rule 5: Embedded IP in APK matches Repeated Communication in PCAP
    obs_repo.insert_one({
        "observation_id": f"obs-apk-ip-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-ip-rep",
        "evidence_id": "ev-apk-1",
        "observation_type": "EMBEDDED_IP",
        "source": "APK",
        "value": "185.220.101.5",
        "confidence": 1.0,
        "timestamp": t_apk
    })
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-rep-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-ip-rep",
        "evidence_id": "ev-pcap-1",
        "observation_type": "REPEATED_COMMUNICATION",
        "source": "PCAP",
        "value": "185.220.101.5",
        "confidence": 1.0,
        "timestamp": t_pcap,
        "metadata": {"packet_count": 42, "interval": 30.0, "pattern_classification": "periodic beaconing"}
    })

    # 2. Rule 6: Temporal alignment on matching domain
    obs_repo.insert_one({
        "observation_id": f"obs-apk-dom-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-dom-time",
        "evidence_id": "ev-apk-1",
        "observation_type": "EMBEDDED_DOMAIN",
        "source": "APK",
        "value": "beacon-host.xyz",
        "confidence": 1.0,
        "timestamp": t_apk
    })
    obs_repo.insert_one({
        "observation_id": f"obs-pcap-dns-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-dom-time",
        "evidence_id": "ev-pcap-1",
        "observation_type": "DNS_QUERY",
        "source": "PCAP",
        "value": "beacon-host.xyz",
        "confidence": 1.0,
        "timestamp": t_pcap
    })

    corrs = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo)
    
    # Rule 5: Periodic/repeated communication match
    periodic_corrs = [c for c in corrs if c.relationship_type == "PERIODIC_COMMUNICATION_MATCH"]
    assert len(periodic_corrs) >= 1
    assert "repeated" in periodic_corrs[0].reason.lower()

    # Rule 6: Temporal alignment match (< 1 hour window)
    temporal_corrs = [c for c in corrs if c.relationship_type == "TEMPORAL_ALIGNMENT"]
    assert len(temporal_corrs) >= 1
    assert "temporal" in temporal_corrs[0].reason.lower()


def test_correlation_multiple_sources_strengthens_confidence(clean_case):
    """Verifies that multiple independent evidence sources produce STRONG relationships and THREAT_INTEL_MATCH."""
    case_id, obs_repo, corr_repo, threat_repo = clean_case

    # Multi-tool APK observations + PCAP observation (3+ tools) -> triggers RULE 1 + RULE 7 elevation
    obs_repo.insert_one({
        "observation_id": f"obs-multi-apk-1-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-multi",
        "evidence_id": "ev-apk-multi",
        "observation_type": "EMBEDDED_DOMAIN",
        "source": "APK",
        "value": "multi-threat-source.net",
        "confidence": 1.0,
        "metadata": {"tool": "androguard"}
    })
    obs_repo.insert_one({
        "observation_id": f"obs-multi-apk-2-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-multi",
        "evidence_id": "ev-apk-multi",
        "observation_type": "EMBEDDED_DOMAIN",
        "source": "APK",
        "value": "multi-threat-source.net",
        "confidence": 1.0,
        "metadata": {"tool": "mobsf"}
    })
    obs_repo.insert_one({
        "observation_id": f"obs-multi-pcap-{case_id}",
        "case_id": case_id,
        "indicator_id": "ind-multi",
        "evidence_id": "ev-pcap-multi",
        "observation_type": "DNS_QUERY",
        "source": "PCAP",
        "value": "multi-threat-source.net",
        "confidence": 1.0,
        "metadata": {"tool": "scapy"}
    })

    # External Threat Intelligence
    threat_repo.insert_one({
        "threat_intel_id": f"ti-multi-{case_id}",
        "case_id": case_id,
        "indicator": "multi-threat-source.net",
        "indicator_type": "DOMAIN",
        "provider": "VirusTotal",
        "threat_name": "Trojan.Android.Banker",
        "verdict": "MALICIOUS",
        "score": 95.0,
        "checked_at": datetime.utcnow()
    })

    threat_intel_list = threat_repo.find_all({"case_id": case_id})
    corrs = CorrelationEngine.correlate(case_id, threat_intel=threat_intel_list, correlation_repo=corr_repo, observation_repo=obs_repo)
    
    # Rule 7 Multi-tool elevation on domain match
    domain_corrs = [c for c in corrs if c.relationship_type == "DOMAIN_MATCH"]
    assert len(domain_corrs) >= 1
    assert domain_corrs[0].strength == "STRONG"
    assert "multiple independent sources" in domain_corrs[0].reason.lower()

    # External threat intel match
    ti_corrs = [c for c in corrs if c.relationship_type == "THREAT_INTEL_MATCH"]
    assert len(ti_corrs) >= 1
    assert ti_corrs[0].strength == "STRONG"
    assert "VirusTotal" in str(ti_corrs[0].metadata) or "Trojan.Android.Banker" in str(ti_corrs[0].reason)
