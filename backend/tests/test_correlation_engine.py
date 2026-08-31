import pytest
from datetime import datetime, timedelta
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.schemas.correlation import CorrelationStrength
from app.schemas.normalized import ObservationType
from app.services.correlation_engine import CorrelationEngine

def test_rule_1_domain_match():
    """RULE 1: APK domain == PCAP DNS domain."""
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-rule1"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
    ind_repo.collection.delete_many({"case_id": case_id})

    apk_ev_id = "apk-ev-1"
    pcap_ev_id = "pcap-ev-1"

    # Insert APK embedded domain observation
    apk_obs = {
        "observation_id": "obs-apk-dom-1",
        "case_id": case_id,
        "indicator_id": "ind-1",
        "evidence_id": apk_ev_id,
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "api.example.com",
        "metadata": {"tool": "androguard"}
    }
    obs_repo.insert_one(apk_obs)

    # Insert PCAP DNS query observation
    pcap_obs = {
        "observation_id": "obs-pcap-dns-1",
        "case_id": case_id,
        "indicator_id": "ind-1",
        "evidence_id": pcap_ev_id,
        "observation_type": ObservationType.DNS_QUERY.value,
        "source": "PCAP",
        "value": "API.EXAMPLE.COM.",
        "metadata": {"tool": "scapy"}
    }
    obs_repo.insert_one(pcap_obs)

    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)

    domain_corrs = [c for c in correlations if c.relationship_type == "DOMAIN_MATCH"]
    assert len(domain_corrs) == 1
    corr = domain_corrs[0]

    assert corr.evidence_class == "CORRELATED"
    assert "api.example.com" in corr.reason
    assert "was embedded in the APK and was independently observed in DNS traffic" in corr.reason
    assert corr.strength in [CorrelationStrength.MODERATE, CorrelationStrength.STRONG]
    assert "obs-apk-dom-1" in corr.source_observation_ids
    assert "obs-pcap-dns-1" in corr.target_observation_ids
    assert apk_ev_id in corr.supporting_evidence_ids
    assert pcap_ev_id in corr.supporting_evidence_ids

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_rule_2_ip_match():
    """RULE 2: APK IP == PCAP destination IP."""
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-rule2"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    apk_ev = "ev-apk-2"
    pcap_ev = "ev-pcap-2"

    obs_repo.insert_one({
        "observation_id": "obs-apk-ip-2",
        "case_id": case_id,
        "indicator_id": "ind-2",
        "evidence_id": apk_ev,
        "observation_type": ObservationType.EMBEDDED_IP.value,
        "source": "APK",
        "value": "198.51.100.25",
        "metadata": {"tool": "androguard"}
    })

    obs_repo.insert_one({
        "observation_id": "obs-pcap-ip-2",
        "case_id": case_id,
        "indicator_id": "ind-2",
        "evidence_id": pcap_ev,
        "observation_type": ObservationType.NETWORK_IP.value,
        "source": "PCAP",
        "value": "198.51.100.25",
        "metadata": {"tool": "scapy"}
    })

    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)

    ip_corrs = [c for c in correlations if c.relationship_type == "IP_MATCH"]
    assert len(ip_corrs) == 1
    corr = ip_corrs[0]

    assert "198.51.100.25" in corr.reason
    assert "was embedded in APK bytecode/assets" in corr.reason
    assert corr.evidence_class == "CORRELATED"
    assert "obs-apk-ip-2" in corr.source_observation_ids
    assert "obs-pcap-ip-2" in corr.target_observation_ids

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_rule_3_domain_resolves_to_pcap_ip():
    """RULE 3: APK domain resolves to IP observed in PCAP."""
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-rule3"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    apk_ev = "ev-apk-3"
    pcap_ev = "ev-pcap-3"

    # APK domain
    obs_repo.insert_one({
        "observation_id": "obs-apk-dom-3",
        "case_id": case_id,
        "indicator_id": "ind-3-dom",
        "evidence_id": apk_ev,
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "c2-domain.org",
        "metadata": {"tool": "androguard"}
    })

    # PCAP DNS response resolving c2-domain.org to 203.0.113.50
    obs_repo.insert_one({
        "observation_id": "obs-pcap-dns-resp-3",
        "case_id": case_id,
        "indicator_id": "ind-3-ip",
        "evidence_id": pcap_ev,
        "observation_type": ObservationType.DNS_RESPONSE.value,
        "source": "PCAP",
        "value": "203.0.113.50",
        "metadata": {"tool": "scapy", "resolved_for": "c2-domain.org"}
    })

    # PCAP Network traffic contacting 203.0.113.50
    obs_repo.insert_one({
        "observation_id": "obs-pcap-ip-traffic-3",
        "case_id": case_id,
        "indicator_id": "ind-3-ip",
        "evidence_id": pcap_ev,
        "observation_type": ObservationType.NETWORK_IP.value,
        "source": "PCAP",
        "value": "203.0.113.50",
        "metadata": {"tool": "scapy"}
    })

    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)

    resolved_corrs = [c for c in correlations if c.relationship_type == "RESOLVED_IP_MATCH"]
    assert len(resolved_corrs) == 1
    corr = resolved_corrs[0]

    assert corr.strength == CorrelationStrength.STRONG
    assert "c2-domain.org" in corr.reason
    assert "203.0.113.50" in corr.reason
    assert "was resolved via DNS in PCAP traffic" in corr.reason

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_rule_4_capability_matching_network_activity():
    """RULE 4: APK network capability + matching network observation."""
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-rule4"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    # APK declared permission
    obs_repo.insert_one({
        "observation_id": "obs-apk-perm-4",
        "case_id": case_id,
        "indicator_id": "ind-4-perm",
        "evidence_id": "ev-apk-4",
        "observation_type": ObservationType.DECLARED_PERMISSION.value,
        "source": "APK",
        "value": "android.permission.INTERNET",
        "metadata": {"tool": "androguard"}
    })

    # PCAP protocol
    obs_repo.insert_one({
        "observation_id": "obs-pcap-proto-4",
        "case_id": case_id,
        "indicator_id": "ind-4-proto",
        "evidence_id": "ev-pcap-4",
        "observation_type": ObservationType.NETWORK_PROTOCOL.value,
        "source": "PCAP",
        "value": "TCP",
        "metadata": {"tool": "scapy"}
    })

    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)

    cap_corrs = [c for c in correlations if c.relationship_type == "CAPABILITY_ACTIVITY_ALIGNMENT"]
    assert len(cap_corrs) == 1
    assert "INTERNET" in cap_corrs[0].reason

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_rule_5_repeated_network_communication_match():
    """RULE 5: Matching indicator + repeated network communication."""
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-rule5"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    # APK embedded IP
    obs_repo.insert_one({
        "observation_id": "obs-apk-ip-5",
        "case_id": case_id,
        "indicator_id": "ind-5",
        "evidence_id": "ev-apk-5",
        "observation_type": ObservationType.EMBEDDED_IP.value,
        "source": "APK",
        "value": "185.120.44.5",
        "metadata": {"tool": "androguard"}
    })

    # PCAP repeated communication pattern
    obs_repo.insert_one({
        "observation_id": "obs-pcap-rep-5",
        "case_id": case_id,
        "indicator_id": "ind-5",
        "evidence_id": "ev-pcap-5",
        "observation_type": ObservationType.REPEATED_COMMUNICATION.value,
        "source": "PCAP",
        "value": "185.120.44.5",
        "metadata": {
            "tool": "scapy",
            "packet_count": 24,
            "mean_interval_seconds": 15.0,
            "std_interval_seconds": 0.4,
            "pattern_classification": "suspicious communication pattern"
        }
    })

    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)

    rep_corrs = [c for c in correlations if c.relationship_type == "PERIODIC_COMMUNICATION_MATCH"]
    assert len(rep_corrs) == 1
    corr = rep_corrs[0]

    assert corr.strength == CorrelationStrength.STRONG
    assert "185.120.44.5" in corr.reason
    assert "suspicious communication pattern" in corr.reason
    # Ensure no arbitrary malware verdict was hardcoded
    assert "c2" not in corr.reason.lower()

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_rule_6_temporal_alignment():
    """RULE 6: Matching indicator + timestamp relationship."""
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-rule6"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    now = datetime.utcnow()
    t_apk = now.isoformat()
    t_pcap = (now + timedelta(seconds=120)).isoformat()

    obs_repo.insert_one({
        "observation_id": "obs-apk-dom-6",
        "case_id": case_id,
        "indicator_id": "ind-6",
        "evidence_id": "ev-apk-6",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "timed-sync.net",
        "timestamp": t_apk,
        "metadata": {"tool": "androguard"}
    })

    obs_repo.insert_one({
        "observation_id": "obs-pcap-dns-6",
        "case_id": case_id,
        "indicator_id": "ind-6",
        "evidence_id": "ev-pcap-6",
        "observation_type": ObservationType.DNS_QUERY.value,
        "source": "PCAP",
        "value": "timed-sync.net",
        "timestamp": t_pcap,
        "metadata": {"tool": "scapy"}
    })

    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)

    temp_corrs = [c for c in correlations if c.relationship_type == "TEMPORAL_ALIGNMENT"]
    assert len(temp_corrs) == 1
    corr = temp_corrs[0]

    assert corr.strength == CorrelationStrength.STRONG
    assert "temporal corroboration" in corr.reason

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_rule_7_multiple_independent_sources_elevation():
    """RULE 7: Multiple independent evidence sources increase relationship strength."""
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-rule7"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    # Tool 1: Androguard (APK)
    obs_repo.insert_one({
        "observation_id": "obs-andro-7",
        "case_id": case_id,
        "indicator_id": "ind-7",
        "evidence_id": "ev-apk-7",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "multi-source-target.org",
        "metadata": {"tool": "androguard"}
    })

    # Tool 2: MobSF (APK)
    obs_repo.insert_one({
        "observation_id": "obs-mobsf-7",
        "case_id": case_id,
        "indicator_id": "ind-7",
        "evidence_id": "ev-apk-7",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "multi-source-target.org",
        "metadata": {"tool": "mobsf"}
    })

    # Tool 3: Scapy (PCAP)
    obs_repo.insert_one({
        "observation_id": "obs-scapy-7",
        "case_id": case_id,
        "indicator_id": "ind-7",
        "evidence_id": "ev-pcap-7",
        "observation_type": ObservationType.DNS_QUERY.value,
        "source": "PCAP",
        "value": "multi-source-target.org",
        "metadata": {"tool": "scapy"}
    })

    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)

    domain_corrs = [c for c in correlations if c.relationship_type == "DOMAIN_MATCH"]
    assert len(domain_corrs) >= 1
    strong_corrs = [c for c in domain_corrs if c.strength == CorrelationStrength.STRONG]
    assert len(strong_corrs) >= 1
    assert "Corroborated across multiple independent sources" in strong_corrs[0].reason

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_optional_threat_intel_correlation():
    """Verify optional Threat Intelligence matching."""
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-ti"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    obs_repo.insert_one({
        "observation_id": "obs-apk-ti",
        "case_id": case_id,
        "indicator_id": "ind-ti",
        "evidence_id": "ev-apk-ti",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "known-bad-phish.net",
        "metadata": {"tool": "androguard"}
    })

    threat_feed = [{
        "indicator": "known-bad-phish.net",
        "threat_name": "Phishing-Campaign-2026",
        "confidence": 0.95
    }]

    correlations = CorrelationEngine.correlate(
        case_id, 
        threat_intel=threat_feed,
        correlation_repo=corr_repo, 
        observation_repo=obs_repo, 
        indicator_repo=ind_repo
    )

    ti_corrs = [c for c in correlations if c.relationship_type == "THREAT_INTEL_MATCH"]
    assert len(ti_corrs) == 1
    assert "Phishing-Campaign-2026" in ti_corrs[0].reason
    assert ti_corrs[0].strength == CorrelationStrength.STRONG

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_negative_non_matching_evidence_produces_no_correlations():
    """
    Acceptance Criteria:
    Non-matching APK + PCAP does NOT produce a false correlation.
    """
    obs_repo = ObservationRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-corr-negative"
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    # APK with innocent domain and internal IP
    obs_repo.insert_one({
        "observation_id": "obs-apk-innocent",
        "case_id": case_id,
        "indicator_id": "ind-innocent",
        "evidence_id": "ev-apk-neg",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "legitimate-app.com",
        "metadata": {"tool": "androguard"}
    })

    obs_repo.insert_one({
        "observation_id": "obs-apk-internal-ip",
        "case_id": case_id,
        "indicator_id": "ind-internal-ip",
        "evidence_id": "ev-apk-neg",
        "observation_type": ObservationType.EMBEDDED_IP.value,
        "source": "APK",
        "value": "10.0.0.1",
        "metadata": {"tool": "androguard"}
    })

    # PCAP with completely different public traffic
    obs_repo.insert_one({
        "observation_id": "obs-pcap-different-dns",
        "case_id": case_id,
        "indicator_id": "ind-diff-dns",
        "evidence_id": "ev-pcap-neg",
        "observation_type": ObservationType.DNS_QUERY.value,
        "source": "PCAP",
        "value": "unrelated-weather-service.net",
        "metadata": {"tool": "scapy"}
    })

    obs_repo.insert_one({
        "observation_id": "obs-pcap-different-ip",
        "case_id": case_id,
        "indicator_id": "ind-diff-ip",
        "evidence_id": "ev-pcap-neg",
        "observation_type": ObservationType.NETWORK_IP.value,
        "source": "PCAP",
        "value": "93.184.216.34",
        "metadata": {"tool": "scapy"}
    })

    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)

    # Assert NO domain or IP match correlations exist
    matching_corrs = [
        c for c in correlations 
        if c.relationship_type in ["DOMAIN_MATCH", "IP_MATCH", "RESOLVED_IP_MATCH", "PERIODIC_COMMUNICATION_MATCH"]
    ]
    assert len(matching_corrs) == 0

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})
