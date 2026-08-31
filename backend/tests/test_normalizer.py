import pytest
from app.schemas.indicator import IndicatorType
from app.schemas.normalized import SourceType, ObservationType
from app.services.normalizer import ValueNormalizer, EvidenceNormalizer
from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.observation_repository import ObservationRepository

def test_value_normalizer_determinism():
    """Verify deterministic normalization across all 11 supported Indicator types."""
    # 1. DOMAIN
    assert ValueNormalizer.normalize(IndicatorType.DOMAIN, "Example.COM.") == "example.com"
    assert ValueNormalizer.normalize(IndicatorType.DOMAIN, "http://api.target.com:8080/v1/endpoint") == "api.target.com"
    assert ValueNormalizer.normalize(IndicatorType.DOMAIN, "  SUB.DOMAIN.ORG  ") == "sub.domain.org"
    assert ValueNormalizer.normalize(IndicatorType.DOMAIN, "c2.server.net/path") == "c2.server.net"

    # 2. IP
    assert ValueNormalizer.normalize(IndicatorType.IP, "192.168.001.001") == "192.168.1.1"
    assert ValueNormalizer.normalize(IndicatorType.IP, "10.0.0.1:443") == "10.0.0.1"
    assert ValueNormalizer.normalize(IndicatorType.IP, "2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
    assert ValueNormalizer.normalize(IndicatorType.IP, " 8.8.8.8 ") == "8.8.8.8"

    # 3. URL
    assert ValueNormalizer.normalize(IndicatorType.URL, "HTTP://EXAMPLE.COM:80/path/to/resource") == "http://example.com/path/to/resource"
    assert ValueNormalizer.normalize(IndicatorType.URL, "https://Example.com:443/") == "https://example.com/"
    assert ValueNormalizer.normalize(IndicatorType.URL, "http://target.org:8080/test?query=1") == "http://target.org:8080/test?query=1"

    # 4. HASH
    assert ValueNormalizer.normalize(IndicatorType.HASH, "A1B2C3D4E5F67890ABCDEF") == "a1b2c3d4e5f67890abcdef"
    assert ValueNormalizer.normalize(IndicatorType.HASH, "  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # 5. PACKAGE
    assert ValueNormalizer.normalize(IndicatorType.PACKAGE, "Com.Example.MalwareApp") == "com.example.malwareapp"

    # 6. PERMISSION
    assert ValueNormalizer.normalize(IndicatorType.PERMISSION, "android.permission.internet") == "ANDROID.PERMISSION.INTERNET"
    assert ValueNormalizer.normalize(IndicatorType.PERMISSION, "  android.permission.SEND_SMS  ") == "ANDROID.PERMISSION.SEND_SMS"

    # 7. PORT
    assert ValueNormalizer.normalize(IndicatorType.PORT, "0080") == "80"
    assert ValueNormalizer.normalize(IndicatorType.PORT, " 443 ") == "443"

    # 8. PROTOCOL
    assert ValueNormalizer.normalize(IndicatorType.PROTOCOL, "tcp") == "TCP"
    assert ValueNormalizer.normalize(IndicatorType.PROTOCOL, " udp ") == "UDP"
    assert ValueNormalizer.normalize(IndicatorType.PROTOCOL, "dns") == "DNS"

    # 9. CERTIFICATE
    assert ValueNormalizer.normalize(IndicatorType.CERTIFICATE, "DEADBEEFCAFE") == "deadbeefcafe"

    # 10. API
    assert ValueNormalizer.normalize(IndicatorType.API, " Ljava/net/URL;->openConnection ") == "Ljava/net/URL;->openConnection"

    # 11. CAPABILITY
    assert ValueNormalizer.normalize(IndicatorType.CAPABILITY, "internet_access") == "INTERNET_ACCESS"


def test_cross_source_domain_convergence():
    """
    Acceptance Criteria:
    The same domain discovered from APK and PCAP must:
    - Refer to the same single normalized Indicator.
    - Produce two separate Observations preserving their respective sources (APK, PCAP)
      and observation types (EMBEDDED_DOMAIN, DNS_QUERY).
    - Preserve evidence provenance (evidence_id).
    """
    ind_repo = IndicatorRepository()
    obs_repo = ObservationRepository()

    case_id = "test-case-convergence-001"
    apk_evidence_id = "evidence-apk-101"
    pcap_evidence_id = "evidence-pcap-202"

    # Cleanup any pre-existing records for this test case
    ind_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})

    # 1. APK static analysis output containing example.com
    apk_provider_results = {
        "androguard": {
            "status": "COMPLETED",
            "output_metadata": {
                "package_name": "com.test.app",
                "domains": ["example.com"],
                "permissions": ["android.permission.INTERNET"]
            }
        }
    }

    apk_report = EvidenceNormalizer.normalize(
        apk_provider_results, case_id, apk_evidence_id, ind_repo, obs_repo
    )
    assert apk_report["indicators_count"] >= 1
    assert apk_report["observations_count"] >= 1

    # Verify Indicator created for example.com
    domain_ind = ind_repo.find_one({
        "case_id": case_id,
        "type": IndicatorType.DOMAIN.value,
        "normalized_value": "example.com"
    })
    assert domain_ind is not None
    ind_id = domain_ind["indicator_id"]
    assert domain_ind["source"] == "APK"
    assert domain_ind["evidence_id"] == apk_evidence_id

    # Verify first Observation from APK
    apk_obs = obs_repo.find_all({"case_id": case_id, "indicator_id": ind_id})
    assert len(apk_obs) == 1
    assert apk_obs[0]["source"] == "APK"
    assert apk_obs[0]["observation_type"] == ObservationType.EMBEDDED_DOMAIN.value
    assert apk_obs[0]["evidence_id"] == apk_evidence_id

    # 2. PCAP network analysis output containing the same example.com in DNS query
    pcap_provider_results = {
        "scapy": {
            "status": "COMPLETED",
            "output_metadata": {
                "dns_queries": ["EXAMPLE.COM."],
                "ips": ["93.184.216.34"],
                "protocols": ["DNS"]
            }
        }
    }

    pcap_report = EvidenceNormalizer.normalize(
        pcap_provider_results, case_id, pcap_evidence_id, ind_repo, obs_repo
    )
    assert pcap_report["observations_count"] >= 1

    # Verify: STILL exactly ONE Indicator exists for example.com in this case
    all_domain_inds = ind_repo.find_all({
        "case_id": case_id,
        "type": IndicatorType.DOMAIN.value,
        "normalized_value": "example.com"
    })
    assert len(all_domain_inds) == 1
    assert all_domain_inds[0]["indicator_id"] == ind_id

    # Verify: Exactly TWO separate Observations exist referring to the same Indicator
    all_obs_for_domain = obs_repo.find_all({"case_id": case_id, "indicator_id": ind_id})
    assert len(all_obs_for_domain) == 2

    # Check APK observation
    apk_observations = [o for o in all_obs_for_domain if o["source"] == "APK"]
    assert len(apk_observations) == 1
    assert apk_observations[0]["observation_type"] == ObservationType.EMBEDDED_DOMAIN.value
    assert apk_observations[0]["evidence_id"] == apk_evidence_id
    assert apk_observations[0]["metadata"]["tool"] == "androguard"

    # Check PCAP observation
    pcap_observations = [o for o in all_obs_for_domain if o["source"] == "PCAP"]
    assert len(pcap_observations) == 1
    assert pcap_observations[0]["observation_type"] == ObservationType.DNS_QUERY.value
    assert pcap_observations[0]["evidence_id"] == pcap_evidence_id
    assert pcap_observations[0]["metadata"]["tool"] == "scapy"

    # Cleanup
    ind_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})


def test_mobsf_heterogeneous_output_normalization():
    """Verify normalization of full MobSF static analysis payload."""
    ind_repo = IndicatorRepository()
    obs_repo = ObservationRepository()

    case_id = "test-case-mobsf-002"
    evidence_id = "evidence-mobsf-202"

    ind_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})

    mobsf_meta = {
        "application": {
            "package_name": "com.target.malware",
            "app_name": "MalwareTarget"
        },
        "permissions": {
            "android.permission.INTERNET": {"status": "normal"},
            "android.permission.SEND_SMS": {"status": "dangerous"}
        },
        "urls": ["https://malicious-command.org/api/v1"],
        "domains": ["malicious-command.org"],
        "ips": ["198.51.100.25"],
        "certificate_info": {
            "sha256": "abcdef1234567890abcdef1234567890",
            "issuer": "CN=MalwareDev"
        },
        "api_analysis": ["Landroid/telephony/SmsManager;->sendTextMessage"],
        "network_capabilities": ["SEND_SMS_OVER_NETWORK"]
    }

    report = EvidenceNormalizer.normalize(
        {"mobsf": {"status": "COMPLETED", "output_metadata": mobsf_meta}},
        case_id,
        evidence_id,
        ind_repo,
        obs_repo
    )

    assert report["indicators_count"] >= 7

    # Verify package
    pkg_ind = ind_repo.find_one({"case_id": case_id, "type": IndicatorType.PACKAGE.value})
    assert pkg_ind["normalized_value"] == "com.target.malware"

    # Verify suspicious permission
    sms_ind = ind_repo.find_one({"case_id": case_id, "type": IndicatorType.PERMISSION.value, "normalized_value": "ANDROID.PERMISSION.SEND_SMS"})
    assert sms_ind is not None
    sms_obs = obs_repo.find_one({"case_id": case_id, "indicator_id": sms_ind["indicator_id"]})
    assert sms_obs["observation_type"] == ObservationType.SUSPICIOUS_PERMISSION.value

    # Verify URL and derived domain
    url_ind = ind_repo.find_one({"case_id": case_id, "type": IndicatorType.URL.value})
    assert url_ind is not None
    dom_ind = ind_repo.find_one({"case_id": case_id, "type": IndicatorType.DOMAIN.value, "normalized_value": "malicious-command.org"})
    assert dom_ind is not None

    # Verify Certificate
    cert_ind = ind_repo.find_one({"case_id": case_id, "type": IndicatorType.CERTIFICATE.value})
    assert cert_ind["normalized_value"] == "abcdef1234567890abcdef1234567890"

    # Verify API
    api_ind = ind_repo.find_one({"case_id": case_id, "type": IndicatorType.API.value})
    assert "SmsManager" in api_ind["normalized_value"]

    # Verify Capability
    cap_ind = ind_repo.find_one({"case_id": case_id, "type": IndicatorType.CAPABILITY.value})
    assert cap_ind["normalized_value"] == "SEND_SMS_OVER_NETWORK"

    # Cleanup
    ind_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})


def test_tshark_and_scapy_pcap_normalization_no_inference_collapse():
    """
    Verify PCAP analysis normalization preserves raw network metrics,
    captures repeated communications, and does NOT collapse observed
    evidence into speculative C2 inferences.
    """
    ind_repo = IndicatorRepository()
    obs_repo = ObservationRepository()

    case_id = "test-case-pcap-003"
    evidence_id = "evidence-pcap-303"

    ind_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})

    scapy_meta = {
        "packet_count": 50,
        "ips": ["10.0.0.5", "203.0.113.88"],
        "protocols": ["TCP", "DNS"],
        "ports": {"tcp": [443, 8080], "udp": [53]},
        "dns_queries": ["beacon-domain.com"],
        "dns_responses": [{
            "query": "beacon-domain.com",
            "answers": ["203.0.113.88"]
        }],
        "repeated_communications": [{
            "source_ip": "10.0.0.5",
            "destination_ip": "203.0.113.88",
            "destination_port": 8080,
            "protocol": "TCP",
            "packet_count": 15,
            "mean_interval_seconds": 10.0,
            "std_interval_seconds": 0.2,
            "pattern_classification": "suspicious communication pattern"
        }]
    }

    report = EvidenceNormalizer.normalize(
        {"scapy": {"status": "COMPLETED", "output_metadata": scapy_meta}},
        case_id,
        evidence_id,
        ind_repo,
        obs_repo
    )

    assert report["indicators_count"] >= 5

    # Check DNS response resolved IP
    resolved_ip_ind = ind_repo.find_one({
        "case_id": case_id,
        "type": IndicatorType.IP.value,
        "normalized_value": "203.0.113.88"
    })
    assert resolved_ip_ind is not None

    # Check Repeated communication observation
    rep_obs = obs_repo.find_all({
        "case_id": case_id,
        "observation_type": ObservationType.REPEATED_COMMUNICATION.value
    })
    assert len(rep_obs) == 1
    # Verify that the pattern classification is stored as observed metadata,
    # NOT as an authoritative C2 verdict
    assert rep_obs[0]["metadata"]["pattern_classification"] == "suspicious communication pattern"
    assert "c2" not in rep_obs[0]["observation_type"].lower()

    # Ports
    port_inds = ind_repo.find_all({"case_id": case_id, "type": IndicatorType.PORT.value})
    port_vals = [p["normalized_value"] for p in port_inds]
    assert "443" in port_vals
    assert "8080" in port_vals
    assert "53" in port_vals

    # Cleanup
    ind_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})


def test_jadx_and_apktool_decompiler_normalization():
    """Verify JADX and APKTool decompiler outputs normalization."""
    ind_repo = IndicatorRepository()
    obs_repo = ObservationRepository()

    case_id = "test-case-jadx-004"
    evidence_id = "evidence-jadx-404"

    ind_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})

    jadx_meta = {
        "package_name": "org.jadx.inspected",
        "permissions": ["android.permission.RECORD_AUDIO"],
        "urls": ["http://injected-beacon.xyz/"],
        "domains": ["injected-beacon.xyz"],
        "apis": ["Landroid/media/MediaRecorder;->start"]
    }

    report = EvidenceNormalizer.normalize(
        {"jadx": {"status": "COMPLETED", "output_metadata": jadx_meta}},
        case_id,
        evidence_id,
        ind_repo,
        obs_repo
    )

    assert report["indicators_count"] >= 4

    obs_records = obs_repo.find_all({"case_id": case_id})
    assert all(o["source"] == "APK" for o in obs_records)
    assert any(o["metadata"].get("tool") == "jadx" for o in obs_records)

    # Cleanup
    ind_repo.collection.delete_many({"case_id": case_id})
    obs_repo.collection.delete_many({"case_id": case_id})
