import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.repositories.threat_intel_repository import ThreatIntelRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.schemas.indicator import IndicatorType
from app.schemas.threat_intel import ThreatIntelligence
from app.services.threat_intel.base import ThreatIntelResult
from app.services.threat_intel.virustotal import VirusTotalProvider
from app.services.threat_intel.urlhaus import URLhausProvider
from app.services.threat_intel.abuseipdb import AbuseIPDBProvider
from app.services.threat_intel.alienvault_otx import AlienVaultOTXProvider
from app.services.threat_intel.service import ThreatIntelService

client = TestClient(app)

def test_pipeline_works_with_no_threat_intel_keys():
    """
    Acceptance Criteria:
    The core investigation pipeline works with no threat-intelligence API keys.
    When all providers are disabled, enrichment completes without error.
    """
    threat_repo = ThreatIntelRepository()
    ind_repo = IndicatorRepository()
    case_id = "test-case-ti-disabled-001"

    threat_repo.collection.delete_many({"case_id": case_id})
    ind_repo.collection.delete_many({"case_id": case_id})

    # Insert an indicator into the case
    ind_repo.insert_one({
        "indicator_id": "ind-pub-1",
        "case_id": case_id,
        "type": IndicatorType.DOMAIN.value,
        "value": "external-threat.org",
        "normalized_value": "external-threat.org"
    })

    # Initialize service with all providers disabled
    service = ThreatIntelService(
        providers=[
            VirusTotalProvider(),
            URLhausProvider(),
            AbuseIPDBProvider(),
            AlienVaultOTXProvider()
        ],
        threat_repo=threat_repo,
        indicator_repo=ind_repo
    )

    with patch.object(VirusTotalProvider, "is_enabled", return_value=False), \
         patch.object(URLhausProvider, "is_enabled", return_value=False), \
         patch.object(AbuseIPDBProvider, "is_enabled", return_value=False), \
         patch.object(AlienVaultOTXProvider, "is_enabled", return_value=False):
        
        results = service.enrich_case(case_id)
        assert results == []

    # Cleanup
    threat_repo.collection.delete_many({"case_id": case_id})
    ind_repo.collection.delete_many({"case_id": case_id})


def test_indicator_relevance_filtering():
    """
    Acceptance Criteria:
    Do not send every indicator automatically. Only enrich relevant indicators.
    """
    # Private / internal IPs must NOT be sent
    assert not ThreatIntelService.is_relevant_indicator("127.0.0.1", IndicatorType.IP)
    assert not ThreatIntelService.is_relevant_indicator("10.0.0.5", IndicatorType.IP)
    assert not ThreatIntelService.is_relevant_indicator("192.168.1.100", IndicatorType.IP)
    assert not ThreatIntelService.is_relevant_indicator("172.16.50.1", IndicatorType.IP)
    assert not ThreatIntelService.is_relevant_indicator("169.254.1.1", IndicatorType.IP)

    # Local hostnames or packages must NOT be sent
    assert not ThreatIntelService.is_relevant_indicator("localhost", IndicatorType.DOMAIN)
    assert not ThreatIntelService.is_relevant_indicator("server.local", IndicatorType.DOMAIN)
    assert not ThreatIntelService.is_relevant_indicator("test.internal", IndicatorType.DOMAIN)
    assert not ThreatIntelService.is_relevant_indicator("android.permission.INTERNET", IndicatorType.PERMISSION)
    assert not ThreatIntelService.is_relevant_indicator("Ljava/net/Socket;->connect", IndicatorType.API)
    assert not ThreatIntelService.is_relevant_indicator("com.example.app", IndicatorType.PACKAGE)

    # Public, external indicators MUST be deemed relevant
    assert ThreatIntelService.is_relevant_indicator("93.184.216.34", IndicatorType.IP)
    assert ThreatIntelService.is_relevant_indicator("bad-domain.com", IndicatorType.DOMAIN)
    assert ThreatIntelService.is_relevant_indicator("https://malware-site.biz/payload.apk", IndicatorType.URL)
    assert ThreatIntelService.is_relevant_indicator("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IndicatorType.HASH)


def test_caching_mechanism_prevents_redundant_network_calls():
    """
    Acceptance Criteria:
    Cache results where practical.
    """
    threat_repo = ThreatIntelRepository()
    case_id = "test-case-ti-cache-002"
    threat_repo.collection.delete_many({"case_id": case_id})

    indicator_val = "cached-domain.net"
    now = datetime.utcnow()

    # Pre-populate MongoDB cache with valid future expiration
    threat_repo.insert_one({
        "threat_intel_id": "ti-cache-1",
        "case_id": case_id,
        "indicator_id": "ind-cache-1",
        "indicator": indicator_val,
        "indicator_type": IndicatorType.DOMAIN.value,
        "provider": "VirusTotal",
        "verdict": "MALICIOUS",
        "score": 85.0,
        "categories": ["Trojan"],
        "raw_result": {"cached": True},
        "checked_at": now,
        "expires_at": now + timedelta(hours=12),
        "metadata": {"cached": True}
    })

    # Mock provider enrich to verify it is NOT called
    mock_vt = VirusTotalProvider()
    mock_vt.enrich = MagicMock()

    service = ThreatIntelService(providers=[mock_vt], threat_repo=threat_repo)

    with patch.object(mock_vt, "is_enabled", return_value=True), \
         patch.object(mock_vt, "is_configured", return_value=True):

        results = service.enrich_indicator(
            indicator_id="ind-cache-1",
            indicator_value=indicator_val,
            indicator_type_str="DOMAIN",
            case_id=case_id,
            provider_name="VirusTotal"
        )

        assert len(results) == 1
        assert results[0].verdict == "MALICIOUS"
        assert results[0].score == 85.0
        # Verify network query was bypassed by cache
        mock_vt.enrich.assert_not_called()

    # Cleanup
    threat_repo.collection.delete_many({"case_id": case_id})


def test_individual_providers_mock_enrichment():
    """
    Acceptance Criteria:
    Providers can be enabled individually.
    Results are stored with provenance.
    Handle API failures, rate limits, missing keys.
    """
    # 1. VirusTotal
    vt = VirusTotalProvider()
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 40, "undetected": 10},
                    "categories": {"VendorA": "phishing"}
                }
            }
        }
        mock_get.return_value = mock_resp

        with patch.object(vt, "is_enabled", return_value=True), \
             patch.object(vt, "is_configured", return_value=True):
            res = vt.enrich("phish-target.com", IndicatorType.DOMAIN)
            assert res is not None
            assert res.verdict == "MALICIOUS"
            assert res.score > 0
            assert "phishing" in res.categories

    # 2. URLhaus
    urlhaus = URLhausProvider()
    with patch("httpx.Client.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["Mirai", "ELF"]
        }
        mock_post.return_value = mock_resp

        with patch.object(urlhaus, "is_enabled", return_value=True):
            res = urlhaus.enrich("http://malware-drop.org/bin.sh", IndicatorType.URL)
            assert res is not None
            assert res.verdict == "MALICIOUS"
            assert "malware_download" in res.categories

    # 3. AbuseIPDB
    abuse = AbuseIPDBProvider()
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 95,
                "totalReports": 42,
                "usageType": "Data Center",
                "isp": "Suspicious Hosting LLC"
            }
        }
        mock_get.return_value = mock_resp

        with patch.object(abuse, "is_enabled", return_value=True), \
             patch.object(abuse, "is_configured", return_value=True):
            res = abuse.enrich("118.25.6.39", IndicatorType.IP)
            assert res is not None
            assert res.verdict == "MALICIOUS"
            assert res.score == 95.0

    # 4. AlienVault OTX
    otx = AlienVaultOTXProvider()
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 7,
                "pulses": [{"name": "APT Campaign 44", "tags": ["apt", "trojan"]}]
            }
        }
        mock_get.return_value = mock_resp

        with patch.object(otx, "is_enabled", return_value=True), \
             patch.object(otx, "is_configured", return_value=True):
            res = otx.enrich("apt-domain.com", IndicatorType.DOMAIN)
            assert res is not None
            assert res.verdict == "MALICIOUS"
            assert "APT Campaign 44" in res.categories


def test_rate_limit_and_error_handling():
    """Verify graceful fallback upon HTTP 429 rate limit or timeout."""
    vt = VirusTotalProvider()
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        with patch.object(vt, "is_enabled", return_value=True), \
             patch.object(vt, "is_configured", return_value=True):
            res = vt.enrich("rate-limit-test.org", IndicatorType.DOMAIN)
            assert res is not None
            assert res.verdict == "UNKNOWN"
            assert "Rate Limited" in res.categories


def test_separation_of_local_observation_and_threat_intel():
    """
    Acceptance Criteria:
    External intelligence is clearly separated from local evidence.
    Do not classify an indicator as malicious solely because one external provider says so.
    """
    threat_repo = ThreatIntelRepository()
    ind_repo = IndicatorRepository()
    case_id = "test-case-ti-separation-003"

    threat_repo.collection.delete_many({"case_id": case_id})
    ind_repo.collection.delete_many({"case_id": case_id})

    # Insert neutral local indicator
    ind_data = {
        "indicator_id": "ind-neutral-1",
        "case_id": case_id,
        "type": IndicatorType.DOMAIN.value,
        "value": "neutral-evidence.com",
        "normalized_value": "neutral-evidence.com",
        "source": "APK"
    }
    ind_repo.insert_one(ind_data)

    mock_vt = VirusTotalProvider()
    mock_vt.enrich = MagicMock(return_value=ThreatIntelResult(
        provider="VirusTotal",
        indicator="neutral-evidence.com",
        indicator_type="DOMAIN",
        verdict="MALICIOUS",
        score=100.0,
        categories=["Phishing"]
    ))

    service = ThreatIntelService(providers=[mock_vt], threat_repo=threat_repo, indicator_repo=ind_repo)

    with patch.object(mock_vt, "is_enabled", return_value=True), \
         patch.object(mock_vt, "is_configured", return_value=True):

        ti_results = service.enrich_case(case_id)
        assert len(ti_results) == 1
        assert ti_results[0].metadata.get("source") == "EXTERNAL_THREAT_INTELLIGENCE"

        # Verify local indicator record remains unchanged and neutral
        local_ind = ind_repo.find_one({"indicator_id": "ind-neutral-1"})
        assert local_ind["value"] == "neutral-evidence.com"
        # The local indicator does NOT have its core source altered
        assert local_ind["source"] == "APK"

    # Cleanup
    threat_repo.collection.delete_many({"case_id": case_id})
    ind_repo.collection.delete_many({"case_id": case_id})


def test_api_threat_intel_endpoints():
    """Verify GET and POST threat-intel API endpoints."""
    res = client.post("/cases", json={"name": "Threat Intel API Case", "description": "Verify API"})
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # GET threat intel (empty initially)
    res = client.get(f"/cases/{case_id}/threat-intel")
    assert res.status_code == 200
    assert res.json() == []

    # Trigger enrichment via POST
    res = client.post(f"/cases/{case_id}/threat-intel/enrich")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
