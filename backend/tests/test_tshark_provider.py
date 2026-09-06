import os
import tempfile
from unittest.mock import patch
from app.services.providers.tshark import TsharkProvider
from app.models.analysis_run import ProviderStatus

def test_tshark_availability_and_version():
    provider = TsharkProvider()
    assert provider.provider_name == "tshark"
    assert provider.is_enabled() is True
    assert provider.is_configured() is True
    
    # Provider must be available either through Docker container or host
    available = provider.is_available()
    assert available is True

    # Version must be a real semver string, not 'unknown'
    version = provider.version
    assert version != "unknown"
    assert len(version.split(".")) >= 2
    assert "4." in version

def test_tshark_unavailable_handling():
    provider = TsharkProvider()
    with patch.object(provider, "is_available", return_value=False):
        record = provider.analyze_pcap("nonexistent.pcap")
        assert record.status == ProviderStatus.UNAVAILABLE
        assert "not available" in record.error.lower()
        assert record.provider_version == provider.version

def test_tshark_parse_real_pcap():
    provider = TsharkProvider()
    pcap_path = os.path.join("storage", "aabb6037-9f26-4eb3-9f7c-517f8be4a95e_dhcp.pcap")
    assert os.path.exists(pcap_path), f"Sample PCAP missing at {pcap_path}"

    record = provider.analyze_pcap(pcap_path)
    assert record.status == ProviderStatus.COMPLETED
    assert record.provider == "tshark"
    assert record.provider_version == provider.version
    assert record.error is None
    
    meta = record.output_metadata
    assert meta["packet_count"] == 4
    assert "0.0.0.0" in meta["ips"]
    assert "192.168.0.1" in meta["ips"]
    assert "UDP" in meta["protocols"]
    assert 67 in meta["ports"]["udp"]
    assert 68 in meta["ports"]["udp"]
    assert len(meta["connections"]) >= 1

def test_tshark_malformed_pcap_error_handling():
    provider = TsharkProvider()
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        f.write(b"CORRUPT_HEADER_AND_INVALID_PAYLOAD_NOT_A_PCAP")
        corrupt_path = f.name

    try:
        record = provider.analyze_pcap(corrupt_path)
        assert record.status == ProviderStatus.FAILED
        assert record.error is not None
        assert "Tshark analysis execution failed" in record.error
        assert record.output_metadata.get("tool_version") == provider.version
    finally:
        if os.path.exists(corrupt_path):
            os.unlink(corrupt_path)
