import sys
import struct
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.services.providers.scapy import ScapyProvider
from app.models.analysis_run import ProviderStatus
from app.db.repositories.case_repository import CaseRepository
from app.db.repositories.evidence_repository import EvidenceRepository

client = TestClient(app)


def create_minimal_pcap_bytes():
    """
    Creates a standard valid 24-byte PCAP file header (microsecond resolution).
    Magic: 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
    """
    return struct.pack(
        "<IHHIIII",
        0xa1b2c3d4,  # magic
        2, 4,        # major, minor
        0,           # timezone
        0,           # sigfigs
        65535,       # snaplen
        1            # network linktype (Ethernet)
    )


def create_minimal_pcapng_bytes():
    """
    Creates a minimal PCAPNG Section Header Block (SHB) with valid 0x0A0D0D0A magic bytes.
    """
    return b"\x0a\x0d\x0d\x0a" + b"\x00" * 28


@pytest.fixture
def temp_case():
    case_repo = CaseRepository()
    case_id = f"test-pcap-pipe-{datetime.utcnow().timestamp()}"
    case_repo.insert_one({
        "case_id": case_id,
        "name": "PCAP Pipeline Test Case",
        "description": "Comprehensive PCAP pipeline test",
        "status": "OPEN",
        "owner_id": "test-investigator-001",
        "assigned_user_ids": ["test-investigator-001"],
        "created_at": datetime.utcnow()
    })
    yield case_id
    case_repo.collection.delete_many({"case_id": case_id})
    EvidenceRepository().collection.delete_many({"case_id": case_id})


def test_pcap_pipeline_valid_standard_pcap_upload(temp_case):
    """Test valid standard libpcap upload with 0xa1b2c3d4 magic bytes."""
    pcap_bytes = create_minimal_pcap_bytes()
    res = client.post(
        f"/cases/{temp_case}/evidence",
        files={"file": ("capture.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")}
    )
    assert res.status_code == 201
    data = res.json()
    assert data["file_type"] == "PCAP"
    assert data["file_size"] == len(pcap_bytes)
    assert data["sha256"] is not None


def test_pcap_pipeline_valid_pcapng_upload(temp_case):
    """Test valid PCAPNG upload with 0x0a0d0d0a magic bytes."""
    pcapng_bytes = create_minimal_pcapng_bytes()
    res = client.post(
        f"/cases/{temp_case}/evidence",
        files={"file": ("capture.pcapng", pcapng_bytes, "application/x-pcapng")}
    )
    assert res.status_code == 201
    data = res.json()
    assert data["file_type"] == "PCAPNG"
    assert data["file_size"] == len(pcapng_bytes)


def test_pcap_pipeline_invalid_magic_bytes_rejected(temp_case):
    """Test rejection of PCAP files with non-pcap magic bytes."""
    bad_bytes = b"NOT_A_PCAP_CAPTURE_STREAM"
    res = client.post(
        f"/cases/{temp_case}/evidence",
        files={"file": ("spoofed.pcap", bad_bytes, "application/octet-stream")}
    )
    assert res.status_code == 400
    assert "Invalid PCAP file signature" in res.json()["detail"]


def test_pcap_pipeline_empty_capture_parsing(tmp_path):
    """Test analyzer behavior on a valid header-only PCAP with zero packet records."""
    empty_pcap = tmp_path / "empty.pcap"
    empty_pcap.write_bytes(create_minimal_pcap_bytes())

    provider = ScapyProvider()
    with patch("scapy.utils.rdpcap", return_value=[]):
        record = provider.analyze_pcap(str(empty_pcap))

    assert record.provider == "scapy"
    assert record.status == ProviderStatus.COMPLETED
    assert record.output_metadata["packet_count"] == 0
    assert len(record.output_metadata["connections"]) == 0


def test_pcap_pipeline_malformed_capture_graceful_handling(tmp_path):
    """Test analyzer behavior on truncated/corrupted packet frame."""
    corrupted_pcap = tmp_path / "malformed.pcap"
    corrupted_pcap.write_bytes(b"PK\x00\x00InvalidPacketData")

    provider = ScapyProvider()
    with patch("scapy.utils.rdpcap", side_effect=Exception("Scapy packet parsing failed: Truncated frame")):
        record = provider.analyze_pcap(str(corrupted_pcap))

    assert record.provider == "scapy"
    assert record.status == ProviderStatus.FAILED
    assert record.error is not None
    assert any(msg in record.error.lower() for msg in ["truncated frame", "failed", "not a supported"])

