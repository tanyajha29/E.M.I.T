import os
import pytest
from datetime import datetime
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.attack_repository import AttackNodeRepository, AttackEdgeRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.schemas.attack_graph import NodeType, RelationshipType, RelationshipClass
from app.schemas.normalized import ObservationType
from app.services.normalizer import EvidenceNormalizer
from app.services.correlation_engine import CorrelationEngine
from app.services.attack_reconstructor import AttackChainReconstructor
from app.services.providers.androguard import AndroguardProvider

def test_androguard_dynamic_package_extraction_dvac():
    """Verify that Androguard extracts the real package name com.zin.dvac from DVACv1.apk."""
    apk_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "test-evidences", "TC-01", "evidences", "DVACv1.apk"))
    if not os.path.exists(apk_path):
        pytest.skip(f"DVACv1.apk not found at {apk_path}")

    provider = AndroguardProvider()
    record = provider.analyze_apk(apk_path)
    assert record.status.value == "COMPLETED"
    assert record.output_metadata.get("package_name") == "com.zin.dvac"
    assert record.output_metadata.get("app_name") == "DVAC"
    assert "android.permission.INTERNET" in record.output_metadata.get("permissions", [])

def test_normalization_and_attack_graph_canonical_package_dvac():
    """Verify that normalizing DVAC evidence creates com.zin.dvac and reconstructs the correct Application node."""
    case_id = "test-case-dvac-canonical-001"
    evidence_apk = "ev-dvac-apk-001"
    evidence_pcap = "ev-dvac-pcap-001"

    obs_repo = ObservationRepository()
    ind_repo = IndicatorRepository()
    node_repo = AttackNodeRepository()
    edge_repo = AttackEdgeRepository()
    corr_repo = CorrelationRepository()

    # Clean up test case data
    obs_repo.delete_many({"case_id": case_id})
    ind_repo.delete_many({"case_id": case_id})
    node_repo.delete_many({"case_id": case_id})
    edge_repo.delete_many({"case_id": case_id})
    corr_repo.delete_many({"case_id": case_id})

    # Mock provider outputs for DVACv1.apk
    dvac_androguard = {
        "package_name": "com.zin.dvac",
        "app_name": "DVAC",
        "permissions": ["android.permission.INTERNET"],
        "ips": ["147.32.83.157"]
    }
    dvac_jadx = {
        "package_name": "com.zin.dvac",
        "packages": ["android.support.v4.app", "android.arch.lifecycle", "com.zin.dvac"],
        "ips": ["147.32.83.157"]
    }
    scapy_pcap = {
        "ips": ["147.32.83.157"]
    }

    # Normalize APK
    EvidenceNormalizer.normalize(
        {"androguard": {"status": "COMPLETED", "output_metadata": dvac_androguard},
         "jadx": {"status": "COMPLETED", "output_metadata": dvac_jadx}},
        case_id,
        evidence_apk,
        ind_repo,
        obs_repo
    )

    # Normalize PCAP
    EvidenceNormalizer.normalize(
        {"scapy": {"status": "COMPLETED", "output_metadata": scapy_pcap}},
        case_id,
        evidence_pcap,
        ind_repo,
        obs_repo
    )

    # Verify PACKAGE_NAME observations only have com.zin.dvac, not android.support.v4
    pkg_obs = obs_repo.find_all({"case_id": case_id, "observation_type": ObservationType.PACKAGE_NAME.value})
    assert len(pkg_obs) > 0
    assert all(o["value"] == "com.zin.dvac" for o in pkg_obs)

    # Correlate
    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)
    assert len(correlations) > 0

    # Reconstruct graph
    graph = AttackChainReconstructor.reconstruct(
        case_id,
        correlations=correlations,
        node_repo=node_repo,
        edge_repo=edge_repo,
        obs_repo=obs_repo,
        ind_repo=ind_repo,
        corr_repo=corr_repo
    )

    # Find APPLICATION node
    app_nodes = [n for n in graph["nodes"] if n["node_type"] == NodeType.APPLICATION.value]
    assert len(app_nodes) == 1
    assert app_nodes[0]["label"] == "com.zin.dvac"
    assert app_nodes[0]["label"] != "com.example.reverseshell2"

    # Find IP node and Network Event node
    ip_nodes = [n for n in graph["nodes"] if n["node_type"] == NodeType.IP.value]
    assert any(n["label"] == "147.32.83.157" for n in ip_nodes)

    net_nodes = [n for n in graph["nodes"] if n["node_type"] == NodeType.NETWORK_EVENT.value]
    assert any("147.32.83.157" in n["label"] for n in net_nodes)

    # Cleanup
    obs_repo.delete_many({"case_id": case_id})
    ind_repo.delete_many({"case_id": case_id})
    node_repo.delete_many({"case_id": case_id})
    edge_repo.delete_many({"case_id": case_id})
    corr_repo.delete_many({"case_id": case_id})
