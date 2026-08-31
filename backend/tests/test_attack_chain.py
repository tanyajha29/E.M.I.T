import pytest
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from app.main import app
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.attack_repository import AttackNodeRepository, AttackEdgeRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.schemas.attack_graph import NodeType, RelationshipType, RelationshipClass
from app.schemas.normalized import ObservationType
from app.services.attack_reconstructor import AttackChainReconstructor
from app.services.correlation_engine import CorrelationEngine

client = TestClient(app)

def test_attack_chain_node_types_and_observed_edges():
    """Verify generation of all required node types and observed edges."""
    obs_repo = ObservationRepository()
    node_repo = AttackNodeRepository()
    edge_repo = AttackEdgeRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-graph-observed-001"
    obs_repo.collection.delete_many({"case_id": case_id})
    node_repo.collection.delete_many({"case_id": case_id})
    edge_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    apk_ev = "ev-apk-100"
    pcap_ev = "ev-pcap-100"

    t0 = datetime(2026, 8, 29, 10, 0, 0)

    # 1. APK Application Package observation
    obs_repo.insert_one({
        "observation_id": "obs-pkg-1",
        "case_id": case_id,
        "indicator_id": "ind-pkg-1",
        "evidence_id": apk_ev,
        "observation_type": ObservationType.PACKAGE_NAME.value,
        "source": "APK",
        "value": "com.threat.sample",
        "timestamp": t0.isoformat()
    })

    # 2. Permission
    obs_repo.insert_one({
        "observation_id": "obs-perm-1",
        "case_id": case_id,
        "indicator_id": "ind-perm-1",
        "evidence_id": apk_ev,
        "observation_type": ObservationType.DECLARED_PERMISSION.value,
        "source": "APK",
        "value": "android.permission.INTERNET",
        "timestamp": t0.isoformat()
    })

    # 3. Capability
    obs_repo.insert_one({
        "observation_id": "obs-cap-1",
        "case_id": case_id,
        "indicator_id": "ind-cap-1",
        "evidence_id": apk_ev,
        "observation_type": ObservationType.CAPABILITY.value,
        "source": "APK",
        "value": "SEND_SMS_OVER_NETWORK",
        "timestamp": t0.isoformat()
    })

    # 4. API
    obs_repo.insert_one({
        "observation_id": "obs-api-1",
        "case_id": case_id,
        "indicator_id": "ind-api-1",
        "evidence_id": apk_ev,
        "observation_type": ObservationType.SUSPICIOUS_API.value,
        "source": "APK",
        "value": "Ljava/net/Socket;->connect",
        "timestamp": t0.isoformat()
    })

    # 5. Embedded Domain
    obs_repo.insert_one({
        "observation_id": "obs-dom-1",
        "case_id": case_id,
        "indicator_id": "ind-dom-1",
        "evidence_id": apk_ev,
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "c2-control.net",
        "timestamp": t0.isoformat()
    })

    # 6. Embedded IP
    obs_repo.insert_one({
        "observation_id": "obs-ip-1",
        "case_id": case_id,
        "indicator_id": "ind-ip-1",
        "evidence_id": apk_ev,
        "observation_type": ObservationType.EMBEDDED_IP.value,
        "source": "APK",
        "value": "198.51.100.77",
        "timestamp": t0.isoformat()
    })

    # 7. PCAP DNS Query
    t1 = t0 + timedelta(minutes=5)
    obs_repo.insert_one({
        "observation_id": "obs-dns-q-1",
        "case_id": case_id,
        "indicator_id": "ind-dom-1",
        "evidence_id": pcap_ev,
        "observation_type": ObservationType.DNS_QUERY.value,
        "source": "PCAP",
        "value": "c2-control.net",
        "timestamp": t1.isoformat()
    })

    # 8. PCAP DNS Response (c2-control.net -> 198.51.100.77)
    obs_repo.insert_one({
        "observation_id": "obs-dns-resp-1",
        "case_id": case_id,
        "indicator_id": "ind-ip-1",
        "evidence_id": pcap_ev,
        "observation_type": ObservationType.DNS_RESPONSE.value,
        "source": "PCAP",
        "value": "198.51.100.77",
        "timestamp": t1.isoformat(),
        "metadata": {"resolved_for": "c2-control.net"}
    })

    # 9. PCAP Network Traffic
    t2 = t0 + timedelta(minutes=6)
    obs_repo.insert_one({
        "observation_id": "obs-net-1",
        "case_id": case_id,
        "indicator_id": "ind-ip-1",
        "evidence_id": pcap_ev,
        "observation_type": ObservationType.NETWORK_IP.value,
        "source": "PCAP",
        "value": "198.51.100.77",
        "timestamp": t2.isoformat()
    })

    # 10. PCAP Periodic Repeated Communication
    obs_repo.insert_one({
        "observation_id": "obs-rep-1",
        "case_id": case_id,
        "indicator_id": "ind-ip-1",
        "evidence_id": pcap_ev,
        "observation_type": ObservationType.REPEATED_COMMUNICATION.value,
        "source": "PCAP",
        "value": "198.51.100.77",
        "timestamp": t2.isoformat(),
        "metadata": {"packet_count": 30, "pattern_classification": "suspicious communication pattern"}
    })

    # Execute Correlation first so correlations exist
    correlations = CorrelationEngine.correlate(case_id, correlation_repo=corr_repo, observation_repo=obs_repo, indicator_repo=ind_repo)
    assert len(correlations) > 0

    # Reconstruct Attack Graph
    graph = AttackChainReconstructor.reconstruct(
        case_id,
        correlations=correlations,
        node_repo=node_repo,
        edge_repo=edge_repo,
        obs_repo=obs_repo,
        ind_repo=ind_repo,
        corr_repo=corr_repo
    )

    assert graph["nodes_count"] >= 7
    assert graph["edges_count"] >= 8

    # Verify Node Types present
    node_types = set(n["node_type"] for n in graph["nodes"])
    assert NodeType.APPLICATION.value in node_types
    assert NodeType.PERMISSION.value in node_types
    assert NodeType.CAPABILITY.value in node_types
    assert NodeType.API.value in node_types
    assert NodeType.DOMAIN.value in node_types
    assert NodeType.IP.value in node_types
    assert NodeType.DNS_EVENT.value in node_types
    assert NodeType.NETWORK_EVENT.value in node_types

    # Verify Relationship Types
    rel_types = set(e["relationship_type"] for e in graph["edges"])
    assert RelationshipType.CONTAINS.value in rel_types
    assert RelationshipType.USES.value in rel_types
    assert RelationshipType.EMBEDS.value in rel_types
    assert RelationshipType.OBSERVED_IN.value in rel_types
    assert RelationshipType.RESOLVES_TO.value in rel_types
    assert RelationshipType.CONNECTS_TO.value in rel_types
    assert RelationshipType.REPEATS.value in rel_types

    # Verify Strict Separation of OBSERVED vs INFERRED
    observed_edges = [e for e in graph["edges"] if e["relationship_class"] == RelationshipClass.OBSERVED.value]
    inferred_edges = [e for e in graph["edges"] if e["relationship_class"] == RelationshipClass.INFERRED.value]
    correlated_edges = [e for e in graph["edges"] if e["relationship_class"] == RelationshipClass.CORRELATED.value]

    assert len(observed_edges) > 0
    assert len(inferred_edges) > 0
    assert len(correlated_edges) > 0

    # Check that INFERRED edges represent the cross-evidence attack chain
    for inf_edge in inferred_edges:
        assert "Inferred" in inf_edge["reason"]
        # Ensure it points to supporting correlation / observations
        assert len(inf_edge["supporting_correlation_ids"]) > 0 or len(inf_edge["supporting_observation_ids"]) > 0

    # Verify all important edges have supporting evidence references
    for edge in graph["edges"]:
        assert len(edge["supporting_evidence_ids"]) > 0 or len(edge["supporting_observation_ids"]) > 0
        assert edge["reason"] != ""

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    node_repo.collection.delete_many({"case_id": case_id})
    edge_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_chronological_ordering_of_sequence():
    """Verify chronological sequence when timestamps are available."""
    obs_repo = ObservationRepository()
    node_repo = AttackNodeRepository()
    edge_repo = AttackEdgeRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-graph-chrono-002"
    obs_repo.collection.delete_many({"case_id": case_id})
    node_repo.collection.delete_many({"case_id": case_id})
    edge_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    t_apk = datetime(2026, 8, 29, 12, 0, 0)
    t_dns = datetime(2026, 8, 29, 12, 10, 0)
    t_conn = datetime(2026, 8, 29, 12, 15, 0)

    obs_repo.insert_one({
        "observation_id": "obs-apk-time",
        "case_id": case_id,
        "indicator_id": "ind-dom-t",
        "evidence_id": "ev-apk",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "time-ordered.org",
        "timestamp": t_apk.isoformat()
    })

    obs_repo.insert_one({
        "observation_id": "obs-pcap-dns-time",
        "case_id": case_id,
        "indicator_id": "ind-dom-t",
        "evidence_id": "ev-pcap",
        "observation_type": ObservationType.DNS_QUERY.value,
        "source": "PCAP",
        "value": "time-ordered.org",
        "timestamp": t_dns.isoformat()
    })

    obs_repo.insert_one({
        "observation_id": "obs-pcap-conn-time",
        "case_id": case_id,
        "indicator_id": "ind-ip-t",
        "evidence_id": "ev-pcap",
        "observation_type": ObservationType.NETWORK_IP.value,
        "source": "PCAP",
        "value": "198.51.100.99",
        "timestamp": t_conn.isoformat()
    })

    graph = AttackChainReconstructor.reconstruct(
        case_id,
        node_repo=node_repo,
        edge_repo=edge_repo,
        obs_repo=obs_repo,
        ind_repo=ind_repo,
        corr_repo=corr_repo
    )

    chrono_seq = graph["chronological_sequence"]
    assert len(chrono_seq) >= 2

    # Assert sequence indices are strictly ascending
    indices = [item["sequence_index"] for item in chrono_seq]
    assert indices == list(range(1, len(indices) + 1))

    # Assert timestamps are chronological
    timestamps = [datetime.fromisoformat(item["timestamp"]) for item in chrono_seq]
    for i in range(len(timestamps) - 1):
        assert timestamps[i] <= timestamps[i + 1]

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    node_repo.collection.delete_many({"case_id": case_id})
    edge_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_determinism_and_no_duplicate_nodes():
    """Verify graph generation is 100% deterministic with zero duplicate nodes on re-run."""
    obs_repo = ObservationRepository()
    node_repo = AttackNodeRepository()
    edge_repo = AttackEdgeRepository()
    corr_repo = CorrelationRepository()
    ind_repo = IndicatorRepository()

    case_id = "test-case-graph-determinism-003"
    obs_repo.collection.delete_many({"case_id": case_id})
    node_repo.collection.delete_many({"case_id": case_id})
    edge_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})

    obs_repo.insert_one({
        "observation_id": "obs-repeat-1",
        "case_id": case_id,
        "indicator_id": "ind-det-1",
        "evidence_id": "ev-apk",
        "observation_type": ObservationType.EMBEDDED_DOMAIN.value,
        "source": "APK",
        "value": "deterministic-test.com",
        "timestamp": datetime.utcnow().isoformat()
    })

    # Run 1
    g1 = AttackChainReconstructor.reconstruct(
        case_id, node_repo=node_repo, edge_repo=edge_repo, obs_repo=obs_repo, ind_repo=ind_repo, corr_repo=corr_repo
    )

    # Run 2
    g2 = AttackChainReconstructor.reconstruct(
        case_id, node_repo=node_repo, edge_repo=edge_repo, obs_repo=obs_repo, ind_repo=ind_repo, corr_repo=corr_repo
    )

    assert g1["nodes_count"] == g2["nodes_count"]
    assert g1["edges_count"] == g2["edges_count"]

    # Verify no duplicate nodes in database
    db_nodes = node_repo.find_all({"case_id": case_id})
    assert len(db_nodes) == g1["nodes_count"]

    # Cleanup
    obs_repo.collection.delete_many({"case_id": case_id})
    node_repo.collection.delete_many({"case_id": case_id})
    edge_repo.collection.delete_many({"case_id": case_id})
    corr_repo.collection.delete_many({"case_id": case_id})


def test_api_graph_endpoint():
    """Verify GET /cases/{case_id}/graph returns full topology payload."""
    # 1. Create Case
    res = client.post("/cases", json={"name": "Graph API Case", "description": "Verify graph API"})
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # Query graph
    res = client.get(f"/cases/{case_id}/graph")
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
    assert "chronological_sequence" in data
    assert data["case_id"] == case_id
