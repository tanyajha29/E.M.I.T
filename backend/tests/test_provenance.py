from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_complete_provenance_chain():
    # 1. Create Case
    res = client.post("/cases", json={"name": "Case Trace", "description": "Trace case"})
    assert res.status_code == 201
    case_id = res.json()["case_id"]

    # 2. Save Evidence Metadata
    file_content = b"PK\x03\x04Mock static payload analysis target"
    res = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("target.apk", file_content, "application/octet-stream")}
    )
    assert res.status_code == 201
    evidence_id = res.json()["evidence_id"]

    # 3. Create Analysis Record
    analysis_payload = {
        "case_id": case_id,
        "evidence_id": evidence_id,
        "provider": "mobsf",
        "provider_version": "v3.5",
        "analysis_type": "APK_STATIC",
        "status": "completed",
        "tool_results": {"raw_key": "raw_val"},
        "normalized_summary": {"findings": []}
    }
    res = client.post("/api/v1/internal/analyses", json=analysis_payload)
    assert res.status_code == 201
    analysis_id = res.json()["analysis_id"]

    # 4. Create Indicator
    indicator_payload = {
        "type": "DOMAIN",
        "value": "malicious-c2.com",
        "normalized_value": "malicious-c2.com",
        "metadata": {}
    }
    res = client.post(f"/cases/{case_id}/indicators", json=indicator_payload)
    assert res.status_code == 201
    indicator_id = res.json()["indicator_id"]

    # 5. Create Observation
    obs_payload = {
        "case_id": case_id,
        "indicator_id": indicator_id,
        "evidence_id": evidence_id,
        "observation_type": "C2_DOMAIN",
        "source": "mobsf_decompiler",
        "value": "malicious-c2.com",
        "metadata": {}
    }
    res = client.post("/api/v1/internal/observations", json=obs_payload)
    assert res.status_code == 201
    observation_id = res.json()["observation_id"]

    # 6. Create Correlation
    corr_payload = {
        "case_id": case_id,
        "source_observation_ids": [observation_id],
        "target_observation_ids": [],
        "relationship_type": "C2_HOSTING",
        "strength": "STRONG",
        "reason": "Observed multiple socket actions pointing to domain",
        "supporting_evidence_ids": [evidence_id]
    }
    res = client.post("/api/v1/internal/correlations", json=corr_payload)
    assert res.status_code == 201
    correlation_id = res.json()["correlation_id"]

    # 7. Create Attack Node
    node_payload = {
        "case_id": case_id,
        "node_type": "DOMAIN",
        "label": "malicious-c2.com",
        "entity_reference": indicator_id,
        "metadata": {}
    }
    res = client.post("/api/v1/internal/attack-nodes", json=node_payload)
    assert res.status_code == 201
    node_id = res.json()["node_id"]

    # 8. Create Attack Edge (with relationship_class CORRELATED)
    edge_payload = {
        "case_id": case_id,
        "source_node_id": node_id,
        "target_node_id": node_id,
        "relationship_type": "RESOLVES_TO",
        "relationship_class": "CORRELATED",
        "strength": "STRONG",
        "reason": "Direct lookup match",
        "supporting_observation_ids": [observation_id],
        "supporting_correlation_ids": [correlation_id],
        "supporting_evidence_ids": [evidence_id]
    }
    res = client.post("/api/v1/internal/attack-edges", json=edge_payload)
    assert res.status_code == 201
    edge_id = res.json()["edge_id"]

    # 9. Create Risk Assessment
    risk_payload = {
        "case_id": case_id,
        "risk_level": "HIGH",
        "confidence": 0.9,
        "summary": "Threat threat threat",
        "supporting_observation_ids": [observation_id],
        "supporting_correlation_ids": [correlation_id],
        "supporting_evidence_ids": [evidence_id],
        "limitations": []
    }
    res = client.post("/api/v1/internal/risk-assessments", json=risk_payload)
    assert res.status_code == 201
    risk_assessment_id = res.json()["risk_assessment_id"]

    # 10. Create Report
    report_payload = {
        "case_id": case_id,
        "report_type": "PDF",
        "storage_path": "/storage/reports/report_case.pdf",
        "status": "COMPLETED"
    }
    res = client.post("/api/v1/internal/reports", json=report_payload)
    assert res.status_code == 201
    report_id = res.json()["report_id"]

    # =================================================================
    # VERIFY TRAIL OF EVIDENCE PROVENANCE
    # =================================================================

    # Verify Report connects to Case
    assert report_payload["case_id"] == case_id

    # Verify Risk Assessment references Case, Evidence, Observation, Correlation
    assert risk_payload["case_id"] == case_id
    assert evidence_id in risk_payload["supporting_evidence_ids"]
    assert observation_id in risk_payload["supporting_observation_ids"]
    assert correlation_id in risk_payload["supporting_correlation_ids"]

    # Verify Attack Edge references Nodes, Observations, Correlations, Evidence
    assert edge_payload["case_id"] == case_id
    assert edge_payload["source_node_id"] == node_id
    assert edge_payload["target_node_id"] == node_id
    assert observation_id in edge_payload["supporting_observation_ids"]
    assert correlation_id in edge_payload["supporting_correlation_ids"]
    assert evidence_id in edge_payload["supporting_evidence_ids"]

    # Verify Correlation references Case, Observations, Evidence
    assert corr_payload["case_id"] == case_id
    assert observation_id in corr_payload["source_observation_ids"]
    assert evidence_id in corr_payload["supporting_evidence_ids"]

    # Verify Observation references Case, Evidence, Indicator
    assert obs_payload["case_id"] == case_id
    assert obs_payload["evidence_id"] == evidence_id
    assert obs_payload["indicator_id"] == indicator_id

    # Verify Analysis references Case, Evidence
    assert analysis_payload["case_id"] == case_id
    assert analysis_payload["evidence_id"] == evidence_id
