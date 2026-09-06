# REST API Specification

This document details the RESTful API endpoints exposed by the E.M.I.T. FastAPI backend orchestrator.

- **Base URL**: `http://127.0.0.1:8000`
- **Default Content-Type**: `application/json`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **ReDoc Documentation**: `http://127.0.0.1:8000/redoc`

---

## 1. System Health

### GET `/health`
Returns the operational health of the orchestrator and database connectivity.

**Response `200 OK`**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": {
    "connected": true,
    "database": "emit"
  },
  "providers": {
    "androguard": true,
    "scapy": true,
    "mobsf": true,
    "tshark": true,
    "jadx": true,
    "apktool": true
  }
}
```

---

## 2. Investigation Cases

### GET `/api/cases`
Retrieve a paginated list of forensic cases.

**Query Parameters**:
- `limit` *(optional, integer, default: 50)*
- `skip` *(optional, integer, default: 0)*
- `status` *(optional, string: `OPEN`, `CLOSED`, `ARCHIVED`)*

**Response `200 OK`**:
```json
[
  {
    "id": "66d3a1f9e2b1c4a5f6789012",
    "case_number": "CASE-2026-089",
    "title": "Mobile Banking Trojan Investigation",
    "description": "Analysis of suspicious SMS-stealing APK package and cellular PCAP capture.",
    "investigator": "Analyst Smith",
    "status": "OPEN",
    "tags": ["banking-trojan", "malware", "sms-stealer"],
    "created_at": "2026-08-30T10:15:00Z",
    "updated_at": "2026-08-30T10:30:00Z"
  }
]
```

### POST `/api/cases`
Create a new investigation case.

**Request Body**:
```json
{
  "title": "Operation Nightshade Incident",
  "description": "Seized Android device forensic examination.",
  "investigator": "Analyst Garcia",
  "tags": ["c2-traffic", "apt"]
}
```

**Response `201 Created`**:
```json
{
  "id": "66d3a2a0e2b1c4a5f6789013",
  "case_number": "CASE-2026-090",
  "title": "Operation Nightshade Incident",
  "description": "Seized Android device forensic examination.",
  "investigator": "Analyst Garcia",
  "status": "OPEN",
  "tags": ["c2-traffic", "apt"],
  "created_at": "2026-08-30T10:35:00Z",
  "updated_at": "2026-08-30T10:35:00Z"
}
```

### GET `/api/cases/{case_id}`
Retrieve complete metadata for a specific case by its MongoDB ObjectId or case number.

### PUT `/api/cases/{case_id}`
Update case title, description, or tags.

### POST `/api/cases/{case_id}/close`
Formally mark an investigation case as closed.

---

## 3. Evidence Ingestion & Management

### POST `/api/evidence/upload`
Ingest forensic artifacts (APK or PCAP/PCAPNG) into the secure evidence vault.

- **Content-Type**: `multipart/form-data`
- **Form Fields**:
  - `case_id` *(string, required)*: Associated case identifier.
  - `file` *(binary upload, required)*: Artifact payload (Max 500 MB).

**Response `201 Created`**:
```json
{
  "id": "66d3a37ce2b1c4a5f6789014",
  "case_id": "66d3a1f9e2b1c4a5f6789012",
  "filename": "trojan_dropper.apk",
  "mime_type": "application/vnd.android.package-archive",
  "size_bytes": 14285712,
  "sha256": "3a7b9c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
  "sha1": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
  "md5": "8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b",
  "uploaded_at": "2026-08-30T10:40:12Z"
}
```

### GET `/api/evidence/case/{case_id}`
List all evidence items registered under a specific case.

### GET `/api/evidence/{evidence_id}`
Retrieve evidence record metadata and hash signatures.

### GET `/api/evidence/{evidence_id}/download`
Download the raw artifact from the evidence vault for offline analysis.

---

## 4. Analysis Jobs & Execution

### POST `/api/analyses/run`
Trigger automated parallel analysis for one or more evidence items.

**Request Body**:
```json
{
  "evidence_ids": ["66d3a37ce2b1c4a5f6789014"],
  "providers": ["androguard", "mobsf", "jadx", "apktool"]
}
```

**Response `202 Accepted`**:
```json
{
  "job_ids": [
    "job-ag-66d3a37c-001",
    "job-ms-66d3a37c-002"
  ],
  "status": "QUEUED",
  "message": "Analysis tasks dispatched to execution queue."
}
```

### GET `/api/analyses/{job_id}`
Poll execution status and logs for a running analysis job.

**Response `200 OK`**:
```json
{
  "job_id": "job-ag-66d3a37c-001",
  "provider": "androguard",
  "status": "COMPLETED",
  "execution_time_seconds": 4.12,
  "error": null,
  "completed_at": "2026-08-30T10:41:05Z"
}
```

### GET `/api/analyses/evidence/{evidence_id}`
Retrieve CEM-normalized analysis findings for a specific evidence item.

### GET `/api/analyses/providers/status`
Check provider readiness, container status, and installed tool versions.

---

## 5. Indicators of Compromise (IOCs)

### GET `/api/indicators/case/{case_id}`
Retrieve all de-duplicated indicators extracted from case evidence.

**Response `200 OK`**:
```json
[
  {
    "id": "66d3a4afe2b1c4a5f6789016",
    "case_id": "66d3a1f9e2b1c4a5f6789012",
    "type": "DOMAIN",
    "value": "c2-gate-sync.net",
    "context": "classes.dex hardcoded string",
    "confidence": 0.95,
    "verified": false,
    "first_seen": "2026-08-30T10:41:00Z"
  }
]
```

### POST `/api/indicators/{indicator_id}/verify`
Allows an investigator to manually mark an indicator as verified malicious or false positive.

---

## 6. Correlation Engine

### POST `/api/correlations/run/{case_id}`
Trigger the 7 deterministic correlation rules across all analyzed evidence in the case.

**Response `200 OK`**:
```json
{
  "case_id": "66d3a1f9e2b1c4a5f6789012",
  "correlations_found": 3,
  "rules_evaluated": 7,
  "execution_time_ms": 328
}
```

### GET `/api/correlations/case/{case_id}`
Fetch all correlation events discovered for the case.

**Response `200 OK`**:
```json
[
  {
    "id": "66d3a54ce2b1c4a5f6789018",
    "case_id": "66d3a1f9e2b1c4a5f6789012",
    "rule_id": "R1_APK_NET_OVERLAP",
    "rule_name": "APK Network Overlap",
    "description": "Extracted APK domain matched live PCAP traffic destination.",
    "evidence_sources": [
      "66d3a37ce2b1c4a5f6789014",
      "66d3a3b0e2b1c4a5f6789015"
    ],
    "matched_entity": "c2-gate-sync.net",
    "confidence": 0.90,
    "created_at": "2026-08-30T10:42:15Z"
  }
]
```

---

## 7. Threat Intelligence

### POST `/api/threat-intel/lookup`
Perform an on-demand external reputation query for an IOC (bypassing or utilizing local 24h cache).

**Request Body**:
```json
{
  "indicator_type": "IP",
  "value": "198.51.100.24"
}
```

**Response `200 OK`**:
```json
{
  "value": "198.51.100.24",
  "cached": true,
  "sources": {
    "abuseipdb": {
      "confidence_score": 85,
      "total_reports": 42,
      "country_code": "RO"
    },
    "virustotal": {
      "malicious_votes": 7,
      "harmless_votes": 12
    }
  }
}
```

### GET `/api/threat-intel/case/{case_id}`
Retrieve all threat intelligence reports linked to indicators within a case.

---

## 8. Risk Assessment

### POST `/api/risk-assessment/case/{case_id}`
Recalculate the deterministic risk assessment score for the specified case.

**Response `200 OK`**:
```json
{
  "case_id": "66d3a1f9e2b1c4a5f6789012",
  "risk_score": 82,
  "risk_level": "CRITICAL",
  "confidence": 0.91,
  "factor_breakdown": [
    {
      "factor": "APK_NETWORK_OVERLAP",
      "impact": 25,
      "description": "Communication to C2 domain matched APK string."
    },
    {
      "factor": "MALICIOUS_TI_OVERLAP",
      "impact": 30,
      "description": "Destination IP listed on AbuseIPDB with 85% abuse confidence."
    },
    {
      "factor": "SUSPICIOUS_PERMISSIONS",
      "impact": 20,
      "description": "Declared SEND_SMS and RECORD_AUDIO capabilities."
    },
    {
      "factor": "CERTIFICATE_ANOMALY",
      "impact": 7,
      "description": "Signed with default Android debug key."
    }
  ],
  "evaluated_at": "2026-08-30T10:43:00Z"
}
```

### GET `/api/risk-assessment/case/{case_id}`
Retrieve the latest computed risk assessment for the case.

---

## 9. Attack Graph & Timeline

### POST `/api/attack-graph/build/{case_id}`
Synthesize evidence, indicators, and correlations into a Directed Acyclic Graph (DAG).

### GET `/api/attack-graph/case/{case_id}`
Retrieve Cytoscape.js compatible nodes and edges for the investigation attack graph.

**Response `200 OK`**:
```json
{
  "nodes": [
    { "data": { "id": "apk-1", "label": "bank_update.apk", "type": "APPLICATION" } },
    { "data": { "id": "dom-1", "label": "c2-gate-sync.net", "type": "DOMAIN" } },
    { "data": { "id": "ip-1", "label": "198.51.100.24", "type": "IP" } }
  ],
  "edges": [
    { "data": { "id": "e1", "source": "apk-1", "target": "dom-1", "provenance": "OBSERVED" } },
    { "data": { "id": "e2", "source": "dom-1", "target": "ip-1", "provenance": "CORRELATED" } }
  ]
}
```

### GET `/api/attack-graph/case/{case_id}/timeline`
Retrieve a chronologically sorted array of evidence and network events.

---

## 10. Reports & Dossiers

### POST `/api/reports/generate/{case_id}`
Generate a complete forensic investigation report.

**Request Body**:
```json
{
  "title": "Forensic Examination - Incident 089",
  "include_raw_evidence": false,
  "include_graph_summary": true
}
```

### GET `/api/reports/{report_id}/download/{format}`
Download generated report artifact in the requested format: `pdf`, `html`, `json`, or `csv`.
