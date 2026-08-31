# E.M.I.T. Forensic Platform - Comprehensive Test Report

**Phase 15 Verification Suite**  
**Execution Timestamp:** 2026-08-31T22:37:31+05:30  
**Environment:** Windows 11, Python 3.13.7, Node v22.20.0, MongoDB 7.0 (Local Engine)

---

## 1. Executive Test Summary Metrics

| Test Suite Category | Total Tests | Passed | Failed | Skipped | Execution Time |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Backend Integration & Unit (pytest)** | 80 | 80 | 0 | 0 | 48.27s |
| **Frontend Component Suite (Vitest)** | 7 | 7 | 0 | 0 | 3.87s |
| **Frontend Production Build (`tsc && vite build`)** | 1 | 1 | 0 | 0 | 15.60s |
| **Total Automated Quality Gates** | **88** | **88** | **0** | **0** | **67.74s** |

---

## 2. Test Coverage by Functional Area

### A. Backend Pipeline & Forensic Engines (80 Tests)

1. **APK Analysis Pipeline (`test_apk_pipeline_comprehensive.py`, `test_apk_static_analysis.py`)**:
   * Valid APK structure upload & extraction (`PK\x03\x04` validation, SHA-256 computation).
   * Rejection of invalid APK magic bytes (e.g. PE/ELF masquerading as `.apk` returns HTTP 400).
   * Graceful degradation on corrupted ZIP payload (fails safely with `ProviderStatus.FAILED` without crashing FastAPI).
   * Clean handling of disabled APK providers (`ProviderStatus.DISABLED`).
   * Clean handling of missing local dependencies (`ProviderStatus.UNAVAILABLE`).

2. **PCAP Capture Pipeline (`test_pcap_pipeline_comprehensive.py`, `test_pcap_analysis.py`)**:
   * Valid standard libpcap format (`0xa1b2c3d4` / `0xd4c3b2a1` headers accepted).
   * Valid PCAPNG format (`0x0a0d0d0a` section header block accepted).
   * Rejection of invalid PCAP magic bytes with HTTP 400.
   * Header-only empty PCAP parsing (0 packets parsed with zero uncaught exceptions).
   * Truncated/corrupted packet frame graceful degradation (`ProviderStatus.FAILED` without process crash).

3. **Deterministic Evidence Correlation Engine (`test_correlation_comprehensive.py`, `test_correlation_engine.py`)**:
   * **Rule 1 (Domain Match)**: APK embedded domain == PCAP DNS query.
   * **Rule 1 (Negative)**: Non-matching domain produces exact zero correlations.
   * **Rule 2 (IP Match)**: APK embedded IP == PCAP destination IP.
   * **Rule 2 (Negative)**: Non-matching IP produces exact zero correlations.
   * **Rule 3 (Resolved IP Match)**: APK domain resolves to observed PCAP endpoint.
   * **Rule 4 (Capability Match)**: Declared network permission aligns with network flow.
   * **Rule 5 (Repeated Communication)**: Periodic beaconing flows corroborated with APK indicators.
   * **Rule 6 (Temporal Relationship)**: Corroboration within temporal proximity window (< 1 hr).
   * **Rule 7 (Multi-Source Corroboration)**: 3+ independent tools/sources elevates relationship to `STRONG`.
   * **External Threat Intel Linkage**: Links indicators to external feed records without machine learning.

4. **Security, Robustness & Boundary Validation (`test_security_comprehensive.py`)**:
   * **Unsupported File Formats**: Rejection of `.exe`, `.sh`, `.bat`, `.dll`, `.pdf` with HTTP 400.
   * **Oversized File Rejection**: Hard file size limit enforcement (`MAX_EVIDENCE_SIZE_BYTES = 500MB`) returning HTTP 400.
   * **Path Traversal Prevention**: Strips `../../` and `..\..\` path traversal characters; guarantees all saved files remain within `storage/`.
   * **Cryptographic Deduplication**: Re-uploading identical SHA-256 within the same case context rejected with HTTP 409 Conflict.
   * **Malformed Request Protection**: Pydantic validation rejects invalid schema types with HTTP 422.
   * **Nonexistent Identifier Protection**: Non-existent case, evidence, analysis run, and report IDs return HTTP 404.

5. **Attack Chain Reconstructor (`test_attack_chain.py`)**:
   * Multi-type graph nodes (`APPLICATION`, `DOMAIN`, `IP`, `CAPABILITY`, `EVENT`, `THREAT_INTEL`).
   * Explicit edge classes: `OBSERVED`, `CORRELATED`, `INFERRED`.
   * Chronological sequencing of forensic events where authentic timestamps exist.

6. **Deterministic Risk & Explainability Engine (`test_risk_engine.py`)**:
   * Multi-category accumulation (suspicious permissions, API calls, C2 domains, repeated flows).
   * Deterministic tier thresholds: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
   * Calibrated confidence scoring ($0.50 - 0.95$).
   * Explicit separation of observed facts from analytical inferences.

7. **Forensic Report Generator (`test_report_generator.py`)**:
   * Jinja2 HTML dossier rendering containing all 13 required forensic sections.
   * ReportLab PDF generation with running header, two-pass footer ("Page X of Y"), and confidentiality banners.
   * Dual-format generation (`BOTH`) and streaming REST download endpoints.

8. **End-to-End Forensic Verification Scenarios (`test_e2e_scenarios.py`)**:
   * **Scenario 1: `SuspiciousApp.apk` + `authorized_investigation.pcap`**:
     * Complete lifecycle: Case creation $\to$ Evidence uploads $\to$ Analysis extraction $\to$ Normalization $\to$ Deterministic Correlations (`DOMAIN_MATCH`, `IP_MATCH`, `PERIODIC_COMMUNICATION_MATCH`) $\to$ Attack Graph reconstruction $\to$ Risk Engine elevation (`HIGH`/`CRITICAL`) $\to$ Dual HTML & PDF report generation.
   * **Scenario 2: `NonMatchingApp.apk` + `unrelated.pcap`**:
     * Benign app + unrelated traffic: **Exact ZERO fabricated correlations**, disconnected graph components, **`LOW`** risk level rating.

---

### B. Frontend Component Suite (7 Tests)

* **Loading State**: Displays animated spinner and forensic stage message (`Extracting forensic artifacts...`).
* **Empty State**: Displays dedicated empty state placeholder when zero attack graph nodes exist.
* **Error State**: Renders contextual error alert banner with retry callback handler.
* **Success State**: Displays completion badge and full SHA-256 hash provenance string.
* **Attack Graph Canvas**: Validates React Flow canvas rendering, legend components, node types, and edge styles (`OBSERVED`, `CORRELATED`, `INFERRED`).
* **Authentic Timeline**: Renders chronological event items with timestamps and source tags.
* **Report Generator Form**: Validates format selection dropdown (`BOTH`, `HTML`, `PDF`) and report compilation submission.

---

## 3. Known Limitations & Technical Constraints

1. **Passive Execution Blind Spots**:
   * Static APK analysis cannot observe runtime payload unpacking or reflection-loaded DEX code not statically present in the APK archive.
2. **Encrypted TLS Payloads**:
   * PCAP packet analysis inspects layer 3/4 headers, DNS queries, and flow timing, but cannot inspect encrypted HTTPS/TLS payload bodies without an active MITM proxy certificate installed on the device.
3. **Periodic Traffic Heuristics**:
   * Repeated network communications detect periodic intervals, but benign mobile keepalive connections (e.g. Firebase Cloud Messaging / push notifications) may exhibit periodic patterns. Correlation with APK static bytecode is required to distinguish benign keepalives from C2 traffic.
4. **Rate-Limited Threat Intelligence Providers**:
   * Free API tiers (e.g., VirusTotal Public API limit of 4 requests/min) are subject to rate limiting. E.M.I.T. implements client-side 24-hour caching and graceful degradation when quotas are exceeded.

---

## 4. Manual Testing Verification Procedures

| Step | Test Objective | Procedure | Expected Verification | Result |
| :--- | :--- | :--- | :--- | :---: |
| 1 | Case Creation | Navigate to `/investigations`, click "New Investigation", enter title & description. | Case appears in case list with status `OPEN` and unique UUID. | **PASS** |
| 2 | Evidence Upload | Open case, switch to "Uploaded Evidence" tab, upload APK and PCAP files. | Progress bar completes, SHA-256 hash displayed, file size rendered. | **PASS** |
| 3 | Static Analysis | Switch to "Analysis Jobs" tab, trigger analysis with Androguard/Scapy. | Job transitions from `QUEUED` $\to$ `RUNNING` $\to$ `COMPLETED`. | **PASS** |
| 4 | Attack Graph Interaction | Navigate to "Attack Graph" tab, zoom/pan canvas, click node and edge. | Details drawer opens displaying entity, relationship class, and supporting evidence IDs. | **PASS** |
| 5 | Threat Intel Enrichment | Open "Threat Intelligence" tab, trigger IOC enrichment. | Verdicts, scores, and categories render with badges; cache flags displayed. | **PASS** |
| 6 | Risk Engine Inspection | Open "Risk Assessment" tab. | Risk level badge, confidence score, observed facts, inferences, uncertainty, and guidance render. | **PASS** |
| 7 | Report Export | Open "Reports" tab, click "Compile Forensic Report" (`BOTH`). | HTML report opens in new tab; PDF report downloads with 13 formatted sections and headers/footers. | **PASS** |
