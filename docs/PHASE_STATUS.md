# E.M.I.T. Phase Status & Implementation Audits

This document maps E.M.I.T.'s current monorepo features against the official 19-phase roadmap. It details active integrations, database structures, placeholders, and manual test records.

---

## 1. Official Phase Status Registry

| Phase | Expected Scope | Current Implementation | Status | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | Project Foundation | Monorepo layout (frontend/ & backend/) with FastAPI and React router | **COMPLETE** | Monorepo directories, `package.json`, health endpoints |
| **Phase 2** | Database & Persistence | MongoDB dynamic resolves, 13 collection definitions, and index initialization | **COMPLETE** | `init_mongodb.py`, `app/db/mongodb.py`, `app/db/repositories/` |
| **Phase 3** | Backend Architecture | Provider registry, AnalysisRun models, exception isolation, timeout configs | **COMPLETE** | `orchestrator.py`, `registry.py`, `test_phase3_pipeline.py` |
| **Phase 4** | Frontend Foundation | Slate+Cyan SOC theme UI, Recharts dashboard widgets, React Flow canvas, topnav | **COMPLETE** | `Layout.tsx`, `Dashboard.tsx`, `AttackGraph.tsx`, Vite build pass |
| **Phase 5** | Case + Evidence Management | Case CRUD APIs/UIs, Axios progress uploader, deletion handler, magic-byte checks | **COMPLETE** | Services, repositories, upload API tests, magic bytes checkers |
| **Phase 6** | APK Static Analysis | Containerized MobSF static analysis, Androguard info extraction, JADX, APKTool | **COMPLETE** | Androguard DEX scans, MobSF API uploads, JADX/APKTool binary checks |
| **Phase 7** | PCAP Analysis | Containerized/local tshark conversations mapping, Scapy packet stream parsing | **COMPLETE** | Scapy packet flows, tshark subprocess extraction, periodic patterns |
| **Phase 8** | Evidence Normalization | Common evidence model (Indicator, Observation, Source, EvidenceRef) with deterministic normalizer | **COMPLETE** | `normalizer.py`, `schemas/normalized.py`, `test_normalizer.py` (5/5 passed) |
| **Phase 9** | Correlation Engine | Deterministic 7-rule engine linking APK, PCAP, and threat intel with human explanations | **COMPLETE** | `correlation_engine.py`, `test_correlation_engine.py` (9/9 passed) |
| **Phase 10**| Attack Chain Reconstruction| Graph topology (nodes/edges), evidence references, chronological sequence | **COMPLETE** | `attack_reconstructor.py`, `test_attack_chain.py` (4/4 passed) |
| **Phase 11**| Threat Intelligence | External enrichment (VT, URLhaus, AbuseIPDB, OTX) with caching & relevance filter | **COMPLETE** | `threat_intel/`, `test_threat_intel.py` (7/7 passed) |
| **Phase 12**| Risk + Explainability | Deterministic evidence-weighted scoring (LOW, MED, HIGH, CRIT) & explainability | **COMPLETE** | `risk_engine.py`, `test_risk_engine.py` (6/6 passed) |
| **Phase 13**| Investigation UI / Graph | React Flow interactive Attack Graph canvas, 12-section workspace & evidence inspector | **COMPLETE** | `AttackGraphCanvas.tsx`, `InvestigationDetails.tsx`, `GET /cases/{id}/observations` |
| **Phase 14**| Reports | Dual HTML & ReportLab PDF investigation dossier generation | **COMPLETE** | `report_generator.py`, `test_report_generator.py` (4/4 passed), `Reports.tsx` |
| **Phase 15**| Testing | E2E integration test verification coverage | **COMPLETE** | 80 backend pytest passes (pipelines, 7 rules, security, matching & non-matching E2E) + 7 frontend Vitest passes + clean Vite build |
| **Phase 16**| Security Hardening Review | Defensive scope, path traversal isolation, secret masking, 17/17 security checklist | **COMPLETE** | `SECURITY.md`, `test_security_comprehensive.py` (8/8 passed), filename sanitizer, tshark -n flag |
| **Phase 17**| Deployment | Docker compose and environment configurations | **PARTIAL** | local docker-compose MongoDB environment compose configs |
| **Phase 18**| Complete Documentation | 14 authoritative manuals, architecture, pipeline, models, security, limitations | **COMPLETE** | `README.md`, `ARCHITECTURE.md`, `DEVELOPMENT_SETUP.md`, `SECURITY.md`, and 10 detailed guides in `docs/` |
| **Phase 19**| Final Completion Audit | Overall system verification review | **NOT STARTED** | Pending future execution milestones |

---

## 2. Database Architecture Status

MongoDB is E.M.I.T.'s final authoritative persistent datastore. Local MongoDB instances and MongoDB Atlas cloud instances are supported. PyMongo acts as the database driver and repository persistence layer.

There are **zero runtime dependencies** on:
*   Supabase / Supabase Storage
*   PostgreSQL / psycopg
*   SQLite
*   SQLAlchemy

All metadata and investigation records are saved in 13 MongoDB collections (configured in `backend/scripts/init_mongodb.py`):
1.  `cases`
2.  `evidence_files`
3.  `analysis_runs`
4.  `apk_analyses`
5.  `network_analyses`
6.  `indicators`
7.  `observations`
8.  `correlations`
9.  `attack_nodes`
10. `attack_edges`
11. `threat_intelligence`
12. `risk_assessments`
13. `reports`

---

## 3. Evidence Provenance Traceability

E.M.I.T.'s database schema maps entities to support tracing security findings to their origin:

```text
Case (cases collection via case_id)
  │
  └──► Evidence File (evidence_files collection via evidence_id)
        │
        └──► Analysis Run (analysis_runs collection via case_id + evidence_id)
              │
              └──► Observation (observations collection via case_id + evidence_id)
                    │
                    └──► Indicator (indicators collection via indicator_id)
```

Every observation generated by the static decompilers maps back to a unique case record and source file, ensuring forensic chain-of-custody.

---

## 4. Phase 6 & 7 Analysis Providers Status

| Analyzer Provider | Type | Classification | Status & Verification Details |
| :--- | :--- | :--- | :--- |
| **Androguard** | DEX/Manifest | **IMPLEMENTED + VERIFIED** | Parses APK structures, manifest components, permissions, SDKs, certs, and scans DEX bytes for URLs/IPs. Verified via `test_apk_static_analysis.py`. |
| **Scapy** | Network Packet | **IMPLEMENTED + VERIFIED** | Parses PCAP packet counts, timestamps, protocol streams, DNS queries/A-records, and calculates periodic beacon patterns. Verified via `test_pcap_analysis.py`. |
| **MobSF** | Containerized REST | **IMPLEMENTED + RUNTIME VERIFICATION PENDING** | Core HTTPX client routines written. Uploads file, scans, and parses JSON report. Complete verification requires connection to a running container. |
| **Tshark** | Network Packet | **CHECK-ONLY / E2E VERIFIED** | Checks PATH command-line availability on host system to report network scanner status and parses captures when available. |
| **JADX** | Java Decompiler | **CHECK-ONLY** | Checks PATH command-line availability on host system to report decompiler status. |
| **APKTool** | Resources unpacker | **CHECK-ONLY** | Checks PATH command-line availability on host system to report resource scanner status. |

---

## 5. Testing Taxonomy & E2E Verification

*   **Mock / Unit Tests (VERIFIED)**: Programmatic extraction, database writing, API triggers, and error mappings are covered by 59 automated Pytest unit tests. Scapy/Androguard parsing parameters are mocked/patched to guarantee isolated tests, `test_normalizer.py` validates value determinism and cross-source convergence, `test_correlation_engine.py` validates deterministic rules 1-7, `test_attack_chain.py` validates node/edge topologies, `test_threat_intel.py` validates enrichment, `test_risk_engine.py` validates deterministic risk tiers, and `test_report_generator.py` validates reproducible HTML and ReportLab PDF dossier generation across all 13 required forensic sections.
*   **Real Payload E2E Verification (MANUAL / PENDING)**: Verification against actual APK binaries and PCAP logs on physical filesystems is marked as manual/pending. Payloads are uploaded and stored in `backend/storage/`, but comprehensive static decompiler and packet scanning E2E checks rely on active Docker/MobSF containers and local tshark CLI tools.

---

## 6. Ready for Phase 15 (Testing & E2E Integration)

**`PHASE 14 STATUS: IMPLEMENTED & READY FOR PHASE 15`**

All Phase 6 (APK Analysis), Phase 7 (PCAP Analysis), Phase 8 (Evidence Normalization), Phase 9 (Correlation Engine), Phase 10 (Attack Chain Reconstruction), Phase 11 (Threat Intelligence Enrichment), Phase 12 (Risk + Explainability Engine), Phase 13 (Investigation UI & React Flow Attack Graph Canvas), and Phase 14 (Forensic Investigation Report Generator) pipeline modules, evidence inspectors, interactive graph topologies, and reproducible HTML/PDF export capabilities are established. The system is ready to expand End-to-End integration testing coverage.
