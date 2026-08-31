# E.M.I.T. System Architecture Specification

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Architecture Paradigm:** Decoupled Forensic Pipelines, Event-Driven Normalization, Deterministic Correlation  
**Target Environments:** SOC Analyst Workstations, Air-Gapped DFIR Laboratories, Hybrid Cloud VPCs

---

## 1. Executive System Topology

E.M.I.T. is engineered as a multi-tier, modular forensic investigation system:

```text
       +--------------------------------------------------------------------+
       |                   React 18 + TypeScript Frontend                   |
       |  (12-Tab Forensic Workspace, React Flow Canvas, Report Center)     |
       +---------------------------------+----------------------------------+
                                         │  HTTP / REST JSON
                                         ▼
       +--------------------------------------------------------------------+
       |                      FastAPI API Gateway & Auth                    |
       |  (Schema Enforcement, Boundary Validation, Error Sanitization)     |
       +---------------------------------+----------------------------------+
                                         │
                                         ▼
       +--------------------------------------------------------------------+
       |                     Orchestration Subsystem                        |
       |               (AnalysisOrchestrator, Job Queue)                    |
       +--------+------------------------+------------------------+---------+
                │                        │                        │
                ▼                        ▼                        ▼
     [ Static APK Pipeline ]   [ PCAP Network Pipeline ]  [ Threat Intel ]
     ├─ Androguard (Local)     ├─ Scapy Engine            ├─ VirusTotal
     ├─ MobSF (Docker REST)    └─ Tshark Dissector (-n)   ├─ URLhaus
     ├─ JADX Decompiler                                   ├─ AbuseIPDB
     └─ APKTool Resource Parser                           └─ AlienVault OTX
                │                        │                        │
                └────────────────────────┼────────────────────────┘
                                         ▼
       +--------------------------------------------------------------------+
       |                    Evidence Normalizer Subsystem                   |
       |      (Common Evidence Model: Indicators, Observations, Hashes)     |
       +---------------------------------+----------------------------------+
                                         │
                                         ▼
       +--------------------------------------------------------------------+
       |               Deterministic Correlation Engine (7 Rules)           |
       |        (Evidence Linkage, Zero Machine Learning / Hallucination)   |
       +---------------------------------+----------------------------------+
                                         │
                                         ▼
       +--------------------------------------------------------------------+
       |                 Attack Chain Reconstructor (DAG)                   |
       |        (React Flow Nodes/Edges, Chronological Sequencing)          |
       +---------------------------------+----------------------------------+
                                         │
                                         ▼
       +--------------------------------------------------------------------+
       |                Deterministic Risk & Explainability Engine          |
       |      (Evidence Weighting, Ground-Truth Facts vs Inferences)        |
       +---------------------------------+----------------------------------+
                                         │
                                         ▼
       +--------------------------------------------------------------------+
       |                    Investigation Report Generator                  |
       |             (Dual Jinja2 HTML & ReportLab PDF Dossiers)            |
       +---------------------------------+----------------------------------+
                                         │
                ┌────────────────────────┴────────────────────────┐
                ▼                                                 ▼
   +--------------------------+                      +--------------------------+
   |   MongoDB Persistence    |                      |   Physical Storage       |
   | (13 Collections, UUIDs)  |                      | (storage/ Encrypted Dir) |
   +--------------------------+                      +--------------------------+
```

---

## 2. End-to-End Forensic Data Lifecycle

```
[1. Evidence Upload] ──> [2. Pre-Flight Validation] ──> [3. Provider Dispatch]
                                                               │
┌──────────────────────────────────────────────────────────────┘
▼
[4. Static/Network Extraction] ──> [5. Evidence Normalization]
                                            │
┌───────────────────────────────────────────┘
▼
[6. Deterministic Correlation] ──> [7. Attack Graph Reconstruction]
                                            │
┌───────────────────────────────────────────┘
▼
[8. Threat Intel Enrichment] ──> [9. Deterministic Risk Assessment]
                                            │
┌───────────────────────────────────────────┘
▼
[10. Interactive UI Inspection] ──> [11. Dual HTML/PDF Forensic Report Dossier]
```

---

## 3. Subsystem Breakdown

### A. Presentation Subsystem (`frontend/src/`)
* **Technology**: React 18, TypeScript, Vite, Tailwind CSS, Lucide React.
* **Workspace Engine (`InvestigationDetails.tsx`)**: 12 modular tabs providing deep inspection into case metadata, uploaded evidence, APK findings, network streams, IOCs, correlations, threat intel, risk assessments, attack graph, timeline, and reports.
* **Graph Canvas (`AttackGraphCanvas.tsx`)**: Utilizes React Flow to render custom color-coded nodes (`APPLICATION`, `DOMAIN`, `IP`, `CAPABILITY`, `EVENT`, `THREAT_INTEL`) and edge styles (`OBSERVED`, `CORRELATED`, `INFERRED`).

### B. Core API & Orchestration (`backend/app/`)
* **Technology**: FastAPI, Python 3.13, Pydantic v2, Uvicorn.
* **`AnalysisOrchestrator`**: Dispatches analysis tasks, isolates tool failures into `ProviderStatus.FAILED`, enforces timeout protections, and records step-by-step progress without halting the application.
* **`EvidenceService`**: Computes SHA-256 hashes server-side, validates binary magic bytes, isolates evidence files under `storage/`, and sanitizes filenames to prevent path traversal attacks.

### C. Analytical Engines
1. **`EvidenceNormalizer`**: Converts raw tool outputs into canonical `Indicator` and `Observation` schemas.
2. **`CorrelationEngine`**: Executes 7 deterministic correlation rules (Domain match, IP match, Resolved IP match, Capability match, Periodic beaconing, Temporal alignment, Multi-source corroboration).
3. **`AttackChainReconstructor`**: Assembles directed acyclic graphs (DAGs) linking observed facts to correlated linkages.
4. **`ThreatIntelService`**: Enriches indicators against VirusTotal, URLhaus, AbuseIPDB, and AlienVault OTX with 24-hour deterministic caching.
5. **`RiskEngine`**: Calculates evidence-weighted risk ratings (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with strict separation of observed facts from inferences.
6. **`ReportGeneratorService`**: Compiles reproducible investigation reports in interactive HTML and standalone ReportLab PDF formats.

### D. Persistence & Storage Subsystems
* **Database**: MongoDB 7.0+ managing 13 dedicated collections (`cases`, `evidence_files`, `analysis_runs`, `apk_analyses`, `network_analyses`, `indicators`, `observations`, `correlations`, `attack_nodes`, `attack_edges`, `threat_intelligence`, `risk_assessments`, `reports`).
* **Storage Provider**: `LocalStorageProvider` strictly isolates files inside `backend/storage/`, returning relative paths to prevent internal host directory disclosure.

---

## 4. Key Architectural Guarantees

* **Zero Execution of Untrusted Code**: Malware is statically unpacked and parsed; emulators and `adb` runners are never invoked.
* **Zero Machine Learning**: All risk scores and correlations are mathematically explainable and backed by direct evidence references.
* **Zero Timestamp Fabrication**: Timestamps are extracted solely from authentic capture headers and file signatures.
* **Air-Gapped Autonomous Operation**: The core platform runs completely offline without any external cloud or threat intelligence dependencies.
