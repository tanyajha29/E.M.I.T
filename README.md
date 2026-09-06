# E.M.I.T. — Evidence-backed Mobile Investigation Tool

**A Defensive Digital Forensics and Incident Response (DFIR) Platform for Android Application Package (APK) and Packet Capture (PCAP) Cross-Evidence Correlation**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-19-cyan.svg)](https://react.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-teal.svg)](https://fastapi.tiangolo.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-6.0+-green.svg)](https://www.mongodb.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](docker-compose.yml)

---

## 1. Executive Summary

**E.M.I.T. (Evidence-backed Mobile Investigation Tool)** is a specialized DFIR platform designed to solve a fundamental challenge in mobile incident response: **connecting what an application was built to do with what the mobile device actually did on the network**.

Traditional digital forensics often separates mobile reverse engineering from network traffic analysis. E.M.I.T. bridges this gap by ingesting both static Android packages (`.apk`) and dynamic network packet captures (`.pcap`, `.pcapng`), normalizing extracted findings into a unified **Common Evidence Model (CEM)**, running **7 deterministic correlation rules**, calculating an **evidence-weighted risk score (0–100)**, and reconstructing an interactive **Directed Acyclic Graph (DAG)** of the attack chain.

Every indicator, correlation, and risk score in E.M.I.T. is mathematically explainable, defensible, and strictly linked to raw evidence bytes. The platform uses **zero black-box machine learning** and **never executes untrusted APKs on the host system**.

---

## 2. The Real-World DFIR Problem

Mobile incident response teams and SOC analysts frequently face critical investigation hurdles:

```text
┌──────────────────────────────────────┐       ┌──────────────────────────────────────┐
│        Malware Reverse Engineering   │       │         Network Traffic SOC          │
│       (Androguard, MobSF, JADX)      │       │        (Wireshark, Zeek, PCAP)       │
│                                      │       │                                      │
│  • Decompiled DEX Bytecode           │       │  • Millions of raw packet frames     │
│  • Hardcoded strings & IP constants  │       │  • Ephemeral DNS queries             │
│  • Declared Android permissions      │       │  • Periodic outbound TCP/UDP beacons │
└──────────────────┬───────────────────┘       └──────────────────┬───────────────────┘
                   │                                              │
                   └───────────────► [ GAP ] ◄────────────────────┘
                                        │
           "Did THIS specific APK initiate THAT suspicious network traffic?"
```

1. **Tool & Context Fragmentation**: Decompiling an APK reveals hardcoded strings and requested permissions, while analyzing a PCAP file yields raw IP conversations and DNS queries. Correlating a string in `classes.dex` with an outbound TLS handshake on an ephemeral port traditionally requires hours of manual cross-referencing.
2. **The "Black-Box" ML Problem**: Many modern security tools generate opaque threat scores (e.g., `"Threat Score: 87"`) using non-deterministic machine learning. In courtrooms, compliance reviews, and forensic audits, opaque scores without transparent proofs are inadmissible.
3. **Evidence Contamination Risks**: Automated tools that resolve network names during packet analysis inadvertently issue live DNS queries, leaking case indicators to attacker-controlled authoritative nameservers.
4. **Execution Hazards**: Dynamically running untrusted mobile malware on host systems introduces sandbox breakout risks and complex emulator maintenance.

---

## 3. The E.M.I.T. Solution

E.M.I.T. delivers a unified, deterministic, and safe investigation environment:

- **Unified Ingestion**: Upload APK and PCAP evidence into a single case vault with automatic SHA-256, SHA-1, and MD5 cryptographic integrity verification.
- **Common Evidence Model (CEM)**: Converts heterogeneous provider findings (DEX classes, strings, packet streams, DNS records) into standardized, typed indicators.
- **7 Deterministic Correlation Rules**: Transparent, rule-based algorithms detect domain overlaps, permission-to-traffic congruence, malicious threat intelligence hits, shared adversary infrastructure, temporal proximity, debug certificates, and anti-analysis evasion techniques.
- **Evidence-Weighted Risk Engine (0–100)**: Transparent scoring formula separating direct empirical observations from deductive inferences.
- **Interactive DAG Attack Graph**: Cytoscape-driven visualization distinguishing `OBSERVED` (solid), `CORRELATED` (dashed), and `INFERRED` (dotted) relationships.
- **Safe Static & Network Analysis**: Untrusted APKs are never executed. Heavy analysis runs inside an isolated Docker container (`emit-mobsf`), and TShark operates with the `-n` flag to eliminate DNS leakage.
- **Multi-Format Reporting**: One-click generation of court-ready forensic dossiers in HTML, PDF, JSON, and CSV formats.

---

## 4. System Architecture & Processing Pipeline

```mermaid
graph TB
    subgraph Client Tier
        UI["React 19 + TypeScript + Vite<br/>Cybersecurity Analyst Console"]
    end

    subgraph Orchestration Tier
        API["FastAPI Orchestrator (Port 8000)<br/>Async Jobs, REST Endpoints, Reporting"]
        CEM["Common Evidence Model (CEM) Normalizer"]
        Corr["Deterministic Correlation Engine (7 Rules)"]
        Risk["Evidence-Weighted Risk Engine (0-100)"]
        DAG["DAG Attack Graph Reconstructor"]
    end

    subgraph Analysis Runtime Tier
        subgraph Local Execution
            AG["Androguard (DEX AST Parser)"]
            SC["Scapy (Python Packet Dissector)"]
        end
        subgraph Docker Container: emit-mobsf (Port 8001)
            MS["MobSF REST API"]
            TS["TShark CLI (-n Safe Dissection)"]
            JX["JADX Decompiler"]
            AP["APKTool Resource Disassembler"]
        end
    end

    subgraph Threat Intelligence
        TI["TI Broker with 24h Cache<br/>(VirusTotal, URLhaus, AbuseIPDB, AlienVault OTX)"]
    end

    subgraph Persistence Tier
        MDB[("MongoDB (13 Collections)<br/>Cases, Evidence, IOCs, Graphs, Reports")]
        Vault["Evidence Vault Storage<br/>(SHA-256 Path-Confined Storage)"]
    end

    UI <-->|HTTP / REST JSON| API
    API --> Vault
    API --> MDB
    API --> CEM
    CEM --> LocalExecution
    CEM --> DockerContainer
    API --> Corr
    API --> Risk
    API --> DAG
    API --> TI
```

For complete technical architecture, data structures, and database collection definitions, see [Architecture Documentation](docs/architecture.md).

---

## 5. Analysis Providers Matrix

E.M.I.T. orchestrates 6 specialized analysis providers:

| Provider | Target Artifact | Runtime Environment | Key Capabilities |
| :--- | :---: | :---: | :--- |
| **Androguard** | APK | Local Python | Native DEX bytecode parsing, AndroidManifest.xml extraction, permission analysis, string extraction, cryptographic API identification. |
| **MobSF** | APK | Containerized (`emit-mobsf`) | Security manifest analysis, CVSS scoring, certificate anomaly detection, hardcoded secrets discovery, CWE classification. |
| **JADX** | APK | Containerized (`emit-mobsf`) | Structural Java source decompilation, obfuscation detection, reflection call identification. |
| **APKTool** | APK | Containerized (`emit-mobsf`) | Smali bytecode disassembly, raw XML and resource decoding, asset extraction. |
| **Scapy** | PCAP / PCAPNG | Local Python | Native packet dissection, TCP/UDP conversation reconstruction, IP stream reassembly, DNS query extraction. |
| **TShark** | PCAP / PCAPNG | Containerized (`emit-mobsf`) | High-throughput packet parsing, TLS SNI extraction, HTTP host extraction, protocol breakdown via safe `-n` execution. |

---

## 6. Technology Stack

| Layer | Technologies | Purpose |
| :--- | :--- | :--- |
| **Frontend UI** | React 19, TypeScript, Vite, Tailwind CSS, Cytoscape.js, Lucide Icons | Dark-mode cybersecurity analyst workstation, interactive metrics grid, interactive attack graph |
| **Backend API** | FastAPI, Python 3.11+, Pydantic v2, Uvicorn, Jinja2, ReportLab | Asynchronous API gateway, analysis job queue, forensic report generation |
| **Database** | MongoDB 6.0+ (PyMongo repository pattern) | Persistent document store for cases, evidence, IOCs, observations, graphs (13 collections) |
| **Container Runtime**| Docker & Docker Compose (`Dockerfile.analysis`) | Sandboxed execution of MobSF, TShark, JADX, and APKTool |
| **Threat Intelligence**| VirusTotal v3, AbuseIPDB v2, URLhaus, AlienVault OTX | Server-side reputation enrichment with 24-hour local caching |
| **Testing** | Pytest, Vitest | Comprehensive backend unit/integration tests and frontend component tests |

---

## 7. Repository Layout

```text
E.M.I.T/
├── docker-compose.yml              # Analysis container orchestration (emit-mobsf)
├── Dockerfile.analysis             # MobSF + TShark + JADX + APKTool image
├── README.md                       # Primary documentation & getting started
├── SECURITY.md                     # Security architecture, threat model & disclosure
├── docs/                           # Focused technical specifications
│   ├── architecture.md             # System topology, CEM model & MongoDB collections
│   ├── correlation_rules.md        # The 7 deterministic rules & risk scoring engine
│   ├── api.md                      # Complete FastAPI REST API reference
│   └── deployment.md               # Production deployment, Nginx & hardening
├── backend/                        # FastAPI backend application
│   ├── app/
│   │   ├── api/                    # REST route controllers
│   │   ├── core/                   # Configuration, settings & logging
│   │   ├── models/                 # Pydantic data schemas
│   │   ├── repositories/           # PyMongo database access layer
│   │   └── services/               # Orchestrator, correlation, risk, providers
│   ├── scripts/
│   │   └── init_mongodb.py         # Database collection & index initialization
│   ├── requirements.txt            # Python dependencies
│   └── .env.example                # Backend environment variable template
└── frontend/                       # React 19 frontend application
    ├── src/
    │   ├── components/             # Reusable UI cards, tables, badges, modals
    │   ├── pages/                  # Analyst workspace pages (Dashboard, Graph, Cases)
    │   ├── services/               # Typed apiService REST clients
    │   └── types/                  # TypeScript domain models
    ├── package.json                # Frontend dependencies & scripts
    └── vite.config.ts              # Vite bundler configuration
```

---

## 8. Prerequisites & System Requirements

- **Operating System**: Linux (Ubuntu 22.04 LTS+, Debian 12+, RHEL 9+), macOS, or Windows 10/11 (with WSL2 / Docker Desktop).
- **Python**: Version 3.11 or higher.
- **Node.js**: Version 20.x LTS or higher (with `npm`).
- **MongoDB**: Version 6.0 or higher (running locally on port `27017` or via network/Atlas).
- **Docker & Docker Compose**: Docker Engine 24.0+ with Compose V2.

---

## 9. Step-by-Step Installation & Setup

### Step 1: Clone the Repository
```bash
git clone https://github.com/tanyajha29/E.M.I.T.git
cd E.M.I.T
```

### Step 2: Start the Containerized Analysis Runtime
Build and launch the `emit-mobsf` container (combines MobSF, TShark, JADX, and APKTool):
```bash
docker compose up -d --build
```
> [!NOTE]
> The container maps host port `8001` to container port `8000` to prevent any port conflict with the FastAPI backend on port `8000`.

### Step 3: Configure and Launch the Backend
```bash
cd backend

# Create and activate a virtual environment
python -m venv venv

# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env

# Initialize MongoDB collections and compound indexes
python scripts/init_mongodb.py

# Start the FastAPI server
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- **Backend API**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **Health Endpoint**: `http://127.0.0.1:8000/health`

### Step 4: Configure and Launch the Frontend
In a separate terminal window:
```bash
cd frontend

# Install Node dependencies
npm install

# Start Vite development server
npm run dev
```
- **Analyst Workstation UI**: `http://localhost:5173`

---

## 10. Environment Configuration

All environment configurations are managed via `backend/.env`. Key parameters:

| Environment Variable | Default Value | Purpose |
| :--- | :--- | :--- |
| `HOST` | `127.0.0.1` | Host address for FastAPI server binding |
| `PORT` | `8000` | Port for FastAPI backend service |
| `MONGODB_URI` | `mongodb://localhost:27017` | MongoDB connection URI |
| `MONGODB_DATABASE` | `emit` | Primary database name for forensic records |
| `MONGODB_TEST_URI` | `mongodb://localhost:27017` | MongoDB URI used for automated tests |
| `MONGODB_TEST_DATABASE`| `emit_test` | Isolated test database instance |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Allowed browser origins |
| `MOBSF_URL` | `http://localhost:8001` | Host URL for containerized MobSF REST API |
| `MOBSF_API_KEY` | `emit_mobsf_api_key_secret` | Shared secret key for authenticating with MobSF |
| `VIRUSTOTAL_API_KEY` | *(optional)* | External API key for VirusTotal reputation lookups |
| `URLHAUS_API_KEY` | *(optional)* | External API key for URLhaus threat intelligence |
| `ABUSEIPDB_API_KEY` | *(optional)* | External API key for AbuseIPDB reputation queries |
| `OTX_API_KEY` | *(optional)* | External API key for AlienVault OTX pulses |
| `MAX_EVIDENCE_SIZE_BYTES`| `524288000` | Maximum artifact upload limit (500 MB) |
| `ANALYSIS_TIMEOUT_SECONDS`| `180` | Per-provider execution timeout in seconds |
| `THREAT_INTEL_CACHE_HOURS`| `24` | Local cache TTL for external threat intelligence |

> [!IMPORTANT]
> The backend settings require `MONGODB_URI` and `MONGODB_DATABASE`. Legacy variable names such as `MONGO_URI` or `MONGO_DB_NAME` will not be loaded.

---

## 11. Investigation Workflow Walkthrough

```text
[ 1. Create Case ] ──► [ 2. Ingest Evidence ] ──► [ 3. Run Analysis ] ──► [ 4. Correlate & Score ] ──► [ 5. Explore Graph ] ──► [ 6. Export Dossier ]
```

1. **Create Case**: Open the web console at `http://localhost:5173`, select **New Investigation**, and supply a case number, title, and tags.
2. **Ingest Evidence**: Upload suspected Android APK packages (`.apk`) and corresponding network captures (`.pcap`, `.pcapng`). E.M.I.T. validates magic byte headers and computes SHA-256 hashes immediately.
3. **Dispatch Analysis**: Trigger parallel analysis across enabled providers. Androguard and Scapy process locally; MobSF, TShark, JADX, and APKTool process inside the analysis container.
4. **Evaluate Correlations & Risk**: The engine runs the 7 deterministic correlation rules, matching APK strings to network communications, detecting dangerous permission behaviors, and calculating the 0–100 risk score.
5. **Explore Attack Chain DAG**: Open the **Attack Graph** tab to interact with the chronological attack graph. Filter by node type (`APPLICATION`, `DOMAIN`, `IP`, `CAPABILITY`, `EVENT`, `THREAT_INTEL`) and examine solid (observed), dashed (correlated), and dotted (inferred) relationships.
6. **Export Dossier**: Navigate to **Reports** to compile a court-ready investigation dossier in PDF, HTML, JSON, or CSV formats.

For a detailed explanation of the 7 correlation rules and the mathematical risk formula, refer to [Correlation Rules & Risk Engine Reference](docs/correlation_rules.md).

---

## 12. Testing & Verification

### Backend Automated Test Suite
Run the test suite using `pytest`:
```bash
cd backend
pytest -v
```

To run a specific test category:
```bash
# Test correlation engine rules
pytest tests/test_correlations.py -v

# Test risk assessment scoring
pytest tests/test_risk_engine.py -v

# Test API endpoints
pytest tests/test_api_endpoints.py -v
```

### Frontend Verification
Run frontend component tests using `vitest`:
```bash
cd frontend
npm run test
```

---

## 13. Security, Privacy & Air-Gap Operations

E.M.I.T. is engineered with strict defensive security controls:

- **Zero Host Execution**: Untrusted mobile binaries are never executed. Static decompilation operates strictly on passive bytecode and AST representations.
- **DNS Leak Prevention (`tshark -n`)**: Packet dissection runs with the `-n` flag, preventing accidental host name resolution requests that alert adversaries.
- **Safe Threat Intelligence Lookups**: Third-party queries are proxied solely by the backend and cached in MongoDB for 24 hours, shielding client browser IP addresses.
- **Air-Gapped Operation**: For classified or closed-network forensics, disable external threat intelligence providers in `.env`. E.M.I.T. operates with 100% functionality on local evidence artifacts.

For complete threat modeling and defensive safeguards, see [Security Policy & Defensive Architecture](SECURITY.md).

---

## 14. Technical Boundaries & Limitations

To maintain forensic honesty, investigators should be aware of specific technical boundaries:

1. **Encrypted Network Traffic (TLS 1.3 / Certificate Pinning)**: E.M.I.T. inspects packet headers, DNS transactions, IP streams, and TLS Server Name Indication (SNI). Full decrypted payload inspection is not possible without an active intercepting MITM proxy deployed during packet capture.
2. **Commercial Native Packers**: Applications packed with advanced proprietary runtime packers or native shared libraries (`.so`) may hide strings from static decompilation until unpacked.
3. **Public Threat Intelligence Quotas**: Free-tier API keys for VirusTotal or AbuseIPDB enforce rate limits (e.g., 4 requests/min). E.M.I.T. mitigates this with 24-hour caching and graceful fallbacks.
4. **Host Antivirus Interference**: Storing live Android malware samples in `data/evidence` may trigger host antivirus (e.g., Windows Defender) quarantine actions. In production SOC deployments, exclude the evidence vault directory or mount it on an isolated forensic volume.

---

## 15. Explicitly Labeled Future Roadmap

The following features are **planned for future major releases** and are **NOT** present in the current production implementation:

- 🔮 **Machine Learning Threat Classifiers**: Predictive clustering models. *(Current implementation: 100% deterministic rules).*
- 🔮 **Live Dynamic Sandbox Automation**: Automated headless Android Virtual Device (AVD/QEMU) container execution. *(Current implementation: passive static analysis & external PCAP ingestion).*
- 🔮 **Frida Dynamic Hooking**: Automated runtime SSL unpinning injection. *(Current implementation: static signature and bytecode checks).*
- 🔮 **STIX/TAXII Threat Sharing Protocol**: Direct integration with external threat-sharing hubs. *(Current implementation: local REST API, JSON, and PDF export).*

---

## 16. Technical Documentation Index

For in-depth specifications, consult the dedicated guides in [`docs/`](docs/):

- **[System Architecture & Technical Design](docs/architecture.md)** — Topology, Common Evidence Model (CEM), and the 13 MongoDB collections.
- **[Deterministic Correlation Rules & Risk Engine](docs/correlation_rules.md)** — Comprehensive specification of Rules 1–7 and the mathematical risk formula.
- **[REST API Specification](docs/api.md)** — Complete endpoint reference with request/response payloads.
- **[Deployment & Production Operations Guide](docs/deployment.md)** — Docker runtime, Nginx reverse proxy configuration, and hardening.
- **[Security Policy & Defensive Architecture](SECURITY.md)** — Ethical mandate, threat model, and vulnerability reporting.

---

## 17. License & Ethical Disclaimer

E.M.I.T. is distributed under the [Apache 2.0 License](LICENSE).

> **DISCLAIMER**: E.M.I.T. is intended exclusively for authorized digital forensics, incident response, and academic security research. Users are solely responsible for ensuring compliance with applicable legal frameworks, privacy regulations, and organizational policies when analyzing mobile applications and network captures.
