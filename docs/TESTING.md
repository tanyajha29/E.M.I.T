# E.M.I.T. Quality Assurance & Testing Suite

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Test Frameworks:** Pytest (Backend Python 3.13) & Vitest (Frontend TypeScript/React)  
**Total Automated Tests:** 90 Quality Gates (83 Backend + 7 Frontend)

---

## 1. Quality Strategy & Testing Pyramid

E.M.I.T.'s testing architecture validates every layer of the forensic pipeline:
1. **Unit Tests**: Provider parsing, schema validation, filename sanitizers, magic-byte inspectors, cryptographic hashing.
2. **Integration Tests**: Database repositories, orchestrator workflow stages, normalizer canonicalization, 7 deterministic correlation rules, risk engine calculations, dual HTML/PDF report compilers.
3. **Security & Hardening Tests**: Path traversal resistance, file size limit enforcement, duplicate hash rejection, API credential isolation, internal path leakage prevention.
4. **End-to-End Scenarios**: Full multi-stage investigation verification comparing matching malicious apps against benign non-matching controls.

---

## 2. Test Execution Commands

### Running Backend Tests (`pytest`)
```bash
# Navigate to backend directory
cd backend

# Activate virtual environment
.\venv\Scripts\Activate.ps1   # Windows PowerShell
source venv/bin/activate       # Linux / macOS

# Run all 83 backend tests
pytest -v

# Run specific test suites
pytest tests/test_security_comprehensive.py -v
pytest tests/test_e2e_scenarios.py -v
pytest tests/test_correlation_engine.py -v
```

### Running Frontend Tests (`vitest`)
```bash
# Navigate to frontend directory
cd frontend

# Run Vitest test suite
npm test

# Run production build validation
npm run build
```

---

## 3. Detailed Test Suite Inventory

### Backend Test Modules (`backend/tests/`)
1. **`test_security_comprehensive.py` (8 tests)**:
   * Rejection of unsupported file formats (`.exe`, `.sh`, `.bat`, `.dll`, `.pdf`).
   * Enforcement of maximum file upload size limit (500 MB).
   * Path traversal attack prevention (`../../` sequences stripped to base directory).
   * Malformed JSON payload rejection (HTTP 422).
   * Nonexistent ID error protection (HTTP 404).
   * Dangerous character filename sanitization and relative path isolation.
   * Credential isolation (API keys never exposed in `/health` or `/cases`).
   * Tshark command line `-n` flag verification (prevents outbound DNS leakage).
2. **`test_apk_pipeline_comprehensive.py` (5 tests)**:
   * Valid APK structure upload and signature verification (`PK\x03\x04`).
   * Invalid APK magic-byte rejection.
   * Corrupted ZIP payload graceful degradation (`ProviderStatus.FAILED` without server crash).
   * Disabled APK provider handling.
   * Missing local dependency handling.
3. **`test_pcap_pipeline_comprehensive.py` (5 tests)**:
   * Standard libpcap magic bytes (`0xa1b2c3d4` / `0xd4c3b2a1`).
   * PCAPNG Section Header Block magic bytes (`0x0a0d0d0a`).
   * Invalid PCAP header rejection.
   * Empty PCAP capture handling (0 packets parsed with 0 errors).
   * Truncated/corrupted packet frame degradation without crash.
4. **`test_correlation_comprehensive.py` (4 tests)**:
   * Domain Match (Rule 1) vs. negative non-matching control.
   * IP Match (Rule 2) vs. negative non-matching control.
   * Periodic beaconing (Rule 5) and temporal proximity (Rule 6).
   * Multi-source corroboration (Rule 7 elevation to `STRONG`).
5. **`test_e2e_scenarios.py` (2 tests)**:
   * **Scenario 1: `SuspiciousApp.apk` + `authorized_investigation.pcap`**: Complete lifecycle: Case creation $\to$ Evidence upload $\to$ Observation extraction $\to$ Normalization $\to$ Deterministic Correlations (`DOMAIN_MATCH`, `IP_MATCH`, `PERIODIC_COMMUNICATION_MATCH`) $\to$ Attack Graph reconstruction $\to$ Risk Engine elevation (`HIGH`/`CRITICAL`) $\to$ Dual HTML and PDF forensic report generation.
   * **Scenario 2: `NonMatchingApp.apk` + `unrelated.pcap`**: Benign app + unrelated traffic: confirms **EXACT ZERO fabricated correlations**, disconnected attack graph, and **`LOW`** risk rating.
6. **Additional Regression Suites (59 tests)**:
   * `test_cases.py`, `test_evidence.py`, `test_normalizer.py`, `test_correlation_engine.py`, `test_attack_chain.py`, `test_threat_intel.py`, `test_risk_engine.py`, `test_report_generator.py`.

### Frontend Component Tests (`frontend/src/tests/`)
* **`frontend.test.tsx` (7 tests)**:
  1. Loading state (animated spinner and stage indicator).
  2. Empty state (placeholder when zero graph nodes exist).
  3. Error state (contextual alert banner with retry callback).
  4. Success state (completion badge and SHA-256 provenance hash).
  5. Attack graph canvas (React Flow canvas, legend, node types, edge classifications).
  6. Authentic timeline (chronological event sequencing with source tags).
  7. Report form & download trigger (format selector and compilation submission).
