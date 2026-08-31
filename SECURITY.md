# E.M.I.T. Security Policy & Hardening Review

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Version:** 1.0.0 (Phase 16 Hardening Review)  
**Security Architecture Mandate:** Purely Defensive Forensic Platform

---

## 1. Ethical Scope & Defensive Use Mandate

E.M.I.T. is engineered exclusively as a **defensive digital forensics and incident response (DFIR) platform**.

> [!IMPORTANT]
> **Ethical Authorization Requirement**:
> * Analysis MUST ONLY be performed on Android applications (`.apk`) and network captures (`.pcap`, `.pcapng`) for which the investigator or enterprise has explicit, written authorization to analyze.
> * E.M.I.T. contains **zero offensive capabilities**: no exploit generation, no remote payload execution, no automated command-and-control hijacking, no privilege escalation payloads, and no denial-of-service capabilities.
> * The tool is strictly designed to observe, correlate, reconstruct, assess, and report evidence.

---

## 2. Threat Model

### A. Primary Assets
1. **Case Files & Investigation Records**: Sensitive forensic cases, notes, timestamps, and findings.
2. **Evidence Binaries**: Suspicious APK binaries and raw network packet captures under investigation.
3. **Extracted Forensic Artifacts**: Normalized IOCs, decompiled bytecode representations, IP addresses, domains.
4. **External API Credentials**: API keys for VirusTotal, AbuseIPDB, and AlienVault OTX.
5. **Database Records**: MongoDB persistent collections storing cases, observations, and reports.

### B. Adversary Profiles & Threats
* **Malicious Evidence Crafting**:
  * An adversary submits an APK or PCAP specifically crafted to exploit vulnerabilities in parsing libraries (e.g. ZIP slip, buffer overflows in Scapy/Tshark, decompression bombs, or regex DoS).
* **Directory Traversal & Arbitrary File Overwrite**:
  * An attacker supplies filenames with `../../` or Windows device names (`CON`, `PRN`, `AUX`) attempting to write outside the sandbox storage root.
* **Malicious Runtime Execution**:
  * Untrusted mobile malware attempting to execute code on the analysis host server.
* **Data & Credential Exfiltration**:
  * External threats attempting to inspect logs, API error messages, or network queries to harvest API keys or case intelligence.
* **Network Query Information Leakage**:
  * Automated tools issuing live DNS resolutions or external connections during PCAP inspection, alerting adversaries that their infrastructure is being investigated.

---

## 3. Comprehensive Security Verification (17/17 Checklist)

| # | Security Verification Requirement | Architectural Control & Mitigation | Verification Status |
| :-: | :--- | :--- | :-: |
| **1** | **Uploaded APKs are never executed** | All APK analysis is strictly static. Decompilation and parsing are performed via Androguard (Python AST/DEX parser), JADX, APKTool, and containerized MobSF. No emulator, dynamic sandbox, or `adb install` / `am start` is ever invoked. | **VERIFIED** |
| **2** | **Uploaded PCAPs are handled safely** | Packet parsing uses Scapy in memory-bounded structures. Tshark is executed with the `-n` flag (no network name resolution) to prevent outbound DNS queries that could alert adversaries or leak internal host IPs. | **VERIFIED** |
| **3** | **File type validation exists** | Magic-byte signature enforcement at the binary upload boundary in `EvidenceService`: APK must match `PK\x03\x04`; PCAP must match `\xd4\xc3\xb2\xa1` or `\xa1\xb2\xc3\xd4`; PCAPNG must match `\x0a\x0d\x0d\x0a`. Extensions alone are never trusted. | **VERIFIED** |
| **4** | **File size limits exist** | Hard upload limit enforced server-side via `settings.MAX_EVIDENCE_SIZE_BYTES` (default 500 MB). Over-limit files are rejected with HTTP 400 before ingestion. | **VERIFIED** |
| **5** | **SHA-256 cryptographic hashing exists** | Cryptographic SHA-256 hashes are calculated server-side from raw bytes upon upload. Client-provided hashes are never trusted. Duplicate hashes within the same case context are rejected with HTTP 409 Conflict to maintain chain-of-custody integrity. | **VERIFIED** |
| **6** | **Path traversal is prevented** | `LocalStorageProvider` enforces path confinement. Filenames are stripped with `os.path.basename()` and canonicalized with `os.path.abspath()`. Any path attempting to escape `base_dir` triggers `PermissionError`. | **VERIFIED** |
| **7** | **Secrets are not hardcoded** | All threat intelligence API keys (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`), MobSF keys, and database credentials are read dynamically via Pydantic `BaseSettings` from environment variables. | **VERIFIED** |
| **8** | **.env is ignored** | Root `.gitignore` explicitly ignores `.env`, `backend/.env`, `frontend/.env`, `.env.local`, and test environment credential files. Verified via `git status --ignored`. | **VERIFIED** |
| **9** | **Uploaded evidence is private** | All storage directories (`storage/`, `backend/storage/`) containing raw evidence binaries, decompiled assets, and compiled PDF reports are ignored by Git. Evidence files are only accessible via case-scoped authenticated APIs. | **VERIFIED** |
| **10**| **External API keys are protected** | Keys are stored solely in backend memory/env. They are never sent to the React frontend, never returned in `/health` or `/cases` responses, and never logged in stdout or files. | **VERIFIED** |
| **11**| **SQL/NoSQL injection is prevented** | Database access uses PyMongo repository abstractions with strongly typed Pydantic schemas. Query parameters are passed as structured dictionaries; string concatenation of queries is strictly prohibited. | **VERIFIED** |
| **12**| **API errors do not expose secrets** | REST API endpoints catch unexpected exceptions, log full diagnostics internally, and return sanitized, generic error descriptions to API consumers. | **VERIFIED** |
| **13**| **Internal filesystem paths are not leaked** | `LocalStorageProvider.save_file` returns relative paths (`storage/{uuid}_{filename}`) rather than absolute host filesystem paths (`C:\Users\...` or `/home/...`), preventing host directory disclosure in API responses and reports. | **VERIFIED** |
| **14**| **Temporary analysis files are cleaned** | Orchestrators and providers execute in isolated, transient scopes. When metadata insertion fails, uploaded binary files are immediately unlinked to prevent orphaned files. | **VERIFIED** |
| **15**| **Failed analysis leaves no unsafe artifacts**| Provider failures are caught and recorded as `ProviderStatus.FAILED`. Incomplete or corrupted runs are marked with `AnalysisStatus.FAILED` without generating unsupported graph edges or phantom correlations. | **VERIFIED** |
| **16**| **User-controlled filenames are sanitized** | Filenames are sanitized with `re.sub(r'[^a-zA-Z0-9_.-]', '_', base)`. Null bytes (`\0`), colons, quotes, asterisks, question marks, and path delimiters are eliminated before filesystem creation. | **VERIFIED** |
| **17**| **Logs do not contain secrets** | Loggers record operations, indicator values, and HTTP status codes, but omit authorization headers, Bearer tokens, and API secret strings. | **VERIFIED** |

---

## 4. Accepted Limitations & Defensive Assumptions

1. **Host Antivirus / EDR Interference**:
   * Storing live Android malware binaries in `storage/` may trigger host antivirus (e.g. Windows Defender) quarantine. In production SOC environments, the `storage/` volume should reside on an isolated volume or encrypted object store (e.g. AWS S3 with KMS or MinIO) with dedicated exclusions.
2. **Encrypted Network Traffic (TLS 1.3)**:
   * PCAP analysis inspects packet headers, DNS lookups, and TCP/UDP flow metadata. Payload inspection of encrypted HTTPS/TLS communication is not possible without an active intercepting MITM proxy certificate installed on the mobile device during capture.
3. **Advanced Anti-Analysis & Dynamic Unpacking**:
   * Heavy obfuscation (e.g. DexGuard, commercial packers, dynamic class loading via native libraries) may hide strings and domains from static analysis. E.M.I.T.'s correlation engine surfaces high-entropy and reflection API indicators to guide the analyst toward dynamic reverse engineering.
4. **Third-Party Threat Intel Rate Limits**:
   * Free-tier external threat intelligence APIs enforce strict rate limits (e.g. VirusTotal 4 requests/min). E.M.I.T. caches lookups for 24 hours and gracefully falls back to local observations when rate limits are encountered.

---

## 5. Security Vulnerability Reporting

If you discover a potential security vulnerability in E.M.I.T., please report it responsibly:
* **Contact:** Security Response Team (`security@emit-forensics.local`)
* **Policy:** Please provide detailed steps to reproduce. Do not disclose public vulnerabilities before a coordinated patch is released.
