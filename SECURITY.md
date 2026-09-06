# Security Policy & Defensive Architecture

This document outlines the security architecture, ethical usage policy, threat model, defensive controls, and vulnerability reporting procedures for **E.M.I.T.** (Evidence-backed Mobile Investigation Tool).

---

## 1. Ethical Scope & Defensive Mandate

E.M.I.T. is engineered exclusively as a **defensive digital forensics and incident response (DFIR) platform**.

> [!IMPORTANT]
> **Ethical Authorization Requirement**:
> - Analysis **MUST ONLY** be performed on Android applications (`.apk`) and network captures (`.pcap`, `.pcapng`) for which the investigator or enterprise has explicit, legal, and written authorization to analyze.
> - E.M.I.T. contains **zero offensive capabilities**: no exploit payloads, no dynamic C2 hijacking, no device rooting or jailbreak exploits, and no denial-of-service functions.
> - The platform operates strictly in an observational, investigative, and analytical capacity.

---

## 2. Threat Model

### Protected Assets
1. **Case Records & Notes**: Sensitive investigation records, case tags, investigator identities, and investigative hypotheses.
2. **Evidence Artifacts**: Potentially malicious APK packages, unpacked resources, and raw network packet captures.
3. **Forensic Findings**: Extracted indicators of compromise (IOCs), normalized entity graphs, and generated PDF/HTML reports.
4. **Third-Party API Secrets**: Integrations with external intelligence providers (VirusTotal, AbuseIPDB, URLhaus, AlienVault OTX, MobSF).
5. **Database Storage**: MongoDB collections storing case metadata and graph relationships.

### Adversary Threats & Mitigation Vectors
- **Malicious Evidence Crafting**:
  - *Risk*: Malicious APKs or PCAPs crafted to exploit parser vulnerabilities (e.g., zip-slip in APK unpackers, memory corruption in packet dissectors, decompression bombs).
  - *Mitigation*: Parsing executes in isolated container environments (`emit-mobsf`), memory-bounded Python processes, and path-confined extraction routines. Magic-byte inspection validates file headers prior to processing.
- **Arbitrary File Overwrite & Path Traversal**:
  - *Risk*: Filenames containing directory traversal sequences (`../../`) or reserved characters attempting to overwrite system files.
  - *Mitigation*: Uploaded filenames are stripped via `os.path.basename`, sanitized with strict alphanumeric regex, and stored under UUID-prefixed paths confined strictly within the evidence vault.
- **Malicious Host Execution**:
  - *Risk*: Malware executing code directly on the host analysis server.
  - *Mitigation*: Uploaded APK files are **never executed**. No emulator, dynamic sandbox, or `adb` runtime is invoked on the host. Analysis is purely static (AST decompilation, bytecode inspection, manifest parsing).
- **DNS Leakage & Adversary Reconnaissance Alerting**:
  - *Risk*: Automated network tools issuing live DNS lookups for domains found in PCAPs, alerting adversaries that their infrastructure is under investigation.
  - *Mitigation*: TShark is executed with the `-n` parameter to disable live DNS resolution. External threat intelligence queries are proxied solely by the backend and cached locally for 24 hours.

---

## 3. Core Security Controls

| # | Security Control | Technical Implementation |
| :-: | :--- | :--- |
| **1** | **No Runtime APK Execution** | All APK analysis is strictly static via Androguard, MobSF REST API, JADX, and APKTool. No emulators or execution sandboxes run on the host. |
| **2** | **Passive Network Dissection** | Packet inspection uses Scapy and TShark with `-n` flag (no DNS resolution), preventing adversary alerting. |
| **3** | **Magic Byte Validation** | Binary headers are validated on upload (`PK\x03\x04` for APK, `\xd4\xc3\xb2\xa1` / `\xa1\xb2\xc3\xd4` for PCAP, `\x0a\x0d\x0d\x0a` for PCAPNG). Extensions alone are never trusted. |
| **4** | **Enforced Upload Limits** | Enforced server-side via `MAX_EVIDENCE_SIZE_BYTES` (default 500 MB). Over-limit files are rejected with HTTP 400. |
| **5** | **Cryptographic Hashing** | SHA-256, SHA-1, and MD5 hashes are generated from raw streams on upload. Client-provided hashes are disregarded. |
| **6** | **Path Traversal Prevention** | Path confinement validates that all operations resolve within the evidence vault root directory; directory escapes trigger immediate exceptions. |
| **7** | **No Hardcoded Secrets** | Credentials and API keys are loaded via Pydantic `BaseSettings` from environment variables. |
| **8** | **Environment Files Ignored** | `.env`, `backend/.env`, and local credentials are systematically ignored in `.gitignore`. |
| **9** | **Private Evidence Vault** | Local evidence directories and generated reports are excluded from version control and accessible only through authenticated APIs. |
| **10** | **Credential Isolation** | External API keys are stored in server memory and never transmitted to the browser UI or returned in client payloads. |
| **11** | **Parameterized Storage** | Database interactions use PyMongo abstraction repositories with strongly typed Pydantic models to prevent NoSQL injection. |
| **12** | **Sanitized Error Handling** | API endpoints catch exceptions, write details to local diagnostic logs, and return sanitized error responses to clients. |
| **13** | **Relative Path Exposure** | API responses reference relative paths or UUIDs rather than disclosing internal server directory hierarchies. |
| **14** | **Filename Sanitization** | Uploaded file basenames are sanitized (`re.sub(r'[^a-zA-Z0-9_.-]', '_', base)`) and null bytes are rejected. |
| **15** | **Failure Containment** | Provider failures set `status: FAILED` without leaving incomplete or corrupt records in the attack graph. |
| **16** | **Safe Logging** | Application logs record operational telemetry while redacting bearer tokens, cookies, and secret API keys. |

---

## 4. Operational Considerations & Environment Assumptions

1. **Host Antivirus / EDR Quarantining**:
   Storing malicious Android binaries on disk may trigger host antivirus (e.g., Microsoft Defender) quarantine actions. In production SOC deployments, store the evidence vault on a dedicated encrypted volume or object storage with appropriate administrative exclusions.
2. **Encrypted Network Traffic (TLS 1.3 / Certificate Pinning)**:
   PCAP analysis inspects packet headers, DNS lookups, TCP/UDP streams, and TLS SNI handshakes. Payload inspection of encrypted TLS traffic is not performed unless a trusted intercepting proxy was deployed during the initial packet capture.
3. **Advanced Anti-Analysis & Native Packers**:
   Commercial packers or dynamic code loading may conceal payloads from static decompilation. E.M.I.T. identifies and flags evasion capabilities (Rule 7) to guide analysts toward targeted manual analysis.

---

## 5. Security Vulnerability Reporting

If you identify a security issue or vulnerability in E.M.I.T., please disclose it responsibly:

- **Contact**: `security@emit-forensics.local` (or submit a confidential issue on the repository)
- **Policy**: Please include detailed reproduction steps and an impact assessment. Allow a reasonable remediation window prior to public disclosure.
