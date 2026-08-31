# E.M.I.T. Limitations & Future Roadmap

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Document Purpose:** Clear boundary definition of current implementation vs. planned future features.

---

## 1. Forensically Accepted Current Limitations

To maintain strict scientific and forensic credibility, E.M.I.T. does not overstate its analytical capabilities. The following technical boundaries are inherent to the current production implementation:

### 1. Passive Analysis & Code Obfuscation
* **Static Analysis Boundaries**:
  * Static APK analysis extracts manifest metadata, strings, and DEX bytecode ASTs.
  * If malware employs commercial packers, native payload loaders (`.so` ELF binaries), or reflective decryption at runtime, the true payload may not be visible in static DEX bytecode.
  * Heavy code obfuscation (e.g. ProGuard, DexGuard) can obscure method names and class hierarchies.

### 2. Encrypted Network Traffic (TLS 1.3 / HTTPS)
* **Payload Opacity**:
  * PCAP packet analysis parses Layer 3/4 headers, DNS queries, and TCP flow timings.
  * E.M.I.T. does **not decrypt TLS payloads**. The contents of encrypted HTTPS requests (POST bodies, API tokens, transmitted exfiltration data) cannot be inspected without an active intercepting MITM certificate installed on the mobile device during live capture.

### 3. Benign Network Heuristics (Keepalive vs. Beaconing)
* **Periodic Flow Disambiguation**:
  * The periodic communication detector flags repetitive connections ($\Delta t \pm 10\%$).
  * In mobile environments, benign background services (e.g. Firebase Cloud Messaging / push notification keepalives, NTP time synchronization) also exhibit periodic traffic patterns.
  * E.M.I.T. flags periodic traffic as a correlation candidate, but requires corroboration with APK bytecode to establish malicious intent.

### 4. External Threat Intelligence API Quotas
* **Public Tier Rate Limits**:
  * Free-tier public APIs for external threat feeds (e.g. VirusTotal 4 requests/min) are strictly rate-limited.
  * While E.M.I.T. implements 24-hour caching and graceful degradation, high-volume indicator enrichment may experience throttling without enterprise API keys.

---

## 2. Explicitly Labeled Future Features (NOT Yet Implemented)

The following capabilities are **planned for future major releases** and are **NOT** present in the current production implementation. Users and auditors must not assume these features are active:

### 🔮 Future Feature: Machine Learning & Predictive Risk Classification
* **Status**: **NOT IMPLEMENTED (PLANNED)**
* **Scope**: Future releases may explore supervised ML models trained on labeled malware corpora for heuristic classification.
* **Current Implementation**: Purely deterministic, evidence-weighted mathematical scoring. Zero ML is currently used.

### 🔮 Future Feature: Dynamic Analysis & Sandbox Execution
* **Status**: **NOT IMPLEMENTED (PLANNED)**
* **Scope**: Automated execution of APKs inside instrumented virtual machine sandboxes to capture runtime behavior.
* **Current Implementation**: Strictly static inspection. APKs are never executed.

### 🔮 Future Feature: Frida Dynamic Instrumentation
* **Status**: **NOT IMPLEMENTED (PLANNED)**
* **Scope**: Runtime hook injection (Frida scripts) to bypass SSL pinning, unmask reflective method calls, and trace runtime crypto keys.
* **Current Implementation**: Static string and DEX AST scanning for Frida-related detection strings.

### 🔮 Future Feature: Android Emulator Orchestration
* **Status**: **NOT IMPLEMENTED (PLANNED)**
* **Scope**: Integrated headless Android emulator (AVD/QEMU) automation for live user interaction simulation and runtime packet capture generation.
* **Current Implementation**: Ingestion of pre-recorded PCAP and PCAPNG files captured externally (e.g., via tcpdump or Wireshark).

### 🔮 Future Feature: Advanced Behavioral Anomaly Modeling
* **Status**: **NOT IMPLEMENTED (PLANNED)**
* **Scope**: Deep neural network behavioral modeling of mobile sensor telemetry and user interaction patterns.
* **Current Implementation**: Static heuristic pattern matching (Rule 1 through Rule 7).

### 🔮 Future Feature: STIX / TAXII Threat Sharing Export
* **Status**: **NOT IMPLEMENTED (PLANNED)**
* **Scope**: Bi-directional ingestion and sharing of cyber threat intelligence in Structured Threat Information Expression (STIX 2.1) and Trusted Automated Exchange of Intelligence Information (TAXII) formats.
* **Current Implementation**: Structured JSON REST APIs and HTML/PDF investigation dossier generation.
