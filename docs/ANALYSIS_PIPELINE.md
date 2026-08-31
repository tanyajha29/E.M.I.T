# E.M.I.T. Forensic Analysis Pipelines

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Pipeline Scope:** Static Android Application Inspection & Packet Stream Dissection

---

## 1. Overview & Architectural Guarantees

E.M.I.T. enforces a **strictly defensive, non-executing** forensic architecture. At no point in the ingestion or analysis cycle are untrusted binaries executed, emulated, or granted system privileges.

The analysis subsystem consists of two isolated pipelines managed by the `AnalysisOrchestrator`:
1. **Static APK Analysis Pipeline**: Ingests Android `.apk` archives and executes static reverse engineering and manifest analysis.
2. **Network PCAP Analysis Pipeline**: Ingests packet captures (`.pcap`, `.pcapng`) and extracts Layer 3–7 network conversations and temporal flow metrics.

---

## 2. Static APK Analysis Pipeline

### Ingestion & Pre-Flight Validation
1. **Magic-Byte Signature Verification**: Before disk persistence, the first 4 bytes must match the ZIP/APK signature `PK\x03\x04` (`0x50 0x4b 0x03 0x04`). Non-APK binaries (ELF, PE, shell scripts) are rejected with HTTP 400.
2. **Cryptographic Hashing**: SHA-256 is computed across the raw byte stream. If an identical hash already exists in the open case, the upload is rejected with HTTP 409 Conflict.
3. **Storage Isolation**: The file is stored in `storage/{uuid}_{sanitized_name}.apk` using path-confinement controls that strip directory traversal characters.

### Provider Execution Suite

```
                       [ Uploaded APK ]
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
           [ Androguard ]        [ MobSF REST ]
           (Local DEX AST)       (Containerized)
                    │                   │
                    └─────────┬─────────┘
                              ▼
                  [ JADX / APKTool Checks ]
                              │
                              ▼
                [ Normalized APK Observations ]
```

1. **Androguard Engine (`app/services/providers/androguard.py`)**:
   * Purely static Python AST and DEX parser.
   * Parses `AndroidManifest.xml` (decodes Android Binary XML).
   * Extracts package name, version codes, target SDK, and requested permissions.
   * Scans bytecode string pools for hardcoded IP addresses, domains, and URLs.
   * Flags suspicious API calls: `DexClassLoader`, `PathClassLoader`, reflection invocations, dynamic cryptographic key generation, and root check strings (`/system/xbin/su`).
2. **MobSF Integration (`app/services/providers/mobsf.py`)**:
   * Connects via REST API to a containerized MobSF instance.
   * Issues authenticated upload and scan requests.
   * Ingests security scores, CVSS findings, tracker detections, and manifest vulnerabilities.
3. **JADX & APKTool Providers (`jadx.py`, `apktool.py`)**:
   * Provides local binary execution verification and manifest extraction when host binaries are present.

---

## 3. Network PCAP Analysis Pipeline

### Ingestion & Pre-Flight Validation
1. **Capture Header Verification**: Validates magic bytes:
   * Standard libpcap: `\xd4\xc3\xb2\xa1` (microsecond resolution) or `\xa1\xb2\xc3\xd4` (nanosecond resolution).
   * PCAPNG: `\x0a\x0d\x0d\x0a` (Section Header Block).
2. **Safe Boundary Processing**: Empty captures (headers only, zero packets) and truncated capture frames are handled gracefully without application crashes.

### Provider Execution Suite

```
                      [ Uploaded PCAP ]
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
            [ Scapy Engine ]      [ Tshark Engine ]
            (Native Parsing)       (Read Mode -n)
                    │                   │
                    └─────────┬─────────┘
                              ▼
              [ Periodic Beaconing Detector ]
                              │
                              ▼
                [ Normalized PCAP Observations ]
```

1. **Scapy Native Dissector (`app/services/providers/scapy.py`)**:
   * Ingests packet flows into bounded in-memory structures.
   * Reconstructs TCP/UDP conversations and extracts Layer 4 ports.
   * Extracts DNS queries (Record type A, AAAA, CNAME) and resolution responses.
   * Extracts unencrypted HTTP request methods, host headers, and URIs.
   * Computes inter-packet arrival times to detect periodic beaconing intervals (Rule 5 candidate).
2. **Tshark External Dissector (`app/services/providers/tshark.py`)**:
   * Spawns `tshark` in strict read-only mode (`-r {path}`).
   * **Crucial Security Flag `-n`**: Network name resolution is strictly disabled. This prevents the host analysis system from issuing live DNS queries to resolve IPs present in the capture, preventing external alerting of threat actors.

---

## 4. Normalization & Hand-Off

Once provider execution completes:
1. Raw extracted data is stored in `apk_analyses` and `network_analyses`.
2. The `EvidenceNormalizer` converts raw findings into canonical `Indicator` and `Observation` models.
3. Observations are passed directly to the `CorrelationEngine` for multi-source synthesis.
