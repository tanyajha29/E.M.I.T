# E.M.I.T. Common Evidence Model

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Model Mandate:** Strict Forensic Provenance, Canonical Indicators, Ground-Truth Separation

---

## 1. Design Philosophy

In digital forensics, **evidence provenance** is paramount. Analysis results are invalid if an investigator cannot prove:
1. *Where* a piece of information was found.
2. *Which tool* observed it.
3. *What raw bytes* or packets produced it.
4. *How* a correlation was deduced.

E.M.I.T. addresses this through the **Common Evidence Model (CEM)**, which cleanly separates:
* **Atomic Indicators**: Abstract technical entities (e.g. `domain`, `ip`, `hash`).
* **Ground-Truth Observations**: Specific instances where an indicator was observed in a concrete evidence item.
* **Correlated Syntheses**: Deductive relationships established between two or more independent observations.

---

## 2. Structural Entity Models

```
 +-------------------------------------------------------------------+
 |                             EVIDENCE                              |
 |   (Evidence ID, File Name, SHA-256 Hash, Byte Size, Format)       |
 +---------------------------------+---------------------------------+
                                   │ produces
                                   ▼
 +-------------------------------------------------------------------+
 |                           OBSERVATION                             |
 |   (Observation ID, Evidence ID, Tool Source, Type, Raw Value,     |
 |    Authentic Timestamp, Confidence 1.0, Byte/Packet Offset)       |
 +---------------------------------+---------------------------------+
                                   │ references
                                   ▼
 +-------------------------------------------------------------------+
 |                            INDICATOR                              |
 |   (Indicator ID, Case ID, Normalized Value, Category Type)        |
 +---------------------------------+---------------------------------+
                                   │ inputs to
                                   ▼
 +-------------------------------------------------------------------+
 |                           CORRELATION                             |
 |   (Rule Name, Relationship Type, Strength, Deductive Reason,      |
 |    Source Observation IDs, Target Observation IDs)                |
 +-------------------------------------------------------------------+
```

---

## 3. Atomic Indicators (`Indicator`)

An `Indicator` represents a standardized technical artifact extracted from evidence.

### Supported Indicator Types
* `DOMAIN`: Fully qualified domain name (FQDN).
* `IP`: IPv4 or IPv6 address.
* `HASH`: Cryptographic checksum (SHA-256, MD5, SHA-1).
* `URL`: Uniform Resource Locator.
* `PACKAGE`: Android application package name (`com.company.app`).
* `API`: Sensitive bytecode API or reflection method signature.
* `PERMISSION`: Android manifest permission string.

### Normalization Logic
To prevent false negatives due to formatting discrepancies, the `EvidenceNormalizer` canonicalizes all indicators:
* Domains: Converted to lowercase, trailing dots stripped, protocol prefixes (`http://`, `https://`) removed.
* IPv4/IPv6: Validated via Python's `ipaddress` library; standard expanded notation.
* Hashes: Lowercased, whitespace removed.
* Permissions: Standardized to Android framework namespace (e.g., `android.permission.INTERNET`).

---

## 4. Ground-Truth Observations (`Observation`)

An `Observation` records the exact fact that an indicator was detected in a specific evidence file.

* **Immutable Provenance**: Every observation maintains a permanent reference to `evidence_id`, guaranteeing complete chain-of-custody.
* **Source Attribution**: Identifies the exact analytical provider (`ANDROGUARD`, `MOBSF`, `SCAPY`, `TSHARK`).
* **Authentic Timestamps**: If the underlying evidence contains an authentic temporal marker (e.g., PCAP frame timestamp, APK signing date), it is preserved. **No synthetic timestamps are ever generated.**
* **Confidence Rating**: Direct observations of binary content carry an absolute confidence rating of `1.0` (factual observation).

---

## 5. Explicit Separation: Observed Fact vs. Inference

A core scientific mandate of E.M.I.T. is that analytical deductions are never conflated with observed ground-truth:

| Concept | Definition | Example |
| :--- | :--- | :--- |
| **OBSERVED FACT** | An indisputable forensic artifact physically present in evidence. | *"The APK bytecode embeds string 'api.command-server.biz'."*<br>*"The PCAP contains a DNS query for 'api.command-server.biz' at 14:02:11 UTC."* |
| **CORRELATED LINKAGE** | A deterministic cross-evidence relationship governed by mathematical rules. | *"The domain embedded in the APK matches the domain queried in the PCAP."* |
| **ANALYTICAL INFERENCE** | A deduction regarding the operational relationship between artifacts. | *"The mobile application initiated an outbound C2 handshake to the external domain."* |

Analytical inferences are displayed in dedicated UI panels and report sections, clearly marked with uncertainty warnings to preserve forensic credibility.
