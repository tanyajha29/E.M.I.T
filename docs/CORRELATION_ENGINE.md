# E.M.I.T. Deterministic Correlation Engine

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Engine Class:** `CorrelationEngine` (`backend/app/services/correlation_engine.py`)  
**Core Innovation:** Deterministic Rule Synthesis (Zero Machine Learning, Zero Hallucinations)

---

## 1. Architectural Philosophy

Traditional threat analysis tools frequently rely on opaque probabilistic algorithms or AI classifiers that output risk ratings like `"Risk = 87"` without explainable evidentiary proof.

In forensic incident response, probabilistic guesswork is legally and scientifically inadmissible.

E.M.I.T. rejects machine learning in favor of an **evidence-weighted deterministic correlation engine**:
* **100% Explainable**: Every correlation generated references the exact source observations and evidence files that triggered it.
* **Deterministic Rules**: The engine executes seven formal correlation rules. If conditions are met, a correlation is created; if conditions are not met, **zero links are fabricated**.
* **Calibrated Strengths**: Relationships are graded as `WEAK`, `MODERATE`, or `STRONG` based on physical corroboration.

---

## 2. The 7 Deterministic Correlation Rules

```
                      [ Normalized Observations ]
                                   │
      ┌────────────────────────────┼────────────────────────────┐
      ▼                            ▼                            ▼
  [ Rule 1 ]                   [ Rule 2 ]                   [ Rule 3 ]
Domain Match                  IP Match                  Resolved IP Match
(APK Domain == PCAP DNS)    (APK IP == PCAP IP)         (DNS Answer Mapping)
      │                            │                            │
      ├────────────────────────────┼────────────────────────────┤
      ▼                            ▼                            ▼
  [ Rule 4 ]                   [ Rule 5 ]                   [ Rule 6 ]
Capability Match            Periodic Beaconing          Temporal Alignment
(Permission == Flow)        (Periodic Interval)         (Occurs within 1 hr)
      │                            │                            │
      └────────────────────────────┼────────────────────────────┘
                                   ▼
                              [ Rule 7 ]
                     Multi-Source Corroboration
                     (3+ Tools Elevates to STRONG)
```

---

### Rule 1: Direct Domain Match (`DOMAIN_MATCH`)
* **Trigger Condition**: An embedded domain extracted from APK bytecode or assets exactly matches a domain queried via DNS in the PCAP capture.
* **Relationship Type**: `EMBEDS` / `RESOLVES_TO`
* **Default Strength**: `MODERATE`
* **Forensic Reason**: *"Domain '{domain}' extracted from APK was actively resolved via DNS in the captured network traffic."*
* **Negative Verification**: If the APK embeds `legit.com` and PCAP queries `evil.com`, **zero correlations are produced**.

---

### Rule 2: Direct IP Match (`IP_MATCH`)
* **Trigger Condition**: A hardcoded IP address extracted from APK bytecode exactly matches a destination IP address observed in TCP/UDP sessions in the PCAP capture.
* **Relationship Type**: `CONNECTS_TO`
* **Default Strength**: `STRONG` (Hardcoding an IP directly in an APK is a severe forensic anomaly).
* **Forensic Reason**: *"IP '{ip}' embedded in APK bytecode matches active destination IP communicating in network capture."*

---

### Rule 3: Resolved IP Indirect Match (`RESOLVED_IP_MATCH`)
* **Trigger Condition**: An APK contains domain $D$. The PCAP does not contain an embedded IP, but the PCAP DNS response maps domain $D$ to IP $I$, and an outbound TCP/UDP connection to IP $I$ is subsequently observed.
* **Relationship Type**: `RESOLVES_TO`
* **Default Strength**: `MODERATE`
* **Forensic Reason**: *"APK embeds domain '{domain}' which DNS resolved to IP '{ip}', subsequently targeted by network connection."*

---

### Rule 4: Declared Capability Alignment (`CAPABILITY_MATCH`)
* **Trigger Condition**: The APK requests sensitive network capabilities in its manifest (e.g. `android.permission.INTERNET`, `ACCESS_NETWORK_STATE`), and the PCAP observes active network flows.
* **Relationship Type**: `USES`
* **Default Strength**: `WEAK` (Necessary precondition for network communication, but insufficient alone to prove malice).
* **Forensic Reason**: *"Application declared permission '{perm}' aligns with observed network packet activity."*

---

### Rule 5: Periodic Communication Pattern (`PERIODIC_COMMUNICATION_MATCH`)
* **Trigger Condition**: The PCAP analysis detects repetitive, periodic connection intervals (beaconing behavior $\Delta t \pm 10\%$) directed toward an IP associated with the APK.
* **Relationship Type**: `REPEATS`
* **Default Strength**: `STRONG`
* **Forensic Reason**: *"Periodic beaconing communication pattern observed toward destination IP '{ip}' (interval: {interval}s)."*

---

### Rule 6: Temporal Proximity Alignment (`TEMPORAL_ALIGNMENT`)
* **Trigger Condition**: Authentic timestamps are present in both the APK signing/build metadata and the PCAP network flows, and the events occur within a 1-hour temporal window.
* **Relationship Type**: `CORRELATED_WITH`
* **Default Strength**: `MODERATE`
* **Forensic Reason**: *"Network event occurred within 1 hour of application installation/compilation activity."*

---

### Rule 7: Multi-Source Corroboration (`MULTI_SOURCE_CORROBORATION`)
* **Trigger Condition**: An indicator or relationship is independently observed by three or more analytical providers (e.g., Androguard + MobSF + Scapy).
* **Action**: Automatically elevates the relationship strength from `WEAK` or `MODERATE` to **`STRONG`**.
* **Forensic Reason**: Appends: *"Corroborated across multiple independent analysis tools: {tools}."*

---

## 3. External Threat Intelligence Integration

When threat intelligence providers are enabled (VirusTotal, URLhaus, AbuseIPDB, AlienVault OTX), matched malicious indicators generate an auxiliary correlation:
* **Rule**: `THREAT_INTEL_MATCH`
* **Relationship Type**: `SUPPORTED_BY`
* **Reason**: *"Indicator '{val}' confirmed as malicious by external intelligence provider '{provider}' (score: {score})."*
* **Scientific Guardrail**: External intelligence alone **never overrides local observation**. If VirusTotal flags a domain but the domain is never present in the APK or PCAP, it is never incorporated into the investigation graph.
