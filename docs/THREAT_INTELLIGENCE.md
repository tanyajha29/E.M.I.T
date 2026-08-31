# E.M.I.T. External Threat Intelligence Enrichment

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Subsystem:** `ThreatIntelService` (`backend/app/services/threat_intel/service.py`)  
**Common Interface:** `ThreatIntelProvider` (`backend/app/services/threat_intel/base.py`)

---

## 1. Overview & Operational Principles

E.M.I.T. features an optional external threat-intelligence enrichment subsystem designed to augment local investigation findings with global threat reputation data.

### Core Architectural Mandates
1. **Common Provider Interface**: All providers implement `ThreatIntelProvider` (`name`, `is_enabled`, `is_configured`, `enrich_indicator()`).
2. **Independent Provider Toggles**: Each provider can be independently enabled or disabled via environment variables.
3. **Local Pipeline Independence**: The core investigation pipeline operates with 100% functionality even when all threat intelligence providers are disabled.
4. **Selective Enrichment**: The system never sends every string to external APIs. Only relevant, normalized indicators (public FQDNs, non-private IPs, SHA-256 hashes) are submitted.
5. **Separation of Local Fact vs. External Intelligence**: External verdicts never alter raw observations. They are stored in a distinct collection (`threat_intelligence`) and displayed in separate UI sections.
6. **No Single-Source Conviction**: An indicator is never marked as conclusively malicious solely because a single external API returns a detection.

---

## 2. Integrated Threat Intelligence Providers

```
                     [ Normalized Indicators ]
                                 │
                   [ Relevance Filter: Public Only ]
                                 │
         ┌───────────────┬───────┴───────┬───────────────┐
         ▼               ▼               ▼               ▼
  [ VirusTotal ]   [ URLhaus ]    [ AbuseIPDB ]   [ AlienVault OTX ]
  (Domains, IPs,  (Malicious      (Public IPv4/   (Threat Pulses &
     Hashes)         URLs)            IPv6)          Advisories)
         │               │               │               │
         └───────────────┼───────────────┴───────────────┘
                         ▼
        [ 24-Hour Deterministic Cache ]
                         │
                         ▼
             [ ThreatIntelResult Record ]
```

### 1. VirusTotal (`virustotal.py`)
* **Supported Indicators**: `DOMAIN`, `IP`, `HASH`.
* **API Version**: v3 REST API (`https://www.virustotal.com/api/v3/`).
* **Credentials**: `VIRUSTOTAL_API_KEY`.
* **Detection Threshold**: Flags `MALICIOUS` if malicious detections $> 0$; flags `SUSPICIOUS` if suspicious detections $> 2$.

### 2. URLhaus (`urlhaus.py`)
* **Supported Indicators**: `URL`, `DOMAIN`, `HASH`.
* **API Version**: URLhaus API (`https://urlhaus-api.abuse.ch/v1/`).
* **Credentials**: Public API (Key optional / unauthenticated queries supported).
* **Detection Criteria**: Checks malware payload database and active C2 host listings.

### 3. AbuseIPDB (`abuseipdb.py`)
* **Supported Indicators**: Public IPv4 and IPv6 addresses.
* **API Version**: v2 Check Endpoint (`https://api.abuseipdb.com/api/v2/check`).
* **Credentials**: `ABUSEIPDB_API_KEY`.
* **Safety Filter**: Private, loopback, link-local, and multicast IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) are automatically filtered and **never queried externally**.
* **Confidence Scoring**: Uses the AbuseIPDB `abuseConfidenceScore` (0–100%).

### 4. AlienVault OTX (`alienvault_otx.py`)
* **Supported Indicators**: `DOMAIN`, `IP`, `HASH`.
* **API Version**: OTX Direct API (`https://otx.alienvault.com/api/v1/indicators/`).
* **Credentials**: `OTX_API_KEY`.
* **Detection Criteria**: Scans community threat pulses, targeted malware tags, and adversary threat groups.

---

## 3. Caching & Fault Tolerance

* **Deterministic 24-Hour Cache**:
  * Lookups are cached in the MongoDB `threat_intelligence` collection with an `expires_at` TTL.
  * Repeated queries within the cache window are served from the database with `cached: true`, eliminating redundant network calls and conserving API quotas.
* **Resilient Error Handling**:
  * API timeouts (`httpx.TimeoutException`), rate limits (HTTP 429), authentication failures (HTTP 401/403), and unknown indicators (HTTP 404) are handled gracefully.
  * Failures return an `UNKNOWN` status with an error description; the investigation pipeline continues uninterrupted.
