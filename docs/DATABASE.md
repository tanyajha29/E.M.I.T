# E.M.I.T. Database Architecture & Schema Specification

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Database Engine:** MongoDB 7.0+ (Local Enterprise / Community or MongoDB Atlas Cloud)  
**Driver & Repository Layer:** PyMongo 4.8.0+ via Strongly-Typed Pydantic Models

---

## 1. Overview & Architectural Principles

E.M.I.T. utilizes **MongoDB** as its authoritative persistent datastore. The system architecture enforces:
1. **Dynamic Database Resolves**: Supports runtime database switching for isolated automated testing suites without state leakage.
2. **Repository Abstraction Pattern**: All business logic interacts with MongoDB through dedicated repository classes (`BaseRepository`), preventing raw query string concatenation and NoSQL injection.
3. **ID Isolation**: Internal MongoDB `_id` ObjectId keys are stripped before passing entities to Pydantic schemas, preserving deterministic UUID provenance.
4. **Strict Schema Validation**: Ingestion models enforce typing, constraints, and UTC ISO timestamps.

---

## 2. The 13 Core Collections

All collections and indexing strategies are initialized automatically via `backend/scripts/init_mongodb.py`:

```
+---------------------------------------------------------------+
|                       E.M.I.T. COLLECTIONS                    |
+-------------------------------+-------------------------------+
| 1. cases                      | 8. correlations               |
| 2. evidence_files             | 9. attack_nodes               |
| 3. analysis_runs              | 10. attack_edges              |
| 4. apk_analyses               | 11. threat_intelligence       |
| 5. network_analyses           | 12. risk_assessments          |
| 6. indicators                 | 13. reports                   |
| 7. observations               |                               |
+-------------------------------+-------------------------------+
```

---

## 3. Collection Specifications & Data Schemas

### 1. `cases`
Represents an ongoing mobile forensic investigation.
* **Fields**:
  * `case_id` (str, UUIDv4): Primary unique identifier.
  * `name` (str): Human-readable investigation title.
  * `description` (str): Objective and context of the inquiry.
  * `status` (str): Case lifecycle state (`OPEN`, `CLOSED`, `ARCHIVED`).
  * `created_at` (datetime UTC): Registration timestamp.
  * `updated_at` (datetime UTC): Last modification timestamp.
* **Indexes**: `case_id` (Unique), `created_at`.

### 2. `evidence_files`
Metadata and chain-of-custody tracking for uploaded evidence binaries.
* **Fields**:
  * `evidence_id` (str, UUIDv4): Unique evidence item identifier.
  * `case_id` (str): Associated case identifier.
  * `file_name` (str): Original sanitized upload filename.
  * `file_type` (str): Validated format (`APK`, `PCAP`, `PCAPNG`).
  * `mime_type` (str): Content-Type header string.
  * `file_size` (int): Byte count.
  * `sha256` (str, 64 hex chars): Server-calculated cryptographic hash.
  * `storage_provider` (str): Storage subsystem (`local`, `s3`).
  * `storage_path` (str): Relative storage reference (e.g. `storage/{uuid}_{name}`).
  * `status` (str): File ingestion status (`uploaded`, `analyzing`, `processed`).
  * `uploaded_at` (datetime UTC): Timestamp of receipt.
* **Indexes**: `evidence_id` (Unique), `case_id`, `(case_id, sha256)` (Compound unique to prevent duplicate uploads within a case).

### 3. `analysis_runs`
Tracks asynchronous execution jobs for static and network forensic providers.
* **Fields**:
  * `analysis_id` (str, UUIDv4): Unique job identifier.
  * `case_id` (str): Parent case identifier.
  * `evidence_id` (str): Target evidence file.
  * `analysis_type` (str): `STATIC_APK` or `NETWORK_PCAP`.
  * `status` (str): `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `PARTIAL`.
  * `current_stage` (str): Pipeline stage (`PRE_FLIGHT`, `EXTRACTION`, `NORMALIZATION`, `COMPLETED`).
  * `providers` (list[dict]): Per-tool execution records (`provider`, `version`, `duration`, `status`, `error`).
  * `created_at` (datetime UTC): Job submission timestamp.
* **Indexes**: `analysis_id` (Unique), `(case_id, evidence_id, analysis_type)`.

### 4. `apk_analyses`
Raw structured extraction findings from APK analysis engines (Androguard, MobSF, JADX, APKTool).
* **Fields**:
  * `apk_analysis_id` (str, UUIDv4): Unique record identifier.
  * `evidence_id` (str): Associated APK file.
  * `case_id` (str): Associated case.
  * `package_name` (str): Android manifest package name.
  * `version_name` / `version_code` (str / int): Application version identifiers.
  * `min_sdk` / `target_sdk` (int): Android API target levels.
  * `permissions` (list[str]): Declared permissions.
  * `activities`, `services`, `receivers`, `providers` (list[str]): Declared components.
  * `suspicious_apis` (list[str]): Flagged bytecode calls (e.g. `DexClassLoader`, crypto ciphers).
  * `embedded_domains` (list[str]): Hardcoded URLs and hostnames extracted from strings/DEX.
  * `embedded_ips` (list[str]): Hardcoded IPv4/IPv6 addresses.
* **Indexes**: `apk_analysis_id` (Unique), `case_id`, `evidence_id`.

### 5. `network_analyses`
Raw structured findings parsed from network captures (Scapy, Tshark).
* **Fields**:
  * `network_analysis_id` (str, UUIDv4): Unique record identifier.
  * `evidence_id` (str): Associated PCAP/PCAPNG file.
  * `case_id` (str): Associated case.
  * `packet_count` (int): Total frames analyzed.
  * `duration_seconds` (float): Capture duration.
  * `dns_queries` (list[dict]): Queried domains, record types, query timestamps.
  * `resolved_ips` (list[dict]): DNS answer mappings (`domain`, `ip`, `ttl`).
  * `connections` (list[dict]): Network 5-tuple sessions (`src_ip`, `dst_ip`, `proto`, `src_port`, `dst_port`, `bytes`).
  * `http_requests` (list[dict]): Unencrypted HTTP methods, URIs, and User-Agents.
  * `repeated_communications` (list[dict]): Periodic beaconing intervals and destination endpoints.
* **Indexes**: `network_analysis_id` (Unique), `case_id`, `evidence_id`.

### 6. `indicators`
Canonical forensic atomic indicators extracted across all evidence sources.
* **Fields**:
  * `indicator_id` (str, UUIDv4): Unique indicator identifier.
  * `case_id` (str): Associated case.
  * `type` (str): `DOMAIN`, `IP`, `HASH`, `URL`, `PACKAGE`, `API`, `PERMISSION`.
  * `value` (str): Raw extracted string.
  * `normalized_value` (str): Lowercased, stripped, defanged canonical representation.
  * `metadata` (dict): Contextual attributes (e.g. port, protocol, source file).
  * `created_at` (datetime UTC): Ingestion timestamp.
* **Indexes**: `indicator_id` (Unique), `(case_id, normalized_value)`.

### 7. `observations`
Concrete, ground-truth evidence occurrences observed within a specific evidence file.
* **Fields**:
  * `observation_id` (str, UUIDv4): Unique observation identifier.
  * `case_id` (str): Associated case.
  * `indicator_id` (str): Linked atomic indicator.
  * `evidence_id` (str): Source evidence file where fact was observed.
  * `observation_type` (str): `EMBEDDED_DOMAIN`, `EMBEDDED_IP`, `DNS_QUERY`, `NETWORK_CONNECTION`, etc.
  * `source` (str): Analytical tool (`ANDROGUARD`, `MOBSF`, `SCAPY`, `TSHARK`).
  * `value` (str): Observed value.
  * `confidence` (float): Observation certainty (1.0 for observed binary facts).
  * `timestamp` (datetime UTC, optional): Authentic occurrence timestamp from capture.
  * `metadata` (dict): Bytecode offset, packet index, protocol flags.
* **Indexes**: `observation_id` (Unique), `case_id`, `indicator_id`, `evidence_id`.

### 8. `correlations`
Deterministic evidence links synthesized across two or more independent observations.
* **Fields**:
  * `correlation_id` (str, UUIDv4): Unique correlation identifier.
  * `case_id` (str): Associated case.
  * `rule_name` (str): Triggered deterministic rule (`DOMAIN_MATCH`, `IP_MATCH`, etc.).
  * `relationship_type` (str): `EMBEDS`, `CONNECTS_TO`, `RESOLVES_TO`, `CORRELATED_WITH`.
  * `strength` (str): `WEAK`, `MODERATE`, `STRONG`.
  * `reason` (str): Explicit human-readable deductive rationale.
  * `source_observation_ids` (list[str]): First-party observation evidence IDs.
  * `target_observation_ids` (list[str]): Corroborating observation evidence IDs.
  * `supporting_evidence_ids` (list[str]): Cryptographic evidence files linked.
* **Indexes**: `correlation_id` (Unique), `case_id`.

### 9. `attack_nodes` & 10. `attack_edges`
Graph topology elements powering the React Flow visual attack chain.
* **Nodes**: `node_id`, `case_id`, `node_type` (`APPLICATION`, `DOMAIN`, `IP`, `CAPABILITY`, `EVENT`, `THREAT_INTEL`), `label`, `entity_reference`, `metadata`.
* **Edges**: `edge_id`, `case_id`, `source_node_id`, `target_node_id`, `relationship_type`, `relationship_class` (`OBSERVED`, `CORRELATED`, `INFERRED`), `strength`, `reason`, `supporting_evidence_ids`.
* **Indexes**: Compound indices on `(case_id, node_id)` and `(case_id, source_node_id, target_node_id)`.

### 11. `threat_intelligence`
External reputation and enrichment data from external providers.
* **Fields**: `intel_id`, `case_id`, `indicator`, `provider` (`VIRUSTOTAL`, `URLHAUS`, `ABUSEIPDB`, `OTX`), `verdict` (`MALICIOUS`, `SUSPICIOUS`, `BENIGN`, `UNKNOWN`), `score`, `categories`, `checked_at`, `expires_at`, `cached`.
* **Indexes**: `(provider, indicator)` (Unique for global cache lookups), `case_id`.

### 12. `risk_assessments`
Deterministic evidence-weighted scoring dossier.
* **Fields**: `assessment_id`, `case_id`, `risk_level` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `confidence_score` (0.0 to 1.0), `risk_score` (0 to 100), `summary`, `observed_facts` (list[str]), `analytical_inferences` (list[str]), `uncertainty_limitations` (list[str]), `analyst_guidance` (list[str]).
* **Indexes**: `assessment_id` (Unique), `case_id`.

### 13. `reports`
Generated investigation dossiers.
* **Fields**: `report_id`, `case_id`, `title`, `format` (`HTML`, `PDF`, `BOTH`), `html_path`, `pdf_path`, `sha256_html`, `sha256_pdf`, `created_at`.
* **Indexes**: `report_id` (Unique), `case_id`.

---

## 4. Legacy Supabase Context vs. Active MongoDB Architecture

Early architecture proposals for E.M.I.T. referenced a PostgreSQL/Supabase backend. During Phase 2, **MongoDB was selected as the permanent, official database engine** for E.M.I.T. due to:
* Dynamic schema elasticity for unstructured APK manifests and arbitrary PCAP protocol dissections.
* Native JSON document manipulation without object-relational impedance.
* Zero external cloud lock-in (runs completely offline and air-gapped on air-gapped forensic workstations).

Supabase/PostgreSQL is **not used** in the current production implementation.
