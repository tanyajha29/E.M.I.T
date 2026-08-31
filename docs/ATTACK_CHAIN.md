# E.M.I.T. Evidence-Backed Attack Chain Reconstructor

**Platform:** Evidence-backed Mobile Investigation Tool (E.M.I.T.)  
**Engine Class:** `AttackChainReconstructor` (`backend/app/services/attack_reconstructor.py`)  
**Frontend Visualization:** React Flow Interactive Canvas (`frontend/src/components/AttackGraphCanvas.tsx`)

---

## 1. Overview & Forensic Graph Theory

The Attack Chain Reconstructor transforms disconnected forensic observations and correlations into an interactive, evidence-backed directed attack graph.

### Architectural Invariants
1. **Zero Unsupported Edges**: No graph edge is created without at least one supporting evidence reference (`supporting_evidence_ids`).
2. **Explicit Edge Classification**:
   * `OBSERVED`: A direct, factual relationship extracted from a single evidence item (e.g. *APK embeds domain*).
   * `CORRELATED`: A deterministic relationship synthesized across multiple evidence items (e.g. *APK embedded domain matches PCAP DNS query*).
   * `INFERRED`: An analytical deduction regarding high-level adversary intent (e.g. *Beaconing traffic represents C2 heartbeat*).
3. **Chronological Sequencing**: When authentic timestamps exist, nodes and edges are ordered chronologically. **Synthetic timestamps are strictly forbidden.**

---

## 2. Graph Node Taxonomy

```
+-------------------------------------------------------------------+
|                        ATTACK GRAPH NODES                         |
+-------------------+-----------------------------------------------+
| Node Type         | Visual Encoding & Definition                  |
+-------------------+-----------------------------------------------+
| APPLICATION       | Emerald Green: Target Android package name    |
| CAPABILITY        | Purple: Declared permissions / APIs           |
| DOMAIN            | Amber: Hardcoded or queried FQDNs             |
| IP                | Sky Blue: Observed IPv4/IPv6 endpoints        |
| DNS_EVENT         | Cyan: Active DNS lookup transactions          |
| NETWORK_EVENT     | Cyan: Outbound TCP/UDP packet conversations   |
| THREAT_INTEL      | Rose Red: External threat reputation record   |
+-------------------+-----------------------------------------------+
```

---

## 3. Relationship (Edge) Taxonomy

Every edge connects a `source_node` to a `target_node` and carries:
* `relationship_type`: The structural relationship.
* `relationship_class`: `OBSERVED`, `CORRELATED`, or `INFERRED`.
* `strength`: `WEAK`, `MODERATE`, or `STRONG`.
* `reason`: Human-readable explanation.
* `supporting_evidence_ids`: Array of evidence UUIDs containing the ground-truth data.

### Supported Edge Types
* `CONTAINS`: Application package contains component (Activity, Service, Receiver).
* `USES`: Application bytecode invokes sensitive capability or API.
* `EMBEDS`: Application archive statically embeds a domain or IP address string.
* `RESOLVES_TO`: DNS query transaction maps a domain to an IP endpoint.
* `CONNECTS_TO`: Outbound network session connects from local host to remote IP.
* `REPEATS`: Network flow repeats at periodic intervals (beaconing behavior).
* `CORRELATED_WITH`: Temporal or multi-source corroboration between events.
* `SUPPORTED_BY`: External threat intelligence record confirms malicious classification.

---

## 4. Visual Rendering & Interactive Controls

The frontend interface utilizes **React Flow** to render a cyber-defense topology:
* **Interactive Canvas**: Pan, zoom, minimap overview, and responsive node rearrangement.
* **Color-Coded Legend**: Top-left visual indicator differentiating node entities and edge classes.
* **Edge Style Distinction**:
  * `OBSERVED`: Solid cyan line.
  * `CORRELATED`: Amber dashed line with animated flow.
  * `INFERRED`: Purple dotted line.
* **Evidence Inspection Drawer**:
  * Clicking any node reveals the entity name, source tool, and linked observations.
  * Clicking any edge reveals the relationship type, confidence, deductive rationale, and clickable links to source evidence files and cryptographic SHA-256 hashes.
