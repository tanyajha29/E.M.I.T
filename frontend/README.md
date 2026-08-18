## 🔐 C2Trace

### Explainable Cross-Layer Evidence Correlation for Android C2 Analysis

C2Trace is a research-oriented Android malware analysis platform designed to identify and explain **Command & Control (C2)-like behavior** by correlating evidence from multiple analysis layers:

**Static Analysis + Runtime Analysis + Network Analysis → Cross-Layer Correlation → Explainable C2 Hypothesis**

The goal is **not** to replace existing malware-analysis tools, but to orchestrate them and connect their outputs into a unified evidence model that an analyst can investigate and understand. 

---

# 🎯 Problem

Android malware can hide C2 infrastructure through:

* Obfuscated or encrypted strings
* Dynamic domain resolution
* Runtime-generated URLs
* Native code
* Encrypted network communication
* Periodic beaconing
* Multiple communication endpoints

A domain found during static analysis alone may not be malicious.

However:

```text
Domain found in APK
        +
Domain revealed during execution
        +
DNS resolution
        +
Network connection
        +
Temporal correlation
        ↓
Stronger C2 hypothesis
```

C2Trace focuses on connecting these observations rather than treating them as isolated alerts. 

---

# 🧠 Core Research Question

> **Does cross-layer evidence correlation improve the detection and explainability of C2-like behavior compared with isolated static or network analysis?**

### Hypothesis

> Combining static, runtime, and network evidence with temporal/entity correlation will provide stronger and more explainable C2 assessments than relying on individual evidence sources.

---

# 🏗️ System Architecture

```text
                         ┌──────────────────────┐
                         │      Analyst UI      │
                         │    React Dashboard   │
                         └──────────┬───────────┘
                                    │
                              REST / WebSocket
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │      FastAPI API     │
                         │   Orchestration Layer│
                         └──────────┬───────────┘
                                    │
                 ┌──────────────────┼──────────────────┐
                 │                  │                  │
                 ▼                  ▼                  ▼
        ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
        │ Static Engine  │ │ Runtime Engine │ │ Network Engine │
        │                │ │                │ │                │
        │ MobSF          │ │ Android        │ │ tcpdump        │
        │ APKTool        │ │ Emulator       │ │ Wireshark      │
        │ JADX           │ │ Frida          │ │ tshark         │
        └───────┬────────┘ └───────┬────────┘ └───────┬────────┘
                │                  │                  │
                └──────────────────┼──────────────────┘
                                   ▼
                         ┌──────────────────────┐
                         │ Evidence Normalizer  │
                         │                      │
                         │ Common Event Schema  │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Correlation Engine   │
                         │                      │
                         │ Entity Matching      │
                         │ Temporal Matching    │
                         │ Behavioral Rules     │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ C2 Scoring Engine    │
                         │                      │
                         │ Evidence Weighting   │
                         │ Confidence Score     │
                         └──────────┬───────────┘
                                    │
                    ┌───────────────┼────────────────┐
                    ▼               ▼                ▼
             ┌────────────┐ ┌────────────┐ ┌──────────────┐
             │ Evidence   │ │ IOC Store  │ │ C2 Timeline  │
             │ Graph      │ │            │ │              │
             └─────┬──────┘ └─────┬──────┘ └──────┬───────┘
                   └───────────────┼───────────────┘
                                   ▼
                         ┌──────────────────────┐
                         │     PostgreSQL       │
                         └──────────────────────┘
```

The architecture follows the proposal's core flow of APK intake → static analysis → controlled runtime analysis → network capture → normalization → correlation → scoring → visualization/reporting. 

---

# 🔬 Analysis Pipeline

## 1. APK Intake

User uploads:

```text
sample.apk
```

System records:

```text
SHA-256
Filename
Size
Upload time
Analysis ID
```

Each analysis receives a unique:

```text
analysis_id
```

---

## 2. Static Analysis

Extract:

```text
Manifest
Permissions
Activities
Services
Receivers
Providers
URLs
Domains
IP addresses
Network APIs
Suspicious strings
Native libraries
Package information
```

Possible tools:

* MobSF
* JADX
* APKTool
* Androguard

Output:

```json
{
  "type": "static_domain",
  "value": "example.com",
  "source": "classes.dex",
  "confidence": 0.4
}
```

---

# 3. Controlled Runtime Analysis

Execute the APK only inside an **isolated Android analysis environment**.

Use:

* Android Emulator
* Frida
* ADB
* Python automation

Observe:

```text
Process creation
API calls
Network APIs
Dynamic strings
Runtime URLs
DNS-related activity
Suspicious behaviors
```

Frida is used for controlled instrumentation of selected APIs and behaviors. 

---

# 4. Network Analysis

Capture traffic generated during execution.

Tools:

* tcpdump
* tshark
* Wireshark
* Python packet-processing libraries

Extract:

```text
DNS queries
Destination IPs
Ports
Protocols
Connection timestamps
Connection frequency
TLS metadata
Repeated connections
```

C2Trace should primarily focus on **metadata and behavior**, rather than attempting to decrypt arbitrary encrypted traffic.

---

# 5. Evidence Normalization

Different tools produce different formats.

Convert everything into a common event structure:

```text
EvidenceEvent

event_id
analysis_id
timestamp
source
event_type
entity
value
process
confidence
metadata
```

Example:

```json
{
  "event_type": "network_connection",
  "entity": "185.x.x.x",
  "timestamp": "10:42:31",
  "process": "com.example.app",
  "source": "pcap"
}
```

---

# 6. Cross-Layer Correlation ⭐

This is the **core of C2Trace**.

Correlate evidence using:

### Entity correlation

```text
domain
IP
package
process
URL
API
```

### Temporal correlation

```text
Static domain
       ↓
Runtime domain observed
       ↓
DNS query
       ↓
Network connection
```

### Behavioral correlation

Look for patterns such as:

```text
Repeated connection
Periodic beaconing
Unexpected external endpoint
Runtime-generated destination
DNS → connection sequence
```

---

# 7. C2 Scoring

Generate an explainable score.

Example:

```text
Static evidence             +2
Runtime evidence            +3
Network evidence            +3
Temporal correlation        +2
Repeated communication      +2
                              ──
                         Score: 12
```

The initial scoring system should remain transparent and rule-based.

Later experiments can investigate whether different weighting strategies improve performance.

---

# 8. Evidence Graph

The key UI feature:

```text
APK
 │
 ├──── Static Domain
 │           │
 │           ▼
 │      example.com
 │           │
 │           │ temporal match
 │           ▼
 ├──── Runtime Event
 │           │
 │           ▼
 │       DNS Query
 │           │
 │           ▼
 └──── Network Connection
             │
             ▼
        C2 Hypothesis
```

The analyst should be able to click any node and see:

```text
What happened?
When?
Which tool observed it?
Which process caused it?
What other evidence supports it?
Why did it contribute to the score?
```

---

# 🖥️ Dashboard

### Overview

```text
Analysis: #A1024

C2 Confidence
      87%

Static Evidence       12
Runtime Evidence       8
Network Evidence      15
Correlations            7

[ Evidence Graph ]

[ Timeline ]

[ IOCs ]

[ Network ]

[ Runtime ]

[ Report ]
```

### Main pages

```text
Dashboard
├── Analysis Overview
├── Static Analysis
├── Runtime Analysis
├── Network Analysis
├── Evidence Graph
├── Timeline
├── IOC Explorer
├── C2 Findings
└── Report
```

---

# 🛠️ Tech Stack

## Frontend

```text
React
TypeScript
Tailwind CSS
Recharts / D3.js
React Flow
WebSocket
```

### Purpose

* Dashboard
* Evidence graph
* Timeline
* Network visualization
* Real-time analysis status

---

## Backend

```text
Python
FastAPI
Pydantic
Celery / Redis
WebSocket
```

### Purpose

* API
* Authentication
* Analysis orchestration
* Job management
* Evidence processing
* Correlation
* Scoring

---

## Malware Analysis

```text
MobSF
JADX
APKTool
Androguard
Frida
ADB
Android Emulator
```

The proposal specifically identifies MobSF, Frida, Android Emulator and related tooling as part of the intended implementation. 

---

## Network

```text
tcpdump
tshark
Wireshark
Scapy
```

---

## Database

```text
PostgreSQL
```

Store:

```text
Users
Samples
Analyses
StaticEvidence
RuntimeEvents
NetworkEvents
IOCs
Correlations
Findings
Scores
Reports
```

---

## Infrastructure

```text
Docker
Docker Compose
Linux
Git/GitHub
```

The analysis environment should be isolated from the normal development environment.

---

# 📁 Suggested Repository Structure

```text
c2trace/
│
├── frontend/
│   ├── components/
│   ├── pages/
│   ├── graphs/
│   ├── timeline/
│   └── services/
│
├── backend/
│   ├── api/
│   ├── models/
│   ├── schemas/
│   ├── services/
│   ├── workers/
│   └── main.py
│
├── analyzers/
│   ├── static/
│   │   ├── mobsf/
│   │   ├── jadx/
│   │   └── apktool/
│   │
│   ├── runtime/
│   │   ├── emulator/
│   │   ├── frida/
│   │   └── adb/
│   │
│   └── network/
│       ├── capture/
│       ├── parser/
│       └── dns/
│
├── correlation/
│   ├── normalizer/
│   ├── entity_matcher/
│   ├── temporal_matcher/
│   └── rules/
│
├── scoring/
│   ├── scorer.py
│   └── rules.yaml
│
├── database/
│   ├── migrations/
│   └── schema/
│
├── reports/
│
├── tests/
│
├── docker/
│
├── docs/
│
└── README.md
```

---

# 🚀 Development Roadmap

## Phase 0 — Research & Design

**Week 1**

* Finalize research question
* Study MobSF / existing platforms
* Define evidence schema
* Define correlation rules
* Define dataset strategy
* Define evaluation metrics
* Design architecture

**Deliverable:** Architecture + research methodology

---

## Phase 1 — Project Foundation

**Week 2**

Build:

* Git repository
* FastAPI backend
* React frontend
* PostgreSQL
* Docker Compose
* Authentication
* Basic dashboard

**Deliverable:**

```text
Login → Dashboard → Create Analysis
```

---

## Phase 2 — APK Intake + Static Analysis

**Week 3–4**

Implement:

```text
APK upload
      ↓
SHA-256
      ↓
MobSF
      ↓
Static evidence
      ↓
Database
```

Dashboard:

```text
APK information
Permissions
Domains
URLs
APIs
Native libraries
```

**Deliverable:** Working static-analysis pipeline.

---

## Phase 3 — Runtime Environment

**Week 5–6**

Set up:

```text
Android Emulator
      ↓
ADB
      ↓
APK installation
      ↓
Frida
      ↓
Runtime events
```

Implement controlled instrumentation.

**Deliverable:** Runtime evidence collection.

---

## Phase 4 — Network Analysis

**Week 7**

Implement:

```text
Emulator
   ↓
tcpdump
   ↓
PCAP
   ↓
tshark/Scapy
   ↓
Network events
```

Extract:

* DNS
* IP
* ports
* timestamps
* connection frequency

**Deliverable:** Network telemetry pipeline.

---

# ⭐ Phase 5 — Cross-Layer Correlation

**Week 8–9**

This is the **most important phase**.

Implement:

```text
Static
   +
Runtime
   +
Network
   ↓
Normalization
   ↓
Entity matching
   ↓
Temporal matching
   ↓
Behavioral rules
   ↓
Correlated evidence
```

**Deliverable:** C2 correlation engine.

---

# ⭐ Phase 6 — Explainable Scoring

**Week 10**

Implement:

```text
Evidence
   ↓
Rules
   ↓
Score
   ↓
Confidence
   ↓
Explanation
```

Example:

```text
C2 Confidence: HIGH

Reasons:
✓ Runtime domain observed
✓ DNS resolution detected
✓ Connection followed within 3 seconds
✓ Repeated communication detected
✓ Static and runtime domains matched
```

**Deliverable:** Explainable C2 assessment.

---

# 🎨 Phase 7 — Evidence Graph + Dashboard

**Week 11**

Build:

* Evidence graph
* Timeline
* IOC explorer
* Network view
* Runtime events
* C2 findings
* Investigation view

**Deliverable:** Complete analyst dashboard.

---

# 🧪 Phase 8 — Evaluation

**Week 12–13**

Create a documented dataset containing:

```text
Benign samples
Controlled malicious samples
Different C2 patterns
```

Run:

```text
Experiment A
Static only

Experiment B
Network only

Experiment C
Static + Runtime

Experiment D
Static + Runtime + Network
```

Measure:

```text
Precision
Recall
F1
False Positive Rate
```

These experiments directly follow the evaluation design in your proposal. 

---

# 📊 Phase 9 — Research Analysis

**Week 14**

Analyze:

* Which layer catches what?
* Which evidence is weak alone?
* How much does correlation improve results?
* Which rules produce false positives?
* Which malware behaviors remain undetected?
* Runtime limitations
* Dataset limitations

Create:

```text
Confusion matrices
Performance tables
Correlation examples
Ablation results
```

---

# 📝 Phase 10 — Paper + Final Demo

**Week 15–16**

Complete:

```text
Research Paper
│
├── Abstract
├── Introduction
├── Related Work
├── Architecture
├── Methodology
├── Correlation Model
├── Experiments
├── Results
├── Limitations
└── Conclusion
```

Final demo:

```text
Upload APK
     ↓
Static analysis
     ↓
Runtime execution
     ↓
Network capture
     ↓
Correlation
     ↓
C2 confidence
     ↓
Evidence graph
     ↓
Generate report
```

---

# 🧪 Evaluation Strategy

The central experiment should remain:

```text
                    C2Trace
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
     Static         Runtime        Network
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                 CORRELATION
                       │
                       ▼
                 C2 HYPOTHESIS
```

Compare:

| Configuration              | Purpose             |
| -------------------------- | ------------------- |
| Static only                | Baseline            |
| Network only               | Baseline            |
| Static + Runtime           | Partial correlation |
| Static + Runtime + Network | **Full C2Trace**    |

Metrics:

```text
Precision
Recall
F1-score
False Positive Rate
```

The proposal explicitly defines these evaluation dimensions. 

---

# 🔐 Security & Ethics

C2Trace must operate only in a controlled laboratory environment.

### Rules

* Only analyze APKs you are authorized to analyze.
* Do not interact with live malicious C2 infrastructure.
* Use isolated Android environments.
* Keep malware execution away from personal/production systems.
* Do not expose captured credentials or personal data.
* Use controlled or documented datasets.
* Clearly label experimental results.
* Do not claim detection accuracy without measured evaluation.

The proposal explicitly defines isolated execution and prohibits attacking live C2 infrastructure or third-party systems. 

---

# 🎯 Final MVP

If time becomes limited, **do not sacrifice the correlation engine to add more features.**

The minimum successful C2Trace should be:

```text
        APK
         │
         ▼
   Static Analysis
         │
         ├──────────┐
         ▼          │
   Runtime Analysis │
         │          │
         ├──────────┤
         ▼          ▼
    Network Capture
         │
         ▼
 Evidence Normalization
         │
         ▼
 Cross-Layer Correlation ⭐
         │
         ▼
 Explainable C2 Score ⭐
         │
         ▼
 Evidence Graph ⭐
         │
         ▼
    Analyst Report
```

### **The three things we absolutely must get right:**

**1. Evidence normalization**

**2. Cross-layer + temporal correlation**

**3. Explainable evidence graph**

Everything else can be progressively added around those three.

---

## 🏆 Project Definition

> **C2Trace is an explainable Android malware-analysis platform that correlates static, runtime, and network evidence to identify and investigate C2-like behavior. Rather than replacing existing analysis tools, it orchestrates their outputs into a common evidence model, applies entity and temporal correlation, produces an interpretable C2 confidence assessment, and presents the resulting evidence as an analyst-friendly investigation graph.**

That should be the **north star of the project**. If a feature doesn't contribute to that sentence, it should probably not be part of the MVP.
