# TC-01 — APK + PCAP Cross-Evidence Correlation Validation

**Status:** PASS  
**Case:** Test Case 1 — Vulnerable Android APK + Matching Network Evidence  
**Date:** 07 Sep 2026

## 1. Test Objective

Verify that E.M.I.T. can:

- analyze an APK without executing it;
- analyze a PCAP/PCAPNG file;
- extract APK and network indicators;
- correlate matching evidence across both artifacts;
- generate an attack graph and forensic report.

## 2. Test Evidence

| Evidence | File |
|---|---|
| APK | [`evidences/DVACv1.apk`](evidences/DVACv1.apk) |
| PCAPNG | [`evidences/matching_youtrack.pcapng`](evidences/matching_youtrack.pcapng) |
| Analysis screenshot | [`scrrenshots/Analysis.png`](scrrenshots/Analysis.png) |
| Overview screenshot | [`scrrenshots/Overview.png`](scrrenshots/Overview.png) |
| Attack Graph screenshot | [`scrrenshots/Attack_Graph.png`](scrrenshots/Attack_Graph.png) |
| Final report | See the generated report in the [`report/`](report/) folder |

### APK Integrity

**SHA-256:** `fbd9ab802d418cc3fbfd89b3cea1c9c4d3cbe20f5f19db79979cbc73ad845516`

## 3. Execution

1. Uploaded `DVACv1.apk` to the TC-01 evidence set.
2. E.M.I.T. completed APK static analysis.
3. Uploaded `matching_youtrack.pcapng`.
4. E.M.I.T. completed TShark and Scapy PCAP analysis.
5. E.M.I.T. normalized the findings and executed correlation.
6. E.M.I.T. generated the attack-chain graph and forensic report.

## 4. Expected vs Actual Result

| Check | Expected | Actual |
|---|---|---|
| APK analysis | Completed successfully | **PASS** |
| PCAP analysis | Completed successfully | **PASS** |
| Network indicators | Extracted from PCAP | **PASS — 17 artifacts** |
| Cross-evidence correlation | Matching indicators detected | **PASS — 6 correlation records** |
| Attack graph | APK → indicator → network activity | **PASS** |
| Forensic report | Evidence-backed report generated | **PASS** |

## 5. Correlation Proof

E.M.I.T. identified the following cross-artifact evidence:

### IP Match — STRONG

`127.0.0.1` was found in the APK and independently observed in the PCAP.

**Proof:** APK observation + Scapy + TShark network observation.

### Capability/Activity Alignment — WEAK

The APK declares:

`android.permission.INTERNET`

The PCAP contains active network traffic involving `127.0.0.1`, `127.0.0.11`, and UDP traffic.

### Temporal Alignment — STRONG

E.M.I.T. recorded temporal alignment for the matching `127.0.0.1` indicator across the available evidence observations.

## 6. Network Evidence

The PCAP produced network artifacts including:

- `127.0.0.1`
- `127.0.0.11`
- DNS query: `youtrack.jetbrains.com`
- DNS response: `63.35.30.167`
- UDP network activity

## 7. APK Evidence

The APK report identified:

- Package: `com.zin.dvac`
- `android.permission.INTERNET`
- `android.permission.READ_CONTACTS`
- `android.permission.READ_EXTERNAL_STORAGE`
- `android.permission.WRITE_EXTERNAL_STORAGE`
- `android.permission.USE_BIOMETRIC`
- Embedded domain: `github.com`
- Embedded domain: `schemas.android.com`
- Embedded IP: `127.0.0.1`

## 8. Visual Proof

### Analysis Completed

![Analysis completed](scrrenshots/Analysis.png)

### Investigation Overview

![Investigation overview](scrrenshots/Overview.png)

### Attack Graph

![Attack graph showing APK-to-network relationships](scrrenshots/Attack_Graph.png)

## 9. Final Result

**TC-01 PASSED.**

The test demonstrates that E.M.I.T. successfully performs static APK analysis, PCAP analysis, deterministic cross-evidence correlation, and attack-graph reconstruction.

The strongest proof is the independently observed `127.0.0.1` indicator appearing in both the APK evidence and the PCAP evidence, with the relationship represented in the attack graph.

**Risk reported by E.M.I.T.: LOW — Score 19**  
**Confidence: 65%**  
**Evidence Strength: MODERATE**

> Note: This test validates correlation functionality. It does not by itself prove that the APK caused every observed network event.
