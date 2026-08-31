import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

from app.db.repositories.risk_repository import RiskRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.threat_intel_repository import ThreatIntelRepository
from app.schemas.risk import RiskAssessment, RiskLevel
from app.schemas.normalized import ObservationType

logger = logging.getLogger("emit.risk_engine")

class RiskEngine:
    """
    Deterministic Risk and Explainability Engine.
    Evaluates evidence categories using documented, deterministic weights without machine learning.
    Strictly separates ground-truth OBSERVED facts from INFERENCES and POSSIBLE INTERPRETATIONS.
    Explicitly documents UNCERTAINTY and provides actionable ANALYST GUIDANCE.
    """

    # -------------------------------------------------------------------------
    # DOCUMENTED DETERMINISTIC WEIGHTING RULES
    # -------------------------------------------------------------------------
    WEIGHT_SUSPICIOUS_PERMISSION = 5        # Per distinct permission (Cap: 15)
    CAP_SUSPICIOUS_PERMISSION = 15

    WEIGHT_SUSPICIOUS_API = 5               # Per distinct API call (Cap: 15)
    CAP_SUSPICIOUS_API = 15

    WEIGHT_EMBEDDED_DOMAIN = 3              # Per static domain reference (Cap: 9)
    CAP_EMBEDDED_DOMAIN = 9

    WEIGHT_EMBEDDED_IP = 5                  # Per hardcoded IP (Cap: 10)
    CAP_EMBEDDED_IP = 10

    WEIGHT_DNS_OBSERVATION = 5              # Active PCAP DNS query (Cap: 10)
    CAP_DNS_OBSERVATION = 10

    WEIGHT_MATCHING_DOMAIN = 15             # APK domain == PCAP DNS query
    WEIGHT_MATCHING_IP = 15                 # APK IP == PCAP destination IP
    WEIGHT_RESOLVED_IP_MATCH = 20           # APK domain resolves to contacted PCAP IP
    WEIGHT_REPEATED_COMMUNICATION = 20      # Repeated / periodic beacon pattern
    WEIGHT_TEMPORAL_ALIGNMENT = 10          # Corroborated time window
    WEIGHT_THREAT_INTEL_MALICIOUS = 25      # External feed verdict MALICIOUS
    WEIGHT_THREAT_INTEL_SUSPICIOUS = 10     # External feed verdict SUSPICIOUS

    # Tier Thresholds
    THRESHOLD_MEDIUM = 25
    THRESHOLD_HIGH = 50
    THRESHOLD_CRITICAL = 75

    @classmethod
    def assess(
        cls,
        normalized_evidence_or_case_id: Any,
        correlations: Optional[List[Any]] = None,
        attack_chain: Optional[Dict[str, Any]] = None,
        risk_repo: Optional[RiskRepository] = None,
        obs_repo: Optional[ObservationRepository] = None,
        corr_repo: Optional[CorrelationRepository] = None,
        threat_repo: Optional[ThreatIntelRepository] = None
    ) -> RiskAssessment:
        """
        Executes evidence-weighted deterministic risk assessment and explainability report generation.
        """
        if isinstance(normalized_evidence_or_case_id, dict):
            case_id = normalized_evidence_or_case_id.get("case_id")
        else:
            case_id = str(normalized_evidence_or_case_id) if normalized_evidence_or_case_id else None

        if not case_id:
            logger.warning("RiskEngine.assess invoked without valid case_id.")
            return RiskAssessment(
                case_id="unknown",
                risk_level=RiskLevel.LOW,
                evidence_strength="WEAK",
                confidence=0.5,
                summary="No case_id provided. Unable to assess risk."
            )

        logger.info(f"RiskEngine starting deterministic assessment for case {case_id}")

        if risk_repo is None:
            risk_repo = RiskRepository()
        if obs_repo is None:
            obs_repo = ObservationRepository()
        if corr_repo is None:
            corr_repo = CorrelationRepository()
        if threat_repo is None:
            threat_repo = ThreatIntelRepository()

        # Gather inputs
        observations = obs_repo.find_all({"case_id": case_id})
        
        raw_correlations = correlations if correlations is not None else corr_repo.find_all({"case_id": case_id})
        case_correlations: List[Dict[str, Any]] = [
            c.model_dump() if hasattr(c, "model_dump") else c for c in raw_correlations
        ]

        threat_intel_records = threat_repo.find_all({"case_id": case_id})

        # Track supporting IDs
        supp_obs_ids: Set[str] = set()
        supp_corr_ids: Set[str] = set()
        supp_ev_ids: Set[str] = set()

        observed_facts: List[str] = []
        inferences: List[str] = []
        possible_interpretations: List[str] = []
        uncertainty: List[str] = []
        analyst_guidance: List[str] = []
        category_scores: Dict[str, Any] = {}

        total_score = 0

        # ---------------------------------------------------------------------
        # 1. EVALUATE STATIC APK OBSERVATIONS
        # ---------------------------------------------------------------------
        # Suspicious permissions
        suspicious_perms = [
            o for o in observations 
            if o.get("observation_type") in [ObservationType.SUSPICIOUS_PERMISSION.value, ObservationType.DECLARED_PERMISSION.value]
            and any(p in o.get("value", "").upper() for p in ["SMS", "BOOT", "ALERT_WINDOW", "INSTALL", "RECORD_AUDIO", "CAMERA", "LOCATION"])
        ]
        perm_score = min(len(suspicious_perms) * cls.WEIGHT_SUSPICIOUS_PERMISSION, cls.CAP_SUSPICIOUS_PERMISSION)
        total_score += perm_score
        category_scores["suspicious_permissions"] = {"score": perm_score, "count": len(suspicious_perms)}
        for p in suspicious_perms:
            supp_obs_ids.add(p.get("observation_id"))
            supp_ev_ids.add(p.get("evidence_id"))
            observed_facts.append(f"APK declares privileged/sensitive permission '{p.get('value')}'.")

        # Suspicious APIs
        suspicious_apis = [
            o for o in observations 
            if o.get("observation_type") == ObservationType.SUSPICIOUS_API.value
        ]
        api_score = min(len(suspicious_apis) * cls.WEIGHT_SUSPICIOUS_API, cls.CAP_SUSPICIOUS_API)
        total_score += api_score
        category_scores["suspicious_apis"] = {"score": api_score, "count": len(suspicious_apis)}
        for a in suspicious_apis:
            supp_obs_ids.add(a.get("observation_id"))
            supp_ev_ids.add(a.get("evidence_id"))
            observed_facts.append(f"APK bytecode invokes sensitive API '{a.get('value')}'.")

        # Embedded Domains & IPs
        embedded_domains = [
            o for o in observations 
            if o.get("source") == "APK" and o.get("observation_type") in [ObservationType.EMBEDDED_DOMAIN.value, ObservationType.EMBEDDED_URL.value, "suspicious_domain"]
        ]
        dom_score = min(len(embedded_domains) * cls.WEIGHT_EMBEDDED_DOMAIN, cls.CAP_EMBEDDED_DOMAIN)
        total_score += dom_score
        category_scores["embedded_domains"] = {"score": dom_score, "count": len(embedded_domains)}
        for d in embedded_domains:
            supp_obs_ids.add(d.get("observation_id"))
            supp_ev_ids.add(d.get("evidence_id"))
            observed_facts.append(f"APK bytecode/assets statically embed domain reference '{d.get('value')}'.")

        embedded_ips = [
            o for o in observations 
            if o.get("source") == "APK" and o.get("observation_type") in [ObservationType.EMBEDDED_IP.value, "suspicious_ip"]
        ]
        ip_score = min(len(embedded_ips) * cls.WEIGHT_EMBEDDED_IP, cls.CAP_EMBEDDED_IP)
        total_score += ip_score
        category_scores["embedded_ips"] = {"score": ip_score, "count": len(embedded_ips)}
        for ip in embedded_ips:
            supp_obs_ids.add(ip.get("observation_id"))
            supp_ev_ids.add(ip.get("evidence_id"))
            observed_facts.append(f"APK bytecode/assets statically embed IP address '{ip.get('value')}'.")

        # ---------------------------------------------------------------------
        # 2. EVALUATE NETWORK PCAP OBSERVATIONS
        # ---------------------------------------------------------------------
        dns_queries = [
            o for o in observations 
            if o.get("source") == "PCAP" and o.get("observation_type") in [ObservationType.DNS_QUERY.value, "dns_domain"]
        ]
        dns_score = min(len(dns_queries) * cls.WEIGHT_DNS_OBSERVATION, cls.CAP_DNS_OBSERVATION)
        total_score += dns_score
        category_scores["dns_observations"] = {"score": dns_score, "count": len(dns_queries)}
        for dq in dns_queries:
            supp_obs_ids.add(dq.get("observation_id"))
            supp_ev_ids.add(dq.get("evidence_id"))
            observed_facts.append(f"Supplied PCAP capture contains DNS query for '{dq.get('value')}'.")

        repeated_comms = [
            o for o in observations 
            if o.get("source") == "PCAP" and o.get("observation_type") in [ObservationType.REPEATED_COMMUNICATION.value, "repeated_communication_pattern"]
        ]
        for rc in repeated_comms:
            supp_obs_ids.add(rc.get("observation_id"))
            supp_ev_ids.add(rc.get("evidence_id"))
            meta = rc.get("metadata", {})
            cnt = meta.get("packet_count", "multiple")
            pat = meta.get("pattern_classification", "repeated communication")
            observed_facts.append(f"PCAP capture contains repeated outbound communication to '{rc.get('value')}' ({cnt} packets, pattern: '{pat}').")

        # ---------------------------------------------------------------------
        # 3. EVALUATE DETERMINISTIC CORRELATIONS
        # ---------------------------------------------------------------------
        corr_types = set(c.get("relationship_type") for c in case_correlations)

        if "DOMAIN_MATCH" in corr_types:
            total_score += cls.WEIGHT_MATCHING_DOMAIN
            category_scores["matching_domain"] = cls.WEIGHT_MATCHING_DOMAIN
            inferences.append("APK embedded domain and PCAP DNS query match with 100% string identity.")

        if "IP_MATCH" in corr_types:
            total_score += cls.WEIGHT_MATCHING_IP
            category_scores["matching_ip"] = cls.WEIGHT_MATCHING_IP
            inferences.append("APK hardcoded IP and PCAP destination network IP match.")

        if "RESOLVED_IP_MATCH" in corr_types:
            total_score += cls.WEIGHT_RESOLVED_IP_MATCH
            category_scores["resolved_ip_match"] = cls.WEIGHT_RESOLVED_IP_MATCH
            inferences.append("APK embedded domain resolved via DNS in PCAP traffic to an IP address that was subsequently contacted.")

        if "PERIODIC_COMMUNICATION_MATCH" in corr_types or repeated_comms:
            total_score += cls.WEIGHT_REPEATED_COMMUNICATION
            category_scores["repeated_communication"] = cls.WEIGHT_REPEATED_COMMUNICATION
            inferences.append("Network endpoint exhibiting repeated/periodic communications correlates with APK embedded indicator.")

        if "TEMPORAL_ALIGNMENT" in corr_types:
            total_score += cls.WEIGHT_TEMPORAL_ALIGNMENT
            category_scores["temporal_alignment"] = cls.WEIGHT_TEMPORAL_ALIGNMENT
            inferences.append("Temporal correlation established between APK compilation artifacts and network event windows.")

        for c in case_correlations:
            supp_corr_ids.add(c.get("correlation_id"))
            for sid in c.get("source_observation_ids", []):
                supp_obs_ids.add(sid)
            for tid in c.get("target_observation_ids", []):
                supp_obs_ids.add(tid)
            for eid in c.get("supporting_evidence_ids", []):
                supp_ev_ids.add(eid)

        # ---------------------------------------------------------------------
        # 4. EVALUATE EXTERNAL THREAT INTELLIGENCE
        # ---------------------------------------------------------------------
        ti_malicious = [ti for ti in threat_intel_records if ti.get("verdict") == "MALICIOUS"]
        ti_suspicious = [ti for ti in threat_intel_records if ti.get("verdict") == "SUSPICIOUS"]

        if ti_malicious:
            total_score += cls.WEIGHT_THREAT_INTEL_MALICIOUS
            category_scores["threat_intel"] = cls.WEIGHT_THREAT_INTEL_MALICIOUS
            inferences.append(f"External threat intelligence feed confirmed {len(ti_malicious)} indicator(s) as MALICIOUS.")
        elif ti_suspicious:
            total_score += cls.WEIGHT_THREAT_INTEL_SUSPICIOUS
            category_scores["threat_intel"] = cls.WEIGHT_THREAT_INTEL_SUSPICIOUS
            inferences.append(f"External threat intelligence feed flagged {len(ti_suspicious)} indicator(s) as SUSPICIOUS.")

        # ---------------------------------------------------------------------
        # 5. ASSIGN DETERMINISTIC RISK LEVEL & EVIDENCE STRENGTH
        # ---------------------------------------------------------------------
        if total_score >= cls.THRESHOLD_CRITICAL:
            risk_level = RiskLevel.CRITICAL
        elif total_score >= cls.THRESHOLD_HIGH:
            risk_level = RiskLevel.HIGH
        elif total_score >= cls.THRESHOLD_MEDIUM:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Evidence strength
        has_apk = any(o.get("source") == "APK" for o in observations)
        has_pcap = any(o.get("source") == "PCAP" for o in observations)
        has_correlations = len(case_correlations) > 0

        if has_apk and has_pcap and has_correlations:
            evidence_strength = "STRONG"
        elif has_apk or has_pcap:
            evidence_strength = "MODERATE"
        else:
            evidence_strength = "WEAK"

        # Deterministic Confidence Calculation (capped at 0.95 to reflect uncertainty)
        conf = 0.50
        if has_apk:
            conf += 0.15
        if has_pcap:
            conf += 0.15
        if has_correlations:
            conf += 0.10
        if ti_malicious or ti_suspicious:
            conf += 0.05
        confidence = round(min(conf, 0.95), 2)

        # ---------------------------------------------------------------------
        # 6. POSSIBLE INTERPRETATIONS, UNCERTAINTY & ANALYST GUIDANCE
        # ---------------------------------------------------------------------
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            possible_interpretations.append(
                "The observed convergence of embedded APK indicators, active DNS resolution, and repeated network flows "
                "strongly suggests coordinated outbound remote communication."
            )
            possible_interpretations.append(
                "Activity is consistent with remote command-and-control (C2) beaconing, automated exfiltration, or telemetry reporting."
            )
            possible_interpretations.append(
                "Forensic caution: Do not claim definitive malicious C2 or data theft as proven fact unless payload plaintext confirms unauthorized transfer."
            )
        elif risk_level == RiskLevel.MEDIUM:
            possible_interpretations.append(
                "The application exhibits notable static permissions or uncorroborated network traffic that warrants scrutiny."
            )
            possible_interpretations.append(
                "The behavior could represent third-party advertising SDKs, analytics frameworks, or legitimate service endpoints."
            )
        else:
            possible_interpretations.append(
                "Minimal suspicious indicators observed. Current evidence is consistent with benign application activity."
            )

        # Explicit Uncertainty documentation
        uncertainty.append("Payload contents were not inspected for TLS-encrypted streams; content cannot be definitively confirmed without session keys.")
        uncertainty.append("Analysis is based on supplied static files and passive network capture without dynamic execution on a physical hardware sandbox.")
        if repeated_comms:
            uncertainty.append("Periodic beaconing patterns can occur in legitimate push notification heartbeats or regular cloud sync services.")

        limitations = [
            "Assessment is deterministic and evidence-weighted; scores represent relative risk priority, not mathematical probabilities.",
            "Obfuscated, encrypted, or dynamically loaded DEX payloads may evade static inspection.",
            "Short PCAP capture durations may not capture long-interval periodic beaconing."
        ]

        # Actionable Analyst Guidance
        analyst_guidance.append("Inspect TLS SNI headers and X.509 certificates to verify remote endpoint ownership.")
        analyst_guidance.append("Examine decompiled Smali/Java classes around identified suspicious APIs to verify execution control flow.")
        if embedded_domains:
            analyst_guidance.append("Cross-reference observed domains against enterprise proxy logs and external WHOIS registration history.")
        if repeated_comms:
            analyst_guidance.append("Perform dynamic runtime execution in an instrumented sandbox (Frida) to intercept unencrypted socket buffers.")

        # Summary Synthesis
        summary = (
            f"Deterministic Evidence-Weighted Assessment: {risk_level.value} Risk (Score: {total_score}, Confidence: {confidence}, Evidence Strength: {evidence_strength}). "
            f"Accumulated evidence includes {len(suspicious_perms)} sensitive permissions, {len(suspicious_apis)} suspicious APIs, "
            f"{len(embedded_domains)} embedded domains, {len(case_correlations)} cross-evidence correlations, and {len(threat_intel_records)} threat intel records."
        )

        assessment = RiskAssessment(
            case_id=case_id,
            risk_level=risk_level,
            evidence_strength=evidence_strength,
            confidence=confidence,
            summary=summary,
            observed_facts=observed_facts[:20],
            inferences=inferences,
            possible_interpretations=possible_interpretations,
            uncertainty=uncertainty,
            limitations=limitations,
            analyst_guidance=analyst_guidance,
            supporting_observation_ids=sorted(list(set([o for o in supp_obs_ids if o]))),
            supporting_correlation_ids=sorted(list(set([c for c in supp_corr_ids if c]))),
            supporting_evidence_ids=sorted(list(set([e for e in supp_ev_ids if e]))),
            category_scores=category_scores,
            metadata={"accumulated_score": total_score, "assessed_at": datetime.utcnow().isoformat()}
        )

        # Persist to database if there are observations, correlations, or threat intel records
        if observations or case_correlations or threat_intel_records:
            existing = risk_repo.find_one({"case_id": case_id})
            if existing:
                risk_repo.collection.replace_one({"case_id": case_id}, assessment.model_dump())
            else:
                risk_repo.insert_one(assessment.model_dump())

        logger.info(f"RiskEngine completed assessment for case {case_id}: {risk_level.value} (Score: {total_score})")
        return assessment
