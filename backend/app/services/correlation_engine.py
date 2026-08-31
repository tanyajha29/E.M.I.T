import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Tuple

from app.db.repositories.correlation_repository import CorrelationRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.schemas.correlation import Correlation, CorrelationStrength
from app.schemas.indicator import IndicatorType
from app.schemas.normalized import ObservationType
from app.services.normalizer import ValueNormalizer

logger = logging.getLogger("emit.correlation_engine")

class CorrelationEngine:
    """
    Deterministic Evidence Correlation Engine for E.M.I.T.
    Correlates evidence across APK static analysis, PCAP network captures,
    and optional threat intelligence feeds without machine learning.
    """

    @staticmethod
    def correlate(
        case_id_or_normalized: Any,
        threat_intel: Optional[List[Dict[str, Any]]] = None,
        correlation_repo: Optional[CorrelationRepository] = None,
        observation_repo: Optional[ObservationRepository] = None,
        indicator_repo: Optional[IndicatorRepository] = None
    ) -> List[Correlation]:
        """
        Executes all deterministic correlation rules across case observations.
        Accepts either a string `case_id` or a normalized output dictionary containing `case_id`.
        """
        if isinstance(case_id_or_normalized, dict):
            case_id = case_id_or_normalized.get("case_id")
        else:
            case_id = str(case_id_or_normalized) if case_id_or_normalized else None

        if not case_id:
            logger.warning("CorrelationEngine invoked without valid case_id.")
            return []

        logger.info(f"CorrelationEngine starting deterministic correlation for case {case_id}")

        if correlation_repo is None:
            correlation_repo = CorrelationRepository()
        if observation_repo is None:
            observation_repo = ObservationRepository()
        if indicator_repo is None:
            indicator_repo = IndicatorRepository()

        # Load all observations for the case
        observations = observation_repo.find_all({"case_id": case_id})
        if not observations:
            logger.info(f"No observations found for case {case_id}. Zero correlations generated.")
            return []

        # Load all indicators for the case to assist canonical mapping
        indicators = indicator_repo.find_all({"case_id": case_id})
        indicator_map = {ind["indicator_id"]: ind for ind in indicators}

        # Segment observations by source
        apk_obs: List[Dict[str, Any]] = []
        pcap_obs: List[Dict[str, Any]] = []
        other_obs: List[Dict[str, Any]] = []

        for obs in observations:
            source = str(obs.get("source", "")).upper()
            if source == "APK":
                apk_obs.append(obs)
            elif source == "PCAP":
                pcap_obs.append(obs)
            else:
                other_obs.append(obs)

        generated_correlations: List[Correlation] = []
        seen_correlation_keys: Set[Tuple[str, str, str]] = set()

        def add_correlation(
            rel_type: str,
            strength: CorrelationStrength,
            reason: str,
            source_obs: List[Dict[str, Any]],
            target_obs: List[Dict[str, Any]],
            supporting_evidence: List[str],
            metadata: Optional[Dict[str, Any]] = None
        ):
            src_ids = sorted([o.get("observation_id") for o in source_obs if o.get("observation_id")])
            tgt_ids = sorted([o.get("observation_id") for o in target_obs if o.get("observation_id")])

            # Deduplication key across runs
            corr_key = (rel_type, ",".join(src_ids), ",".join(tgt_ids))
            if corr_key in seen_correlation_keys:
                return

            seen_correlation_keys.add(corr_key)

            src_ev_id = source_obs[0].get("evidence_id") if source_obs else None
            tgt_ev_id = target_obs[0].get("evidence_id") if target_obs else None
            all_ev_ids = list(set([ev for ev in supporting_evidence if ev]))

            corr = Correlation(
                case_id=case_id,
                source_observation_ids=src_ids,
                target_observation_ids=tgt_ids,
                source_evidence_id=src_ev_id,
                target_evidence_id=tgt_ev_id,
                relationship_type=rel_type,
                strength=strength,
                reason=reason,
                evidence_class="CORRELATED",
                supporting_evidence_ids=all_ev_ids,
                metadata=metadata or {}
            )
            generated_correlations.append(corr)

        # =====================================================================
        # RULE 1: APK domain == PCAP DNS domain
        # =====================================================================
        apk_domain_observations = [
            o for o in apk_obs 
            if o.get("observation_type") in [
                ObservationType.EMBEDDED_DOMAIN.value, 
                ObservationType.EMBEDDED_URL.value, 
                "suspicious_domain", 
                "suspicious_url"
            ]
        ]
        pcap_dns_observations = [
            o for o in pcap_obs 
            if o.get("observation_type") in [
                ObservationType.DNS_QUERY.value, 
                "dns_domain"
            ]
        ]

        domain_groups: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for o in apk_domain_observations + pcap_dns_observations:
            d_norm = ValueNormalizer.normalize(IndicatorType.DOMAIN, o.get("value", ""))
            if not d_norm or "." not in d_norm:
                continue
            if d_norm not in domain_groups:
                domain_groups[d_norm] = {"APK": [], "PCAP": []}
            src = str(o.get("source", "")).upper()
            if src in domain_groups[d_norm]:
                domain_groups[d_norm][src].append(o)

        for d_norm, group in domain_groups.items():
            if group["APK"] and group["PCAP"]:
                all_tools = set()
                for o in group["APK"] + group["PCAP"]:
                    t = o.get("metadata", {}).get("tool")
                    if t:
                        all_tools.add(t)

                # RULE 7: 3+ independent tools/sources elevates to STRONG
                strength = CorrelationStrength.STRONG if len(all_tools) >= 3 else CorrelationStrength.MODERATE
                reason = (
                    f"Domain '{d_norm}' was embedded in the APK and was independently "
                    f"observed in DNS traffic within the supplied PCAP."
                )
                if strength == CorrelationStrength.STRONG:
                    reason += f" Corroborated across multiple independent sources: {', '.join(sorted(all_tools))}."

                add_correlation(
                    rel_type="DOMAIN_MATCH",
                    strength=strength,
                    reason=reason,
                    source_obs=group["APK"],
                    target_obs=group["PCAP"],
                    supporting_evidence=[o.get("evidence_id") for o in group["APK"] + group["PCAP"]],
                    metadata={"domain": d_norm, "tools": list(all_tools), "rule": "RULE_1_AND_7"}
                )

        # =====================================================================
        # RULE 2: APK IP == PCAP destination IP
        # =====================================================================
        apk_ip_observations = [
            o for o in apk_obs 
            if o.get("observation_type") in [
                ObservationType.EMBEDDED_IP.value, 
                "suspicious_ip"
            ]
        ]
        pcap_ip_observations = [
            o for o in pcap_obs 
            if o.get("observation_type") in [
                ObservationType.NETWORK_IP.value, 
                ObservationType.NETWORK_CONNECTION.value,
                "network_address"
            ]
        ]

        ip_groups: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for o in apk_ip_observations + pcap_ip_observations:
            ip_norm = ValueNormalizer.normalize(IndicatorType.IP, o.get("value", ""))
            if not ip_norm:
                continue
            if ip_norm not in ip_groups:
                ip_groups[ip_norm] = {"APK": [], "PCAP": []}
            src = str(o.get("source", "")).upper()
            if src in ip_groups[ip_norm]:
                ip_groups[ip_norm][src].append(o)

        for ip_norm, group in ip_groups.items():
            if group["APK"] and group["PCAP"]:
                all_tools = set()
                for o in group["APK"] + group["PCAP"]:
                    t = o.get("metadata", {}).get("tool")
                    if t:
                        all_tools.add(t)

                strength = CorrelationStrength.STRONG if len(all_tools) >= 3 else CorrelationStrength.MODERATE
                reason = (
                    f"IP address '{ip_norm}' was embedded in APK bytecode/assets and was independently "
                    f"observed as an active network endpoint in the PCAP capture."
                )
                if strength == CorrelationStrength.STRONG:
                    reason += f" Corroborated across multiple independent sources: {', '.join(sorted(all_tools))}."

                add_correlation(
                    rel_type="IP_MATCH",
                    strength=strength,
                    reason=reason,
                    source_obs=group["APK"],
                    target_obs=group["PCAP"],
                    supporting_evidence=[o.get("evidence_id") for o in group["APK"] + group["PCAP"]],
                    metadata={"ip": ip_norm, "tools": list(all_tools), "rule": "RULE_2_AND_7"}
                )

        # =====================================================================
        # RULE 3: APK domain resolves to IP observed in PCAP
        # =====================================================================
        pcap_dns_response_obs = [
            o for o in pcap_obs 
            if o.get("observation_type") in [
                ObservationType.DNS_RESPONSE.value, 
                "dns_response"
            ]
        ]

        for a_obs in apk_domain_observations:
            a_dom = ValueNormalizer.normalize(IndicatorType.DOMAIN, a_obs.get("value", ""))
            if not a_dom:
                continue

            for resp_obs in pcap_dns_response_obs:
                resolved_for = ValueNormalizer.normalize(
                    IndicatorType.DOMAIN, 
                    resp_obs.get("metadata", {}).get("resolved_for", "")
                )
                resolved_ip = ValueNormalizer.normalize(IndicatorType.IP, resp_obs.get("value", ""))

                if resolved_for and resolved_for == a_dom and resolved_ip:
                    # Check if resolved_ip was also contacted in PCAP network traffic
                    contacted_obs = [
                        p for p in pcap_ip_observations 
                        if ValueNormalizer.normalize(IndicatorType.IP, p.get("value", "")) == resolved_ip
                    ]

                    reason = (
                        f"Domain '{a_dom}' embedded in the APK was resolved via DNS in PCAP traffic "
                        f"to IP '{resolved_ip}', which was independently captured as an active endpoint."
                    )
                    target_obs_list = [resp_obs] + contacted_obs
                    ev_ids = [a_obs.get("evidence_id"), resp_obs.get("evidence_id")] + [c.get("evidence_id") for c in contacted_obs]

                    add_correlation(
                        rel_type="RESOLVED_IP_MATCH",
                        strength=CorrelationStrength.STRONG,
                        reason=reason,
                        source_obs=[a_obs],
                        target_obs=target_obs_list,
                        supporting_evidence=ev_ids,
                        metadata={"domain": a_dom, "resolved_ip": resolved_ip, "rule": "RULE_3"}
                    )

        # =====================================================================
        # RULE 4: APK network capability + matching network observation
        # =====================================================================
        apk_capability_obs = [
            o for o in apk_obs 
            if o.get("observation_type") in [
                ObservationType.CAPABILITY.value,
                ObservationType.DECLARED_PERMISSION.value,
                ObservationType.SUSPICIOUS_PERMISSION.value,
                ObservationType.SUSPICIOUS_API.value
            ]
        ]

        pcap_traffic_obs = [
            o for o in pcap_obs 
            if o.get("observation_type") in [
                ObservationType.NETWORK_PROTOCOL.value,
                ObservationType.NETWORK_PORT.value,
                ObservationType.NETWORK_IP.value
            ]
        ]

        # Check for network capability linkage if network traffic was actually captured
        if pcap_traffic_obs:
            for cap_obs in apk_capability_obs:
                cap_val = cap_obs.get("value", "").upper()
                if any(k in cap_val for k in ["INTERNET", "ACCESS_NETWORK_STATE", "SOCKET", "HTTP", "CONNECT"]):
                    # Link declared capability to captured traffic
                    sample_traffic = pcap_traffic_obs[:3]
                    sample_types = ", ".join(sorted(set(t.get("value", "") for t in sample_traffic)))
                    strength = CorrelationStrength.MODERATE if "SOCKET" in cap_val or "HTTP" in cap_val else CorrelationStrength.WEAK
                    reason = (
                        f"APK declared network capability/permission '{cap_obs.get('value')}' "
                        f"aligns with observed active network traffic ({sample_types}) in the PCAP capture."
                    )
                    add_correlation(
                        rel_type="CAPABILITY_ACTIVITY_ALIGNMENT",
                        strength=strength,
                        reason=reason,
                        source_obs=[cap_obs],
                        target_obs=sample_traffic,
                        supporting_evidence=[cap_obs.get("evidence_id")] + [t.get("evidence_id") for t in sample_traffic],
                        metadata={"capability": cap_obs.get("value"), "rule": "RULE_4"}
                    )
                    # Create one representative capability correlation to avoid explosion
                    break

        # =====================================================================
        # RULE 5: Matching indicator + repeated network communication
        # =====================================================================
        pcap_repeated_obs = [
            o for o in pcap_obs 
            if o.get("observation_type") in [
                ObservationType.REPEATED_COMMUNICATION.value,
                "repeated_communication_pattern"
            ]
        ]

        for rep_obs in pcap_repeated_obs:
            rep_ip = ValueNormalizer.normalize(IndicatorType.IP, rep_obs.get("value", ""))
            meta_rep = rep_obs.get("metadata", {})
            pattern_classification = meta_rep.get("pattern_classification", "repeated communication")
            packet_count = meta_rep.get("packet_count", 0)

            # Check if rep_ip matches an embedded IP in APK or resolved domain IP
            matching_apk = [
                a for a in apk_ip_observations 
                if ValueNormalizer.normalize(IndicatorType.IP, a.get("value", "")) == rep_ip
            ]

            # Also check if it matches a resolved domain from APK
            for a_dom_obs in apk_domain_observations:
                a_dom = ValueNormalizer.normalize(IndicatorType.DOMAIN, a_dom_obs.get("value", ""))
                for resp_obs in pcap_dns_response_obs:
                    resolved_for = ValueNormalizer.normalize(IndicatorType.DOMAIN, resp_obs.get("metadata", {}).get("resolved_for", ""))
                    resolved_ip = ValueNormalizer.normalize(IndicatorType.IP, resp_obs.get("value", ""))
                    if resolved_for == a_dom and resolved_ip == rep_ip and a_dom_obs not in matching_apk:
                        matching_apk.append(a_dom_obs)

            if matching_apk:
                reason = (
                    f"Indicator '{rep_ip}' embedded in the APK was observed in repeated network communications "
                    f"in the PCAP (packet count: {packet_count}, pattern: '{pattern_classification}')."
                )
                add_correlation(
                    rel_type="PERIODIC_COMMUNICATION_MATCH",
                    strength=CorrelationStrength.STRONG,
                    reason=reason,
                    source_obs=matching_apk,
                    target_obs=[rep_obs],
                    supporting_evidence=[m.get("evidence_id") for m in matching_apk] + [rep_obs.get("evidence_id")],
                    metadata={
                        "ip": rep_ip, 
                        "pattern_classification": pattern_classification,
                        "packet_count": packet_count,
                        "rule": "RULE_5"
                    }
                )

        # =====================================================================
        # RULE 6: Matching indicator + timestamp relationship
        # =====================================================================
        for a_obs in apk_domain_observations + apk_ip_observations:
            a_val = ValueNormalizer.normalize(IndicatorType.DOMAIN, a_obs.get("value", "")) or ValueNormalizer.normalize(IndicatorType.IP, a_obs.get("value", ""))
            a_time = a_obs.get("timestamp")

            for p_obs in pcap_dns_observations + pcap_ip_observations:
                p_val = ValueNormalizer.normalize(IndicatorType.DOMAIN, p_obs.get("value", "")) or ValueNormalizer.normalize(IndicatorType.IP, p_obs.get("value", ""))
                p_time = p_obs.get("timestamp")

                if a_val and a_val == p_val and a_time and p_time:
                    # Parse if strings
                    dt_a = datetime.fromisoformat(a_time) if isinstance(a_time, str) else a_time
                    dt_p = datetime.fromisoformat(p_time) if isinstance(p_time, str) else p_time

                    if dt_a and dt_p:
                        time_diff_sec = abs((dt_p - dt_a).total_seconds())
                        reason = (
                            f"Indicator '{a_val}' demonstrates temporal corroboration between evidence sources "
                            f"(APK observation time: {dt_a.isoformat()}, PCAP observation time: {dt_p.isoformat()}, "
                            f"interval delta: {time_diff_sec:.1f}s)."
                        )
                        add_correlation(
                            rel_type="TEMPORAL_ALIGNMENT",
                            strength=CorrelationStrength.STRONG,
                            reason=reason,
                            source_obs=[a_obs],
                            target_obs=[p_obs],
                            supporting_evidence=[a_obs.get("evidence_id"), p_obs.get("evidence_id")],
                            metadata={"indicator": a_val, "time_delta_seconds": time_diff_sec, "rule": "RULE_6"}
                        )
                        break  # Match once per indicator

        # =====================================================================
        # OPTIONAL THREAT INTELLIGENCE CORRELATION
        # =====================================================================
        if threat_intel:
            for ti in threat_intel:
                ti_val = ValueNormalizer.normalize(IndicatorType.DOMAIN, ti.get("indicator", "")) or ValueNormalizer.normalize(IndicatorType.IP, ti.get("indicator", ""))
                threat_name = ti.get("threat_name") or ti.get("label") or "Known Threat Feed"

                if not ti_val:
                    continue

                matching_obs = [
                    o for o in observations 
                    if (ValueNormalizer.normalize(IndicatorType.DOMAIN, o.get("value", "")) == ti_val or 
                        ValueNormalizer.normalize(IndicatorType.IP, o.get("value", "")) == ti_val)
                ]

                if matching_obs:
                    reason = (
                        f"Indicator '{ti_val}' observed in evidence matches external threat intelligence "
                        f"record '{threat_name}'."
                    )
                    add_correlation(
                        rel_type="THREAT_INTEL_MATCH",
                        strength=CorrelationStrength.STRONG,
                        reason=reason,
                        source_obs=matching_obs,
                        target_obs=[],
                        supporting_evidence=[m.get("evidence_id") for m in matching_obs],
                        metadata={"indicator": ti_val, "threat_name": threat_name}
                    )

        # Persist generated correlations to MongoDB
        for corr in generated_correlations:
            # Check if this correlation record is already saved in DB
            query = {
                "case_id": case_id,
                "relationship_type": corr.relationship_type,
                "source_observation_ids": corr.source_observation_ids,
                "target_observation_ids": corr.target_observation_ids
            }
            existing = correlation_repo.find_one(query)
            if not existing:
                correlation_repo.insert_one(corr.model_dump())

        logger.info(f"CorrelationEngine completed. Generated {len(generated_correlations)} correlations for case {case_id}.")
        return generated_correlations
