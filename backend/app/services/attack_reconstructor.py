import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Set, Tuple

from app.db.repositories.attack_repository import AttackNodeRepository, AttackEdgeRepository
from app.db.repositories.observation_repository import ObservationRepository
from app.db.repositories.indicator_repository import IndicatorRepository
from app.db.repositories.correlation_repository import CorrelationRepository
from app.schemas.attack_graph import (
    AttackNode, AttackEdge, NodeType, RelationshipType, RelationshipClass
)
from app.schemas.indicator import IndicatorType
from app.schemas.normalized import ObservationType
from app.services.normalizer import ValueNormalizer

logger = logging.getLogger("emit.attack_reconstructor")

class AttackChainReconstructor:
    """
    Evidence-backed Attack Chain Reconstructor.
    Builds graph topology (nodes, edges, evidence references, and chronological sequencing)
    from normalized indicators, observations, and deterministic correlations.
    Strictly separates OBSERVED edges from INFERRED attack chain edges.
    """

    @staticmethod
    def reconstruct(
        normalized_evidence_or_case_id: Any,
        correlations: Optional[List[Any]] = None,
        node_repo: Optional[AttackNodeRepository] = None,
        edge_repo: Optional[AttackEdgeRepository] = None,
        obs_repo: Optional[ObservationRepository] = None,
        ind_repo: Optional[IndicatorRepository] = None,
        corr_repo: Optional[CorrelationRepository] = None
    ) -> Dict[str, Any]:
        """
        Reconstructs the graph of nodes and edges for a given case.
        """
        if isinstance(normalized_evidence_or_case_id, dict):
            case_id = normalized_evidence_or_case_id.get("case_id")
        else:
            case_id = str(normalized_evidence_or_case_id) if normalized_evidence_or_case_id else None

        if not case_id:
            logger.warning("AttackChainReconstructor invoked without valid case_id.")
            return {"nodes": [], "edges": [], "chronological_sequence": [], "nodes_count": 0, "edges_count": 0}

        logger.info(f"AttackChainReconstructor starting topology generation for case {case_id}")

        if node_repo is None:
            node_repo = AttackNodeRepository()
        if edge_repo is None:
            edge_repo = AttackEdgeRepository()
        if obs_repo is None:
            obs_repo = ObservationRepository()
        if ind_repo is None:
            ind_repo = IndicatorRepository()
        if corr_repo is None:
            corr_repo = CorrelationRepository()

        # Clean stale nodes and edges for this case before reconstructing fresh graph
        node_repo.delete_many({"case_id": case_id})
        edge_repo.delete_many({"case_id": case_id})

        # Load case observations, indicators, and correlations
        observations = obs_repo.find_all({"case_id": case_id})
        indicators = ind_repo.find_all({"case_id": case_id})
        
        # Load correlations from argument or DB
        raw_correlations = correlations if correlations is not None else corr_repo.find_all({"case_id": case_id})
        # Normalize correlations to dict or model access
        case_correlations: List[Dict[str, Any]] = [
            c.model_dump() if hasattr(c, "model_dump") else c for c in raw_correlations
        ]

        nodes_by_key: Dict[Tuple[str, str], AttackNode] = {}  # (node_type, label) -> AttackNode
        edges: List[AttackEdge] = []
        seen_edge_keys: Set[Tuple[str, str, str, str]] = set()

        def get_or_create_node(
            node_type: NodeType, 
            label: str, 
            entity_ref: str,
            timestamp: Optional[datetime] = None,
            metadata: Optional[Dict[str, Any]] = None
        ) -> AttackNode:
            key = (node_type.value, label)
            if key in nodes_by_key:
                # Update timestamp if earlier
                existing = nodes_by_key[key]
                if timestamp and (not existing.timestamp or timestamp < existing.timestamp):
                    existing.timestamp = timestamp
                return existing

            # Check DB if previously saved in this run
            existing_db = node_repo.find_one({
                "case_id": case_id,
                "node_type": node_type.value,
                "label": label
            })
            if existing_db:
                node = AttackNode(**existing_db)
                nodes_by_key[key] = node
                return node

            node = AttackNode(
                case_id=case_id,
                node_type=node_type.value,
                label=label,
                entity_reference=entity_ref,
                timestamp=timestamp,
                metadata=metadata or {}
            )
            node_repo.insert_one(node.model_dump())
            nodes_by_key[key] = node
            return node

        def add_edge(
            source_node: AttackNode,
            target_node: AttackNode,
            rel_type: RelationshipType,
            rel_class: RelationshipClass,
            strength: str,
            reason: str,
            supporting_obs: List[str],
            supporting_ev: List[str],
            supporting_corrs: Optional[List[str]] = None,
            timestamp: Optional[datetime] = None,
            metadata: Optional[Dict[str, Any]] = None
        ):
            if source_node.node_id == target_node.node_id:
                return

            edge_key = (source_node.node_id, target_node.node_id, rel_type.value, rel_class.value)
            if edge_key in seen_edge_keys:
                return
            seen_edge_keys.add(edge_key)

            clean_obs = sorted(list(set([o for o in supporting_obs if o])))
            clean_ev = sorted(list(set([e for e in supporting_ev if e])))
            clean_corr = sorted(list(set([c for c in (supporting_corrs or []) if c])))

            edge = AttackEdge(
                case_id=case_id,
                source_node_id=source_node.node_id,
                target_node_id=target_node.node_id,
                relationship_type=rel_type.value,
                relationship_class=rel_class,
                strength=strength,
                reason=reason,
                timestamp=timestamp,
                supporting_observation_ids=clean_obs,
                supporting_evidence_ids=clean_ev,
                supporting_correlation_ids=clean_corr,
                metadata=metadata or {}
            )
            edge_repo.insert_one(edge.model_dump())
            edges.append(edge)

        # ---------------------------------------------------------------------
        # 1. PROCESS APK EVIDENCE & OBSERVED RELATIONSHIPS
        # ---------------------------------------------------------------------
        apk_app_nodes: Dict[str, AttackNode] = {}  # evidence_id -> App Node

        for obs in observations:
            src = str(obs.get("source", "")).upper()
            ev_id = obs.get("evidence_id", "")
            obs_type = obs.get("observation_type", "")
            val = obs.get("value", "")
            obs_id = obs.get("observation_id", "")
            t_raw = obs.get("timestamp")
            t_dt = datetime.fromisoformat(t_raw) if isinstance(t_raw, str) else t_raw

            if src == "APK":
                # Ensure Application node exists for this APK evidence
                if ev_id not in apk_app_nodes:
                    # Find authoritative package name for this evidence
                    pkg_candidates = [
                        o for o in observations
                        if o.get("evidence_id") == ev_id and o.get("observation_type") == ObservationType.PACKAGE_NAME.value and o.get("value")
                    ]
                    pkg_obs = None
                    if pkg_candidates:
                        # Prioritize androguard/mobsf
                        pkg_obs = next(
                            (o for o in pkg_candidates if o.get("metadata", {}).get("tool") in ["androguard", "mobsf"]),
                            pkg_candidates[0]
                        )
                    pkg_name = pkg_obs.get("value") if pkg_obs else "Android Application"
                    app_node = get_or_create_node(
                        NodeType.APPLICATION, pkg_name, ev_id, timestamp=t_dt, metadata={"evidence_id": ev_id, "package_name": pkg_name}
                    )
                    apk_app_nodes[ev_id] = app_node
                app_node = apk_app_nodes[ev_id]

                # OBSERVED: Application -> Permission
                if obs_type in [ObservationType.DECLARED_PERMISSION.value, ObservationType.SUSPICIOUS_PERMISSION.value]:
                    perm_node = get_or_create_node(NodeType.PERMISSION, val, obs.get("indicator_id", obs_id))
                    add_edge(
                        source_node=app_node,
                        target_node=perm_node,
                        rel_type=RelationshipType.CONTAINS,
                        rel_class=RelationshipClass.OBSERVED,
                        strength="STRONG",
                        reason=f"Application manifest declared permission '{val}'.",
                        supporting_obs=[obs_id],
                        supporting_ev=[ev_id],
                        timestamp=t_dt
                    )

                # OBSERVED: Application -> Capability
                elif obs_type == ObservationType.CAPABILITY.value:
                    cap_node = get_or_create_node(NodeType.CAPABILITY, val, obs.get("indicator_id", obs_id))
                    add_edge(
                        source_node=app_node,
                        target_node=cap_node,
                        rel_type=RelationshipType.USES,
                        rel_class=RelationshipClass.OBSERVED,
                        strength="STRONG",
                        reason=f"Application employs capability '{val}'.",
                        supporting_obs=[obs_id],
                        supporting_ev=[ev_id],
                        timestamp=t_dt
                    )

                # OBSERVED: Application -> API
                elif obs_type == ObservationType.SUSPICIOUS_API.value:
                    api_node = get_or_create_node(NodeType.API, val, obs.get("indicator_id", obs_id))
                    add_edge(
                        source_node=app_node,
                        target_node=api_node,
                        rel_type=RelationshipType.USES,
                        rel_class=RelationshipClass.OBSERVED,
                        strength="STRONG",
                        reason=f"Application bytecode references API '{val}'.",
                        supporting_obs=[obs_id],
                        supporting_ev=[ev_id],
                        timestamp=t_dt
                    )

                # OBSERVED: Application -> Domain
                elif obs_type in [ObservationType.EMBEDDED_DOMAIN.value, ObservationType.EMBEDDED_URL.value, "suspicious_domain", "suspicious_url"]:
                    d_norm = ValueNormalizer.normalize(IndicatorType.DOMAIN, val)
                    if d_norm and "." in d_norm:
                        dom_node = get_or_create_node(NodeType.DOMAIN, d_norm, obs.get("indicator_id", obs_id), timestamp=t_dt)
                        add_edge(
                            source_node=app_node,
                            target_node=dom_node,
                            rel_type=RelationshipType.EMBEDS,
                            rel_class=RelationshipClass.OBSERVED,
                            strength="STRONG",
                            reason=f"Application bytecode/assets statically embed domain '{d_norm}'.",
                            supporting_obs=[obs_id],
                            supporting_ev=[ev_id],
                            timestamp=t_dt
                        )

                # OBSERVED: Application -> IP
                elif obs_type in [ObservationType.EMBEDDED_IP.value, "suspicious_ip"]:
                    ip_norm = ValueNormalizer.normalize(IndicatorType.IP, val)
                    if ip_norm:
                        ip_node = get_or_create_node(NodeType.IP, ip_norm, obs.get("indicator_id", obs_id), timestamp=t_dt)
                        add_edge(
                            source_node=app_node,
                            target_node=ip_node,
                            rel_type=RelationshipType.EMBEDS,
                            rel_class=RelationshipClass.OBSERVED,
                            strength="STRONG",
                            reason=f"Application statically embeds IP address '{ip_norm}'.",
                            supporting_obs=[obs_id],
                            supporting_ev=[ev_id],
                            timestamp=t_dt
                        )

        # ---------------------------------------------------------------------
        # 2. PROCESS PCAP EVIDENCE & OBSERVED RELATIONSHIPS
        # ---------------------------------------------------------------------
        for obs in observations:
            src = str(obs.get("source", "")).upper()
            ev_id = obs.get("evidence_id", "")
            obs_type = obs.get("observation_type", "")
            val = obs.get("value", "")
            obs_id = obs.get("observation_id", "")
            t_raw = obs.get("timestamp")
            t_dt = datetime.fromisoformat(t_raw) if isinstance(t_raw, str) else t_raw

            if src == "PCAP":
                # OBSERVED: DNS Query event
                if obs_type in [ObservationType.DNS_QUERY.value, "dns_domain"]:
                    d_norm = ValueNormalizer.normalize(IndicatorType.DOMAIN, val)
                    if d_norm:
                        dns_event_node = get_or_create_node(
                            NodeType.DNS_EVENT, f"DNS: {d_norm}", obs_id, timestamp=t_dt, metadata={"domain": d_norm}
                        )
                        dom_node = get_or_create_node(NodeType.DOMAIN, d_norm, obs.get("indicator_id", obs_id), timestamp=t_dt)
                        add_edge(
                            source_node=dns_event_node,
                            target_node=dom_node,
                            rel_type=RelationshipType.OBSERVED_IN,
                            rel_class=RelationshipClass.OBSERVED,
                            strength="STRONG",
                            reason=f"Captured network traffic performed DNS query for domain '{d_norm}'.",
                            supporting_obs=[obs_id],
                            supporting_ev=[ev_id],
                            timestamp=t_dt
                        )

                # OBSERVED: DNS Response (Domain resolves to IP)
                elif obs_type in [ObservationType.DNS_RESPONSE.value, "dns_response"]:
                    resolved_for = ValueNormalizer.normalize(IndicatorType.DOMAIN, obs.get("metadata", {}).get("resolved_for", ""))
                    ip_norm = ValueNormalizer.normalize(IndicatorType.IP, val)
                    if resolved_for and ip_norm:
                        dom_node = get_or_create_node(NodeType.DOMAIN, resolved_for, obs.get("indicator_id", obs_id), timestamp=t_dt)
                        ip_node = get_or_create_node(NodeType.IP, ip_norm, obs.get("indicator_id", obs_id), timestamp=t_dt)
                        add_edge(
                            source_node=dom_node,
                            target_node=ip_node,
                            rel_type=RelationshipType.RESOLVES_TO,
                            rel_class=RelationshipClass.OBSERVED,
                            strength="STRONG",
                            reason=f"DNS query for '{resolved_for}' resolved to IP address '{ip_norm}'.",
                            supporting_obs=[obs_id],
                            supporting_ev=[ev_id],
                            timestamp=t_dt
                        )

                # OBSERVED: Network Traffic Event -> Destination IP
                elif obs_type in [ObservationType.NETWORK_IP.value, ObservationType.NETWORK_CONNECTION.value, "network_address"]:
                    ip_norm = ValueNormalizer.normalize(IndicatorType.IP, val)
                    if ip_norm:
                        net_event_node = get_or_create_node(
                            NodeType.NETWORK_EVENT, f"Traffic: {ip_norm}", obs_id, timestamp=t_dt, metadata={"ip": ip_norm}
                        )
                        ip_node = get_or_create_node(NodeType.IP, ip_norm, obs.get("indicator_id", obs_id), timestamp=t_dt)
                        add_edge(
                            source_node=net_event_node,
                            target_node=ip_node,
                            rel_type=RelationshipType.CONNECTS_TO,
                            rel_class=RelationshipClass.OBSERVED,
                            strength="STRONG",
                            reason=f"Captured network flow establishes active connection to IP '{ip_norm}'.",
                            supporting_obs=[obs_id],
                            supporting_ev=[ev_id],
                            timestamp=t_dt
                        )

                # OBSERVED: Repeated / Periodic Communication Event
                elif obs_type in [ObservationType.REPEATED_COMMUNICATION.value, "repeated_communication_pattern"]:
                    ip_norm = ValueNormalizer.normalize(IndicatorType.IP, val)
                    if ip_norm:
                        meta = obs.get("metadata", {})
                        pkt_count = meta.get("packet_count", 0)
                        pattern = meta.get("pattern_classification", "repeated communication")
                        rep_event_node = get_or_create_node(
                            NodeType.NETWORK_EVENT, f"Periodic Beacon: {ip_norm}", obs_id, timestamp=t_dt, metadata=meta
                        )
                        ip_node = get_or_create_node(NodeType.IP, ip_norm, obs.get("indicator_id", obs_id), timestamp=t_dt)
                        add_edge(
                            source_node=rep_event_node,
                            target_node=ip_node,
                            rel_type=RelationshipType.REPEATS,
                            rel_class=RelationshipClass.OBSERVED,
                            strength="STRONG",
                            reason=f"Network traffic exhibited repeated periodic communication pattern to '{ip_norm}' (count: {pkt_count}, pattern: '{pattern}').",
                            supporting_obs=[obs_id],
                            supporting_ev=[ev_id],
                            timestamp=t_dt
                        )

        # ---------------------------------------------------------------------
        # 3. PROCESS CORRELATIONS -> CORRELATED EDGES
        # ---------------------------------------------------------------------
        for corr in case_correlations:
            corr_id = corr.get("correlation_id", "")
            rel_type_str = corr.get("relationship_type", "")
            strength = corr.get("strength", "MODERATE")
            reason = corr.get("reason", "")
            src_obs_ids = corr.get("source_observation_ids", [])
            tgt_obs_ids = corr.get("target_observation_ids", [])
            supp_ev_ids = corr.get("supporting_evidence_ids", [])
            meta = corr.get("metadata", {})

            # Domain correlation: DOMAIN (APK) <-> DNS_EVENT (PCAP)
            if rel_type_str == "DOMAIN_MATCH":
                dom_val = meta.get("domain")
                if dom_val:
                    dom_node = get_or_create_node(NodeType.DOMAIN, dom_val, dom_val)
                    dns_event_node = get_or_create_node(NodeType.DNS_EVENT, f"DNS: {dom_val}", dom_val)
                    add_edge(
                        source_node=dom_node,
                        target_node=dns_event_node,
                        rel_type=RelationshipType.CORRELATED_WITH,
                        rel_class=RelationshipClass.CORRELATED,
                        strength=strength,
                        reason=reason,
                        supporting_obs=src_obs_ids + tgt_obs_ids,
                        supporting_ev=supp_ev_ids,
                        supporting_corrs=[corr_id]
                    )

            # IP correlation: IP (APK) <-> NETWORK_EVENT (PCAP)
            elif rel_type_str == "IP_MATCH":
                ip_val = meta.get("ip")
                if ip_val:
                    ip_node = get_or_create_node(NodeType.IP, ip_val, ip_val)
                    net_event_node = get_or_create_node(NodeType.NETWORK_EVENT, f"Traffic: {ip_val}", ip_val)
                    add_edge(
                        source_node=ip_node,
                        target_node=net_event_node,
                        rel_type=RelationshipType.CORRELATED_WITH,
                        rel_class=RelationshipClass.CORRELATED,
                        strength=strength,
                        reason=reason,
                        supporting_obs=src_obs_ids + tgt_obs_ids,
                        supporting_ev=supp_ev_ids,
                        supporting_corrs=[corr_id]
                    )

            # Threat Intel correlation
            elif rel_type_str == "THREAT_INTEL_MATCH":
                ind_val = meta.get("indicator")
                threat_name = meta.get("threat_name", "Threat Intel Match")
                if ind_val:
                    ti_node = get_or_create_node(NodeType.THREAT_INTEL, threat_name, ind_val)
                    # Connect to DOMAIN or IP node
                    target_type = NodeType.DOMAIN if "." in ind_val and not any(c.isdigit() for c in ind_val.split(".")[0]) else NodeType.IP
                    target_node = get_or_create_node(target_type, ind_val, ind_val)
                    add_edge(
                        source_node=ti_node,
                        target_node=target_node,
                        rel_type=RelationshipType.SUPPORTED_BY,
                        rel_class=RelationshipClass.CORRELATED,
                        strength=strength,
                        reason=reason,
                        supporting_obs=src_obs_ids,
                        supporting_ev=supp_ev_ids,
                        supporting_corrs=[corr_id]
                    )

        # ---------------------------------------------------------------------
        # 4. INFER ATTACK CHAIN RELATIONSHIPS (INFERRED EDGES)
        # ---------------------------------------------------------------------
        # Infer linkage: Application -> Destination IP (when Domain/IP was correlated across APK & PCAP)
        for app_node in apk_app_nodes.values():
            app_ev_id = app_node.metadata.get("evidence_id")

            # Look for domains embedded by this app that resolved to or correlated with PCAP IPs
            for corr in case_correlations:
                corr_id = corr.get("correlation_id", "")
                rel_type = corr.get("relationship_type", "")
                meta = corr.get("metadata", {})
                supp_ev = corr.get("supporting_evidence_ids", [])
                src_obs_ids = corr.get("source_observation_ids", [])
                tgt_obs_ids = corr.get("target_observation_ids", [])

                if rel_type == "RESOLVED_IP_MATCH":
                    dom = meta.get("domain")
                    resolved_ip = meta.get("resolved_ip")
                    if resolved_ip:
                        ip_node = get_or_create_node(NodeType.IP, resolved_ip, resolved_ip)
                        # INFERRED EDGE: Application -> IP
                        reason = (
                            f"Inferred communication chain: Application embeds domain '{dom}', "
                            f"which was resolved via DNS in PCAP traffic to IP '{resolved_ip}', "
                            f"establishing a completed client-to-server communication sequence."
                        )
                        add_edge(
                            source_node=app_node,
                            target_node=ip_node,
                            rel_type=RelationshipType.CONNECTS_TO,
                            rel_class=RelationshipClass.INFERRED,
                            strength="STRONG",
                            reason=reason,
                            supporting_obs=src_obs_ids + tgt_obs_ids,
                            supporting_ev=supp_ev,
                            supporting_corrs=[corr_id]
                        )

                elif rel_type == "PERIODIC_COMMUNICATION_MATCH":
                    rep_ip = meta.get("ip")
                    pattern = meta.get("pattern_classification", "periodic")
                    if rep_ip:
                        ip_node = get_or_create_node(NodeType.IP, rep_ip, rep_ip)
                        # INFERRED EDGE: Application -> IP (Repeated beacon)
                        reason = (
                            f"Inferred periodic attack chain: Application network destination '{rep_ip}' "
                            f"corresponds with repeated periodic communication pattern observed in PCAP traffic."
                        )
                        add_edge(
                            source_node=app_node,
                            target_node=ip_node,
                            rel_type=RelationshipType.REPEATS,
                            rel_class=RelationshipClass.INFERRED,
                            strength="STRONG",
                            reason=reason,
                            supporting_obs=src_obs_ids + tgt_obs_ids,
                            supporting_ev=supp_ev,
                            supporting_corrs=[corr_id]
                        )

        # ---------------------------------------------------------------------
        # 5. CHRONOLOGICAL SEQUENCING
        # ---------------------------------------------------------------------
        all_timed_items: List[Tuple[datetime, str, str, str]] = []  # (dt, event_type, desc, entity_id)

        for node in nodes_by_key.values():
            if node.timestamp:
                all_timed_items.append((node.timestamp, node.node_type, f"Node: {node.label}", node.node_id))

        for edge in edges:
            if edge.timestamp:
                all_timed_items.append((edge.timestamp, edge.relationship_type, f"Edge ({edge.relationship_class.value}): {edge.reason[:80]}...", edge.edge_id))

        # Sort chronologically
        all_timed_items.sort(key=lambda x: x[0])

        chronological_sequence = []
        for idx, (dt, ev_type, desc, entity_id) in enumerate(all_timed_items):
            chronological_sequence.append({
                "sequence_index": idx + 1,
                "timestamp": dt.isoformat(),
                "event_type": ev_type,
                "description": desc,
                "entity_id": entity_id
            })

        # Apply sequence_index to edges where timestamp is present
        for edge in edges:
            if edge.timestamp:
                for seq in chronological_sequence:
                    if seq["entity_id"] == edge.edge_id:
                        edge.sequence_index = seq["sequence_index"]
                        break

        # Summary counts
        observed_count = sum(1 for e in edges if e.relationship_class == RelationshipClass.OBSERVED)
        correlated_count = sum(1 for e in edges if e.relationship_class == RelationshipClass.CORRELATED)
        inferred_count = sum(1 for e in edges if e.relationship_class == RelationshipClass.INFERRED)

        result = {
            "case_id": case_id,
            "nodes": [n.model_dump() for n in nodes_by_key.values()],
            "edges": [e.model_dump() for e in edges],
            "chronological_sequence": chronological_sequence,
            "nodes_count": len(nodes_by_key),
            "edges_count": len(edges),
            "observed_edges_count": observed_count,
            "correlated_edges_count": correlated_count,
            "inferred_edges_count": inferred_count,
            "generated_at": datetime.utcnow().isoformat()
        }

        logger.info(
            f"AttackChainReconstructor generated {len(nodes_by_key)} nodes, {len(edges)} edges "
            f"({observed_count} observed, {correlated_count} correlated, {inferred_count} inferred) for case {case_id}."
        )
        return result
