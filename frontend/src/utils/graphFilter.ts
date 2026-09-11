import { AttackNode, AttackEdge } from '../services/api';

export type GraphViewMode = 'FOCUS' | 'FULL';
export type GraphFilterCategory = 'ALL' | 'CORRELATIONS' | 'THREAT_INTEL' | 'NETWORK';

export interface InvestigationStoryStep {
  stepNumber: number;
  phase: 'EVIDENCE' | 'CAPABILITY' | 'CORRELATION' | 'NETWORK' | 'INTEL';
  title: string;
  description: string;
  nodeId?: string;
  edgeId?: string;
}

export interface FocusExtractionResult {
  nodes: AttackNode[];
  edges: AttackEdge[];
  totalNodesCount: number;
  totalEdgesCount: number;
  correlatedNodeIds: Set<string>;
  threatIntelNodeIds: Set<string>;
  reductionPercent: number;
  storySteps: InvestigationStoryStep[];
  hasCorrelations: boolean;
}

export interface PositionedNode extends AttackNode {
  x: number;
  y: number;
  column: number;
  tier?: number;
  isCorrelated?: boolean;
  isDimmed?: boolean;
  isHighlighted?: boolean;
  summaryCount?: number;
}

export interface PositionedGraph {
  nodes: PositionedNode[];
  edges: AttackEdge[];
}

/**
 * Assigns a conceptual 4-Column Left-to-Right position for Investigation Focus:
 * Column 0: Evidence / Application (x = 60)
 * Column 1: Capability / Permission (x = 360)
 * Column 2: Correlated Indicator (x = 660)
 * Column 3: Observed Network Activity (x = 960)
 * Column 4: Threat Intelligence (x = 1260)
 */
export const getFocusColumn = (nodeType: string): number => {
  const type = (nodeType || '').toUpperCase();
  switch (type) {
    case 'APPLICATION':
      return 0; // COLUMN 1: Evidence / Application
    case 'PERMISSION':
    case 'CAPABILITY':
    case 'API':
      return 1; // COLUMN 2: Capability / Permission
    case 'IP':
    case 'DOMAIN':
    case 'DNS_EVENT':
      return 2; // COLUMN 3: Correlated Indicator
    case 'NETWORK_EVENT':
      return 3; // COLUMN 4: Observed Network Event
    case 'THREAT_INTEL':
      return 4; // COLUMN 5: Threat Intel
    default:
      return 2;
  }
};

/**
 * Assigns general tier for Full Provenance mode (0 to 4).
 */
export const getNodeTier = (nodeType: string): number => {
  const type = (nodeType || '').toUpperCase();
  switch (type) {
    case 'APPLICATION':
      return 0;
    case 'PERMISSION':
    case 'CAPABILITY':
    case 'API':
      return 1;
    case 'DOMAIN':
    case 'IP':
    case 'DNS_EVENT':
      return 2;
    case 'NETWORK_EVENT':
      return 3;
    case 'THREAT_INTEL':
      return 4;
    default:
      return 2;
  }
};

/**
 * IP and Domain Classification helpers for forensic prioritization.
 * Ensures local loopback, Docker DNS, broadcast, and emulator infrastructure
 * are not promoted above real external threat indicators.
 */
export const isLoopback = (ipOrRef?: string): boolean => {
  if (!ipOrRef) return false;
  const clean = ipOrRef.trim().toLowerCase().replace(/^traffic:\s*/, '').replace(/^periodic\s+beacon:\s*/, '');
  if (clean === 'localhost' || clean === '::1' || clean === '127.0.0.1') return true;
  if (clean.startsWith('127.')) return true;
  return false;
};

export const isBroadcast = (ipOrRef?: string): boolean => {
  if (!ipOrRef) return false;
  const clean = ipOrRef.trim().toLowerCase().replace(/^traffic:\s*/, '');
  return clean === '255.255.255.255' || clean === '0.0.0.0';
};

export const isMulticast = (ipOrRef?: string): boolean => {
  if (!ipOrRef) return false;
  const clean = ipOrRef.trim().toLowerCase().replace(/^traffic:\s*/, '');
  if (clean.startsWith('ff00::')) return true;
  const parts = clean.split('.');
  if (parts.length === 4) {
    const first = parseInt(parts[0], 10);
    if (!isNaN(first) && first >= 224 && first <= 239) return true;
  }
  return false;
};

export const isDockerInfrastructure = (ipOrRef?: string): boolean => {
  if (!ipOrRef) return false;
  const clean = ipOrRef.trim().toLowerCase().replace(/^traffic:\s*/, '');
  // Docker embedded DNS resolver is 127.0.0.11
  if (clean === '127.0.0.11') return true;
  // Android emulator loopback host & DNS
  if (clean === '10.0.2.2' || clean === '10.0.2.3' || clean === '10.0.2.15') return true;
  return false;
};

export const isPrivate = (ipOrRef?: string): boolean => {
  if (!ipOrRef) return false;
  const clean = ipOrRef.trim().toLowerCase().replace(/^traffic:\s*/, '');
  const parts = clean.split('.');
  if (parts.length === 4) {
    const a = parseInt(parts[0], 10);
    const b = parseInt(parts[1], 10);
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local
  }
  return false;
};

export const isLocalOrInfrastructure = (labelOrRef?: string): boolean => {
  if (!labelOrRef) return false;
  return (
    isLoopback(labelOrRef) ||
    isDockerInfrastructure(labelOrRef) ||
    isBroadcast(labelOrRef) ||
    isMulticast(labelOrRef)
  );
};

/**
 * Backward-compatible alias
 */
export const isLocalOrLoopback = isLocalOrInfrastructure;

/**
 * Calculates a defensible forensic priority score for a cross-artifact candidate edge.
 * Deterministic scoring criteria:
 *   +100 exact APK ↔ PCAP external IP match
 *   +90 exact APK ↔ PCAP domain match
 *   +70 explicit STRONG correlation
 *   +50 MEDIUM correlation
 *   +30 capability/activity alignment
 *   +20 temporal alignment
 *   -100 loopback (127.0.0.0/8, ::1, localhost)
 *   -90 Docker/local infrastructure (127.0.0.11, 10.0.2.2)
 *   -80 broadcast/multicast (0.0.0.0, 255.255.255.255, 224.x)
 *   -50 weak inferred-only relationship
 */
export const scoreCorrelationEdge = (
  edge: AttackEdge,
  nodeMap: Map<string, AttackNode>,
  forwardEdges: Map<string, AttackEdge[]>
): number => {
  let score = 0;
  const srcNode = nodeMap.get(edge.source_node_id);
  const tgtNode = nodeMap.get(edge.target_node_id);

  if (!srcNode || !tgtNode) return -999;

  const strength = (edge.strength || '').toUpperCase();
  const relType = (edge.relationship_type || '').toUpperCase();
  const relClass = (edge.relationship_class || '').toUpperCase();

  // 1. Exact APK <-> PCAP External IP Match (+100)
  const isTargetExternalIp = tgtNode.node_type === 'IP' && !isLocalOrInfrastructure(tgtNode.label);
  const isSourceExternalIp = srcNode.node_type === 'IP' && !isLocalOrInfrastructure(srcNode.label);
  if (isTargetExternalIp || isSourceExternalIp) {
    if (relType === 'IP_MATCH' || relType === 'CORRELATED_WITH' || relType === 'CONNECTS_TO') {
      score += 100;
    } else {
      score += 80;
    }
  }

  // 2. Exact APK <-> PCAP Domain Match (+90)
  const isTargetExternalDomain = tgtNode.node_type === 'DOMAIN' && !isLocalOrInfrastructure(tgtNode.label);
  const isSourceExternalDomain = srcNode.node_type === 'DOMAIN' && !isLocalOrInfrastructure(srcNode.label);
  if (isTargetExternalDomain || isSourceExternalDomain) {
    if (relType === 'DOMAIN_MATCH' || relType === 'CORRELATED_WITH') {
      score += 90;
    } else {
      score += 70;
    }
  }

  // 3. Explicit Strength Bonus
  if (strength === 'STRONG') score += 70;
  else if (strength === 'MODERATE' || strength === 'MEDIUM') score += 50;
  else if (strength === 'WEAK') score += 10;

  // 4. Capability / Activity Alignment (+30)
  if (relType === 'CAPABILITY_ACTIVITY_ALIGNMENT' || relType === 'USES' || relType === 'SUPPORTS') {
    score += 30;
  }

  // 5. Temporal Alignment (+20)
  if (relType === 'TEMPORAL_ALIGNMENT') {
    score += 20;
  }

  // 6. Threat Intelligence Connection (+40)
  const srcOutgoing = forwardEdges.get(srcNode.node_id) || [];
  const tgtOutgoing = forwardEdges.get(tgtNode.node_id) || [];
  const hasThreatIntel = [...srcOutgoing, ...tgtOutgoing].some((e) => {
    const t = nodeMap.get(e.target_node_id);
    return t && t.node_type === 'THREAT_INTEL';
  });
  if (hasThreatIntel) score += 40;

  // 7. Penalties for Local / Infrastructure Dummy Nodes
  const isSrcLoopback = isLoopback(srcNode.label) || isLoopback(srcNode.entity_reference);
  const isTgtLoopback = isLoopback(tgtNode.label) || isLoopback(tgtNode.entity_reference);
  if (isSrcLoopback || isTgtLoopback) {
    score -= 100; // Loopback penalty
  }

  const isSrcDocker = isDockerInfrastructure(srcNode.label) || isDockerInfrastructure(srcNode.entity_reference);
  const isTgtDocker = isDockerInfrastructure(tgtNode.label) || isDockerInfrastructure(tgtNode.entity_reference);
  if (isSrcDocker || isTgtDocker) {
    score -= 90; // Docker / local infra penalty
  }

  const isSrcBroadOrMulti = isBroadcast(srcNode.label) || isMulticast(srcNode.label) || isBroadcast(srcNode.entity_reference) || isMulticast(srcNode.entity_reference);
  const isTgtBroadOrMulti = isBroadcast(tgtNode.label) || isMulticast(tgtNode.label) || isBroadcast(tgtNode.entity_reference) || isMulticast(tgtNode.entity_reference);
  if (isSrcBroadOrMulti || isTgtBroadOrMulti) {
    score -= 80; // Broadcast / multicast penalty
  }

  if (relClass === 'INFERRED' && !isTargetExternalIp && !isSourceExternalIp) {
    score -= 50; // Weak inferred-only relationship penalty
  }

  return score;
};

/**
 * Builds a concise, high-signal "Primary Evidence Chain" for Investigation Focus.
 * Strictly enforces a hard node budget of <= 8 visible nodes (typically 4–6).
 *
 * Story Sequence:
 *   APPLICATION ─── CONTAINS ───► PERMISSION ─── SUPPORTS ───► CORRELATED INDICATOR ─── CONNECTS_TO ───► NETWORK EVENT (─── INTEL MATCH ───► THREAT INTEL)
 */
export const buildPrimaryInvestigationChain = (
  allNodes: AttackNode[],
  allEdges: AttackEdge[],
  focusPathNodeId?: string | null
): FocusExtractionResult => {
  const totalNodesCount = allNodes.length;
  const totalEdgesCount = allEdges.length;

  if (totalNodesCount === 0) {
    return {
      nodes: [],
      edges: [],
      totalNodesCount: 0,
      totalEdgesCount: 0,
      correlatedNodeIds: new Set(),
      threatIntelNodeIds: new Set(),
      reductionPercent: 0,
      storySteps: [],
      hasCorrelations: false,
    };
  }

  const nodeMap = new Map<string, AttackNode>();
  allNodes.forEach((n) => nodeMap.set(n.node_id, n));

  // Adjacency maps
  const forwardEdges = new Map<string, AttackEdge[]>();
  const backwardEdges = new Map<string, AttackEdge[]>();

  allEdges.forEach((e) => {
    if (!forwardEdges.has(e.source_node_id)) forwardEdges.set(e.source_node_id, []);
    forwardEdges.get(e.source_node_id)!.push(e);

    if (!backwardEdges.has(e.target_node_id)) backwardEdges.set(e.target_node_id, []);
    backwardEdges.get(e.target_node_id)!.push(e);
  });

  const selectedNodeIds = new Set<string>();
  const selectedEdgeIds = new Set<string>();
  const correlatedNodeIds = new Set<string>();
  const threatIntelNodeIds = new Set<string>();

  // -------------------------------------------------------------------------
  // STEP 1: Find and Forensically Rank Candidate Correlations
  // -------------------------------------------------------------------------
  const candidateCorrelations = allEdges.filter((e) => {
    const isCorrClass = e.relationship_class === 'CORRELATED' || e.relationship_class === 'INFERRED';
    const isCorrType =
      e.relationship_type === 'CORRELATED_WITH' ||
      e.relationship_type === 'IP_MATCH' ||
      e.relationship_type === 'DOMAIN_MATCH' ||
      e.relationship_type === 'RESOLVED_IP_MATCH' ||
      e.relationship_type === 'PERIODIC_COMMUNICATION_MATCH' ||
      e.relationship_type === 'CONNECTS_TO';
    const hasCorrIds = (e.supporting_correlation_ids || []).length > 0;
    return isCorrClass || isCorrType || hasCorrIds;
  });

  // Rank candidate correlation bridges forensically (score DESC, label ASC, edge_id ASC)
  const rankedCorrelations = [...candidateCorrelations].sort((a, b) => {
    const scoreA = scoreCorrelationEdge(a, nodeMap, forwardEdges);
    const scoreB = scoreCorrelationEdge(b, nodeMap, forwardEdges);
    if (scoreB !== scoreA) return scoreB - scoreA;

    const aLabel = (nodeMap.get(a.source_node_id)?.label || '') + (nodeMap.get(a.target_node_id)?.label || '');
    const bLabel = (nodeMap.get(b.source_node_id)?.label || '') + (nodeMap.get(b.target_node_id)?.label || '');
    const labelComp = aLabel.localeCompare(bLabel);
    if (labelComp !== 0) return labelComp;

    return a.edge_id.localeCompare(b.edge_id);
  });

  const hasCorrelations = rankedCorrelations.length > 0;

  // If a specific path node is requested to focus on:
  let primaryCorrelation: AttackEdge | null = null;
  if (focusPathNodeId && nodeMap.has(focusPathNodeId)) {
    const connectedEdges = [...(forwardEdges.get(focusPathNodeId) || []), ...(backwardEdges.get(focusPathNodeId) || [])];
    const pathCorr = connectedEdges.find((e) => rankedCorrelations.some((rc) => rc.edge_id === e.edge_id));
    primaryCorrelation = pathCorr || rankedCorrelations[0] || null;
  } else {
    primaryCorrelation = rankedCorrelations.length > 0 ? rankedCorrelations[0] : null;
  }

  if (primaryCorrelation) {
    selectedEdgeIds.add(primaryCorrelation.edge_id);
    if (nodeMap.has(primaryCorrelation.source_node_id)) {
      selectedNodeIds.add(primaryCorrelation.source_node_id);
      correlatedNodeIds.add(primaryCorrelation.source_node_id);
    }
    if (nodeMap.has(primaryCorrelation.target_node_id)) {
      selectedNodeIds.add(primaryCorrelation.target_node_id);
      correlatedNodeIds.add(primaryCorrelation.target_node_id);
    }
  }

  // -------------------------------------------------------------------------
  // STEP 2: Upstream Trace to Root Evidence / Application
  // -------------------------------------------------------------------------
  const appNodes = allNodes.filter((n) => n.node_type === 'APPLICATION');
  const rootApp = appNodes.length > 0 ? appNodes[0] : null;

  if (rootApp) {
    selectedNodeIds.add(rootApp.node_id);
  }

  // -------------------------------------------------------------------------
  // STEP 3: Single Relevant Permission (e.g. android.permission.INTERNET)
  // -------------------------------------------------------------------------
  const hasNetworkActivity = Array.from(selectedNodeIds).some((id) => {
    const n = nodeMap.get(id);
    return n && (n.node_type === 'NETWORK_EVENT' || n.node_type === 'IP' || n.node_type === 'DOMAIN');
  });

  const syntheticFocusEdges: AttackEdge[] = [];

  let chosenPerm: AttackNode | null = null;
  if (hasNetworkActivity && rootApp) {
    // Look strictly for INTERNET permission or network capability
    chosenPerm =
      allNodes.find(
        (n) =>
          (n.node_type === 'PERMISSION' || n.node_type === 'CAPABILITY') &&
          n.label.toUpperCase().includes('INTERNET')
      ) ||
      allNodes.find((n) => n.node_type === 'PERMISSION' || n.node_type === 'CAPABILITY') ||
      null;

    if (chosenPerm) {
      selectedNodeIds.add(chosenPerm.node_id);

      // App -> Perm edge (CONTAINS / DECLARES)
      const permEdge = (forwardEdges.get(rootApp.node_id) || []).find(
        (e) => e.target_node_id === chosenPerm!.node_id
      );
      if (permEdge) {
        selectedEdgeIds.add(permEdge.edge_id);
      } else {
        const containsEdgeId = `focus-edge-contains-${rootApp.node_id}-${chosenPerm.node_id}`;
        selectedEdgeIds.add(containsEdgeId);
        syntheticFocusEdges.push({
          edge_id: containsEdgeId,
          case_id: rootApp.case_id || 'case',
          source_node_id: rootApp.node_id,
          target_node_id: chosenPerm.node_id,
          relationship_type: 'CONTAINS',
          relationship_class: 'OBSERVED',
          strength: 'STRONG',
          reason: 'Application manifest declares capability/permission',
          supporting_observation_ids: [],
          supporting_correlation_ids: [],
          supporting_evidence_ids: [],
          metadata: { isCleanStoryEdge: true },
          created_at: new Date().toISOString(),
        });
      }

      // Perm -> Indicator edge (SUPPORTS)
      const primaryIndicatorId =
        Array.from(correlatedNodeIds).find((id) => {
          const n = nodeMap.get(id);
          return n && (n.node_type === 'IP' || n.node_type === 'DOMAIN');
        }) ||
        Array.from(selectedNodeIds).find((id) => {
          const n = nodeMap.get(id);
          return n && (n.node_type === 'IP' || n.node_type === 'DOMAIN');
        });

      if (primaryIndicatorId) {
        const existingSupportEdge = (forwardEdges.get(chosenPerm.node_id) || []).find(
          (e) => e.target_node_id === primaryIndicatorId
        );
        if (existingSupportEdge) {
          selectedEdgeIds.add(existingSupportEdge.edge_id);
        } else {
          const supportEdgeId = `focus-edge-supports-${chosenPerm.node_id}-${primaryIndicatorId}`;
          selectedEdgeIds.add(supportEdgeId);
          syntheticFocusEdges.push({
            edge_id: supportEdgeId,
            case_id: rootApp.case_id || 'case',
            source_node_id: chosenPerm.node_id,
            target_node_id: primaryIndicatorId,
            relationship_type: 'SUPPORTS',
            relationship_class: 'INFERRED',
            strength: 'MODERATE',
            reason: 'Permission declares network capability supporting communication',
            supporting_observation_ids: [],
            supporting_correlation_ids: [],
            supporting_evidence_ids: [],
            metadata: { isCleanStoryEdge: true },
            created_at: new Date().toISOString(),
          });
        }
      }
    } else {
      // If no permission node exists, link App directly to Indicator
      const primaryIndicatorId = Array.from(selectedNodeIds).find((id) => {
        const n = nodeMap.get(id);
        return n && (n.node_type === 'IP' || n.node_type === 'DOMAIN');
      });
      if (primaryIndicatorId) {
        const directEdge = (forwardEdges.get(rootApp.node_id) || []).find(
          (e) => e.target_node_id === primaryIndicatorId
        );
        if (directEdge) {
          selectedEdgeIds.add(directEdge.edge_id);
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // STEP 4: Threat Intelligence Hit (0 or 1 Node ONLY if real threat-intel exists)
  // -------------------------------------------------------------------------
  Array.from(correlatedNodeIds).forEach((anchorId) => {
    const outgoing = forwardEdges.get(anchorId) || [];
    const tiEdge = outgoing.find((e) => {
      const target = nodeMap.get(e.target_node_id);
      return target && target.node_type === 'THREAT_INTEL';
    });

    if (tiEdge) {
      selectedNodeIds.add(tiEdge.target_node_id);
      selectedEdgeIds.add(tiEdge.edge_id);
      threatIntelNodeIds.add(tiEdge.target_node_id);
    }
  });

  // -------------------------------------------------------------------------
  // STEP 5: Fallback for Single-Artifact Cases (APK-Only or PCAP-Only)
  // -------------------------------------------------------------------------
  if (selectedNodeIds.size < 3) {
    if (rootApp) selectedNodeIds.add(rootApp.node_id);

    // Pick top indicator (IP / Domain)
    const topIndicators = allNodes
      .filter((n) => n.node_type === 'IP' || n.node_type === 'DOMAIN')
      .sort((a, b) => {
        const aInfra = isLocalOrInfrastructure(a.label) ? 1 : 0;
        const bInfra = isLocalOrInfrastructure(b.label) ? 1 : 0;
        return aInfra - bInfra;
      })
      .slice(0, 1);

    topIndicators.forEach((ind) => {
      selectedNodeIds.add(ind.node_id);
      if (rootApp) {
        const directEdge = (forwardEdges.get(rootApp.node_id) || []).find((e) => e.target_node_id === ind.node_id);
        if (directEdge) selectedEdgeIds.add(directEdge.edge_id);
      }
    });

    // Pick top network event if PCAP
    const topNetEvents = allNodes.filter((n) => n.node_type === 'NETWORK_EVENT').slice(0, 1);
    topNetEvents.forEach((ne) => selectedNodeIds.add(ne.node_id));

    // Pick threat intel hit if any
    const topTi = allNodes.find((n) => n.node_type === 'THREAT_INTEL');
    if (topTi) selectedNodeIds.add(topTi.node_id);
  }

  // -------------------------------------------------------------------------
  // STEP 6: STRICT HARD NODE BUDGET ENFORCEMENT (<= 8 Nodes Max, Typically 4–6)
  // -------------------------------------------------------------------------
  let candidateNodeList = allNodes.filter((n) => selectedNodeIds.has(n.node_id));
  if (candidateNodeList.length > 8) {
    candidateNodeList = candidateNodeList.slice(0, 8);
  }

  const finalNodeIds = new Set(candidateNodeList.map((n) => n.node_id));
  const allAvailableEdges = [...allEdges, ...syntheticFocusEdges];

  // In Focus mode, avoid redundant long bypass edges if a linear chain exists
  // e.g., if App -> Perm and Perm -> IP exist, don't also render App -> IP to prevent messy diagonal crossing
  const hasAppPermEdge = candidateNodeList.some((n) => n.node_type === 'APPLICATION') &&
    candidateNodeList.some((n) => n.node_type === 'PERMISSION' || n.node_type === 'CAPABILITY');

  const filteredEdges = allAvailableEdges.filter((e) => {
    if (!finalNodeIds.has(e.source_node_id) || !finalNodeIds.has(e.target_node_id)) return false;
    if (!selectedEdgeIds.has(e.edge_id)) return false;

    // Suppress App -> IP direct bypass if App -> Perm is already bridging to IP
    if (hasAppPermEdge) {
      const src = nodeMap.get(e.source_node_id);
      const tgt = nodeMap.get(e.target_node_id);
      if (src && tgt && src.node_type === 'APPLICATION' && (tgt.node_type === 'IP' || tgt.node_type === 'DOMAIN')) {
        return false;
      }
    }

    return true;
  });

  // If any selected nodes are disconnected, look for any direct edge in allAvailableEdges
  allAvailableEdges.forEach((e) => {
    if (finalNodeIds.has(e.source_node_id) && finalNodeIds.has(e.target_node_id)) {
      if (!filteredEdges.some((fe) => fe.edge_id === e.edge_id)) {
        const src = nodeMap.get(e.source_node_id);
        const tgt = nodeMap.get(e.target_node_id);
        const isBypass = hasAppPermEdge && src?.node_type === 'APPLICATION' && (tgt?.node_type === 'IP' || tgt?.node_type === 'DOMAIN');
        if (!isBypass) {
          filteredEdges.push(e);
        }
      }
    }
  });

  // -------------------------------------------------------------------------
  // STEP 7: BUILD "WHY THIS PATH?" INVESTIGATION NARRATIVE
  // -------------------------------------------------------------------------
  const storySteps: InvestigationStoryStep[] = [];
  let stepIdx = 1;

  if (rootApp) {
    storySteps.push({
      stepNumber: stepIdx++,
      phase: 'EVIDENCE',
      title: 'Target Application Ingested',
      description: `Forensic binary ${rootApp.label} decompiled and mapped to evidence hierarchy.`,
      nodeId: rootApp.node_id,
    });
  }

  const permNode = candidateNodeList.find(
    (n) => (n.node_type === 'PERMISSION' || n.node_type === 'CAPABILITY') && n.label.toUpperCase().includes('INTERNET')
  ) || candidateNodeList.find((n) => n.node_type === 'PERMISSION' || n.node_type === 'CAPABILITY');

  if (permNode) {
    storySteps.push({
      stepNumber: stepIdx++,
      phase: 'CAPABILITY',
      title: 'Network Permission Declared',
      description: `Manifest explicitly authorizes outbound socket communication (${permNode.label}).`,
      nodeId: permNode.node_id,
    });
  }

  const correlatedIndicators = candidateNodeList.filter(
    (n) => correlatedNodeIds.has(n.node_id) && (n.node_type === 'IP' || n.node_type === 'DOMAIN')
  );
  if (correlatedIndicators.length > 0) {
    const indNames = correlatedIndicators.map((i) => i.label).join(', ');
    storySteps.push({
      stepNumber: stepIdx++,
      phase: 'CORRELATION',
      title: 'Hardcoded Indicator Matched',
      description: `Embedded indicator (${indNames}) extracted from bytecode verified against dynamic PCAP traffic.`,
      nodeId: correlatedIndicators[0].node_id,
    });
  }

  const netEvents = candidateNodeList.filter((n) => n.node_type === 'NETWORK_EVENT');
  if (netEvents.length > 0) {
    storySteps.push({
      stepNumber: stepIdx++,
      phase: 'NETWORK',
      title: 'Dynamic Traffic Observed',
      description: `Active network socket transmissions observed connecting to correlated destination endpoint.`,
      nodeId: netEvents[0].node_id,
    });
  }

  const tiNodes = candidateNodeList.filter((n) => n.node_type === 'THREAT_INTEL');
  if (tiNodes.length > 0) {
    storySteps.push({
      stepNumber: stepIdx++,
      phase: 'INTEL',
      title: 'Threat Intelligence Attribution',
      description: `External IOC feed correlated indicator with malicious threat actor infrastructure.`,
      nodeId: tiNodes[0].node_id,
    });
  }

  const reductionPercent =
    totalNodesCount > 0
      ? Math.round(((totalNodesCount - candidateNodeList.length) / totalNodesCount) * 100)
      : 0;

  return {
    nodes: candidateNodeList,
    edges: filteredEdges,
    totalNodesCount,
    totalEdgesCount,
    correlatedNodeIds,
    threatIntelNodeIds,
    reductionPercent: Math.max(0, reductionPercent),
    storySteps,
    hasCorrelations,
  };
};

/**
 * Backward-compatible alias for buildPrimaryInvestigationChain.
 */
export const extractInvestigationFocus = buildPrimaryInvestigationChain;

/**
 * Computes deterministic Left-to-Right layout coordinates.
 *
 * In FOCUS Mode:
 *   Dynamically collapses to only non-empty stages.
 *   Enforces compact column spacing (nodeWidth = 260, horizontalGap = 100).
 *   Vertically centers sibling nodes within each column.
 *   Centers the entire graph bounding box around (0, 0) for perfect viewport framing.
 *
 * In FULL Mode:
 *   5-Tier hierarchical DAG with sub-columns and collision avoidance.
 *   Centers bounding box around (0, 0).
 */
export const calculateTieredLayout = (
  nodes: AttackNode[],
  edges: AttackEdge[],
  isFocused: boolean,
  correlatedNodeIds?: Set<string>,
  highlightedNodeIds?: Set<string> | null
): PositionedGraph => {
  if (nodes.length === 0) {
    return { nodes: [], edges };
  }

  const positionedNodes: PositionedNode[] = [];

  const NODE_WIDTH = 260;
  const NODE_HEIGHT = 86;

  if (isFocused) {
    // -----------------------------------------------------------------------
    // DYNAMIC COLLAPSIBLE COMPACT DAG LAYOUT FOR INVESTIGATION FOCUS
    // -----------------------------------------------------------------------
    const HORIZONTAL_GAP = 100;
    const VERTICAL_GAP = 30;
    const COL_STEP = NODE_WIDTH + HORIZONTAL_GAP;
    const ROW_STEP = NODE_HEIGHT + VERTICAL_GAP;

    // 1. Group nodes by conceptual stage (0 to 4)
    const stageBuckets: Record<number, AttackNode[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };

    nodes.forEach((n) => {
      const stage = getFocusColumn(n.node_type);
      if (!stageBuckets[stage]) stageBuckets[stage] = [];
      stageBuckets[stage].push(n);
    });

    // 2. Filter only stages that actually contain nodes (Dynamic Collapse)
    const activeStages = [0, 1, 2, 3, 4].filter((stage) => (stageBuckets[stage] || []).length > 0);

    const tempPositioned: PositionedNode[] = [];

    activeStages.forEach((stage, colIndex) => {
      const nodesInCol = stageBuckets[stage] || [];
      const colX = colIndex * COL_STEP;

      // Sort nodes in column: correlated nodes first, then by label ASC
      const sorted = [...nodesInCol].sort((a, b) => {
        const aCorr = correlatedNodeIds?.has(a.node_id) ? 1 : 0;
        const bCorr = correlatedNodeIds?.has(b.node_id) ? 1 : 0;
        if (bCorr !== aCorr) return bCorr - aCorr;
        return a.label.localeCompare(b.label);
      });

      const totalInCol = sorted.length;
      const startY = -((totalInCol - 1) * ROW_STEP) / 2;

      sorted.forEach((node, rowIdx) => {
        const isCorrelated = correlatedNodeIds ? correlatedNodeIds.has(node.node_id) : false;
        const isHighlighted = highlightedNodeIds ? highlightedNodeIds.has(node.node_id) : false;
        const isDimmed = highlightedNodeIds ? !isHighlighted : false;

        tempPositioned.push({
          ...node,
          x: colX,
          y: startY + rowIdx * ROW_STEP,
          column: colIndex,
          tier: stage,
          isCorrelated,
          isHighlighted,
          isDimmed,
        });
      });
    });

    // 3. Compute Bounding Box and Center Graph at (0, 0)
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;

    tempPositioned.forEach((n) => {
      if (n.x < minX) minX = n.x;
      if (n.x + NODE_WIDTH > maxX) maxX = n.x + NODE_WIDTH;
      if (n.y < minY) minY = n.y;
      if (n.y + NODE_HEIGHT > maxY) maxY = n.y + NODE_HEIGHT;
    });

    const centerX = (minX + maxX) / 2;
    const centerY = (minY + maxY) / 2;

    tempPositioned.forEach((n) => {
      positionedNodes.push({
        ...n,
        x: Math.round(n.x - centerX),
        y: Math.round(n.y - centerY),
      });
    });

    return { nodes: positionedNodes, edges };
  }

  // -------------------------------------------------------------------------
  // FULL PROVENANCE 5-TIER HIERARCHICAL LAYOUT
  // -------------------------------------------------------------------------
  const tierBuckets: Record<number, AttackNode[]> = { 0: [], 1: [], 2: [], 3: [], 4: [] };

  nodes.forEach((n) => {
    const tier = getNodeTier(n.node_type);
    if (!tierBuckets[tier]) tierBuckets[tier] = [];
    tierBuckets[tier].push(n);
  });

  const xSpacing = 320;
  const ySpacing = 105;
  const maxNodesPerColumn = 16;
  const tempFullPositioned: PositionedNode[] = [];

  Object.entries(tierBuckets).forEach(([tierStr, nodesInTier]) => {
    const tier = parseInt(tierStr, 10);
    if (nodesInTier.length === 0) return;

    const columnCount = Math.ceil(nodesInTier.length / maxNodesPerColumn);

    for (let colIdx = 0; colIdx < columnCount; colIdx++) {
      const colNodes = nodesInTier.slice(colIdx * maxNodesPerColumn, (colIdx + 1) * maxNodesPerColumn);
      const totalInCol = colNodes.length;
      const startY = -((totalInCol - 1) * ySpacing) / 2;
      const colX = (tier + colIdx * 0.5) * xSpacing;

      colNodes.forEach((node, rowIdx) => {
        const isCorrelated = correlatedNodeIds ? correlatedNodeIds.has(node.node_id) : false;
        const isHighlighted = highlightedNodeIds ? highlightedNodeIds.has(node.node_id) : false;
        const isDimmed = highlightedNodeIds ? !isHighlighted : false;

        tempFullPositioned.push({
          ...node,
          tier,
          column: tier,
          x: colX,
          y: startY + rowIdx * ySpacing,
          isCorrelated,
          isHighlighted,
          isDimmed,
        });
      });
    }
  });

  // Center full provenance bounding box around (0, 0)
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;

  tempFullPositioned.forEach((n) => {
    if (n.x < minX) minX = n.x;
    if (n.x + NODE_WIDTH > maxX) maxX = n.x + NODE_WIDTH;
    if (n.y < minY) minY = n.y;
    if (n.y + NODE_HEIGHT > maxY) maxY = n.y + NODE_HEIGHT;
  });

  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;

  tempFullPositioned.forEach((n) => {
    positionedNodes.push({
      ...n,
      x: Math.round(n.x - centerX),
      y: Math.round(n.y - centerY),
    });
  });

  return { nodes: positionedNodes, edges };
};

/**
 * Computes Directed Acyclic Graph (DAG) Ancestors(n) ∪ Descendants(n) for interactive path highlighting.
 */
export const computeHighlightedPath = (
  selectedId: string | null,
  nodes: AttackNode[],
  edges: AttackEdge[]
): Set<string> | null => {
  if (!selectedId) return null;

  const initialIds = new Set<string>();

  const isNode = nodes.some((n) => n.node_id === selectedId);
  const selectedEdge = edges.find((e) => e.edge_id === selectedId);

  if (isNode) {
    initialIds.add(selectedId);
  } else if (selectedEdge) {
    initialIds.add(selectedEdge.source_node_id);
    initialIds.add(selectedEdge.target_node_id);
  } else {
    return null;
  }

  // Forward and backward lookup maps
  const forwardMap = new Map<string, string[]>();
  const backwardMap = new Map<string, string[]>();

  edges.forEach((e) => {
    if (!forwardMap.has(e.source_node_id)) forwardMap.set(e.source_node_id, []);
    forwardMap.get(e.source_node_id)!.push(e.target_node_id);

    if (!backwardMap.has(e.target_node_id)) backwardMap.set(e.target_node_id, []);
    backwardMap.get(e.target_node_id)!.push(e.source_node_id);
  });

  const result = new Set<string>(initialIds);

  // 1. Ancestors (upstream walk)
  const queueUp = Array.from(initialIds);
  while (queueUp.length > 0) {
    const curr = queueUp.shift()!;
    const parents = backwardMap.get(curr) || [];
    parents.forEach((p) => {
      if (!result.has(p)) {
        result.add(p);
        queueUp.push(p);
      }
    });
  }

  // 2. Descendants (downstream walk)
  const queueDown = Array.from(initialIds);
  while (queueDown.length > 0) {
    const curr = queueDown.shift()!;
    const children = forwardMap.get(curr) || [];
    children.forEach((c) => {
      if (!result.has(c)) {
        result.add(c);
        queueDown.push(c);
      }
    });
  }

  return result;
};
