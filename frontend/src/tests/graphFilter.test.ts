import { describe, it, expect } from 'vitest';
import { 
  extractInvestigationFocus, 
  calculateTieredLayout, 
  computeHighlightedPath,
  getNodeTier 
} from '../utils/graphFilter';
import { AttackNode, AttackEdge } from '../services/api';

describe('Attack Graph Filtering & Layout Engine', () => {
  const rootApp: AttackNode = {
    node_id: 'app-1',
    case_id: 'case-tc01',
    node_type: 'APPLICATION',
    label: 'DVACv1.apk',
    entity_reference: 'com.dvac.app',
    created_at: new Date().toISOString(),
    metadata: {}
  };

  const internetPerm: AttackNode = {
    node_id: 'perm-internet',
    case_id: 'case-tc01',
    node_type: 'PERMISSION',
    label: 'android.permission.INTERNET',
    entity_reference: 'android.permission.INTERNET',
    created_at: new Date().toISOString(),
    metadata: {}
  };

  const targetIp: AttackNode = {
    node_id: 'ip-147',
    case_id: 'case-tc01',
    node_type: 'IP',
    label: '147.32.83.157',
    entity_reference: '147.32.83.157',
    created_at: new Date().toISOString(),
    metadata: {}
  };

  const networkEvent: AttackNode = {
    node_id: 'net-flow-1',
    case_id: 'case-tc01',
    node_type: 'NETWORK_EVENT',
    label: 'HTTP POST 147.32.83.157:8080/api/track',
    entity_reference: 'matching_youtrack.pcapng',
    created_at: new Date().toISOString(),
    metadata: {}
  };

  const threatIntel: AttackNode = {
    node_id: 'ti-1',
    case_id: 'case-tc01',
    node_type: 'THREAT_INTEL',
    label: 'ThreatFox: Malicious C2 IP (147.32.83.157)',
    entity_reference: 'abuse.ch',
    created_at: new Date().toISOString(),
    metadata: {}
  };

  // Generate 50 noisy static string / API nodes
  const noiseNodes: AttackNode[] = Array.from({ length: 50 }, (_, i) => ({
    node_id: `noise-${i}`,
    case_id: 'case-tc01',
    node_type: i % 2 === 0 ? 'API' : 'CAPABILITY',
    label: `Landroid/util/Log;->d(Tag_${i})`,
    entity_reference: `class_ref_${i}`,
    created_at: new Date().toISOString(),
    metadata: {}
  }));

  const coreEdges: AttackEdge[] = [
    {
      edge_id: 'edge-app-ip',
      case_id: 'case-tc01',
      source_node_id: 'app-1',
      target_node_id: 'ip-147',
      relationship_type: 'EMBEDS',
      relationship_class: 'OBSERVED',
      strength: 'STRONG',
      reason: 'Hardcoded C2 address in DEX binary',
      supporting_observation_ids: [],
      supporting_correlation_ids: [],
      supporting_evidence_ids: [],
      metadata: {},
      created_at: new Date().toISOString()
    },
    {
      edge_id: 'edge-app-perm',
      case_id: 'case-tc01',
      source_node_id: 'app-1',
      target_node_id: 'perm-internet',
      relationship_type: 'USES',
      relationship_class: 'OBSERVED',
      strength: 'STRONG',
      reason: 'AndroidManifest declared permission',
      supporting_observation_ids: [],
      supporting_correlation_ids: [],
      supporting_evidence_ids: [],
      metadata: {},
      created_at: new Date().toISOString()
    },
    {
      edge_id: 'edge-ip-pcap-corr',
      case_id: 'case-tc01',
      source_node_id: 'ip-147',
      target_node_id: 'net-flow-1',
      relationship_type: 'CORRELATED_WITH',
      relationship_class: 'CORRELATED',
      strength: 'STRONG',
      reason: 'IP match between APK static constant and PCAP network socket stream',
      supporting_observation_ids: [],
      supporting_correlation_ids: ['corr-ip-match-001'],
      supporting_evidence_ids: [],
      metadata: {},
      created_at: new Date().toISOString()
    },
    {
      edge_id: 'edge-ip-ti',
      case_id: 'case-tc01',
      source_node_id: 'ip-147',
      target_node_id: 'ti-1',
      relationship_type: 'SUPPORTED_BY',
      relationship_class: 'CORRELATED',
      strength: 'STRONG',
      reason: 'External IOC intelligence match',
      supporting_observation_ids: [],
      supporting_correlation_ids: [],
      supporting_evidence_ids: [],
      metadata: {},
      created_at: new Date().toISOString()
    }
  ];

  const noiseEdges: AttackEdge[] = noiseNodes.map((n, i) => ({
    edge_id: `edge-noise-${i}`,
    case_id: 'case-tc01',
    source_node_id: 'app-1',
    target_node_id: n.node_id,
    relationship_type: 'USES',
    relationship_class: 'OBSERVED' as const,
    strength: 'WEAK' as const,
    reason: 'Routine framework invocation',
    supporting_observation_ids: [],
    supporting_correlation_ids: [],
    supporting_evidence_ids: [],
    metadata: {},
    created_at: new Date().toISOString()
  }));

  const allNodes = [rootApp, internetPerm, targetIp, networkEvent, threatIntel, ...noiseNodes];
  const allEdges = [...coreEdges, ...noiseEdges];

  it('assigns correct left-to-right tiers for all node types', () => {
    expect(getNodeTier('APPLICATION')).toBe(0);
    expect(getNodeTier('PERMISSION')).toBe(1);
    expect(getNodeTier('CAPABILITY')).toBe(1);
    expect(getNodeTier('API')).toBe(1);
    expect(getNodeTier('DOMAIN')).toBe(2);
    expect(getNodeTier('IP')).toBe(2);
    expect(getNodeTier('DNS_EVENT')).toBe(2);
    expect(getNodeTier('NETWORK_EVENT')).toBe(3);
    expect(getNodeTier('THREAT_INTEL')).toBe(4);
  });

  it('extracts the critical investigation focus sub-graph while filtering out noise', () => {
    const focusResult = extractInvestigationFocus(allNodes, allEdges);

    expect(focusResult.totalNodesCount).toBe(55);
    // Focused nodes should be concise (rootApp, targetIp, networkEvent, internetPerm, threatIntel)
    expect(focusResult.nodes.length).toBeLessThanOrEqual(6);
    expect(focusResult.nodes.length).toBeGreaterThanOrEqual(4);

    const focusedIds = new Set(focusResult.nodes.map(n => n.node_id));
    expect(focusedIds.has('app-1')).toBe(true);
    expect(focusedIds.has('ip-147')).toBe(true);
    expect(focusedIds.has('net-flow-1')).toBe(true);
    expect(focusedIds.has('perm-internet')).toBe(true);
    expect(focusedIds.has('ti-1')).toBe(true);

    // Noise nodes should be filtered out
    expect(focusedIds.has('noise-0')).toBe(false);
    expect(focusedIds.has('noise-25')).toBe(false);

    // Strong correlation edge and manifest permission edge must be retained
    const edgeIds = new Set(focusResult.edges.map(e => e.edge_id));
    expect(edgeIds.has('edge-ip-pcap-corr')).toBe(true);
    expect(edgeIds.has('edge-app-perm')).toBe(true);
    expect(edgeIds.has('edge-noise-0')).toBe(false);

    // High noise reduction percentage
    expect(focusResult.reductionPercent).toBeGreaterThanOrEqual(85);
  });

  it('computes collision-free tiered layout positions in strict 4-column L-to-R order', () => {
    const focusResult = extractInvestigationFocus(allNodes, allEdges);
    const layout = calculateTieredLayout(focusResult.nodes, focusResult.edges, true, focusResult.correlatedNodeIds);

    expect(layout.nodes.length).toBe(focusResult.nodes.length);

    // Verify left-to-right monotonicity: root (Col 1) X < Perm (Col 2) X < IP (Col 3) X < Network Event (Col 4) X < TI (Col 5) X
    const appPos = layout.nodes.find(n => n.node_id === 'app-1')!;
    const permPos = layout.nodes.find(n => n.node_id === 'perm-internet')!;
    const ipPos = layout.nodes.find(n => n.node_id === 'ip-147')!;
    const netPos = layout.nodes.find(n => n.node_id === 'net-flow-1')!;
    const tiPos = layout.nodes.find(n => n.node_id === 'ti-1')!;

    expect(appPos.x).toBeLessThan(permPos.x);
    expect(permPos.x).toBeLessThan(ipPos.x);
    expect(ipPos.x).toBeLessThan(netPos.x);
    expect(netPos.x).toBeLessThan(tiPos.x);

    // Verify horizontal alignment on the same baseline
    expect(appPos.y).toBe(permPos.y);
    expect(permPos.y).toBe(ipPos.y);
    expect(ipPos.y).toBe(netPos.y);
    expect(netPos.y).toBe(tiPos.y);

    // Ensure correlated node is marked
    expect(ipPos.isCorrelated).toBe(true);
    expect(netPos.isCorrelated).toBe(true);

    // Verify zero collision between any pair of nodes (card width: 220, card height: 80)
    for (let i = 0; i < layout.nodes.length; i++) {
      for (let j = i + 1; j < layout.nodes.length; j++) {
        const n1 = layout.nodes[i];
        const n2 = layout.nodes[j];
        const xDist = Math.abs(n1.x - n2.x);
        const yDist = Math.abs(n1.y - n2.y);
        const hasHorizontalGap = xDist >= 220;
        const hasVerticalGap = yDist >= 80;
        expect(hasHorizontalGap || hasVerticalGap).toBe(true);
      }
    }
  });

  it('preserves full provenance mode with all 55 nodes', () => {
    const fullLayout = calculateTieredLayout(allNodes, allEdges, false);
    expect(fullLayout.nodes.length).toBe(55);
    expect(fullLayout.edges.length).toBe(allEdges.length);
  });

  it('computes transitive connected path when an anchor is clicked', () => {
    // When clicking target IP 147.32.83.157
    const path = computeHighlightedPath('ip-147', allNodes, allEdges);
    expect(path).not.toBeNull();
    expect(path!.has('ip-147')).toBe(true);
    expect(path!.has('app-1')).toBe(true); // Upstream parent
    expect(path!.has('net-flow-1')).toBe(true); // Downstream child
    expect(path!.has('ti-1')).toBe(true); // Threat intel child
    expect(path!.has('noise-5')).toBe(false); // Disconnected noise
  });

  it('handles single-artifact APK-only cases gracefully', () => {
    const singleApkNodes = [rootApp, internetPerm, targetIp, noiseNodes[0]];
    const singleApkEdges = [coreEdges[0], coreEdges[1], noiseEdges[0]];

    const result = extractInvestigationFocus(singleApkNodes, singleApkEdges);
    expect(result.nodes.length).toBeGreaterThan(0);
    expect(result.nodes.some(n => n.node_id === 'app-1')).toBe(true);
  });

  it('handles PCAP-only cases without crashing or fabricating fake correlations', () => {
    const pcapOnlyNodes = [targetIp, networkEvent, threatIntel];
    const pcapOnlyEdges = [
      {
        edge_id: 'edge-pcap-1',
        case_id: 'case-pcap',
        source_node_id: 'ip-147',
        target_node_id: 'net-flow-1',
        relationship_type: 'OBSERVED_IN',
        relationship_class: 'OBSERVED' as const,
        strength: 'STRONG' as const,
        reason: 'Packet stream to destination',
        supporting_observation_ids: [],
        supporting_correlation_ids: [],
        supporting_evidence_ids: [],
        metadata: {},
        created_at: new Date().toISOString()
      }
    ];

    const result = extractInvestigationFocus(pcapOnlyNodes, pcapOnlyEdges);
    expect(result.nodes.length).toBeGreaterThan(0);
    expect(result.nodes.some(n => n.node_id === 'ip-147')).toBe(true);
  });

  it('prioritizes external public IP correlation over loopback and Docker infrastructure', () => {
    const loopbackNode: AttackNode = {
      node_id: 'ip-127',
      case_id: 'case-tc01',
      node_type: 'IP',
      label: '127.0.0.1',
      entity_reference: '127.0.0.1',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const dockerNode: AttackNode = {
      node_id: 'ip-docker',
      case_id: 'case-tc01',
      node_type: 'IP',
      label: '127.0.0.11',
      entity_reference: '127.0.0.11',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const loopbackNetEvent: AttackNode = {
      node_id: 'net-127',
      case_id: 'case-tc01',
      node_type: 'NETWORK_EVENT',
      label: 'Traffic: 127.0.0.1',
      entity_reference: 'pcap',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const loopbackCorrEdge: AttackEdge = {
      edge_id: 'edge-corr-loopback',
      case_id: 'case-tc01',
      source_node_id: 'ip-127',
      target_node_id: 'net-127',
      relationship_type: 'IP_MATCH',
      relationship_class: 'CORRELATED',
      strength: 'STRONG',
      reason: 'Loopback match',
      supporting_observation_ids: [],
      supporting_correlation_ids: ['corr-loopback'],
      supporting_evidence_ids: [],
      metadata: {},
      created_at: new Date().toISOString()
    };

    const mixedNodes = [rootApp, internetPerm, loopbackNode, dockerNode, targetIp, networkEvent, loopbackNetEvent];
    const mixedEdges = [...coreEdges, loopbackCorrEdge];

    const focusResult = extractInvestigationFocus(mixedNodes, mixedEdges);

    // Must pick external IP 147.32.83.157 over 127.0.0.1
    const selectedIds = new Set(focusResult.nodes.map(n => n.node_id));
    expect(selectedIds.has('ip-147')).toBe(true);
    expect(selectedIds.has('net-flow-1')).toBe(true);
    expect(selectedIds.has('ip-127')).toBe(false);
    expect(selectedIds.has('ip-docker')).toBe(false);
    expect(selectedIds.has('net-127')).toBe(false);
  });

  it('selects at most one primary indicator and one network event when only local loopback exists (4 nodes total)', () => {
    const loopbackNode: AttackNode = {
      node_id: 'ip-127',
      case_id: 'case-tc01',
      node_type: 'IP',
      label: '127.0.0.1',
      entity_reference: '127.0.0.1',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const dockerNode: AttackNode = {
      node_id: 'ip-docker',
      case_id: 'case-tc01',
      node_type: 'IP',
      label: '127.0.0.11',
      entity_reference: '127.0.0.11',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const loopbackNetEvent: AttackNode = {
      node_id: 'net-127',
      case_id: 'case-tc01',
      node_type: 'NETWORK_EVENT',
      label: 'Traffic: 127.0.0.1',
      entity_reference: 'pcap',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const dockerNetEvent: AttackNode = {
      node_id: 'net-docker',
      case_id: 'case-tc01',
      node_type: 'NETWORK_EVENT',
      label: 'Traffic: 127.0.0.11',
      entity_reference: 'pcap',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const loopbackCorrEdge: AttackEdge = {
      edge_id: 'edge-corr-loopback',
      case_id: 'case-tc01',
      source_node_id: 'ip-127',
      target_node_id: 'net-127',
      relationship_type: 'IP_MATCH',
      relationship_class: 'CORRELATED',
      strength: 'STRONG',
      reason: 'Loopback match',
      supporting_observation_ids: [],
      supporting_correlation_ids: ['corr-loopback'],
      supporting_evidence_ids: [],
      metadata: {},
      created_at: new Date().toISOString()
    };

    const dockerCorrEdge: AttackEdge = {
      edge_id: 'edge-corr-docker',
      case_id: 'case-tc01',
      source_node_id: 'ip-docker',
      target_node_id: 'net-docker',
      relationship_type: 'IP_MATCH',
      relationship_class: 'CORRELATED',
      strength: 'STRONG',
      reason: 'Docker match',
      supporting_observation_ids: [],
      supporting_correlation_ids: ['corr-docker'],
      supporting_evidence_ids: [],
      metadata: {},
      created_at: new Date().toISOString()
    };

    const localOnlyNodes = [rootApp, internetPerm, loopbackNode, dockerNode, loopbackNetEvent, dockerNetEvent];
    const localOnlyEdges = [
      {
        edge_id: 'edge-app-perm',
        case_id: 'case-tc01',
        source_node_id: 'app-1',
        target_node_id: 'perm-internet',
        relationship_type: 'USES',
        relationship_class: 'OBSERVED' as const,
        strength: 'STRONG' as const,
        reason: 'Perm',
        supporting_observation_ids: [],
        supporting_correlation_ids: [],
        supporting_evidence_ids: [],
        metadata: {},
        created_at: new Date().toISOString()
      },
      loopbackCorrEdge,
      dockerCorrEdge
    ];

    const result = extractInvestigationFocus(localOnlyNodes, localOnlyEdges);

    // Exactly 4 nodes: App, Perm, 1 IP, 1 Net Event (no duplicated branches)
    expect(result.nodes.length).toBe(4);
    const nodeTypes = result.nodes.map(n => n.node_type);
    expect(nodeTypes.filter(t => t === 'APPLICATION').length).toBe(1);
    expect(nodeTypes.filter(t => t === 'PERMISSION').length).toBe(1);
    expect(nodeTypes.filter(t => t === 'IP').length).toBe(1);
    expect(nodeTypes.filter(t => t === 'NETWORK_EVENT').length).toBe(1);
  });

  it('omits threat intel node when no threat intel evidence is present', () => {
    // Only core evidence without threat intel
    const noTiNodes = [rootApp, internetPerm, targetIp, networkEvent];
    const noTiEdges = coreEdges.filter(e => e.target_node_id !== 'ti-1');

    const result = extractInvestigationFocus(noTiNodes, noTiEdges);
    expect(result.nodes.length).toBe(4);
    expect(result.nodes.some(n => n.node_type === 'THREAT_INTEL')).toBe(false);
    expect(result.threatIntelNodeIds.size).toBe(0);
  });

  it('produces 100% deterministic output across multiple runs', () => {
    const run1 = extractInvestigationFocus(allNodes, allEdges);
    const run2 = extractInvestigationFocus(allNodes, allEdges);

    expect(run1.nodes.map(n => n.node_id)).toEqual(run2.nodes.map(n => n.node_id));
    expect(run1.edges.map(e => e.edge_id)).toEqual(run2.edges.map(e => e.edge_id));
  });

  it('handles completely unrelated APK and PCAP without fabricating correlations', () => {
    const unrelatedApp: AttackNode = {
      node_id: 'unrelated-app',
      case_id: 'unrelated',
      node_type: 'APPLICATION',
      label: 'calculator.apk',
      entity_reference: 'com.calc',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const unrelatedNet: AttackNode = {
      node_id: 'unrelated-net',
      case_id: 'unrelated',
      node_type: 'NETWORK_EVENT',
      label: 'Traffic: 8.8.8.8',
      entity_reference: 'pcap',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const unrelatedResult = extractInvestigationFocus([unrelatedApp, unrelatedNet], []);
    expect(unrelatedResult.correlatedNodeIds.size).toBe(0);
    // Should not synthesize fake correlation edges
    expect(unrelatedResult.edges.some(e => e.relationship_class === 'CORRELATED')).toBe(false);
  });

  it('dynamically collapses empty stages into compact adjacent columns without gaps', () => {
    // Stage 0 (Application) and Stage 2 (IP) and Stage 3 (Network Event) - missing Stage 1 (Permission)
    const collapsedNodes = [rootApp, targetIp, networkEvent];
    const collapsedEdges = [
      {
        edge_id: 'edge-direct-app-ip',
        case_id: 'case-tc01',
        source_node_id: 'app-1',
        target_node_id: 'ip-147',
        relationship_type: 'EMBEDS',
        relationship_class: 'OBSERVED' as const,
        strength: 'STRONG' as const,
        reason: 'Direct link',
        supporting_observation_ids: [],
        supporting_correlation_ids: [],
        supporting_evidence_ids: [],
        metadata: {},
        created_at: new Date().toISOString()
      },
      coreEdges[2]
    ];

    const layout = calculateTieredLayout(collapsedNodes, collapsedEdges, true);
    expect(layout.nodes.length).toBe(3);

    const appNode = layout.nodes.find(n => n.node_id === 'app-1')!;
    const ipNode = layout.nodes.find(n => n.node_id === 'ip-147')!;
    const netNode = layout.nodes.find(n => n.node_id === 'net-flow-1')!;

    // Columns should be strictly 0, 1, 2 (collapsed from stages 0, 2, 3)
    expect(appNode.column).toBe(0);
    expect(ipNode.column).toBe(1);
    expect(netNode.column).toBe(2);

    // Compact inter-column distance (COL_STEP = 360)
    expect(ipNode.x - appNode.x).toBe(360);
    expect(netNode.x - ipNode.x).toBe(360);
  });

  it('stacks multiple parallel correlation lanes compactly and vertically centered', () => {
    const ip2: AttackNode = {
      node_id: 'ip-2',
      case_id: 'case-tc01',
      node_type: 'IP',
      label: '198.51.100.45',
      entity_reference: '198.51.100.45',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const multiNodes = [rootApp, targetIp, ip2];
    const multiEdges = [coreEdges[0]];

    const layout = calculateTieredLayout(multiNodes, multiEdges, true);
    expect(layout.nodes.length).toBe(3);

    const ip1Pos = layout.nodes.find(n => n.node_id === 'ip-147')!;
    const ip2Pos = layout.nodes.find(n => n.node_id === 'ip-2')!;

    // Same column, different Y coordinates
    expect(ip1Pos.x).toBe(ip2Pos.x);
    expect(Math.abs(ip1Pos.y - ip2Pos.y)).toBe(116); // ROW_STEP = 86 + 30 = 116
    // Card centers are vertically symmetrical around y = 0: (y1 + 43) + (y2 + 43) === 0
    const center1 = ip1Pos.y + 43;
    const center2 = ip2Pos.y + 43;
    expect(center1 + center2).toBe(0);
  });

  it('correctly models 2 correlation branches as parallel lanes without crossing edges', () => {
    const netEvent2: AttackNode = {
      node_id: 'net-flow-2',
      case_id: 'case-tc01',
      node_type: 'NETWORK_EVENT',
      label: 'HTTP GET 198.51.100.45:443/status',
      entity_reference: 'matching_youtrack.pcapng',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const ip2: AttackNode = {
      node_id: 'ip-2',
      case_id: 'case-tc01',
      node_type: 'IP',
      label: '198.51.100.45',
      entity_reference: '198.51.100.45',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const corrEdge2: AttackEdge = {
      edge_id: 'edge-corr-2',
      case_id: 'case-tc01',
      source_node_id: 'ip-2',
      target_node_id: 'net-flow-2',
      relationship_type: 'IP_MATCH',
      relationship_class: 'CORRELATED',
      strength: 'STRONG',
      reason: 'IP 2 match',
      supporting_observation_ids: [],
      supporting_correlation_ids: ['corr-002'],
      supporting_evidence_ids: [],
      metadata: {},
      created_at: new Date().toISOString()
    };

    const branchNodes = [rootApp, internetPerm, targetIp, networkEvent, ip2, netEvent2];
    const branchEdges = [...coreEdges.slice(0, 3), corrEdge2];

    const layout = calculateTieredLayout(branchNodes, branchEdges, true);
    expect(layout.nodes.length).toBe(6);

    const appNode = layout.nodes.find(n => n.node_id === 'app-1')!;
    const permNode = layout.nodes.find(n => n.node_id === 'perm-internet')!;
    const ip1 = layout.nodes.find(n => n.node_id === 'ip-147')!;
    const ip2Node = layout.nodes.find(n => n.node_id === 'ip-2')!;
    const net1 = layout.nodes.find(n => n.node_id === 'net-flow-1')!;
    const net2 = layout.nodes.find(n => n.node_id === 'net-flow-2')!;

    // Columns are strictly ordered
    expect(appNode.x).toBeLessThan(permNode.x);
    expect(permNode.x).toBeLessThan(ip1.x);
    expect(ip1.x).toBe(ip2Node.x);
    expect(ip1.x).toBeLessThan(net1.x);
    expect(net1.x).toBe(net2.x);

    // Root and perm are vertically centered between the two lanes
    expect(appNode.y + 43).toBe(0);
    expect(permNode.y + 43).toBe(0);

    // Parallel lanes are non-overlapping
    expect(Math.abs(ip1.y - ip2Node.y)).toBeGreaterThanOrEqual(116);
    expect(Math.abs(net1.y - net2.y)).toBeGreaterThanOrEqual(116);
  });

  it('correctly models 3+ correlation branches cleanly centered around root and permission', () => {
    const ip3: AttackNode = {
      node_id: 'ip-3',
      case_id: 'case-tc01',
      node_type: 'IP',
      label: '203.0.113.88',
      entity_reference: '203.0.113.88',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const net3: AttackNode = {
      node_id: 'net-flow-3',
      case_id: 'case-tc01',
      node_type: 'NETWORK_EVENT',
      label: 'TCP 203.0.113.88:9001',
      entity_reference: 'pcap',
      created_at: new Date().toISOString(),
      metadata: {}
    };

    const branchNodes = [rootApp, internetPerm, targetIp, networkEvent, ip3, net3];
    const layout = calculateTieredLayout(branchNodes, [], true);

    expect(layout.nodes.length).toBe(6);
    const appPos = layout.nodes.find(n => n.node_id === 'app-1')!;
    const permPos = layout.nodes.find(n => n.node_id === 'perm-internet')!;
    
    // Root and perm stay vertically centered
    expect(appPos.y + 43).toBe(0);
    expect(permPos.y + 43).toBe(0);
  });

  it('enforces hard visual budget of <= 8 visible nodes on a large 227-node graph', () => {
    // Construct a large 227-node dataset
    const bigNoiseNodes: AttackNode[] = Array.from({ length: 222 }, (_, i) => ({
      node_id: `big-noise-${i}`,
      case_id: 'case-tc01',
      node_type: i % 3 === 0 ? 'API' : i % 3 === 1 ? 'CAPABILITY' : 'STRING_CONSTANT',
      label: `Lcom/example/ObfuscatedClass_${i};->method_${i}()`,
      entity_reference: `ref_${i}`,
      created_at: new Date().toISOString(),
      metadata: {}
    }));

    const bigNodes = [rootApp, internetPerm, targetIp, networkEvent, threatIntel, ...bigNoiseNodes];
    expect(bigNodes.length).toBe(227);

    const focusResult = extractInvestigationFocus(bigNodes, coreEdges);
    expect(focusResult.totalNodesCount).toBe(227);
    expect(focusResult.nodes.length).toBeLessThanOrEqual(8);
    expect(focusResult.nodes.length).toBeGreaterThanOrEqual(4);
    expect(focusResult.reductionPercent).toBeGreaterThanOrEqual(95);
  });

  it('correctly reports hasCorrelations flag and story steps matching real evidence only', () => {
    const focusResult = extractInvestigationFocus(allNodes, coreEdges);
    expect(focusResult.hasCorrelations).toBe(true);
    expect(focusResult.storySteps.length).toBe(5);

    // Verify step titles match real node evidence
    expect(focusResult.storySteps[0].title).toBe('Target Application Ingested');
    expect(focusResult.storySteps[1].title).toBe('Network Permission Declared');
    expect(focusResult.storySteps[2].title).toBe('Hardcoded Indicator Matched');
    expect(focusResult.storySteps[3].title).toBe('Dynamic Traffic Observed');
    expect(focusResult.storySteps[4].title).toBe('Threat Intelligence Attribution');

    // Case without threat intel
    const noTiNodes = [rootApp, internetPerm, targetIp, networkEvent];
    const noTiEdges = coreEdges.filter(e => e.target_node_id !== 'ti-1');
    const noTiResult = extractInvestigationFocus(noTiNodes, noTiEdges);
    expect(noTiResult.storySteps.some(s => s.phase === 'INTEL')).toBe(false);
    expect(noTiResult.storySteps.length).toBe(4);
  });

  it('extracts focused path deterministically when focusPathNodeId is provided', () => {
    const pathResult = extractInvestigationFocus(allNodes, coreEdges, 'ip-147');
    expect(pathResult.nodes.length).toBeLessThanOrEqual(8);
    const nodeIds = new Set(pathResult.nodes.map(n => n.node_id));
    expect(nodeIds.has('ip-147')).toBe(true);
    expect(nodeIds.has('app-1')).toBe(true);
    expect(nodeIds.has('net-flow-1')).toBe(true);
  });

  it('handles empty graphs without error', () => {
    const emptyResult = extractInvestigationFocus([], []);
    expect(emptyResult.nodes).toEqual([]);
    expect(emptyResult.edges).toEqual([]);
    expect(emptyResult.reductionPercent).toBe(0);
    expect(emptyResult.hasCorrelations).toBe(false);

    const emptyLayout = calculateTieredLayout([], [], true);
    expect(emptyLayout.nodes).toEqual([]);
  });
});
