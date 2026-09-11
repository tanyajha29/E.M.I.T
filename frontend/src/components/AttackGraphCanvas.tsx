import React, { useMemo, useState, useCallback, useRef } from 'react';
import ReactFlow, {
  Controls,
  Background,
  MiniMap,
  Node,
  Edge,
  MarkerType,
  Position,
  Handle,
  ReactFlowInstance,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { 
  AttackNode, 
  AttackEdge 
} from '../services/api';
import { 
  Cpu, 
  Globe, 
  Server, 
  ShieldAlert, 
  Activity, 
  AlertTriangle, 
  Layers, 
  X, 
  Info,
  ExternalLink,
  GitCommit,
  Focus,
  Eye,
  Search,
  Zap,
  CheckCircle2,
  ChevronRight,
  BookOpen
} from 'lucide-react';
import {
  GraphViewMode,
  buildPrimaryInvestigationChain,
  calculateTieredLayout,
  computeHighlightedPath,
  getFocusColumn,
  PositionedNode
} from '../utils/graphFilter';

interface AttackGraphCanvasProps {
  nodesData: AttackNode[];
  edgesData: AttackEdge[];
  height?: string;
  initialMode?: GraphViewMode;
}

// ---------------------------------------------------------------------------
// HELPER: SHORTENED FORENSIC EDGE LABELS
// ---------------------------------------------------------------------------
const getCleanEdgeLabel = (relType?: string): string => {
  if (!relType) return '';
  const clean = relType.toUpperCase().trim();
  switch (clean) {
    case 'CORRELATED_WITH':
      return 'MATCH';
    case 'IP_MATCH':
      return 'IP MATCH';
    case 'DOMAIN_MATCH':
      return 'DOMAIN MATCH';
    case 'RESOLVED_IP_MATCH':
      return 'RESOLVES TO';
    case 'PERIODIC_COMMUNICATION_MATCH':
      return 'BEACON';
    case 'CAPABILITY_ACTIVITY_ALIGNMENT':
      return 'SUPPORTS';
    case 'TEMPORAL_ALIGNMENT':
      return 'TEMPORAL';
    case 'THREAT_INTEL_MATCH':
    case 'SUPPORTED_BY':
      return 'INTEL MATCH';
    case 'CONNECTS_TO':
      return 'CONNECTS TO';
    case 'RESOLVES_TO':
      return 'RESOLVES TO';
    case 'OBSERVED_IN':
      return 'OBSERVED';
    case 'CONTAINS':
      return 'CONTAINS';
    case 'USES':
      return 'USES';
    case 'EMBEDS':
      return 'EMBEDS';
    case 'SUPPORTS':
      return 'SUPPORTS';
    default:
      return clean.replace(/_/g, ' ');
  }
};

// ---------------------------------------------------------------------------
// CUSTOM NODE RENDERER (FORENSIC EVIDENCE CARD)
// ---------------------------------------------------------------------------
const CustomAttackNode: React.FC<{ 
  data: PositionedNode & { 
    selectedNodeId?: string;
    isPathHighlighted?: boolean;
    isDimmed?: boolean;
    viewMode?: GraphViewMode;
  } 
}> = ({ data }) => {
  const isSelected = data.selectedNodeId === data.node_id;
  const isDimmed = data.isDimmed && !isSelected && !data.isPathHighlighted;
  const isHighlighted = isSelected || data.isPathHighlighted;

  const { icon: Icon, typeLabel, bgClass, borderClass, textClass, badgeClass } = useMemo(() => {
    switch (data.node_type) {
      case 'APPLICATION':
        return {
          icon: Cpu,
          typeLabel: 'APPLICATION',
          bgClass: 'bg-[#0A120A]',
          borderClass: 'border-[#00FF00]/50 hover:border-[#00FF00]',
          textClass: 'text-[#00FF00]',
          badgeClass: 'bg-[#00FF00]/10 text-[#00FF00] border-[#00FF00]/30'
        };
      case 'PERMISSION':
      case 'CAPABILITY':
        return {
          icon: ShieldAlert,
          typeLabel: 'PERMISSION',
          bgClass: 'bg-[#100C16]',
          borderClass: 'border-[#A78BFA]/40 hover:border-[#A78BFA]',
          textClass: 'text-[#A78BFA]',
          badgeClass: 'bg-[#A78BFA]/10 text-[#A78BFA] border-[#A78BFA]/30'
        };
      case 'IP':
        return {
          icon: Server,
          typeLabel: 'CORRELATED IP',
          bgClass: 'bg-[#140024]',
          borderClass: 'border-[#BB88FF]/60 hover:border-[#BB88FF] shadow-[0_0_12px_rgba(187,136,255,0.2)]',
          textClass: 'text-[#BB88FF]',
          badgeClass: 'bg-[#BB88FF]/15 text-[#BB88FF] border-[#BB88FF]/40'
        };
      case 'DOMAIN':
        return {
          icon: Globe,
          typeLabel: 'DOMAIN INDICATOR',
          bgClass: 'bg-[#1A0E00]',
          borderClass: 'border-[#FF8800]/50 hover:border-[#FF8800]',
          textClass: 'text-[#FF8800]',
          badgeClass: 'bg-[#FF8800]/15 text-[#FF8800] border-[#FF8800]/40'
        };
      case 'NETWORK_EVENT':
        return {
          icon: Activity,
          typeLabel: 'PCAP NETWORK EVENT',
          bgClass: 'bg-[#001A00]/95',
          borderClass: 'border-[#00FF00]/60 hover:border-[#00FF00]',
          textClass: 'text-[#00FF00]',
          badgeClass: 'bg-[#00FF00]/15 text-[#00FF00] border-[#00FF00]/40'
        };
      case 'THREAT_INTEL':
        return {
          icon: AlertTriangle,
          typeLabel: 'THREAT INTEL',
          bgClass: 'bg-[#1A0808]',
          borderClass: 'border-[#FF3333]/50 hover:border-[#FF3333]',
          textClass: 'text-[#FF3333]',
          badgeClass: 'bg-[#FF3333]/15 text-[#FF3333] border-[#FF3333]/40'
        };
      default:
        return {
          icon: Layers,
          typeLabel: data.node_type,
          bgClass: 'bg-[#0E0E0E]',
          borderClass: 'border-[#2A2A2A] hover:border-[#444444]',
          textClass: 'text-white',
          badgeClass: 'bg-[#181818] text-[#AAAAAA] border-[#333333]'
        };
    }
  }, [data.node_type]);

  const sourceBadge = useMemo(() => {
    if (data.metadata?.source) return data.metadata.source;
    if (data.isCorrelated) return 'APK + PCAP MATCH';
    if (data.node_type === 'APPLICATION') return 'APK INGESTED';
    if (data.node_type === 'PERMISSION' || data.node_type === 'CAPABILITY') return 'APK MANIFEST';
    if (data.node_type === 'NETWORK_EVENT') return 'PCAP OBSERVED';
    if (data.node_type === 'THREAT_INTEL') return 'EXTERNAL IOC';
    return data.entity_reference || 'OBSERVED';
  }, [data.node_type, data.isCorrelated, data.metadata?.source, data.entity_reference]);

  return (
    <div
      title={`${typeLabel}: ${data.label} • ${sourceBadge}`}
      className={`px-3 py-2 rounded-lg border shadow-xl w-[250px] max-w-[250px] min-h-[80px] max-h-[86px] flex flex-col justify-between transition-all duration-200 cursor-pointer ${bgClass} ${borderClass} ${
        isSelected 
          ? 'ring-2 ring-[#00FF00] scale-[1.03] shadow-[0_0_20px_rgba(0,255,0,0.6)] z-30' 
          : isHighlighted
            ? 'ring-1 ring-[#FF8800] shadow-[0_0_14px_rgba(255,136,0,0.4)] z-20'
            : isDimmed 
              ? 'opacity-20 grayscale' 
              : 'opacity-100'
      }`}
    >
      {/* Invisible Connection Ports */}
      <Handle 
        id="target-left"
        type="target" 
        position={Position.Left} 
        className="opacity-0 w-2 h-2 pointer-events-none" 
      />
      <Handle 
        id="source-right"
        type="source" 
        position={Position.Right} 
        className="opacity-0 w-2 h-2 pointer-events-none" 
      />
      
      {/* Card Header: Node Type + Correlated Badge */}
      <div className="flex items-center justify-between gap-1.5">
        <div className="flex items-center gap-1 min-w-0 shrink-0" title={typeLabel}>
          <Icon className={`h-3 w-3 ${textClass} shrink-0`} />
          <span className={`text-[8.5px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border whitespace-nowrap shrink-0 ${badgeClass}`}>
            {typeLabel}
          </span>
        </div>
        
        {data.isCorrelated && (
          <span 
            title="Correlated Bridge: Observed across both APK static bytecode and dynamic PCAP network capture"
            className="flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-[#FF8800]/20 border border-[#FF8800]/60 text-[8px] font-mono font-bold text-[#FF8800] shrink-0 whitespace-nowrap"
          >
            <Zap className="h-2 w-2" />
            <span>CORRELATED</span>
          </span>
        )}
      </div>

      {/* Main Title / Forensic Value with Full Value Tooltip */}
      <div 
        className="font-mono text-xs font-bold text-white truncate select-all cursor-text my-1 leading-snug" 
        title={data.label}
      >
        {data.label}
      </div>

      {/* Card Footer: Source / Artifact Provenance */}
      <div className="flex items-center justify-between pt-1 border-t border-white/10 font-mono text-[8.5px] text-[#888888]">
        <span className="truncate max-w-[230px]" title={sourceBadge}>
          {sourceBadge}
        </span>
      </div>
    </div>
  );
};

const nodeTypes = {
  customAttackNode: CustomAttackNode,
};

export const AttackGraphCanvas: React.FC<AttackGraphCanvasProps> = ({
  nodesData,
  edgesData,
  height = '620px',
  initialMode = 'FOCUS'
}) => {
  const [viewMode, setViewMode] = useState<GraphViewMode>(initialMode);
  const [searchQuery, setSearchQuery] = useState('');
  const [showStoryNarrative, setShowStoryNarrative] = useState(true);
  const [showLegend, setShowLegend] = useState(false);
  
  const [selectedNode, setSelectedNode] = useState<AttackNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<AttackEdge | null>(null);
  const [pinnedPathId, setPinnedPathId] = useState<string | null>(null);
  const [focusPathId, setFocusPathId] = useState<string | null>(null);

  const reactFlowInstance = useRef<ReactFlowInstance | null>(null);

  // 1. Build Primary Evidence Chain for Investigation Focus
  const focusData = useMemo(() => {
    return buildPrimaryInvestigationChain(nodesData, edgesData, focusPathId);
  }, [nodesData, edgesData, focusPathId]);

  // 2. Select active dataset based on mode
  const activeDataset = useMemo(() => {
    if (viewMode === 'FULL') {
      return {
        nodes: nodesData,
        edges: edgesData,
        correlatedNodeIds: focusData.correlatedNodeIds,
      };
    }

    return {
      nodes: focusData.nodes,
      edges: focusData.edges,
      correlatedNodeIds: focusData.correlatedNodeIds,
    };
  }, [viewMode, nodesData, edgesData, focusData]);

  // 3. Compute active path highlights (transitive upstream/downstream ancestry)
  const activeHighlightId = pinnedPathId || selectedNode?.node_id || selectedEdge?.edge_id || null;
  const highlightedNodeIds = useMemo(() => {
    return computeHighlightedPath(activeHighlightId, activeDataset.nodes, activeDataset.edges);
  }, [activeHighlightId, activeDataset.nodes, activeDataset.edges]);

  // 4. Compute deterministic left-to-right tiered layout
  const { flowNodes, flowEdges } = useMemo(() => {
    const positioned = calculateTieredLayout(
      activeDataset.nodes,
      activeDataset.edges,
      viewMode === 'FOCUS',
      activeDataset.correlatedNodeIds,
      highlightedNodeIds
    );

    const mappedNodes: Node[] = positioned.nodes.map((node) => {
      const isPathHighlighted = highlightedNodeIds ? highlightedNodeIds.has(node.node_id) : false;
      const isSearchMatch = searchQuery.trim() !== '' && 
        (node.label.toLowerCase().includes(searchQuery.toLowerCase()) || 
         node.node_type.toLowerCase().includes(searchQuery.toLowerCase()));

      return {
        id: node.node_id,
        type: 'customAttackNode',
        position: { x: node.x, y: node.y },
        data: {
          ...node,
          selectedNodeId: selectedNode?.node_id,
          isPathHighlighted: isPathHighlighted || isSearchMatch,
          isDimmed: (highlightedNodeIds !== null && !isPathHighlighted) || (searchQuery.trim() !== '' && !isSearchMatch),
          viewMode,
        },
      };
    });

    const visibleNodeIdSet = new Set(positioned.nodes.map(n => n.node_id));

    // Only render edges where BOTH source and target nodes are actively in the canvas
    const validEdges = activeDataset.edges.filter(
      e => visibleNodeIdSet.has(e.source_node_id) && visibleNodeIdSet.has(e.target_node_id)
    );

    const mappedEdges: Edge[] = validEdges.map((edge) => {
      const isSelected = selectedEdge?.edge_id === edge.edge_id;
      const isSourceHighlighted = highlightedNodeIds ? highlightedNodeIds.has(edge.source_node_id) : false;
      const isTargetHighlighted = highlightedNodeIds ? highlightedNodeIds.has(edge.target_node_id) : false;
      const isEdgeHighlighted = isSelected || (isSourceHighlighted && isTargetHighlighted);
      const isDimmed = highlightedNodeIds !== null && !isEdgeHighlighted;

      const sourceHandle = 'source-right';
      const targetHandle = 'target-left';

      const isCorrelated = edge.relationship_class === 'CORRELATED' || edge.relationship_type === 'CORRELATED_WITH' || edge.relationship_type === 'IP_MATCH' || edge.relationship_type === 'DOMAIN_MATCH';
      const isSupporting = edge.relationship_type === 'SUPPORTS' || edge.relationship_class === 'INFERRED';

      let stroke = '#00FF00'; // default observed: neon green
      let strokeDasharray: string | undefined = undefined;
      let strokeWidth = isSelected ? 3.5 : isEdgeHighlighted ? 2.5 : 2;
      let labelFill = '#00FF00';
      let labelBgStroke = '#00FF00';
      let fontSize = 8.5;

      if (isCorrelated) {
        stroke = '#FF8800'; // vibrant amber/orange
        strokeDasharray = '5,3';
        strokeWidth = isSelected ? 4 : isEdgeHighlighted ? 3.5 : 2.5;
        labelFill = '#FF8800';
        labelBgStroke = '#FF8800';
        fontSize = 8.5;
      } else if (isSupporting) {
        stroke = '#A78BFA'; // soft lavender/purple
        strokeDasharray = '4,4';
        strokeWidth = isSelected ? 3 : isEdgeHighlighted ? 2.5 : 1.8;
        labelFill = '#A78BFA';
        labelBgStroke = '#A78BFA';
        fontSize = 8.5;
      } else if (edge.relationship_class === 'OBSERVED') {
        stroke = '#00FF00'; // neon green
      }

      const shortLabel = getCleanEdgeLabel(edge.relationship_type);

      return {
        id: edge.edge_id,
        source: edge.source_node_id,
        target: edge.target_node_id,
        sourceHandle,
        targetHandle,
        type: 'smoothstep', // Clean orthogonal smoothstep routing
        animated: isCorrelated || isEdgeHighlighted,
        label: shortLabel,
        labelStyle: { 
          fill: isDimmed ? '#666666' : labelFill, 
          fontSize, 
          fontFamily: 'JetBrains Mono, monospace', 
          fontWeight: 700,
          letterSpacing: '0.02em',
        },
        labelBgStyle: { 
          fill: '#0A0A0A', 
          fillOpacity: 0.96, 
          stroke: isDimmed ? '#222222' : labelBgStroke,
          strokeWidth: isCorrelated ? 1 : 0.6,
          rx: 3, 
          ry: 3 
        },
        labelBgPadding: [6, 3],
        style: {
          stroke: isDimmed ? '#2A2A2A' : stroke,
          strokeWidth: isDimmed ? 1 : strokeWidth,
          strokeDasharray,
          opacity: isDimmed ? 0.2 : 1,
          transition: 'all 0.2s ease-in-out',
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isDimmed ? '#2A2A2A' : stroke,
          width: isCorrelated ? 14 : 12,
          height: isCorrelated ? 14 : 12,
        },
      };
    });

    return { flowNodes: mappedNodes, flowEdges: mappedEdges };
  }, [activeDataset, viewMode, selectedNode, selectedEdge, highlightedNodeIds, searchQuery]);

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    const raw = activeDataset.nodes.find((n) => n.node_id === node.id);
    setSelectedNode(raw || null);
    setSelectedEdge(null);
  }, [activeDataset.nodes]);

  const onEdgeClick = useCallback((_: React.MouseEvent, edge: Edge) => {
    const raw = activeDataset.edges.find((e) => e.edge_id === edge.id);
    setSelectedEdge(raw || null);
    setSelectedNode(null);
  }, [activeDataset.edges]);

  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
    setSelectedEdge(null);
    setPinnedPathId(null);
  }, []);

  const handleInitFlow = useCallback((instance: ReactFlowInstance) => {
    reactFlowInstance.current = instance;
    setTimeout(() => {
      instance.fitView({ padding: 0.2, maxZoom: 1.05, minZoom: 0.4 });
    }, 60);
  }, []);

  // Auto-fit on mode or dataset switch
  React.useEffect(() => {
    const timer = setTimeout(() => {
      if (reactFlowInstance.current) {
        reactFlowInstance.current.fitView({
          padding: viewMode === 'FOCUS' ? 0.2 : 0.15,
          maxZoom: 1.05,
          minZoom: 0.4,
          duration: 250,
        });
      }
    }, 60);
    return () => clearTimeout(timer);
  }, [viewMode, activeDataset.nodes.length, focusPathId]);

  const handleTogglePathPin = (id: string) => {
    setPinnedPathId(prev => (prev === id ? null : id));
  };

  const handleFocusOnPath = (nodeId: string) => {
    setFocusPathId(nodeId);
    setViewMode('FOCUS');
    setSelectedNode(null);
    setSelectedEdge(null);
    setPinnedPathId(nodeId);
  };

  const handleSelectStoryStep = (nodeId?: string) => {
    if (!nodeId) return;
    const raw = activeDataset.nodes.find(n => n.node_id === nodeId);
    if (raw) {
      setSelectedNode(raw);
      setSelectedEdge(null);
      setPinnedPathId(raw.node_id);
    }
  };

  if (nodesData.length === 0) {
    return (
      <div 
        className="flex flex-col items-center justify-center p-8 text-center bg-[#000000] border border-dashed border-[#222222] rounded-lg"
        style={{ height }}
      >
        <GitCommit className="h-10 w-10 text-[#666666] mb-3" />
        <h4 className="text-sm font-mono font-bold text-slate-300 uppercase tracking-widest">No Attack Graph Data</h4>
        <p className="text-xs font-mono text-[#888888] max-w-md mt-2">
          Execute the APK or PCAP analysis pipeline to extract evidence entities, build cross-artifact correlations, and generate graph topology.
        </p>
      </div>
    );
  }

  return (
    <div className="relative border border-[#222222] rounded-lg overflow-hidden bg-[#000000] flex flex-col" style={{ height }}>
      {/* ===================================================================== */}
      {/* TOP CONTROLS TOOLBAR & VIEW SWITCHER */}
      {/* ===================================================================== */}
      <div className="z-10 bg-[#0A0A0A]/95 backdrop-blur-md border-b border-[#222222] px-4 py-2.5 flex flex-wrap justify-between items-center gap-3 shrink-0">
        {/* Left: Mode Switcher & Count Badge */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center p-0.5 bg-[#141414] border border-[#222222] rounded font-mono text-xs">
            <button
              onClick={() => {
                setViewMode('FOCUS');
                setFocusPathId(null);
                setSelectedNode(null);
                setSelectedEdge(null);
                setPinnedPathId(null);
                setTimeout(() => reactFlowInstance.current?.fitView({ padding: 0.2 }), 80);
              }}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded font-bold uppercase transition-all ${
                viewMode === 'FOCUS'
                  ? 'bg-[#00FF00] text-black shadow-[0_0_12px_rgba(0,255,0,0.3)]'
                  : 'text-[#888888] hover:text-white'
              }`}
            >
              <Focus className="h-3.5 w-3.5" />
              <span>Investigation Focus</span>
            </button>

            <button
              onClick={() => {
                setViewMode('FULL');
                setSelectedNode(null);
                setSelectedEdge(null);
                setPinnedPathId(null);
                setTimeout(() => reactFlowInstance.current?.fitView({ padding: 0.2 }), 80);
              }}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded font-bold uppercase transition-all ${
                viewMode === 'FULL'
                  ? 'bg-[#181818] text-[#00FF00] border border-[#00FF00]/40'
                  : 'text-[#888888] hover:text-white'
              }`}
            >
              <Eye className="h-3.5 w-3.5" />
              <span>Full Provenance</span>
            </button>
          </div>

          {/* Strict Count Badge */}
          {viewMode === 'FOCUS' ? (
            <div className="flex items-center gap-1.5 px-3 py-1 bg-[#181818] border border-[#00FF00]/30 rounded font-mono text-[11px] text-[#AAAAAA]">
              <CheckCircle2 className="h-3.5 w-3.5 text-[#00FF00]" />
              <span>Investigation Focus: <strong className="text-white">{focusData.nodes.length}</strong> of <span className="text-[#888888]">{focusData.totalNodesCount} nodes</span></span>
              {focusData.reductionPercent > 0 && (
                <span className="px-1.5 py-0.2 bg-[#00FF00]/10 text-[#00FF00] rounded font-bold border border-[#00FF00]/30 text-[10px]">
                  {focusData.reductionPercent}% fewer nodes shown
                </span>
              )}
            </div>
          ) : (
            <div className="flex items-center gap-1.5 px-3 py-1 bg-[#141414] border border-[#222222] rounded font-mono text-[11px] text-[#888888]">
              <span>Full Provenance: <strong className="text-white">{nodesData.length}</strong> nodes &bull; <strong className="text-white">{edgesData.length}</strong> edges</span>
            </div>
          )}
        </div>

        {/* Right: Quick Search & Narrative Toggle */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {viewMode === 'FOCUS' && focusData.storySteps.length > 0 && (
            <button
              onClick={() => setShowStoryNarrative(prev => !prev)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded font-mono text-[11px] border transition-colors ${
                showStoryNarrative 
                  ? 'bg-[#181818] text-[#00FF00] border-[#00FF00]/40 font-bold' 
                  : 'bg-[#101010] text-[#888888] border-[#222222] hover:text-white'
              }`}
            >
              <BookOpen className="h-3.5 w-3.5" />
              <span>{showStoryNarrative ? 'Hide Narrative' : 'Investigation Story'}</span>
            </button>
          )}

          {/* Quick Find Input */}
          <div className="relative">
            <Search className="h-3.5 w-3.5 absolute left-2.5 top-2 text-[#666666]" />
            <input
              type="text"
              placeholder="Find indicator / IP / app..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#101010] border border-[#222222] pl-8 pr-3 py-1 rounded text-xs text-white font-mono placeholder:text-[#555555] focus:outline-none focus:border-[#00FF00] w-48 sm:w-56"
            />
            {searchQuery && (
              <button 
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1.5 text-[#888888] hover:text-white"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* "WHY THIS PATH?" INVESTIGATION NARRATIVE STRIP */}
      {/* ===================================================================== */}
      {viewMode === 'FOCUS' && showStoryNarrative && focusData.storySteps.length > 0 && (
        <div className="z-10 bg-[#0A0A0A] border-b border-[#222222] px-4 py-2 flex items-center gap-2 overflow-x-auto text-[11px] font-mono shrink-0">
          <span className="text-[#00FF00] font-bold uppercase tracking-wider flex items-center gap-1 shrink-0">
            <BookOpen className="h-3.5 w-3.5" />
            <span>Investigation Story:</span>
          </span>

          <div className="flex items-center gap-2 flex-nowrap">
            {focusData.storySteps.map((step, idx) => (
              <React.Fragment key={step.stepNumber}>
                <button
                  onClick={() => handleSelectStoryStep(step.nodeId)}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded border transition-all shrink-0 text-left ${
                    selectedNode?.node_id === step.nodeId
                      ? 'bg-[#181818] border-[#00FF00] text-white shadow-[0_0_8px_rgba(0,255,0,0.25)]'
                      : 'bg-[#101010] border-[#222222] text-[#AAAAAA] hover:text-white hover:border-[#333333]'
                  }`}
                  title={step.description}
                >
                  <span className="h-4 w-4 rounded-full bg-[#181818] border border-[#333333] flex items-center justify-center text-[9px] text-[#00FF00] font-bold">
                    {step.stepNumber}
                  </span>
                  <span className="font-bold text-white text-[10px]">{step.title}</span>
                </button>
                {idx < focusData.storySteps.length - 1 && (
                  <ChevronRight className="h-3.5 w-3.5 text-[#444444] shrink-0" />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* NO CROSS-ARTIFACT CORRELATION BANNER */}
      {/* ===================================================================== */}
      {viewMode === 'FOCUS' && !focusData.hasCorrelations && nodesData.length > 0 && (
        <div className="z-10 bg-[#141006] border-b border-[#FF8800]/40 px-4 py-1.5 flex items-center gap-2 text-xs font-mono text-[#FF8800]">
          <Info className="h-4 w-4 shrink-0 text-[#FF8800]" />
          <span>
            <strong>NO CROSS-ARTIFACT CORRELATION:</strong> Static and network evidence were analyzed independently. No corroborated relationship was established.
          </span>
        </div>
      )}

      {/* ===================================================================== */}
      {/* GRAPH CANVAS & OVERLAYS */}
      {/* ===================================================================== */}
      <div className="relative flex-1 bg-[#000000]">
        <style>{`
          .react-flow__attribution {
            display: none !important;
          }
          .react-flow__controls {
            background: #141414 !important;
            border: 1px solid #333333 !important;
            border-radius: 6px !important;
            box-shadow: 0 4px 14px rgba(0, 0, 0, 0.6) !important;
            overflow: hidden !important;
          }
          .react-flow__controls-button {
            background: #141414 !important;
            border-bottom: 1px solid #242424 !important;
            fill: #E0E0E0 !important;
            color: #E0E0E0 !important;
            width: 28px !important;
            height: 28px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            transition: all 0.15s ease !important;
          }
          .react-flow__controls-button:hover {
            background: #242424 !important;
            fill: #00FF00 !important;
            color: #00FF00 !important;
          }
          .react-flow__controls-button svg {
            max-width: 14px !important;
            max-height: 14px !important;
            fill: currentColor !important;
          }
          .react-flow__controls-button:last-child {
            border-bottom: none !important;
          }
        `}</style>

        {/* Compact Collapsible Legend (Positioned to the right of zoom controls) */}
        <div className="absolute bottom-2.5 left-12 z-10 font-mono">
          {showLegend ? (
            <div className="bg-[#101010]/95 backdrop-blur-sm border border-[#222222] p-2.5 rounded text-[10px] space-y-1.5 shadow-xl max-w-sm">
              <div className="font-bold text-white uppercase tracking-wider flex items-center justify-between pb-1 border-b border-[#222222]">
                <span className="flex items-center gap-1.5"><Info className="h-3 w-3 text-[#00FF00]" /> Graph Legend</span>
                <button 
                  onClick={() => setShowLegend(false)}
                  className="text-[#888888] hover:text-white text-[9px] px-1 bg-[#181818] rounded border border-[#333333]"
                >
                  Collapse ▴
                </button>
              </div>

              <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[9px]">
                <span className="flex items-center gap-1 text-[#00FF00]"><span className="h-2 w-2 rounded-full bg-[#00FF00]"></span> Application</span>
                <span className="flex items-center gap-1 text-[#A78BFA]"><span className="h-2 w-2 rounded-full bg-[#A78BFA]"></span> Permission</span>
                <span className="flex items-center gap-1 text-[#BB88FF]"><span className="h-2 w-2 rounded-full bg-[#BB88FF]"></span> Correlated IP</span>
                <span className="flex items-center gap-1 text-[#00FF00]"><span className="h-2 w-2 rounded-full bg-[#00FF00]"></span> Network Event</span>
                <span className="flex items-center gap-1 text-[#FF3333]"><span className="h-2 w-2 rounded-full bg-[#FF3333]"></span> Threat Intel</span>
              </div>

              <div className="flex items-center gap-3 pt-1 border-t border-[#222222] text-[9px] flex-wrap">
                <span className="flex items-center gap-1 text-[#00FF00]"><span className="w-3 h-0.5 bg-[#00FF00]"></span> Observed</span>
                <span className="flex items-center gap-1 text-[#FF8800]"><span className="w-3 h-0.5 border-b-2 border-dashed border-[#FF8800]"></span> Correlated</span>
                <span className="flex items-center gap-1 text-[#A78BFA]"><span className="w-3 h-0.5 border-b-2 border-dashed border-[#A78BFA]"></span> Supporting</span>
              </div>
            </div>
          ) : (
            <button
              onClick={() => setShowLegend(true)}
              className="flex items-center gap-1.5 bg-[#101010]/90 backdrop-blur-sm border border-[#222222] hover:border-[#00FF00]/40 px-2.5 py-1 rounded text-[10px] text-[#AAAAAA] hover:text-white shadow-md transition-all"
            >
              <Info className="h-3 w-3 text-[#00FF00]" />
              <span>Legend ▾</span>
            </button>
          )}
        </div>

        {/* Active Path Focus Indicator Banner */}
        {highlightedNodeIds && (
          <div className="absolute top-4 left-1/2 -translate-x-1/2 z-10 bg-[#101010]/95 border border-[#00FF00]/50 px-4 py-1.5 rounded-full shadow-[0_0_20px_rgba(0,255,0,0.25)] flex items-center gap-3 font-mono text-xs">
            <span className="flex items-center gap-1.5 text-[#00FF00] font-bold text-[11px]">
              <Zap className="h-3.5 w-3.5 text-[#00FF00] animate-pulse" />
              <span>Tracing Active Evidence Chain ({highlightedNodeIds.size} nodes highlighted)</span>
            </span>
            <button
              onClick={onPaneClick}
              className="text-[#888888] hover:text-white flex items-center gap-1 pl-2 border-l border-[#333333] text-[10px]"
            >
              <X className="h-3 w-3" />
              <span>Reset Selection</span>
            </button>
          </div>
        )}

        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          nodeTypes={nodeTypes}
          onNodeClick={onNodeClick}
          onEdgeClick={onEdgeClick}
          onPaneClick={onPaneClick}
          onInit={handleInitFlow}
          fitView
          minZoom={0.2}
          maxZoom={2.0}
          className="bg-[#000000]"
        >
          <Controls position="bottom-left" showInteractive={false} className="m-2.5" />
          <Background color="#161616" gap={28} size={1} />
          {viewMode === 'FULL' && (
            <MiniMap 
              nodeColor={(n) => {
                const t = n.data?.node_type;
                if (t === 'APPLICATION' || t === 'DNS_EVENT' || t === 'NETWORK_EVENT') return '#00FF00';
                if (t === 'DOMAIN' || t === 'PERMISSION' || t === 'CAPABILITY') return '#FF8800';
                if (t === 'IP') return '#BB88FF';
                if (t === 'THREAT_INTEL') return '#FF3333';
                return '#00FF00';
              }}
              className="bg-[#101010] border border-[#222222] rounded" 
            />
          )}
        </ReactFlow>

        {/* ===================================================================== */}
        {/* INSPECTION DRAWER - NODE */}
        {/* ===================================================================== */}
        {selectedNode && (
          <div className="absolute top-3 right-3 z-20 w-84 max-h-[90%] overflow-y-auto bg-[#0A0A0A]/95 backdrop-blur-md border border-[#00FF00]/40 rounded-lg p-4 shadow-2xl space-y-3 font-mono text-xs">
            <div className="flex justify-between items-start border-b border-[#222222] pb-2">
              <div>
                <span className="text-[9px] font-bold uppercase tracking-wider text-[#00FF00] block">
                  Node Provenance Details
                </span>
                <h4 className="font-bold text-white text-sm select-all">{selectedNode.label}</h4>
              </div>
              <button onClick={() => setSelectedNode(null)} className="text-[#888888] hover:text-white p-1">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-2 text-[11px]">
              <div className="flex justify-between">
                <div>
                  <span className="text-[#666666] text-[10px] block">NODE TYPE</span>
                  <span className="text-white font-bold">{selectedNode.node_type}</span>
                </div>
                <div>
                  <span className="text-[#666666] text-[10px] block">PROVENANCE COLUMN</span>
                  <span className="text-[#00FF00] font-bold">Column {getFocusColumn(selectedNode.node_type) + 1}</span>
                </div>
              </div>

              <div>
                <span className="text-[#666666] text-[10px] block">ENTITY REFERENCE</span>
                <span className="text-slate-300 break-all select-all font-mono">{selectedNode.entity_reference}</span>
              </div>

              {selectedNode.timestamp && (
                <div>
                  <span className="text-[#666666] text-[10px] block">TIMESTAMP</span>
                  <span className="text-slate-300">{new Date(selectedNode.timestamp).toLocaleString()}</span>
                </div>
              )}

              {/* Action: Focus on Connected Path */}
              <div className="space-y-1.5 pt-1">
                <button
                  onClick={() => handleTogglePathPin(selectedNode.node_id)}
                  className={`w-full py-1.5 px-3 rounded flex items-center justify-center gap-1.5 font-bold uppercase text-[10px] transition-colors ${
                    pinnedPathId === selectedNode.node_id
                      ? 'bg-[#00FF00] text-black shadow-[0_0_10px_rgba(0,255,0,0.3)]'
                      : 'bg-[#181818] hover:bg-[#222222] text-[#00FF00] border border-[#00FF00]/40'
                  }`}
                >
                  <Focus className="h-3.5 w-3.5" />
                  <span>{pinnedPathId === selectedNode.node_id ? 'Release Path Highlight' : 'Highlight Connected Path'}</span>
                </button>

                {viewMode === 'FULL' && (
                  <button
                    onClick={() => handleFocusOnPath(selectedNode.node_id)}
                    className="w-full py-1.5 px-3 rounded flex items-center justify-center gap-1.5 font-bold uppercase text-[10px] bg-[#00FF00]/15 hover:bg-[#00FF00]/25 text-[#00FF00] border border-[#00FF00]/50 transition-colors"
                  >
                    <Zap className="h-3.5 w-3.5" />
                    <span>Focus On This Path</span>
                  </button>
                )}
              </div>

              <div>
                <span className="text-[#666666] text-[10px] block mb-1">METADATA & OBSERVATIONS</span>
                <div className="bg-[#101010] p-2 rounded border border-[#222222] text-[10px] space-y-1 text-slate-400 max-h-40 overflow-y-auto">
                  {Object.entries(selectedNode.metadata || {}).map(([k, v]) => (
                    <div key={k} className="flex justify-between gap-2">
                      <span className="text-[#666666] uppercase">{k}:</span>
                      <span className="text-slate-200 truncate select-all">{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================== */}
        {/* INSPECTION DRAWER - EDGE */}
        {/* ===================================================================== */}
        {selectedEdge && (
          <div className="absolute top-3 right-3 z-20 w-84 max-h-[90%] overflow-y-auto bg-[#0A0A0A]/95 backdrop-blur-md border border-[#FF8800]/50 rounded-lg p-4 shadow-2xl space-y-3 font-mono text-xs">
            <div className="flex justify-between items-start border-b border-[#222222] pb-2">
              <div>
                <span className="text-[9px] font-bold uppercase tracking-wider text-[#FF8800] block">
                  Edge Relationship
                </span>
                <h4 className="font-bold text-white text-sm">{selectedEdge.relationship_type}</h4>
              </div>
              <button onClick={() => setSelectedEdge(null)} className="text-[#888888] hover:text-white p-1">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-2 text-[11px]">
              <div className="flex justify-between items-center">
                <div>
                  <span className="text-[#666666] text-[10px] block">CLASSIFICATION</span>
                  <span className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${
                    selectedEdge.relationship_class === 'OBSERVED' ? 'bg-[#00FF00]/15 text-[#00FF00] border border-[#00FF00]/40' :
                    selectedEdge.relationship_class === 'CORRELATED' ? 'bg-[#FF8800]/15 text-[#FF8800] border border-[#FF8800]/40' :
                    'bg-[#BB88FF]/15 text-[#BB88FF] border border-[#BB88FF]/40'
                  }`}>
                    {selectedEdge.relationship_class}
                  </span>
                </div>
                <div>
                  <span className="text-[#666666] text-[10px] block">STRENGTH</span>
                  <span className="text-white font-bold uppercase">{selectedEdge.strength}</span>
                </div>
              </div>

              <div>
                <span className="text-[#666666] text-[10px] block mb-1">REASON / EVIDENCE LINK</span>
                <p className="text-slate-200 bg-[#101010] p-2.5 rounded border border-[#222222] text-[11px] leading-relaxed">
                  {selectedEdge.reason}
                </p>
              </div>

              {/* Action: Focus on Edge Path */}
              <button
                onClick={() => handleTogglePathPin(selectedEdge.edge_id)}
                className={`w-full py-1.5 px-3 rounded flex items-center justify-center gap-1.5 font-bold uppercase text-[10px] transition-colors ${
                  pinnedPathId === selectedEdge.edge_id
                    ? 'bg-[#FF8800] text-black shadow-[0_0_10px_rgba(255,136,0,0.3)]'
                    : 'bg-[#181818] hover:bg-[#222222] text-[#FF8800] border border-[#FF8800]/40'
                }`}
              >
                <Focus className="h-3.5 w-3.5" />
                <span>{pinnedPathId === selectedEdge.edge_id ? 'Release Correlation Focus' : 'Trace Supporting Chain'}</span>
              </button>

              {selectedEdge.supporting_evidence_ids && selectedEdge.supporting_evidence_ids.length > 0 && (
                <div>
                  <span className="text-[#666666] text-[10px] block mb-1">SUPPORTING EVIDENCE</span>
                  <div className="space-y-1">
                    {selectedEdge.supporting_evidence_ids.map((id, idx) => (
                      <div key={idx} className="flex items-center gap-1 text-[10px] text-[#00FF00] bg-[#101010] px-2 py-1 rounded border border-[#222222]">
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        <span className="truncate select-all">{id}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AttackGraphCanvas;
