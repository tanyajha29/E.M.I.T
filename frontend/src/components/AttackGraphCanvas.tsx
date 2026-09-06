import React, { useMemo, useState } from 'react';
import ReactFlow, {
  Controls,
  Background,
  MiniMap,
  Node,
  Edge,
  MarkerType,
  Position,
  Handle,
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
  GitCommit
} from 'lucide-react';

interface AttackGraphCanvasProps {
  nodesData: AttackNode[];
  edgesData: AttackEdge[];
  height?: string;
}

// ---------------------------------------------------------------------------
// CUSTOM NODE RENDERER
// ---------------------------------------------------------------------------
const CustomAttackNode: React.FC<{ data: AttackNode & { selectedNodeId?: string } }> = ({ data }) => {
  const isSelected = data.selectedNodeId === data.node_id;

  const { icon: Icon, bgClass, borderClass, textClass, badgeClass } = useMemo(() => {
    switch (data.node_type) {
      case 'APPLICATION':
        return {
          icon: Cpu,
          bgClass: 'bg-[#001A00]/95',
          borderClass: 'border-[#00FF00]/80 hover:border-[#00FF00] shadow-[0_0_12px_rgba(0,255,0,0.25)]',
          textClass: 'text-[#00FF00]',
          badgeClass: 'bg-[#00FF00]/15 text-[#00FF00] border-[#00FF00]/40'
        };
      case 'DOMAIN':
        return {
          icon: Globe,
          bgClass: 'bg-[#1A0E00]/95',
          borderClass: 'border-[#FF8800]/80 hover:border-[#FF8800] shadow-[0_0_12px_rgba(255,136,0,0.25)]',
          textClass: 'text-[#FF8800]',
          badgeClass: 'bg-[#FF8800]/15 text-[#FF8800] border-[#FF8800]/40'
        };
      case 'IP':
        return {
          icon: Server,
          bgClass: 'bg-[#120024]/95',
          borderClass: 'border-[#BB88FF]/80 hover:border-[#BB88FF] shadow-[0_0_12px_rgba(187,136,255,0.25)]',
          textClass: 'text-[#BB88FF]',
          badgeClass: 'bg-[#BB88FF]/15 text-[#BB88FF] border-[#BB88FF]/40'
        };
      case 'CAPABILITY':
      case 'PERMISSION':
      case 'API':
        return {
          icon: ShieldAlert,
          bgClass: 'bg-[#1A1000]/95',
          borderClass: 'border-[#FF8800]/80 hover:border-[#FF8800] shadow-[0_0_12px_rgba(255,136,0,0.25)]',
          textClass: 'text-[#FF8800]',
          badgeClass: 'bg-[#FF8800]/15 text-[#FF8800] border-[#FF8800]/40'
        };
      case 'DNS_EVENT':
      case 'NETWORK_EVENT':
        return {
          icon: Activity,
          bgClass: 'bg-[#001A00]/95',
          borderClass: 'border-[#00FF00]/80 hover:border-[#00FF00]',
          textClass: 'text-[#00FF00]',
          badgeClass: 'bg-[#00FF00]/15 text-[#00FF00] border-[#00FF00]/40'
        };
      case 'THREAT_INTEL':
        return {
          icon: AlertTriangle,
          bgClass: 'bg-[#220000]/95',
          borderClass: 'border-[#FF3333]/80 hover:border-[#FF3333] shadow-[0_0_12px_rgba(255,51,51,0.25)]',
          textClass: 'text-[#FF3333]',
          badgeClass: 'bg-[#FF3333]/15 text-[#FF3333] border-[#FF3333]/40'
        };
      default:
        return {
          icon: Layers,
          bgClass: 'bg-[#101010]/95',
          borderClass: 'border-[#222222] hover:border-[#444444]',
          textClass: 'text-white',
          badgeClass: 'bg-[#181818] text-[#AAAAAA] border-[#222222]'
        };
    }
  }, [data.node_type]);

  return (
    <div
      className={`px-3.5 py-2.5 rounded border-2 shadow-lg min-w-[190px] max-w-[280px] transition-all cursor-pointer ${bgClass} ${borderClass} ${
        isSelected ? 'ring-2 ring-[#00FF00] shadow-[0_0_16px_rgba(0,255,0,0.5)]' : ''
      }`}
    >
      <Handle type="target" position={Position.Left} className="w-2.5 h-2.5 bg-[#00FF00] border border-black" />
      
      <div className="flex items-center justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-1.5">
          <Icon className={`h-3.5 w-3.5 ${textClass} shrink-0`} />
          <span className={`text-[9px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${badgeClass}`}>
            {data.node_type}
          </span>
        </div>
        {data.timestamp && (
          <span className="text-[9px] text-emit-muted font-mono">
            {new Date(data.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
        )}
      </div>

      <div className="font-mono text-xs font-bold text-slate-100 truncate" title={data.label}>
        {data.label}
      </div>

      <Handle type="source" position={Position.Right} className="w-2.5 h-2.5 bg-slate-400 border border-emit-bg" />
    </div>
  );
};

const nodeTypes = {
  customAttackNode: CustomAttackNode,
};

export const AttackGraphCanvas: React.FC<AttackGraphCanvasProps> = ({
  nodesData,
  edgesData,
  height = '580px'
}) => {
  const [selectedNode, setSelectedNode] = useState<AttackNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<AttackEdge | null>(null);

  // Compute deterministic layout positions
  const { flowNodes, flowEdges } = useMemo(() => {
    // Group nodes by type layer for clean left-to-right attack chain layout
    const layerOrder: Record<string, number> = {
      APPLICATION: 0,
      CAPABILITY: 1,
      PERMISSION: 1,
      API: 1,
      DOMAIN: 2,
      IP: 3,
      DNS_EVENT: 2,
      NETWORK_EVENT: 4,
      THREAT_INTEL: 5,
    };

    const layerBuckets: Record<number, AttackNode[]> = { 0: [], 1: [], 2: [], 3: [], 4: [], 5: [] };

    nodesData.forEach((node) => {
      const layer = layerOrder[node.node_type] ?? 2;
      layerBuckets[layer].push(node);
    });

    const xSpacing = 280;
    const ySpacing = 100;

    const mappedNodes: Node[] = [];

    Object.entries(layerBuckets).forEach(([layerStr, nodesInLayer]) => {
      const layer = parseInt(layerStr, 10);
      const totalInLayer = nodesInLayer.length;
      const startY = -((totalInLayer - 1) * ySpacing) / 2;

      nodesInLayer.forEach((node, idx) => {
        mappedNodes.push({
          id: node.node_id,
          type: 'customAttackNode',
          position: {
            x: layer * xSpacing,
            y: startY + idx * ySpacing,
          },
          data: {
            ...node,
            selectedNodeId: selectedNode?.node_id,
          },
        });
      });
    });

    // Map Edges with styling based on relationship_class
    const mappedEdges: Edge[] = edgesData.map((edge) => {
      const isSelected = selectedEdge?.edge_id === edge.edge_id;

      let stroke = '#00FF00'; // default observed: neon green
      let strokeDasharray: string | undefined = undefined;
      let strokeWidth = isSelected ? 3 : 1.5;

      if (edge.relationship_class === 'INFERRED') {
        stroke = '#BB88FF'; // light purple
        strokeDasharray = '4,4';
      } else if (edge.relationship_class === 'CORRELATED') {
        stroke = '#FF8800'; // vibrant orange
        strokeDasharray = '6,4';
        strokeWidth = isSelected ? 3.5 : 2;
      } else if (edge.relationship_class === 'OBSERVED') {
        stroke = '#00FF00'; // neon green
      }

      return {
        id: edge.edge_id,
        source: edge.source_node_id,
        target: edge.target_node_id,
        animated: edge.relationship_class === 'INFERRED' || edge.relationship_type === 'CONNECTS_TO',
        label: edge.relationship_type,
        labelStyle: { fill: stroke, fontSize: 9, fontFamily: 'JetBrains Mono', fontWeight: 600 },
        labelBgStyle: { fill: '#0A0A0A', fillOpacity: 0.95, rx: 4, ry: 4 },
        labelBgPadding: [4, 2],
        style: {
          stroke,
          strokeWidth,
          strokeDasharray,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: stroke,
          width: 14,
          height: 14,
        },
      };
    });

    return { flowNodes: mappedNodes, flowEdges: mappedEdges };
  }, [nodesData, edgesData, selectedNode, selectedEdge]);

  const onNodeClick = (_: React.MouseEvent, node: Node) => {
    const raw = nodesData.find((n) => n.node_id === node.id);
    setSelectedNode(raw || null);
    setSelectedEdge(null);
  };

  const onEdgeClick = (_: React.MouseEvent, edge: Edge) => {
    const raw = edgesData.find((e) => e.edge_id === edge.id);
    setSelectedEdge(raw || null);
    setSelectedNode(null);
  };

  const onPaneClick = () => {
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  if (nodesData.length === 0) {
    return (
      <div 
        className="flex flex-col items-center justify-center p-8 text-center bg-emit-bg border border-dashed border-emit-border rounded-lg"
        style={{ height }}
      >
        <GitCommit className="h-10 w-10 text-emit-muted mb-3" />
        <h4 className="text-sm font-mono font-bold text-slate-300 uppercase tracking-widest">No Attack Graph Data</h4>
        <p className="text-xs font-mono text-emit-muted max-w-md mt-2">
          Run APK or PCAP analysis pipeline to extract evidence entities, build correlations, and generate graph nodes.
        </p>
      </div>
    );
  }

  return (
    <div className="relative border border-emit-border rounded-lg overflow-hidden bg-emit-bg" style={{ height }}>
      {/* Legend Header */}
      <div className="absolute top-3 left-3 z-10 bg-[#101010]/95 backdrop-blur-sm border border-[#222222] p-3 rounded text-[10px] space-y-2 shadow-lg">
        <div className="font-mono font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
          <Info className="h-3.5 w-3.5 text-[#00FF00]" /> Graph Legend
        </div>
        <div className="grid grid-cols-3 gap-x-4 gap-y-1.5 font-mono">
          <span className="flex items-center gap-1.5 text-[#00FF00]"><span className="h-2 w-2 rounded-full bg-[#00FF00]"></span> Application</span>
          <span className="flex items-center gap-1.5 text-[#FF8800]"><span className="h-2 w-2 rounded-full bg-[#FF8800]"></span> Domain</span>
          <span className="flex items-center gap-1.5 text-[#BB88FF]"><span className="h-2 w-2 rounded-full bg-[#BB88FF]"></span> IP / Capability</span>
          <span className="flex items-center gap-1.5 text-[#00FF00]"><span className="h-2 w-2 rounded-full bg-[#00FF00]"></span> Event</span>
          <span className="flex items-center gap-1.5 text-[#FF3333]"><span className="h-2 w-2 rounded-full bg-[#FF3333]"></span> Threat Intel</span>
        </div>
        <div className="flex items-center gap-3 pt-1.5 border-t border-[#222222] font-mono text-[9px]">
          <span className="flex items-center gap-1 text-[#00FF00]"><span className="w-3 h-0.5 bg-[#00FF00]"></span> Observed</span>
          <span className="flex items-center gap-1 text-[#FF8800]"><span className="w-3 h-0.5 border-b border-dashed border-[#FF8800]"></span> Correlated</span>
          <span className="flex items-center gap-1 text-[#BB88FF]"><span className="w-3 h-0.5 border-b border-dotted border-[#BB88FF]"></span> Inferred</span>
        </div>
      </div>

      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        onPaneClick={onPaneClick}
        fitView
        minZoom={0.2}
        maxZoom={1.8}
        className="bg-[#000000]"
      >
        <Controls className="bg-[#101010] border border-[#222222] text-white fill-white" />
        <Background color="#161616" gap={20} size={1} />
        <MiniMap 
          nodeColor={(n) => {
            const t = n.data?.node_type;
            if (t === 'APPLICATION' || t === 'DNS_EVENT' || t === 'NETWORK_EVENT') return '#00FF00';
            if (t === 'DOMAIN' || t === 'CAPABILITY') return '#FF8800';
            if (t === 'IP') return '#BB88FF';
            if (t === 'THREAT_INTEL') return '#FF3333';
            return '#00FF00';
          }}
          className="bg-[#101010] border border-[#222222] rounded" 
        />
      </ReactFlow>

      {/* INSPECTION DRAWER - NODE */}
      {selectedNode && (
        <div className="absolute top-3 right-3 z-20 w-80 max-h-[90%] overflow-y-auto bg-emit-bg-secondary/95 backdrop-blur border border-emit-violet/50 rounded-lg p-4 shadow-2xl space-y-3 font-mono text-xs">
          <div className="flex justify-between items-start border-b border-emit-border pb-2">
            <div>
              <span className="text-[9px] font-bold uppercase tracking-wider text-emit-violet-light block">Node Details</span>
              <h4 className="font-bold text-white text-sm">{selectedNode.label}</h4>
            </div>
            <button onClick={() => setSelectedNode(null)} className="text-emit-muted hover:text-white p-1">
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="space-y-2 text-[11px]">
            <div>
              <span className="text-emit-muted text-[10px] block">NODE TYPE</span>
              <span className="text-slate-200 font-bold">{selectedNode.node_type}</span>
            </div>
            <div>
              <span className="text-emit-muted text-[10px] block">ENTITY REFERENCE</span>
              <span className="text-slate-300 break-all">{selectedNode.entity_reference}</span>
            </div>
            {selectedNode.timestamp && (
              <div>
                <span className="text-emit-muted text-[10px] block">TIMESTAMP</span>
                <span className="text-slate-300">{new Date(selectedNode.timestamp).toLocaleString()}</span>
              </div>
            )}
            <div>
              <span className="text-emit-muted text-[10px] block">METADATA & OBSERVATIONS</span>
              <div className="bg-emit-bg p-2 rounded border border-emit-border text-[10px] space-y-1 text-slate-400 max-h-40 overflow-y-auto">
                {Object.entries(selectedNode.metadata || {}).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <span className="text-slate-500 uppercase">{k}:</span>
                    <span className="text-slate-300 truncate">{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* INSPECTION DRAWER - EDGE */}
      {selectedEdge && (
        <div className="absolute top-3 right-3 z-20 w-80 max-h-[90%] overflow-y-auto bg-emit-bg-secondary/95 backdrop-blur border border-emit-amber/50 rounded-lg p-4 shadow-2xl space-y-3 font-mono text-xs">
          <div className="flex justify-between items-start border-b border-emit-border pb-2">
            <div>
              <span className="text-[9px] font-bold uppercase tracking-wider text-emit-amber block">Edge Relationship</span>
              <h4 className="font-bold text-white text-sm">{selectedEdge.relationship_type}</h4>
            </div>
            <button onClick={() => setSelectedEdge(null)} className="text-emit-muted hover:text-white p-1">
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="space-y-2 text-[11px]">
            <div className="flex justify-between">
              <div>
                <span className="text-emit-muted text-[10px] block">CLASSIFICATION</span>
                <span className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${
                  selectedEdge.relationship_class === 'OBSERVED' ? 'bg-emit-teal/15 text-emit-teal border border-emit-teal/40' :
                  selectedEdge.relationship_class === 'CORRELATED' ? 'bg-emit-amber/15 text-emit-amber border border-emit-amber/40' :
                  'bg-emit-violet/15 text-emit-violet-light border border-emit-violet/40'
                }`}>
                  {selectedEdge.relationship_class}
                </span>
              </div>
              <div>
                <span className="text-emit-muted text-[10px] block">STRENGTH</span>
                <span className="text-slate-200 font-bold">{selectedEdge.strength}</span>
              </div>
            </div>

            <div>
              <span className="text-emit-muted text-[10px] block">REASON / EVIDENCE LINK</span>
              <p className="text-slate-300 bg-emit-bg p-2 rounded border border-emit-border text-[11px] leading-relaxed">
                {selectedEdge.reason}
              </p>
            </div>

            {selectedEdge.supporting_evidence_ids?.length > 0 && (
              <div>
                <span className="text-emit-muted text-[10px] block mb-1">SUPPORTING EVIDENCE</span>
                <div className="space-y-1">
                  {selectedEdge.supporting_evidence_ids.map((id, idx) => (
                    <div key={idx} className="flex items-center gap-1 text-[10px] text-emit-teal bg-emit-bg px-2 py-1 rounded border border-emit-border">
                      <ExternalLink className="h-3 w-3" />
                      <span className="truncate">{id}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default AttackGraphCanvas;
