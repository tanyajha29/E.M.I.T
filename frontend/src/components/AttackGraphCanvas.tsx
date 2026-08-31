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
          bgClass: 'bg-emerald-950/80',
          borderClass: 'border-emerald-500',
          textClass: 'text-emerald-300',
          badgeClass: 'bg-emerald-900/60 text-emerald-300 border-emerald-700/60'
        };
      case 'DOMAIN':
        return {
          icon: Globe,
          bgClass: 'bg-amber-950/80',
          borderClass: 'border-amber-500',
          textClass: 'text-amber-300',
          badgeClass: 'bg-amber-900/60 text-amber-300 border-amber-700/60'
        };
      case 'IP':
        return {
          icon: Server,
          bgClass: 'bg-sky-950/80',
          borderClass: 'border-sky-500',
          textClass: 'text-sky-300',
          badgeClass: 'bg-sky-900/60 text-sky-300 border-sky-700/60'
        };
      case 'CAPABILITY':
      case 'PERMISSION':
      case 'API':
        return {
          icon: ShieldAlert,
          bgClass: 'bg-purple-950/80',
          borderClass: 'border-purple-500',
          textClass: 'text-purple-300',
          badgeClass: 'bg-purple-900/60 text-purple-300 border-purple-700/60'
        };
      case 'DNS_EVENT':
      case 'NETWORK_EVENT':
        return {
          icon: Activity,
          bgClass: 'bg-cyan-950/80',
          borderClass: 'border-cyan-500',
          textClass: 'text-cyan-300',
          badgeClass: 'bg-cyan-900/60 text-cyan-300 border-cyan-700/60'
        };
      case 'THREAT_INTEL':
        return {
          icon: AlertTriangle,
          bgClass: 'bg-rose-950/80',
          borderClass: 'border-rose-500',
          textClass: 'text-rose-300',
          badgeClass: 'bg-rose-900/60 text-rose-300 border-rose-700/60'
        };
      default:
        return {
          icon: Layers,
          bgClass: 'bg-slate-900',
          borderClass: 'border-slate-700',
          textClass: 'text-slate-300',
          badgeClass: 'bg-slate-800 text-slate-400 border-slate-700'
        };
    }
  }, [data.node_type]);

  return (
    <div
      className={`px-3.5 py-2.5 rounded-lg border-2 shadow-lg min-w-[190px] max-w-[280px] transition-all cursor-pointer ${bgClass} ${borderClass} ${
        isSelected ? 'ring-2 ring-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.4)]' : ''
      }`}
    >
      <Handle type="target" position={Position.Left} className="w-2.5 h-2.5 bg-slate-400 border border-slate-900" />
      
      <div className="flex items-center justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-1.5">
          <Icon className={`h-4 w-4 ${textClass} shrink-0`} />
          <span className={`text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded border ${badgeClass}`}>
            {data.node_type}
          </span>
        </div>
        {data.timestamp && (
          <span className="text-[9px] text-slate-400 font-mono">
            {new Date(data.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
          </span>
        )}
      </div>

      <div className="font-mono text-xs font-bold text-slate-100 truncate" title={data.label}>
        {data.label}
      </div>

      <Handle type="source" position={Position.Right} className="w-2.5 h-2.5 bg-slate-400 border border-slate-900" />
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

      let stroke = '#64748b'; // default slate (OBSERVED)
      let strokeDasharray: string | undefined = undefined;
      let strokeWidth = isSelected ? 3 : 1.5;

      if (edge.relationship_class === 'INFERRED') {
        stroke = '#a855f7'; // purple
        strokeDasharray = '4,4';
      } else if (edge.relationship_class === 'CORRELATED') {
        stroke = '#f59e0b'; // amber
        strokeDasharray = '6,4';
        strokeWidth = isSelected ? 3.5 : 2;
      } else if (edge.relationship_class === 'OBSERVED') {
        stroke = '#06b6d4'; // cyan
      }

      return {
        id: edge.edge_id,
        source: edge.source_node_id,
        target: edge.target_node_id,
        animated: edge.relationship_class === 'INFERRED' || edge.relationship_type === 'CONNECTS_TO',
        label: edge.relationship_type,
        labelStyle: { fill: stroke, fontSize: 9, fontFamily: 'monospace', fontWeight: 600 },
        labelBgStyle: { fill: '#090d16', fillOpacity: 0.85, rx: 4, ry: 4 },
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
        className="flex flex-col items-center justify-center p-8 text-center bg-slate-950 border border-dashed border-slate-800 rounded-lg"
        style={{ height }}
      >
        <GitCommit className="h-10 w-10 text-slate-700 mb-3" />
        <h4 className="text-sm font-bold text-slate-300 uppercase tracking-widest">No Attack Graph Data</h4>
        <p className="text-xs text-slate-500 max-w-md mt-2">
          Run APK or PCAP analysis pipeline to extract evidence entities, build correlations, and generate graph nodes.
        </p>
      </div>
    );
  }

  return (
    <div className="relative border border-slate-800 rounded-lg overflow-hidden bg-slate-950" style={{ height }}>
      {/* Legend Header */}
      <div className="absolute top-3 left-3 z-10 bg-slate-900/90 backdrop-blur-sm border border-slate-800 p-2.5 rounded-lg text-[10px] space-y-2 shadow-md">
        <div className="font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
          <Info className="h-3.5 w-3.5 text-cyan-400" /> Graph Legend
        </div>
        <div className="grid grid-cols-3 gap-x-4 gap-y-1.5 font-mono">
          <span className="flex items-center gap-1 text-emerald-400"><span className="h-2 w-2 rounded-full bg-emerald-500"></span> Application</span>
          <span className="flex items-center gap-1 text-amber-400"><span className="h-2 w-2 rounded-full bg-amber-500"></span> Domain</span>
          <span className="flex items-center gap-1 text-sky-400"><span className="h-2 w-2 rounded-full bg-sky-500"></span> IP</span>
          <span className="flex items-center gap-1 text-purple-400"><span className="h-2 w-2 rounded-full bg-purple-500"></span> Capability</span>
          <span className="flex items-center gap-1 text-cyan-400"><span className="h-2 w-2 rounded-full bg-cyan-500"></span> Event</span>
          <span className="flex items-center gap-1 text-rose-400"><span className="h-2 w-2 rounded-full bg-rose-500"></span> Threat Intel</span>
        </div>
        <div className="flex items-center gap-3 pt-1 border-t border-slate-800 font-mono text-[9px]">
          <span className="flex items-center gap-1 text-cyan-400"><span className="w-3 h-0.5 bg-cyan-400"></span> Observed</span>
          <span className="flex items-center gap-1 text-amber-400"><span className="w-3 h-0.5 border-b border-dashed border-amber-400"></span> Correlated</span>
          <span className="flex items-center gap-1 text-purple-400"><span className="w-3 h-0.5 border-b border-dotted border-purple-400"></span> Inferred</span>
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
        className="bg-slate-950"
      >
        <Controls className="bg-slate-900 border border-slate-800 text-slate-200 fill-slate-200" />
        <Background color="#334155" gap={20} size={1} />
        <MiniMap 
          nodeColor={(n) => {
            const t = n.data?.node_type;
            if (t === 'APPLICATION') return '#10b981';
            if (t === 'DOMAIN') return '#f59e0b';
            if (t === 'IP') return '#0ea5e9';
            if (t === 'THREAT_INTEL') return '#f43f5e';
            return '#06b6d4';
          }}
          className="bg-slate-900 border border-slate-800 rounded" 
        />
      </ReactFlow>

      {/* INSPECTION DRAWER - NODE */}
      {selectedNode && (
        <div className="absolute top-3 right-3 z-20 w-80 max-h-[90%] overflow-y-auto bg-slate-900/95 backdrop-blur border border-cyan-800/60 rounded-lg p-4 shadow-2xl space-y-3 font-mono text-xs">
          <div className="flex justify-between items-start border-b border-slate-800 pb-2">
            <div>
              <span className="text-[9px] font-bold uppercase tracking-wider text-cyan-400 block">Node Details</span>
              <h4 className="font-bold text-slate-100 text-sm">{selectedNode.label}</h4>
            </div>
            <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-200 p-1">
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="space-y-2 text-[11px]">
            <div>
              <span className="text-slate-500 text-[10px] block">NODE TYPE</span>
              <span className="text-slate-200 font-bold">{selectedNode.node_type}</span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px] block">ENTITY REFERENCE</span>
              <span className="text-slate-300 break-all">{selectedNode.entity_reference}</span>
            </div>
            {selectedNode.timestamp && (
              <div>
                <span className="text-slate-500 text-[10px] block">TIMESTAMP</span>
                <span className="text-slate-300">{new Date(selectedNode.timestamp).toLocaleString()}</span>
              </div>
            )}
            <div>
              <span className="text-slate-500 text-[10px] block">METADATA & OBSERVATIONS</span>
              <div className="bg-slate-950 p-2 rounded border border-slate-800 text-[10px] space-y-1 text-slate-400 max-h-40 overflow-y-auto">
                {Object.entries(selectedNode.metadata || {}).map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-2">
                    <span className="text-slate-500">{k}:</span>
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
        <div className="absolute top-3 right-3 z-20 w-80 max-h-[90%] overflow-y-auto bg-slate-900/95 backdrop-blur border border-amber-800/60 rounded-lg p-4 shadow-2xl space-y-3 font-mono text-xs">
          <div className="flex justify-between items-start border-b border-slate-800 pb-2">
            <div>
              <span className="text-[9px] font-bold uppercase tracking-wider text-amber-400 block">Edge Relationship</span>
              <h4 className="font-bold text-slate-100 text-sm">{selectedEdge.relationship_type}</h4>
            </div>
            <button onClick={() => setSelectedEdge(null)} className="text-slate-400 hover:text-slate-200 p-1">
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="space-y-2 text-[11px]">
            <div className="flex justify-between">
              <div>
                <span className="text-slate-500 text-[10px] block">CLASSIFICATION</span>
                <span className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${
                  selectedEdge.relationship_class === 'OBSERVED' ? 'bg-cyan-950 text-cyan-400 border border-cyan-800' :
                  selectedEdge.relationship_class === 'CORRELATED' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                  'bg-purple-950 text-purple-400 border border-purple-800'
                }`}>
                  {selectedEdge.relationship_class}
                </span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">CONFIDENCE</span>
                <span className="text-slate-200 font-bold">{selectedEdge.strength}</span>
              </div>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] block">REASON / EVIDENCE LINK</span>
              <p className="text-slate-300 bg-slate-950 p-2 rounded border border-slate-800 text-[11px] leading-relaxed">
                {selectedEdge.reason}
              </p>
            </div>

            {selectedEdge.supporting_evidence_ids?.length > 0 && (
              <div>
                <span className="text-slate-500 text-[10px] block mb-1">SUPPORTING EVIDENCE</span>
                <div className="space-y-1">
                  {selectedEdge.supporting_evidence_ids.map((id, idx) => (
                    <div key={idx} className="flex items-center gap-1 text-[10px] text-cyan-400 bg-slate-950 px-2 py-1 rounded border border-slate-800">
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
