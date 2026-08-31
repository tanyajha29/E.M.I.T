import React, { useEffect, useState } from 'react';
import { apiService, Case, AttackGraphResponse } from '../services/api';
import { AttackGraphCanvas } from '../components/AttackGraphCanvas';
import { Loader2, AlertTriangle, RefreshCw, Share2 } from 'lucide-react';

export const AttackGraph: React.FC = () => {
  const [cases, setCases] = useState<Case[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [graphData, setGraphData] = useState<AttackGraphResponse>({ nodes: [], edges: [] });
  
  const [loading, setLoading] = useState(true);
  const [graphLoading, setGraphLoading] = useState(false);
  const [error, setError] = useState(false);

  useEffect(() => {
    const fetchCases = async () => {
      try {
        setLoading(true);
        setError(false);
        const data = await apiService.getCases();
        setCases(data);
        if (data.length > 0) {
          setSelectedCaseId(data[0].case_id);
        }
      } catch (err) {
        console.error('Failed to load cases in attack graph:', err);
        setError(true);
      } finally {
        setLoading(false);
      }
    };

    fetchCases();
  }, []);

  useEffect(() => {
    if (!selectedCaseId) {
      setGraphData({ nodes: [], edges: [] });
      return;
    }

    const fetchGraph = async () => {
      try {
        setGraphLoading(true);
        const res = await apiService.getGraphForCase(selectedCaseId);
        setGraphData(res);
      } catch (err) {
        console.error('Failed to fetch attack graph:', err);
        setGraphData({ nodes: [], edges: [] });
      } finally {
        setGraphLoading(false);
      }
    };

    fetchGraph();
  }, [selectedCaseId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
        <span className="text-sm font-semibold tracking-wider text-slate-400 uppercase">Loading Graph Workbench...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="border border-rose-950 bg-rose-950/20 p-6 rounded flex items-start gap-4">
        <AlertTriangle className="h-6 w-6 text-rose-500 shrink-0 mt-0.5" />
        <div>
          <h3 className="text-md font-bold text-rose-400 uppercase tracking-wider">Canvas Error</h3>
          <p className="text-sm text-slate-400 mt-1">Unable to initialize graphic network. Check E.M.I.T backend server state.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 flex flex-col h-[calc(100vh-10rem)]">
      {/* Selection Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Share2 className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Attack Chain Provenance Graph</h3>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">Interactive evidence-backed graph showing nodes, relationships, and chronological sequence.</p>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          <select
            value={selectedCaseId}
            onChange={(e) => setSelectedCaseId(e.target.value)}
            className="w-full sm:w-64 bg-slate-950 border border-slate-800 px-3 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="">SELECT INVESTIGATION CASE...</option>
            {cases.map(c => (
              <option key={c.case_id} value={c.case_id}>{c.name}</option>
            ))}
          </select>

          {selectedCaseId && (
            <button
              onClick={() => {
                setGraphLoading(true);
                apiService.getGraphForCase(selectedCaseId)
                  .then(setGraphData)
                  .finally(() => setGraphLoading(false));
              }}
              title="Refresh Graph"
              className="p-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
            >
              <RefreshCw className={`h-4 w-4 ${graphLoading ? 'animate-spin' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* React Flow Canvas Container */}
      <div className="flex-1 min-h-[400px]">
        {graphLoading ? (
          <div className="flex flex-col items-center justify-center h-full bg-slate-950 border border-slate-800 rounded-lg gap-3">
            <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">Generating Case Attack Graph...</span>
          </div>
        ) : (
          <AttackGraphCanvas
            nodesData={graphData.nodes}
            edgesData={graphData.edges}
            height="100%"
          />
        )}
      </div>
    </div>
  );
};

export default AttackGraph;
