import React, { useEffect, useState } from 'react';
import { apiService, Case, AttackGraphResponse } from '../services/api';
import { AttackGraphCanvas } from '../components/AttackGraphCanvas';
import { Loader2, RefreshCw, Share2, Filter } from 'lucide-react';
import { ErrorState } from '../components/ui/ErrorState';
import { useUser } from '../context/UserContext';

export const AttackGraph: React.FC = () => {
  const { currentUser, filterMode, setFilterMode, isCaseAssigned } = useUser();
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
          const assigned = data.filter(c => isCaseAssigned(c.case_id));
          setSelectedCaseId(assigned.length > 0 ? assigned[0].case_id : data[0].case_id);
        }
      } catch (err) {
        console.error('Failed to load cases in attack graph:', err);
        setError(true);
      } finally {
        setLoading(false);
      }
    };

    fetchCases();
  }, [isCaseAssigned]);

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

  const displayedCases = filterMode === 'MY_CASES'
    ? cases.filter(c => isCaseAssigned(c.case_id))
    : cases;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3 font-mono text-white">
        <Loader2 className="h-8 w-8 text-[#00FF00] animate-spin" />
        <span className="text-xs font-semibold tracking-wider text-[#AAAAAA] uppercase">
          Initializing Provenance Graph Canvas...
        </span>
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Attack Graph Store Inaccessible"
        message="Unable to initialize forensic attack graph engine. Check E.M.I.T. backend server state."
      />
    );
  }

  return (
    <div className="space-y-5 flex flex-col h-[calc(100vh-8.5rem)] font-mono text-xs text-white">
      {/* Selection Toolbar */}
      <div className="bg-[#101010] border border-[#222222] rounded p-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <Share2 className="h-4 w-4 text-[#00FF00]" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Attack Chain Provenance Graph
            </h3>
          </div>
          <p className="text-[11px] text-[#AAAAAA] mt-0.5">
            {filterMode === 'MY_CASES' 
              ? `Displaying assigned case graphs for Investigator ${currentUser.name}`
              : 'Displaying provenance graphs across all platform investigations'}
          </p>
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          {/* Scope toggle */}
          <button
            onClick={() => setFilterMode(filterMode === 'MY_CASES' ? 'ALL_CASES' : 'MY_CASES')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 text-xs text-[#AAAAAA] hover:text-[#00FF00] transition-colors"
          >
            <Filter className="h-3 w-3 text-[#00FF00]" />
            <span>{filterMode === 'MY_CASES' ? 'My Assigned' : 'All Cases'}</span>
          </button>

          <select
            value={selectedCaseId}
            onChange={(e) => setSelectedCaseId(e.target.value)}
            className="w-full sm:w-64 bg-[#0A0A0A] border border-[#222222] px-3 py-2 text-white text-xs rounded focus:outline-none focus:border-[#00FF00] cursor-pointer"
          >
            <option value="">SELECT INVESTIGATION CASE...</option>
            {displayedCases.map(c => (
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
              className="p-2 bg-[#181818] hover:bg-[#222222] border border-[#222222] rounded text-[#AAAAAA] hover:text-white transition-colors"
            >
              <RefreshCw className={`h-4 w-4 ${graphLoading ? 'animate-spin text-[#00FF00]' : ''}`} />
            </button>
          )}
        </div>
      </div>

      {/* React Flow Canvas Container */}
      <div className="flex-1 min-h-[400px]">
        {graphLoading ? (
          <div className="flex flex-col items-center justify-center h-full bg-[#000000] border border-[#222222] rounded gap-3">
            <Loader2 className="h-8 w-8 text-[#00FF00] animate-spin" />
            <span className="text-xs font-mono text-[#AAAAAA] uppercase tracking-wider">
              Rendering Case Attack Graph...
            </span>
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
