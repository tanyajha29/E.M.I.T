import React, { useEffect, useState } from 'react';
import { apiService, AnalysisRun } from '../services/api';
import { 
  Cpu, 
  RefreshCw, 
  Search, 
  SlidersHorizontal,
  Loader2,
  AlertTriangle
} from 'lucide-react';

const Analysis: React.FC = () => {
  const [runs, setRuns] = useState<(AnalysisRun & { caseName: string })[]>([]);
  
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(false);

  // Filters state
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');

  const fetchGlobalRuns = async (isSilent: boolean = false) => {
    try {
      if (!isSilent) setLoading(true);
      else setRefreshing(true);
      setError(false);

      const caseList = await apiService.getCases();

      if (caseList.length > 0) {
        const promises = caseList.map(async (c) => {
          const runList = await apiService.getAnalysesForCase(c.case_id).catch(() => [] as AnalysisRun[]);
          return runList.map(run => ({
            ...run,
            caseName: c.name
          }));
        });
        const results = await Promise.all(promises);
        setRuns(results.flat());
      } else {
        setRuns([]);
      }
    } catch (err) {
      console.error('Failed to load global analysis runs:', err);
      setError(true);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchGlobalRuns();
  }, []);

  const filteredRuns = runs.filter(run => {
    const matchSearch = run.caseName.toLowerCase().includes(searchTerm.toLowerCase()) || 
      run.analysis_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchStatus = statusFilter === 'ALL' || run.status === statusFilter;
    const matchType = typeFilter === 'ALL' || run.analysis_type === typeFilter;
    return matchSearch && matchStatus && matchType;
  });

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
        <span className="text-sm font-semibold tracking-wider text-slate-400 uppercase">Resolving Global Orchestrator Runs...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="border border-red-950 bg-red-950/20 p-6 rounded flex items-start gap-4">
        <AlertTriangle className="h-6 w-6 text-red-500 shrink-0 mt-0.5" />
        <div>
          <h3 className="text-md font-bold text-red-400 uppercase tracking-wider">Connection Failure</h3>
          <p className="text-sm text-slate-400 mt-1">Unable to gather orchestration lists from the FastAPI server.</p>
          <button 
            onClick={() => fetchGlobalRuns()}
            className="mt-4 px-4 py-2 border border-red-800 text-red-400 hover:bg-red-900/20 text-xs font-bold uppercase rounded transition-colors"
          >
            Retry Fetch
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header toolbar */}
      <div className="flex justify-between items-center">
        <div>
          <p className="text-xs font-bold text-slate-500 uppercase tracking-widest">Global Pipeline Tracking</p>
        </div>
        <button
          onClick={() => fetchGlobalRuns(true)}
          disabled={refreshing}
          className="flex items-center gap-2 px-3 py-2 border border-slate-800 hover:bg-slate-800 text-slate-300 disabled:text-slate-600 text-xs font-bold uppercase tracking-wider rounded transition-all"
        >
          <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col md:flex-row gap-4 items-center">
        {/* Search */}
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-2.5 h-4.5 w-4.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by case file name or run ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded focus:outline-none focus:border-cyan-500 transition-colors placeholder:text-slate-650"
          />
        </div>

        {/* Filters Selects */}
        <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
          {/* Status */}
          <div className="flex items-center gap-2 w-full">
            <SlidersHorizontal className="h-4 w-4 text-slate-500 shrink-0" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 px-3 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-cyan-500 transition-colors cursor-pointer"
            >
              <option value="ALL">ALL STATUSES</option>
              <option value="PENDING">PENDING</option>
              <option value="COMPLETED">COMPLETED</option>
              <option value="PARTIAL">PARTIAL</option>
              <option value="FAILED">FAILED</option>
            </select>
          </div>

          {/* Type */}
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="w-full sm:w-32 bg-slate-950 border border-slate-800 px-3 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-cyan-500 transition-colors cursor-pointer"
          >
            <option value="ALL">ALL TYPES</option>
            <option value="APK">APK STATIC</option>
            <option value="PCAP">PCAP NET</option>
          </select>
        </div>
      </div>

      {/* Runs List Table */}
      {filteredRuns.length > 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900 px-6 py-3 text-slate-400 uppercase tracking-wider">
                  <th className="p-4 font-semibold">Run ID</th>
                  <th className="p-4 font-semibold">Case Name</th>
                  <th className="p-4 font-semibold">Pipeline</th>
                  <th className="p-4 font-semibold">Stage</th>
                  <th className="p-4 font-semibold">Execution Status</th>
                  <th className="p-4 font-semibold">Timestamps</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850/40 font-mono text-slate-300">
                {filteredRuns.map((run) => (
                  <tr key={run.analysis_id} className="hover:bg-slate-800/10 transition-colors">
                    <td className="p-4 font-semibold text-cyan-400 select-all">{run.analysis_id.slice(0, 8)}...</td>
                    <td className="p-4 font-semibold">{run.caseName}</td>
                    <td className="p-4">
                      <span className="px-2 py-0.5 border border-cyan-800/40 bg-cyan-950/20 text-cyan-400 text-[10px] rounded font-bold">
                        {run.analysis_type}
                      </span>
                    </td>
                    <td className="p-4 text-slate-400 font-bold uppercase">{run.current_stage}</td>
                    <td className="p-4">
                      <span className={`inline-block px-2.5 py-0.5 rounded border text-[9px] font-bold ${
                        run.status === 'COMPLETED'
                          ? 'border-emerald-850 bg-emerald-950/25 text-emerald-400'
                          : run.status === 'PARTIAL'
                            ? 'border-amber-850 bg-amber-950/25 text-amber-400'
                            : run.status === 'FAILED'
                              ? 'border-rose-850 bg-rose-950/25 text-rose-500'
                              : 'border-slate-800 text-slate-500 animate-pulse'
                      }`}>
                        {run.status}
                      </span>
                    </td>
                    <td className="p-4 text-slate-500 text-[11px] space-y-0.5">
                      <div className="flex justify-between gap-4"><span className="text-slate-600">ST:</span> <span>{new Date(run.started_at).toLocaleString()}</span></div>
                      {run.completed_at && (
                        <div className="flex justify-between gap-4"><span className="text-slate-600">ED:</span> <span>{new Date(run.completed_at).toLocaleString()}</span></div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="py-20 text-center border border-dashed border-slate-800 rounded bg-slate-900/10">
          <Cpu className="h-10 w-10 text-slate-700 mx-auto mb-3" />
          <p className="text-xs text-slate-500 uppercase tracking-widest">No matching pipeline runs found</p>
        </div>
      )}
    </div>
  );
};

export default Analysis;
