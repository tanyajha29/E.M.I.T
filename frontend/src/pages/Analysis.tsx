import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiService, AnalysisRun, ProviderExecutionRecord } from '../services/api';
import { 
  RefreshCw, 
  Search, 
  SlidersHorizontal,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  Filter,
  Binary
} from 'lucide-react';
import { StatusBadge } from '../components/ui/StatusBadge';
import { LoadingSkeleton } from '../components/ui/LoadingSkeleton';
import { ErrorState } from '../components/ui/ErrorState';
import { EmptyState } from '../components/ui/EmptyState';
import { useUser } from '../context/UserContext';

export const Analysis: React.FC = () => {
  const { currentUser, filterMode, setFilterMode, isCaseAssigned } = useUser();
  const [runs, setRuns] = useState<(AnalysisRun & { caseName: string })[]>([]);
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);
  
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

  const scopedRuns = filterMode === 'MY_CASES'
    ? runs.filter(r => isCaseAssigned(r.case_id))
    : runs;

  const filteredRuns = scopedRuns.filter(run => {
    const matchSearch = run.caseName.toLowerCase().includes(searchTerm.toLowerCase()) || 
      run.analysis_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchStatus = statusFilter === 'ALL' || run.status === statusFilter;
    const matchType = typeFilter === 'ALL' || run.analysis_type === typeFilter;
    return matchSearch && matchStatus && matchType;
  });

  const toggleExpand = (runId: string) => {
    setExpandedRunId(expandedRunId === runId ? null : runId);
  };

  if (loading) {
    return (
      <div className="space-y-6 font-mono text-white">
        <div className="flex justify-between items-center">
          <div className="h-6 w-52 bg-[#181818] rounded animate-pulse" />
          <div className="h-4 w-40 bg-[#181818] rounded animate-pulse" />
        </div>
        <LoadingSkeleton type="table" rows={6} />
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Analysis Telemetry Inaccessible"
        message="Unable to retrieve global pipeline execution logs from the E.M.I.T. orchestrator."
        onRetry={() => fetchGlobalRuns()}
      />
    );
  }

  return (
    <div className="space-y-6 font-mono text-xs text-white">
      {/* Header Toolbar */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 p-4 rounded bg-[#101010] border border-[#222222]">
        <div>
          <div className="flex items-center gap-2">
            <Binary className="h-4 w-4 text-[#00FF00]" />
            <h2 className="text-base font-bold tracking-wider uppercase text-white">
              Analysis Pipelines
            </h2>
          </div>
          <p className="text-xs text-[#AAAAAA] mt-1">
            {filterMode === 'MY_CASES' 
              ? `Showing analysis jobs for Investigator ${currentUser.name} (${currentUser.badgeId})`
              : 'Global containerized orchestration telemetry and provider execution records'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Scope toggle */}
          <button
            onClick={() => setFilterMode(filterMode === 'MY_CASES' ? 'ALL_CASES' : 'MY_CASES')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 text-xs text-[#AAAAAA] hover:text-[#00FF00] transition-colors"
          >
            <Filter className="h-3 w-3 text-[#00FF00]" />
            <span>{filterMode === 'MY_CASES' ? 'My Assigned' : 'All Cases'}</span>
          </button>

          <button
            onClick={() => fetchGlobalRuns(true)}
            disabled={refreshing}
            className="inline-flex items-center gap-2 px-3.5 py-2 bg-[#181818] hover:bg-[#222222] border border-[#222222] text-white rounded font-bold uppercase text-[11px] transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin text-[#00FF00]' : ''}`} />
            <span>Refresh Feeds</span>
          </button>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="bg-[#101010] border border-[#222222] rounded p-4 flex flex-col md:flex-row gap-4 items-center justify-between">
        {/* Search */}
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-[#666666]" />
          <input
            type="text"
            placeholder="Search by case file name or execution run UUID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#0A0A0A] border border-[#222222] text-white text-xs rounded focus:outline-none focus:border-[#00FF00] transition-colors placeholder:text-[#666666]"
          />
        </div>

        {/* Filter Selects */}
        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          {/* Status Filter */}
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <SlidersHorizontal className="h-3.5 w-3.5 text-[#666666] shrink-0" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full sm:w-36 bg-[#0A0A0A] border border-[#222222] px-2.5 py-2 text-white text-xs rounded focus:outline-none focus:border-[#00FF00] cursor-pointer"
            >
              <option value="ALL">ALL STATUSES</option>
              <option value="PENDING">PENDING</option>
              <option value="ANALYZING">ANALYZING</option>
              <option value="COMPLETED">COMPLETED</option>
              <option value="PARTIAL">PARTIAL</option>
              <option value="FAILED">FAILED</option>
            </select>
          </div>

          {/* Type Filter */}
          <div className="w-full sm:w-auto">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full sm:w-36 bg-emit-bg border border-emit-border px-2.5 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-emit-violet cursor-pointer"
            >
              <option value="ALL">ALL PIPELINES</option>
              <option value="APK">APK STATIC</option>
              <option value="PCAP">PCAP NETWORK</option>
            </select>
          </div>
        </div>
      </div>

      {/* Global Runs Table */}
      {filteredRuns.length > 0 ? (
        <div className="border border-[#222222] rounded overflow-hidden bg-[#101010]">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#222222] bg-[#0A0A0A] text-[#666666] uppercase tracking-wider text-[10px]">
                  <th className="py-3 px-4 font-semibold">Run ID</th>
                  <th className="py-3 px-4 font-semibold">Associated Case</th>
                  <th className="py-3 px-4 font-semibold">Pipeline Type</th>
                  <th className="py-3 px-4 font-semibold">Current Stage</th>
                  <th className="py-3 px-4 font-semibold">Execution Status</th>
                  <th className="py-3 px-4 font-semibold">Timestamps</th>
                  <th className="py-3 px-4 font-semibold text-right">Providers</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A] text-[#AAAAAA]">
                {filteredRuns.map((run) => {
                  const isExpanded = expandedRunId === run.analysis_id;
                  const providerCount = Object.keys(run.provider_results || {}).length;

                  return (
                    <React.Fragment key={run.analysis_id}>
                      <tr className="hover:bg-[#151515] transition-colors">
                        <td className="py-3.5 px-4 font-bold text-white select-all">
                          {run.analysis_id.slice(0, 8)}...
                        </td>
                        <td className="py-3.5 px-4">
                          <Link
                            to={`/investigations/${run.case_id}`}
                            className="font-bold text-[#00FF00] hover:underline flex items-center gap-1"
                          >
                            <span>{run.caseName}</span>
                            <ArrowRight className="h-3 w-3" />
                          </Link>
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="px-2 py-0.5 rounded border border-[#222222] bg-[#0A0A0A] text-[10px] font-bold text-[#00FF00]">
                            {run.analysis_type}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-white font-bold uppercase text-[11px]">
                          {run.current_stage}
                        </td>
                        <td className="py-3.5 px-4">
                          <StatusBadge status={run.status} size="sm" />
                        </td>
                        <td className="py-3.5 px-4 text-[#666666] text-[11px] space-y-0.5">
                          <div>Start: {new Date(run.started_at).toLocaleString()}</div>
                          {run.completed_at && (
                            <div>Done: {new Date(run.completed_at).toLocaleString()}</div>
                          )}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <button
                            onClick={() => toggleExpand(run.analysis_id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 rounded text-[10px] text-[#AAAAAA] hover:text-white transition-colors"
                          >
                            <span>{providerCount} providers</span>
                            {isExpanded ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                          </button>
                        </td>
                      </tr>

                      {/* Expandable Provider Records Row */}
                      {isExpanded && (
                        <tr className="bg-[#0A0A0A] border-b border-[#222222]">
                          <td colSpan={7} className="p-4">
                            <div className="space-y-3">
                              <span className="text-[10px] font-bold text-[#666666] uppercase tracking-wider block">
                                Container Execution Records for Run {run.analysis_id}
                              </span>

                              {providerCount > 0 ? (
                                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                                  {Object.entries(run.provider_results).map(([pName, rec]: [string, ProviderExecutionRecord]) => (
                                    <div
                                      key={pName}
                                      className="p-3 bg-[#101010] border border-[#222222] rounded space-y-1.5"
                                    >
                                      <div className="flex justify-between items-start">
                                        <div>
                                          <span className="font-bold text-white text-xs block uppercase">
                                            {rec.provider || pName}
                                          </span>
                                          <span className="text-[10px] text-[#AAAAAA]">
                                            {rec.provider_version ? `v${rec.provider_version}` : 'Version: —'}
                                          </span>
                                        </div>
                                        <StatusBadge status={rec.status} size="sm" />
                                      </div>

                                      <div className="text-[10px] text-[#AAAAAA] pt-1 border-t border-[#1C1C1C] space-y-1">
                                        <div className="flex justify-between">
                                          <span>DURATION:</span>
                                          <span className="text-white font-bold">
                                            {rec.duration !== undefined ? `${rec.duration.toFixed(2)}s` : '—'}
                                          </span>
                                        </div>

                                        {rec.output_metadata && Object.keys(rec.output_metadata).length > 0 && (
                                          <div className="space-y-0.5 pt-0.5 text-[9px]">
                                            {Object.entries(rec.output_metadata).slice(0, 3).map(([k, v]) => (
                                              <div key={k} className="flex justify-between truncate">
                                                <span className="text-[#666666] uppercase">{k}:</span>
                                                <span className="text-white truncate max-w-[120px]">{String(v)}</span>
                                              </div>
                                            ))}
                                          </div>
                                        )}
                                      </div>

                                      {rec.error && (
                                        <div className="p-2 bg-[#FF3333]/10 border border-[#FF3333]/30 rounded text-[#FF3333] text-[10px]">
                                          {rec.error}
                                        </div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <p className="text-xs text-[#AAAAAA]">
                                  No provider records emitted yet for this pipeline run.
                                </p>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <EmptyState
          title="No Pipeline Runs Logged"
          description={searchTerm || statusFilter !== 'ALL' || typeFilter !== 'ALL'
            ? "No pipeline executions match the active filter criteria."
            : "No analysis jobs executed yet across all investigations."}
        />
      )}
    </div>
  );
};

export default Analysis;
