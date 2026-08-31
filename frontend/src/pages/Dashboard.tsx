import React, { useEffect, useState, useCallback } from 'react';
import { apiService, Case, HealthResponse, EvidenceFile, AnalysisRun } from '../services/api';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Terminal, 
  Activity, 
  FolderOpen, 
  AlertTriangle,
  Server
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from 'recharts';

const Dashboard: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [cases, setCases] = useState<Case[]>([]);
  const [evidenceCount, setEvidenceCount] = useState<number>(0);
  const [runsCount, setRunsCount] = useState<number>(0);
  const [evidenceFiles, setEvidenceFiles] = useState<EvidenceFile[]>([]);
  const [analysisRuns, setAnalysisRuns] = useState<AnalysisRun[]>([]);
  
  const [indicatorCount, setIndicatorCount] = useState<number>(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const loadDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      setError(false);

      // Fetch health
      const healthData = await apiService.getHealth().catch(() => null);
      setHealth(healthData);

      // Fetch cases
      const caseList = await apiService.getCases();
      setCases(caseList);

      // Fetch case-specific details in parallel (evidence, analysis runs, indicators)
      if (caseList.length > 0) {
        const evidencePromises = caseList.map(c => 
          apiService.getEvidenceForCase(c.case_id).catch(() => [] as EvidenceFile[])
        );
        const analysisPromises = caseList.map(c => 
          apiService.getAnalysesForCase(c.case_id).catch(() => [] as AnalysisRun[])
        );
        const indicatorPromises = caseList.map(c =>
          apiService.getIndicatorsForCase(c.case_id).catch(() => [] as any[])
        );

        const [evidenceResults, analysisResults, indicatorResults] = await Promise.all([
          Promise.all(evidencePromises),
          Promise.all(analysisPromises),
          Promise.all(indicatorPromises),
        ]);

        const allEvidence = evidenceResults.flat();
        const allRuns = analysisResults.flat();
        const allIndicators = indicatorResults.flat();

        setEvidenceFiles(allEvidence);
        setEvidenceCount(allEvidence.length);
        setAnalysisRuns(allRuns);
        setRunsCount(allRuns.length);
        setIndicatorCount(allIndicators.length);
      } else {
        setEvidenceCount(0);
        setRunsCount(0);
        setIndicatorCount(0);
        setEvidenceFiles([]);
        setAnalysisRuns([]);
      }
    } catch (err) {
      console.error('Dashboard load failed:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  const activeCasesCount = cases.filter(c => c.status === 'OPEN' || c.status === 'ANALYZING').length;

  // Process data for charts
  // 1. Evidence Type distribution (Pie Chart)
  const apkCount = evidenceFiles.filter(e => e.file_type === 'APK').length;
  const pcapCount = evidenceFiles.filter(e => e.file_type === 'PCAP' || e.file_type === 'PCAPNG').length;

  const pieData = [
    { name: 'APKs (Static Analysis)', value: apkCount },
    { name: 'PCAPs (Network Logs)', value: pcapCount }
  ].filter(item => item.value > 0);

  const COLORS = ['#06b6d4', '#14b8a6']; // Cyan and Teal

  // 2. Timeline activity chart data (Area Chart)
  // Maps runs over past days or timestamps dynamically
  const chartData = analysisRuns
    .map(run => {
      const date = new Date(run.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
      return { date, count: 1 };
    })
    .reduce((acc, curr) => {
      const existing = acc.find(item => item.date === curr.date);
      if (existing) {
        existing.count += 1;
      } else {
        acc.push(curr);
      }
      return acc;
    }, [] as { date: string; count: number }[])
    .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <Activity className="h-8 w-8 text-cyan-400 animate-spin" />
        <span className="text-sm font-semibold tracking-wider text-slate-400 uppercase">Loading Dashboard Analytics...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="border border-rose-900/50 bg-rose-950/20 p-6 rounded-lg flex items-start gap-4">
        <AlertTriangle className="h-6 w-6 text-rose-500 shrink-0 mt-0.5" />
        <div>
          <h3 className="text-md font-bold text-rose-400 uppercase tracking-wider">System Connection Error</h3>
          <p className="text-sm text-slate-400 mt-1">Unable to connect to E.M.I.T. backend services. Verify API host connection.</p>
          <button
            onClick={() => loadDashboardData()}
            className="mt-4 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold uppercase rounded transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Top Status Banner */}
      <section className="bg-slate-900 border border-slate-800 rounded p-6">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">Core Orchestrator Integration</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Backend Status */}
          <div className="bg-slate-950 p-4 rounded border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Server className="h-7 w-7 text-cyan-400" />
              <div>
                <h4 className="font-bold text-slate-200">API Host Status</h4>
                <p className="text-xs text-slate-500">FastAPI platform services</p>
              </div>
            </div>
            {health ? (
              <span className="inline-flex items-center gap-1.5 text-xs text-cyan-400 font-bold bg-cyan-950/30 px-3 py-1 rounded border border-cyan-800/40 uppercase tracking-widest">
                <ShieldCheck className="h-4 w-4" /> Connected
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs text-rose-500 font-bold bg-rose-950/30 px-3 py-1 rounded border border-rose-900/40 uppercase tracking-widest">
                <ShieldAlert className="h-4 w-4" /> Offline
              </span>
            )}
          </div>

          {/* Database Status */}
          <div className="bg-slate-950 p-4 rounded border border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Terminal className="h-7 w-7 text-cyan-400" />
              <div>
                <h4 className="font-bold text-slate-200">Database Engine</h4>
                <p className="text-xs text-slate-500">MongoDB Persistence</p>
              </div>
            </div>
            {health?.database?.status === 'connected' ? (
              <span className="inline-flex items-center gap-1.5 text-xs text-cyan-400 font-bold bg-cyan-950/30 px-3 py-1 rounded border border-cyan-800/40 uppercase tracking-widest">
                <ShieldCheck className="h-4 w-4" /> Connected
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs text-rose-500 font-bold bg-rose-950/30 px-3 py-1 rounded border border-rose-900/40 uppercase tracking-widest">
                <ShieldAlert className="h-4 w-4" /> Disconnected
              </span>
            )}
          </div>
        </div>
      </section>

      {/* Metrics Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded p-4 relative overflow-hidden">
          <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Total Cases</p>
          <p className="text-2xl font-bold mt-2 text-slate-100">{cases.length}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded p-4 relative overflow-hidden">
          <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Active Cases</p>
          <p className="text-2xl font-bold mt-2 text-cyan-400">{activeCasesCount}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded p-4 relative overflow-hidden">
          <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Evidence Files</p>
          <p className="text-2xl font-bold mt-2 text-slate-100">{evidenceCount}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded p-4 relative overflow-hidden">
          <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Analysis Jobs</p>
          <p className="text-2xl font-bold mt-2 text-slate-100">{runsCount}</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded p-4 relative overflow-hidden">
          <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">Extracted IOCs</p>
          <p className="text-2xl font-bold mt-2 text-purple-400">{indicatorCount}</p>
        </div>
      </div>

      {/* Analytics Charts & Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Timeline Chart */}
        <div className="bg-slate-900 border border-slate-800 rounded p-5 lg:col-span-2">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-6">Orchestration Activity Timeline</h3>
          {chartData.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2}/>
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', fontFamily: 'monospace' }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#colorCount)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center border border-dashed border-slate-800 rounded bg-slate-950/30">
              <p className="text-xs text-slate-500 uppercase tracking-wider">No analysis activity available yet.</p>
            </div>
          )}
        </div>

        {/* Evidence Distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded p-5">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-6">Evidence Distribution</h3>
          {pieData.length > 0 ? (
            <div className="h-64 flex flex-col items-center justify-center">
              <ResponsiveContainer width="100%" height="80%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={70}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((_entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f8fafc', fontFamily: 'monospace' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex justify-center gap-4 text-xs mt-2">
                {pieData.map((item, idx) => (
                  <span key={item.name} className="flex items-center gap-1.5 text-slate-400">
                    <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: COLORS[idx % COLORS.length] }}></span>
                    {item.name}: {item.value}
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center border border-dashed border-slate-800 rounded bg-slate-950/30">
              <p className="text-xs text-slate-500 uppercase tracking-wider">No evidence uploaded yet.</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Investigations List */}
      <section className="bg-slate-900 border border-slate-800 rounded p-5">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">Recent Active Cases</h3>
        {cases.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider">
                  <th className="py-3 font-semibold">Case Name</th>
                  <th className="py-3 font-semibold">Status</th>
                  <th className="py-3 font-semibold">Created Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40 text-slate-300">
                {cases.slice(0, 5).map((c) => (
                  <tr key={c.case_id} className="hover:bg-slate-800/10 transition-colors">
                    <td className="py-3.5 font-semibold text-cyan-400">{c.name}</td>
                    <td className="py-3.5">
                      <span className={`inline-block px-2.5 py-0.5 rounded border text-[10px] font-bold ${
                        c.status === 'OPEN' 
                          ? 'border-cyan-800/40 bg-cyan-950/20 text-cyan-400'
                          : c.status === 'ANALYZING'
                            ? 'border-amber-800/40 bg-amber-950/20 text-amber-400 animate-pulse'
                            : 'border-slate-700 bg-slate-800/20 text-slate-400'
                      }`}>
                        {c.status}
                      </span>
                    </td>
                    <td className="py-3.5 text-slate-500">{new Date(c.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center border border-dashed border-slate-800 rounded bg-slate-950/20">
            <FolderOpen className="h-8 w-8 text-slate-600 mx-auto mb-2" />
            <p className="text-xs text-slate-500 uppercase tracking-wider">No cases found in database. Create one to begin.</p>
          </div>
        )}
      </section>
    </div>
  );
};

export default Dashboard;
