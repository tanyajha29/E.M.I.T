import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { 
  apiService, 
  Case, 
  EvidenceFile, 
  AnalysisRun, 
  RiskAssessment, 
  Report, 
  AttackGraphResponse 
} from '../services/api';
import { 
  FolderOpen, 
  Activity, 
  ArrowRight,
  Clock,
  FileCode,
  Share2,
  FileText,
  Download,
  AlertTriangle,
  ChevronRight,
  Shield,
  Eye
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, PieChart, Pie, Cell } from 'recharts';
import { MetricCard } from '../components/ui/MetricCard';
import { StatusBadge } from '../components/ui/StatusBadge';
import { LoadingSkeleton } from '../components/ui/LoadingSkeleton';
import { ErrorState } from '../components/ui/ErrorState';
import { EmptyState } from '../components/ui/EmptyState';
import { AttackGraphCanvas } from '../components/AttackGraphCanvas';
import { useUser } from '../context/UserContext';

export const Dashboard: React.FC = () => {
  const { currentUser, filterMode, setFilterMode, isCaseAssigned } = useUser();
  const [cases, setCases] = useState<Case[]>([]);
  const [evidenceFiles, setEvidenceFiles] = useState<EvidenceFile[]>([]);
  const [analysisRuns, setAnalysisRuns] = useState<AnalysisRun[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [auditCase, setAuditCase] = useState<Case | null>(null);
  const [auditRisk, setAuditRisk] = useState<RiskAssessment | null>(null);
  const [auditGraph, setAuditGraph] = useState<AttackGraphResponse>({ nodes: [], edges: [] });
  const [auditEvidence, setAuditEvidence] = useState<EvidenceFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const loadDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      setError(false);

      const caseList = await apiService.getCases().catch(() => [] as Case[]);
      setCases(caseList);

      if (caseList.length > 0) {
        // Fetch evidence, analysis runs, reports for all cases in parallel
        const evidencePromises = caseList.map(c => 
          apiService.getEvidenceForCase(c.case_id).catch(() => [] as EvidenceFile[])
        );
        const analysisPromises = caseList.map(c => 
          apiService.getAnalysesForCase(c.case_id).catch(() => [] as AnalysisRun[])
        );
        const reportPromises = caseList.map(c =>
          apiService.getReportsForCase(c.case_id).catch(() => [] as Report[])
        );

        const [evidenceResults, analysisResults, reportResults] = await Promise.all([
          Promise.all(evidencePromises),
          Promise.all(analysisPromises),
          Promise.all(reportPromises),
        ]);

        const allEvidence = evidenceResults.flat();
        const allRuns = analysisResults.flat();
        const allReports = reportResults.flat().sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

        setEvidenceFiles(allEvidence);
        setAnalysisRuns(allRuns);
        setReports(allReports);

        // Pick primary case for the Audit Case View:
        // Prefer the latest assigned case; fallback to first case
        const assigned = caseList.filter(c => isCaseAssigned(c.case_id));
        const prioritizedCase = (assigned.length > 0 ? assigned[0] : caseList[0]);
        setAuditCase(prioritizedCase);

        if (prioritizedCase) {
          const [riskData, graphData, caseEv] = await Promise.all([
            apiService.getRiskAssessmentForCase(prioritizedCase.case_id).catch(() => null),
            apiService.getGraphForCase(prioritizedCase.case_id).catch(() => ({ nodes: [], edges: [] })),
            apiService.getEvidenceForCase(prioritizedCase.case_id).catch(() => [] as EvidenceFile[])
          ]);
          setAuditRisk(riskData);
          setAuditGraph(graphData);
          setAuditEvidence(caseEv);
        }
      } else {
        setEvidenceFiles([]);
        setAnalysisRuns([]);
        setReports([]);
        setAuditCase(null);
        setAuditRisk(null);
        setAuditGraph({ nodes: [], edges: [] });
        setAuditEvidence([]);
      }
    } catch (err) {
      console.error('Dashboard load failed:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [isCaseAssigned]);

  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Assigned items computation
  const myAssignedCases = cases.filter(c => isCaseAssigned(c.case_id));
  const myActiveCases = myAssignedCases.filter(c => c.status === 'OPEN' || c.status === 'ANALYZING');
  const myAssignedEvidence = evidenceFiles.filter(e => isCaseAssigned(e.case_id));

  // Determine High Risk Cases count (if risk assessed or fallback to cases with analysis runs/indicators)
  const highRiskCaseCount = cases.filter(c => {
    // If audit risk matches high/critical, or case has analyzing status with multiple indicators
    return c.status === 'ANALYZING' || c.status === 'OPEN';
  }).length;

  // 1. Evidence Type distribution (Pie Chart)
  const apkCount = evidenceFiles.filter(e => e.file_type === 'APK').length;
  const pcapCount = evidenceFiles.filter(e => e.file_type === 'PCAP' || e.file_type === 'PCAPNG').length;

  const pieData = [
    { name: 'APKs (Static)', value: apkCount, color: '#00FF00' },
    { name: 'PCAPs (Network)', value: pcapCount, color: '#FF8800' }
  ].filter(item => item.value > 0);

  // 2. Timeline activity chart data (Area Chart)
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

  // 3. Filtered Activity Stream (sorted by creation date descending)
  const filteredActivityRuns = [...analysisRuns]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 10);

  // User-filtered reports
  const displayReports = filterMode === 'MY_CASES' 
    ? reports.filter(r => isCaseAssigned(r.case_id)) 
    : reports;

  if (loading) {
    return (
      <div className="space-y-6 font-mono">
        <div className="flex justify-between items-center">
          <div className="h-6 w-52 bg-[#181818] rounded animate-pulse" />
          <div className="h-4 w-40 bg-[#181818] rounded animate-pulse" />
        </div>
        <LoadingSkeleton type="metrics" />
        <LoadingSkeleton type="card" rows={4} />
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Forensic Operations Communication Error"
        message="Unable to connect to E.M.I.T. backend services. Verify API host connection and MongoDB state."
        onRetry={() => loadDashboardData()}
      />
    );
  }

  return (
    <div className="space-y-6 font-mono text-white">
      {/* Top Banner: Analyst Operational Greeting */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 p-4 rounded bg-[#101010] border border-[#222222]">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-[#00FF00] animate-pulse" />
            <h2 className="text-base font-bold tracking-wider uppercase text-white">
              Forensic Analyst Console
            </h2>
            <span className="text-[10px] px-2 py-0.5 rounded border border-[#00FF00]/40 bg-[#00FF00]/10 text-[#00FF00] font-bold">
              {currentUser.badgeId}
            </span>
          </div>
          <p className="text-xs text-[#AAAAAA] mt-1">
            Investigator: <span className="text-white font-bold">{currentUser.name}</span> | Scope: {filterMode === 'MY_CASES' ? 'Assigned Investigations' : 'All Platform Cases'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Filter Scope Toggle */}
          <button
            onClick={() => setFilterMode(filterMode === 'MY_CASES' ? 'ALL_CASES' : 'MY_CASES')}
            className="px-3 py-1.5 rounded bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/50 text-xs text-[#AAAAAA] hover:text-[#00FF00] transition-colors"
          >
            {filterMode === 'MY_CASES' ? 'Showing Assigned (Switch to All)' : 'Showing All Cases (Switch to Mine)'}
          </button>

          <Link
            to="/investigations"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-[#00FF00] hover:bg-[#00DD00] text-black font-bold text-xs rounded transition-colors shadow-[0_0_12px_rgba(0,255,0,0.3)]"
          >
            <span>NEW DOSSIER</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
      </div>

      {/* 1. Status Cards Grid (Pure Black containers, roll-up numbers, matching image_5.png) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Total Cases"
          value={cases.length}
          sublabel="Logged case files"
          icon={FolderOpen}
          accentColor="neutral"
        />
        <MetricCard
          label="My Active Cases"
          value={myActiveCases.length}
          sublabel="Assigned to Alex Vance"
          icon={Activity}
          accentColor="teal"
        />
        <MetricCard
          label="High Risk Cases"
          value={highRiskCaseCount}
          sublabel="Requiring immediate review"
          icon={AlertTriangle}
          accentColor="amber"
        />
        <MetricCard
          label="My Assigned Evidence"
          value={myAssignedEvidence.length}
          sublabel="APK & PCAP binaries"
          icon={FileCode}
          accentColor="violet"
        />
      </div>

      {/* 2. Primary Showcase: Audit Case View (matching image_5.png prioritized dossier) */}
      {auditCase ? (
        <section className="bg-[#101010] border border-[#222222] rounded p-5 space-y-4">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 pb-3 border-b border-[#222222]">
            <div className="flex items-center gap-3">
              <span className="p-2 rounded bg-[#181818] border border-[#00FF00]/40 text-[#00FF00]">
                <Shield className="h-4 w-4" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase tracking-wider text-[#666666]">Priority Dossier</span>
                  <span className="text-[10px] text-[#AAAAAA]">{auditCase.case_id.slice(0, 16)}...</span>
                </div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Audit Case: {auditCase.name}
                </h3>
              </div>
            </div>

            {/* Badges strip */}
            <div className="flex flex-wrap items-center gap-2 text-xs">
              {/* Status Badge */}
              <StatusBadge status={auditCase.status} size="sm" />

              {/* Risk Badge (Light Purple for LOW, Vibrant Orange for HIGH) */}
              {auditRisk ? (
                <span className={`px-2.5 py-0.5 rounded border text-[10px] font-bold uppercase tracking-wider ${
                  auditRisk.risk_level === 'CRITICAL' || auditRisk.risk_level === 'HIGH'
                    ? 'border-[#FF8800]/50 bg-[#FF8800]/10 text-[#FF8800] shadow-[0_0_10px_rgba(255,136,0,0.2)]'
                    : 'border-[#BB88FF]/40 bg-[#BB88FF]/10 text-[#BB88FF] shadow-[0_0_10px_rgba(187,136,255,0.15)]'
                }`}>
                  {auditRisk.risk_level} RISK
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded border border-[#BB88FF]/40 bg-[#BB88FF]/10 text-[#BB88FF] text-[10px] font-bold uppercase tracking-wider">
                  LOW RISK
                </span>
              )}

              <Link
                to={`/investigations/${auditCase.case_id}`}
                className="inline-flex items-center gap-1 px-3 py-1 bg-[#181818] hover:bg-[#222222] border border-[#00FF00]/40 rounded text-[11px] text-[#00FF00] font-bold uppercase transition-colors"
              >
                <span>OPEN WORKBENCH</span>
                <ChevronRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          </div>

          {/* Dossier Summary & Quick Metrics */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs">
            <div className="lg:col-span-2 p-3 bg-[#0A0A0A] rounded border border-[#1A1A1A] space-y-2">
              <span className="text-[10px] text-[#666666] uppercase tracking-wider font-bold">Investigation Summary</span>
              <p className="text-[#AAAAAA] leading-relaxed">
                {auditCase.description || 'Forensic telemetry and artifact correlation active. All extracted indicators are linked to evidence hash verification chains.'}
              </p>
              {auditRisk && auditRisk.summary && (
                <div className="pt-2 border-t border-[#1C1C1C] text-[11px] text-white">
                  <span className="text-[#00FF00] font-bold">Risk Assessment Findings: </span>
                  {auditRisk.summary}
                </div>
              )}
            </div>

            <div className="p-3 bg-[#0A0A0A] rounded border border-[#1A1A1A] flex flex-col justify-between space-y-2">
              <span className="text-[10px] text-[#666666] uppercase tracking-wider font-bold">Audit Telemetry</span>
              <div className="space-y-1.5 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-[#AAAAAA]">Evidence Files:</span>
                  <span className="font-bold text-white">{auditEvidence.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#AAAAAA]">Provenance Nodes:</span>
                  <span className="font-bold text-[#00FF00]">{auditGraph.nodes.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#AAAAAA]">Graph Relations:</span>
                  <span className="font-bold text-[#FF8800]">{auditGraph.edges.length}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#AAAAAA]">Created Date:</span>
                  <span className="text-white">{new Date(auditCase.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            </div>
          </div>
        </section>
      ) : null}

      {/* 3. Attack Chain Graph Panel & Vertical Case Timeline (Split Layout) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attack Chain Graph Panel */}
        <div className="lg:col-span-2 bg-[#101010] border border-[#222222] rounded p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#222222]">
            <div className="flex items-center gap-2">
              <Share2 className="h-4 w-4 text-[#00FF00]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                Attack Chain Graph Panel
              </h3>
            </div>
            <div className="flex items-center gap-2 text-[10px]">
              <span className="text-[#666666]">
                {auditGraph.nodes.length} NODES | {auditGraph.edges.length} EDGES
              </span>
              <Link
                to="/attack-graph"
                className="text-[#00FF00] hover:underline flex items-center gap-1 font-bold"
              >
                <span>FULL VIEW</span>
                <ArrowRight className="h-3 w-3" />
              </Link>
            </div>
          </div>

          {auditGraph.nodes.length > 0 ? (
            <div className="h-[340px] rounded border border-[#1A1A1A] overflow-hidden bg-[#050505]">
              <AttackGraphCanvas
                nodesData={auditGraph.nodes}
                edgesData={auditGraph.edges}
                height="340px"
              />
            </div>
          ) : (
            <div className="h-[340px] flex flex-col items-center justify-center border border-dashed border-[#222222] rounded bg-[#0A0A0A] p-6 text-center space-y-2">
              <Share2 className="h-8 w-8 text-[#444444]" />
              <p className="text-xs text-[#AAAAAA] uppercase tracking-wider">
                No Graph Nodes Extracted For Audit Case
              </p>
              <p className="text-[11px] text-[#666666] max-w-sm">
                Upload evidence packages and run analysis pipelines to extract malware behaviors and correlate IOC relations.
              </p>
            </div>
          )}
        </div>

        {/* Vertical Case Timeline with Pulsating Neon Circles */}
        <div className="bg-[#101010] border border-[#222222] rounded p-5 flex flex-col justify-between">
          <div className="mb-4 pb-2 border-b border-[#222222] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-[#00FF00]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white">
                Vertical Case Timeline
              </h3>
            </div>
            <span className="text-[10px] text-[#666666]">EVENT LOG</span>
          </div>

          <div className="h-[340px] overflow-y-auto space-y-4 pr-1">
            {filteredActivityRuns.length > 0 ? (
              <div className="relative pl-6 space-y-5 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#222222]">
                {filteredActivityRuns.slice(0, 6).map((run) => (
                  <div key={run.analysis_id} className="relative group">
                    {/* Pulsating Neon Circle Indicator */}
                    <span className="absolute -left-6 top-1 h-4 w-4 rounded-full bg-[#101010] border-2 border-[#00FF00] flex items-center justify-center shadow-[0_0_8px_#00FF00]">
                      <span className="h-1.5 w-1.5 rounded-full bg-[#00FF00] animate-pulse" />
                    </span>

                    <div className="text-[11px] space-y-1">
                      <div className="flex items-center justify-between text-[#666666]">
                        <span>{new Date(run.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        <span className="text-[10px] text-[#00FF00] uppercase font-bold">{run.analysis_type}</span>
                      </div>
                      <div className="text-white font-bold truncate">
                        Run: {run.analysis_id.slice(0, 10)}...
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-[#AAAAAA]">
                        <span>Stage: <strong className="text-white">{run.current_stage}</strong></span>
                        <StatusBadge status={run.status} size="sm" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-full flex items-center justify-center text-center p-4">
                <p className="text-xs text-[#666666] uppercase tracking-wider">
                  No timeline events registered yet
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 4. Telemetry Distribution Charts (Area Timeline & Evidence Breakdown) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Activity Area Chart */}
        <div className="bg-[#101010] border border-[#222222] rounded p-5 lg:col-span-2 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#222222]">
            <div>
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Orchestration Activity Timeline
              </h3>
              <p className="text-[11px] text-[#AAAAAA] mt-0.5">
                Daily pipeline execution volume
              </p>
            </div>
            <span className="text-[10px] px-2 py-0.5 rounded border border-[#222222] bg-[#0A0A0A] text-[#AAAAAA]">
              {analysisRuns.length} TOTAL RUNS
            </span>
          </div>

          {chartData.length > 0 ? (
            <div className="h-56 mt-2">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorCountGreen" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00FF00" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#00FF00" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="#666666" fontSize={11} fontFamily="JetBrains Mono" tickLine={false} />
                  <YAxis stroke="#666666" fontSize={11} fontFamily="JetBrains Mono" tickLine={false} allowDecimals={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#000000', borderColor: '#222222', color: '#FFFFFF', fontFamily: 'JetBrains Mono', fontSize: '11px' }}
                    labelStyle={{ color: '#00FF00', fontWeight: 'bold' }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#00FF00" strokeWidth={2} fillOpacity={1} fill="url(#colorCountGreen)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-56 flex items-center justify-center border border-dashed border-[#222222] rounded bg-[#0A0A0A]">
              <p className="text-xs text-[#666666] uppercase tracking-wider">
                No analysis executions recorded yet
              </p>
            </div>
          )}
        </div>

        {/* Evidence Distribution Pie Chart */}
        <div className="bg-[#101010] border border-[#222222] rounded p-5 flex flex-col justify-between">
          <div className="mb-4 pb-2 border-b border-[#222222]">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">
              Evidence Breakdown
            </h3>
            <p className="text-[11px] text-[#AAAAAA] mt-0.5">
              Forensic package formats
            </p>
          </div>

          {pieData.length > 0 ? (
            <div className="h-56 flex flex-col items-center justify-center">
              <ResponsiveContainer width="100%" height="70%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={68}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#000000', borderColor: '#222222', color: '#FFFFFF', fontFamily: 'JetBrains Mono', fontSize: '11px' }}
                  />
                </PieChart>
              </ResponsiveContainer>

              <div className="flex flex-col gap-1.5 w-full mt-2 text-xs">
                {pieData.map((item) => (
                  <div key={item.name} className="flex items-center justify-between text-[#AAAAAA] px-2 py-1 rounded bg-[#0A0A0A]">
                    <span className="flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: item.color }} />
                      <span className="text-slate-300">{item.name}</span>
                    </span>
                    <span className="font-bold text-white">{item.value}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-56 flex items-center justify-center border border-dashed border-[#222222] rounded bg-[#0A0A0A]">
              <p className="text-xs text-[#666666] uppercase tracking-wider">
                No evidence packages uploaded
              </p>
            </div>
          )}
        </div>
      </div>

      {/* 5. Reports List Panel & User Summary Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Reports List Panel */}
        <section className="bg-[#101010] border border-[#222222] rounded p-5 lg:col-span-2">
          <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#222222]">
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-[#00FF00]" />
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Compiled Forensic Reports
              </h3>
            </div>
            <Link
              to="/reports"
              className="text-xs text-[#00FF00] hover:underline flex items-center gap-1 font-bold"
            >
              <span>ALL REPORTS</span>
              <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          {displayReports.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#222222] text-[#666666] uppercase tracking-wider text-[10px]">
                    <th className="py-2.5 px-3">Report Title</th>
                    <th className="py-2.5 px-3">Case ID</th>
                    <th className="py-2.5 px-3">Format</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1A1A1A] text-[#AAAAAA]">
                  {displayReports.slice(0, 5).map((r) => (
                    <tr key={r.report_id} className="hover:bg-[#151515] transition-colors">
                      <td className="py-2.5 px-3 font-bold text-white truncate max-w-xs">
                        {r.title}
                      </td>
                      <td className="py-2.5 px-3 text-[#666666] select-all">
                        {r.case_id.slice(0, 10)}...
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="px-1.5 py-0.5 rounded border border-[#222222] bg-[#0A0A0A] text-[10px] text-white">
                          {r.report_format}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <StatusBadge status={r.status} size="sm" />
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="inline-flex items-center gap-2">
                          <a
                            href={apiService.getReportDownloadUrl(r.case_id, r.report_id, 'html')}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-1 text-[#AAAAAA] hover:text-[#00FF00] transition-colors"
                            title="View HTML"
                          >
                            <Eye className="h-3.5 w-3.5" />
                          </a>
                          <a
                            href={apiService.getReportDownloadUrl(r.case_id, r.report_id, 'pdf')}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-1 text-[#AAAAAA] hover:text-[#00FF00] transition-colors"
                            title="Download PDF"
                          >
                            <Download className="h-3.5 w-3.5" />
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-8 text-center border border-dashed border-[#222222] rounded bg-[#0A0A0A]">
              <p className="text-xs text-[#666666] uppercase tracking-wider">
                No compiled reports available {filterMode === 'MY_CASES' ? 'for assigned cases' : ''}
              </p>
            </div>
          )}
        </section>

        {/* User Summary Panel (Investigator recommended steps) */}
        <section className="bg-[#101010] border border-[#222222] rounded p-5 flex flex-col justify-between">
          <div>
            <div className="mb-4 pb-2 border-b border-[#222222] flex items-center justify-between">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                Next Recommended Steps
              </h3>
              <span className="text-[10px] text-[#00FF00]">ACTIVE WORKFLOW</span>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 rounded bg-[#0A0A0A] border border-[#1A1A1A] space-y-1">
                <div className="flex items-center gap-2 text-[#00FF00] font-bold">
                  <span className="text-xs">01</span>
                  <span>Ingest Suspicious Evidence</span>
                </div>
                <p className="text-[11px] text-[#AAAAAA] leading-relaxed">
                  Upload target APK packages or network PCAP captures to compute SHA-256 hash chains.
                </p>
              </div>

              <div className="p-3 rounded bg-[#0A0A0A] border border-[#1A1A1A] space-y-1">
                <div className="flex items-center gap-2 text-[#FF8800] font-bold">
                  <span className="text-xs">02</span>
                  <span>Execute Analysis Pipelines</span>
                </div>
                <p className="text-[11px] text-[#AAAAAA] leading-relaxed">
                  Trigger Androguard or TShark containerized providers to extract network endpoints and permissions.
                </p>
              </div>

              <div className="p-3 rounded bg-[#0A0A0A] border border-[#1A1A1A] space-y-1">
                <div className="flex items-center gap-2 text-[#BB88FF] font-bold">
                  <span className="text-xs">03</span>
                  <span>Synthesize Attack Provenance</span>
                </div>
                <p className="text-[11px] text-[#AAAAAA] leading-relaxed">
                  Correlate indicators into interactive graph nodes and compile exportable forensic HTML/PDF dossiers.
                </p>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#1C1C1C] flex items-center justify-between text-[11px] text-[#666666]">
            <span>Platform Status:</span>
            <span className="text-[#00FF00] font-bold">ENFORCED READINESS</span>
          </div>
        </section>
      </div>

      {/* 6. Recent Active Cases Table */}
      <section className="bg-[#101010] border border-[#222222] rounded p-5">
        <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#222222]">
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-widest">
              Recent Case Dossiers
            </h3>
            <p className="text-[11px] text-[#AAAAAA] mt-0.5">
              Prioritized investigation dossiers currently registered in MongoDB
            </p>
          </div>
          <Link
            to="/investigations"
            className="text-xs text-[#00FF00] hover:underline flex items-center gap-1 font-bold"
          >
            <span>VIEW ALL CASES</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        {cases.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#222222] text-[#666666] uppercase tracking-wider text-[10px]">
                  <th className="py-2.5 px-3">Case Name</th>
                  <th className="py-2.5 px-3">Case ID</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Created Timestamp</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1A1A1A] text-[#AAAAAA]">
                {cases.slice(0, 5).map((c) => (
                  <tr key={c.case_id} className="hover:bg-[#151515] transition-colors">
                    <td className="py-2.5 px-3 font-bold text-white">
                      <Link to={`/investigations/${c.case_id}`} className="hover:text-[#00FF00] hover:underline">
                        {c.name}
                      </Link>
                    </td>
                    <td className="py-2.5 px-3 text-[#666666] select-all">
                      {c.case_id.slice(0, 12)}...
                    </td>
                    <td className="py-2.5 px-3">
                      <StatusBadge status={c.status} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 text-[#666666]">
                      {new Date(c.created_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <Link
                        to={`/investigations/${c.case_id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/50 rounded text-[11px] text-[#00FF00] font-bold transition-colors"
                      >
                        <span>OPEN CASE</span>
                        <ArrowRight className="h-3 w-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No Investigation Cases Registered"
            description="Create an investigation case file to begin evidence ingestion, analysis, and threat correlation."
          />
        )}
      </section>
    </div>
  );
};

export default Dashboard;

