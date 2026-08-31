import React, { useEffect, useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { 
  apiService, 
  Case, 
  EvidenceFile, 
  AnalysisRun, 
  Indicator, 
  Observation,
  Correlation,
  ThreatIntelligence,
  RiskAssessment,
  AttackGraphResponse,
  CaseStatus,
  Report
} from '../services/api';
import { AttackGraphCanvas } from '../components/AttackGraphCanvas';
import { 
  Loader2, 
  AlertTriangle, 
  FileCode, 
  Cpu, 
  ShieldAlert, 
  Layers, 
  History, 
  FileText,
  Upload,
  Play,
  Trash2,
  Calendar,
  Globe,
  Share2,
  CheckCircle2,
  RefreshCw,
  Search,
  ExternalLink,
  HelpCircle,
  Clock,
  Radio,
  FileCheck2,
  ShieldQuestion,
  ChevronRight,
  Download
} from 'lucide-react';

export const InvestigationDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const caseId = id || '';

  const [activeTab, setActiveTab] = useState<
    'overview' | 'evidence' | 'analysis' | 'apk_findings' | 'network_findings' | 
    'indicators' | 'correlations' | 'threat_intel' | 'risk_assessment' | 'attack_graph' | 'timeline' | 'reports'
  >('overview');
  
  // Data State
  const [caseObj, setCaseObj] = useState<Case | null>(null);
  const [evidenceList, setEvidenceList] = useState<EvidenceFile[]>([]);
  const [analysesList, setAnalysesList] = useState<AnalysisRun[]>([]);
  const [indicatorsList, setIndicatorsList] = useState<Indicator[]>([]);
  const [observationsList, setObservationsList] = useState<Observation[]>([]);
  const [correlationsList, setCorrelationsList] = useState<Correlation[]>([]);
  const [threatIntelList, setThreatIntelList] = useState<ThreatIntelligence[]>([]);
  const [riskAssessment, setRiskAssessment] = useState<RiskAssessment | null>(null);
  const [graphData, setGraphData] = useState<AttackGraphResponse>({ nodes: [], edges: [] });
  const [reportsList, setReportsList] = useState<Report[]>([]);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [reportFormat, setReportFormat] = useState<'BOTH' | 'HTML' | 'PDF'>('BOTH');
  const [reportTitle, setReportTitle] = useState('E.M.I.T. Forensic Investigation Dossier');

  // Selected Evidence for Drill-down Modal
  const [inspectEvidence, setInspectEvidence] = useState<EvidenceFile | null>(null);

  // Loading / Error states
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [assessing, setAssessing] = useState(false);

  // Form states
  const [uploadLoading, setUploadLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const [runEvidenceId, setRunEvidenceId] = useState('');
  const [runType, setRunType] = useState<'APK' | 'PCAP'>('APK');
  const [runLoading, setRunLoading] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);

  // Filter states
  const [searchFilter, setSearchFilter] = useState('');

  const loadCaseData = useCallback(async () => {
    if (!caseId) return;
    try {
      setLoading(true);
      setError(false);
      
      const [
        caseData,
        evidenceData,
        analysesData,
        indicatorsData,
        obsData,
        corrData,
        threatData,
        riskData,
        graphRes,
        repData
      ] = await Promise.all([
        apiService.getCase(caseId).catch(() => null),
        apiService.getEvidenceForCase(caseId).catch(() => []),
        apiService.getAnalysesForCase(caseId).catch(() => []),
        apiService.getIndicatorsForCase(caseId).catch(() => []),
        apiService.getObservationsForCase(caseId).catch(() => []),
        apiService.getCorrelationsForCase(caseId).catch(() => []),
        apiService.getThreatIntelForCase(caseId).catch(() => []),
        apiService.getRiskAssessmentForCase(caseId).catch(() => null),
        apiService.getGraphForCase(caseId).catch(() => ({ nodes: [], edges: [] })),
        apiService.getReportsForCase(caseId).catch(() => [])
      ]);

      if (!caseData) {
        setError(true);
        return;
      }

      setCaseObj(caseData);
      setEvidenceList(evidenceData);
      setAnalysesList(analysesData);
      setIndicatorsList(indicatorsData);
      setObservationsList(obsData);
      setCorrelationsList(corrData);
      setThreatIntelList(threatData);
      setRiskAssessment(riskData);
      setGraphData(graphRes);
      setReportsList(repData.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()));
    } catch (err) {
      console.error('Failed to load case workspace:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    loadCaseData();
  }, [loadCaseData]);

  const handleStatusChange = async (newStatus: CaseStatus) => {
    if (!caseObj) return;
    try {
      const updated = await apiService.updateCase(caseId, { status: newStatus });
      setCaseObj(updated);
    } catch (err) {
      console.error('Status update failed:', err);
    }
  };

  const handleFileUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;

    try {
      setUploadLoading(true);
      setUploadProgress(0);
      setUploadError(null);
      await apiService.uploadEvidence(caseId, selectedFile, (pct) => {
        setUploadProgress(pct);
      });
      setSelectedFile(null);
      setUploadProgress(null);
      
      const fileInput = document.getElementById('evidence-upload-input') as HTMLInputElement;
      if (fileInput) fileInput.value = '';
      
      await loadCaseData();
    } catch (err: any) {
      console.error('File upload failed:', err);
      setUploadProgress(null);
      setUploadError(err.response?.data?.detail || 'Upload failed. Verify magic bytes / file signature.');
    } finally {
      setUploadLoading(false);
    }
  };

  const handleDeleteEvidence = async (evidenceId: string) => {
    if (!window.confirm('Delete this evidence file and all associated metrics?')) return;
    try {
      await apiService.deleteEvidence(caseId, evidenceId);
      await loadCaseData();
    } catch (err) {
      console.error('Delete evidence failed:', err);
    }
  };

  const handleTriggerAnalysis = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!runEvidenceId) {
      setRunError('Please select an evidence file to analyze');
      return;
    }

    try {
      setRunLoading(true);
      setRunError(null);
      await apiService.triggerAnalysis(caseId, runEvidenceId, runType);
      setRunEvidenceId('');
      await loadCaseData();
    } catch (err: any) {
      console.error('Analysis trigger failed:', err);
      setRunError(err.response?.data?.detail || 'Analysis pipeline initialization failed.');
    } finally {
      setRunLoading(false);
    }
  };

  const handleTriggerEnrichment = async () => {
    try {
      setEnriching(true);
      const enriched = await apiService.enrichThreatIntel(caseId);
      setThreatIntelList(enriched);
      // Also refresh risk and graph
      const [updatedRisk, updatedGraph] = await Promise.all([
        apiService.getRiskAssessmentForCase(caseId).catch(() => null),
        apiService.getGraphForCase(caseId).catch(() => ({ nodes: [], edges: [] }))
      ]);
      setRiskAssessment(updatedRisk);
      setGraphData(updatedGraph);
    } catch (err) {
      console.error('Threat intelligence enrichment failed:', err);
    } finally {
      setEnriching(false);
    }
  };

  const handleRecalculateRisk = async () => {
    try {
      setAssessing(true);
      const assessed = await apiService.triggerRiskAssessment(caseId);
      setRiskAssessment(assessed);
    } catch (err) {
      console.error('Risk recalculation failed:', err);
    } finally {
      setAssessing(false);
    }
  };

  // Filtered views
  const apkObservations = observationsList.filter(o => o.source === 'APK');
  const networkObservations = observationsList.filter(o => o.source === 'PCAP');

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
        <span className="text-sm font-semibold tracking-wider text-slate-400 uppercase">Opening Investigation Workspace...</span>
      </div>
    );
  }

  if (error || !caseObj) {
    return (
      <div className="border border-rose-900/40 bg-rose-950/20 p-6 rounded flex items-start gap-4">
        <AlertTriangle className="h-6 w-6 text-rose-500 shrink-0 mt-0.5" />
        <div>
          <h3 className="text-md font-bold text-rose-400 uppercase tracking-wider">Access Denied / Not Found</h3>
          <p className="text-sm text-slate-400 mt-1">Unable to locate investigation case file. It may have been deleted or the identifier is invalid.</p>
          <div className="flex gap-3 mt-4">
            <button
              onClick={() => loadCaseData()}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold uppercase rounded transition-colors flex items-center gap-2"
            >
              <RefreshCw className="h-3.5 w-3.5" /> Retry Connection
            </button>
            <Link 
              to="/investigations"
              className="px-4 py-2 border border-rose-800 text-rose-400 hover:bg-rose-900/20 text-xs font-bold uppercase rounded transition-colors"
            >
              Back to Investigations
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ===================================================================== */}
      {/* WORKSPACE TOP HEADER */}
      {/* ===================================================================== */}
      <div className="bg-slate-900 border border-slate-800 rounded p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Case Workspace</span>
              <span className="text-slate-600 font-mono text-[10px]">/</span>
              <span className="text-[10px] text-slate-400 font-mono">ID: {caseObj.case_id}</span>
            </div>
            <h2 className="text-xl font-bold text-slate-100">{caseObj.name}</h2>
            <p className="text-xs text-slate-400 max-w-3xl leading-relaxed">{caseObj.description || 'No case description provided.'}</p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            {/* Risk Badge Preview */}
            {riskAssessment && (
              <div className={`px-3 py-1.5 rounded border font-mono text-xs flex items-center gap-2 ${
                riskAssessment.risk_level === 'CRITICAL' ? 'bg-rose-950/40 border-rose-600 text-rose-400' :
                riskAssessment.risk_level === 'HIGH' ? 'bg-amber-950/40 border-amber-600 text-amber-400' :
                riskAssessment.risk_level === 'MEDIUM' ? 'bg-yellow-950/30 border-yellow-700 text-yellow-300' :
                'bg-emerald-950/30 border-emerald-700 text-emerald-400'
              }`}>
                <ShieldAlert className="h-4 w-4" />
                <span className="font-bold">{riskAssessment.risk_level} RISK</span>
                <span className="text-[10px] opacity-75 font-normal">({(riskAssessment.confidence * 100).toFixed(0)}% conf)</span>
              </div>
            )}

            {/* Status Selector */}
            <div className="flex items-center gap-2 bg-slate-950 border border-slate-800 px-3 py-1.5 rounded">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">STATUS:</span>
              <select
                value={caseObj.status}
                onChange={(e) => handleStatusChange(e.target.value as CaseStatus)}
                className="bg-transparent text-cyan-400 text-xs font-bold focus:outline-none cursor-pointer"
              >
                <option value="OPEN">OPEN</option>
                <option value="ANALYZING">ANALYZING</option>
                <option value="COMPLETED">COMPLETED</option>
                <option value="ARCHIVED">ARCHIVED</option>
              </select>
            </div>

            {/* Refresh Button */}
            <button
              onClick={loadCaseData}
              title="Refresh case data from MongoDB"
              className="p-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
            >
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Quick Stats Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mt-6 pt-5 border-t border-slate-850/80 font-mono text-xs">
          <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
            <span className="text-[10px] text-slate-500 uppercase block">EVIDENCE</span>
            <span className="text-slate-200 font-bold text-sm">{evidenceList.length} files</span>
          </div>
          <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
            <span className="text-[10px] text-slate-500 uppercase block">RUNS</span>
            <span className="text-slate-200 font-bold text-sm">{analysesList.length} jobs</span>
          </div>
          <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
            <span className="text-[10px] text-slate-500 uppercase block">INDICATORS</span>
            <span className="text-cyan-400 font-bold text-sm">{indicatorsList.length} IOCs</span>
          </div>
          <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
            <span className="text-[10px] text-slate-500 uppercase block">OBSERVATIONS</span>
            <span className="text-slate-200 font-bold text-sm">{observationsList.length} items</span>
          </div>
          <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
            <span className="text-[10px] text-slate-500 uppercase block">CORRELATIONS</span>
            <span className="text-amber-400 font-bold text-sm">{correlationsList.length} rules</span>
          </div>
          <div className="bg-slate-950/60 p-2.5 rounded border border-slate-850">
            <span className="text-[10px] text-slate-500 uppercase block">GRAPH NODES</span>
            <span className="text-purple-400 font-bold text-sm">{graphData.nodes.length} nodes</span>
          </div>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* TAB NAVIGATION & WORKBENCH GRID */}
      {/* ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        {/* Navigation Sidebar */}
        <div className="bg-slate-900 border border-slate-800 rounded p-3 flex flex-col space-y-1">
          {[
            { id: 'overview', name: '1. Overview', icon: Calendar, badge: null },
            { id: 'evidence', name: '2. Uploaded Evidence', icon: FileCode, badge: evidenceList.length },
            { id: 'analysis', name: '3. Analysis Jobs', icon: Cpu, badge: analysesList.length },
            { id: 'apk_findings', name: '4. APK Findings', icon: FileCheck2, badge: apkObservations.length },
            { id: 'network_findings', name: '5. Network Findings', icon: Radio, badge: networkObservations.length },
            { id: 'indicators', name: '6. Indicators (IOCs)', icon: ShieldAlert, badge: indicatorsList.length },
            { id: 'correlations', name: '7. Correlations', icon: Layers, badge: correlationsList.length },
            { id: 'threat_intel', name: '8. Threat Intel', icon: Globe, badge: threatIntelList.length },
            { id: 'risk_assessment', name: '9. Risk Assessment', icon: ShieldQuestion, badge: riskAssessment?.risk_level },
            { id: 'attack_graph', name: '10. Attack Graph', icon: Share2, badge: graphData.nodes.length },
            { id: 'timeline', name: '11. Timeline', icon: History, badge: null },
            { id: 'reports', name: '12. Reports', icon: FileText, badge: null },
          ].map((tab) => {
            const Icon = tab.icon;
            const isTabActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center justify-between px-3.5 py-2.5 rounded text-left text-xs font-bold uppercase transition-all ${
                  isTabActive
                    ? 'bg-slate-850 text-cyan-400 border-l-2 border-cyan-500 pl-3'
                    : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                }`}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon className="h-4 w-4 shrink-0" />
                  <span className="truncate">{tab.name}</span>
                </div>
                {tab.badge !== null && tab.badge !== undefined && (
                  <span className="text-[10px] font-mono font-bold bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-slate-400">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Tab Content Display Area */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded p-6 min-h-[620px]">
          
          {/* ================================================================= */}
          {/* 1. OVERVIEW TAB */}
          {/* ================================================================= */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Investigation Case Overview</h3>
                <span className="text-[10px] font-mono text-slate-500">MongoDB Persistence Layer</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
                <div>
                  <h4 className="font-bold text-slate-400 mb-2 uppercase tracking-wider">Case Metadata</h4>
                  <ul className="space-y-3 bg-slate-950 p-4 rounded border border-slate-850/60 font-mono">
                    <li className="flex justify-between"><span className="text-slate-500">CASE ID:</span> <span className="text-slate-300">{caseObj.case_id}</span></li>
                    <li className="flex justify-between"><span className="text-slate-500">STATUS:</span> <span className="text-cyan-400 font-bold">{caseObj.status}</span></li>
                    <li className="flex justify-between"><span className="text-slate-500">CREATED:</span> <span className="text-slate-300">{new Date(caseObj.created_at).toLocaleString()}</span></li>
                    <li className="flex justify-between"><span className="text-slate-500">UPDATED:</span> <span className="text-slate-300">{new Date(caseObj.updated_at).toLocaleString()}</span></li>
                  </ul>
                </div>
                
                <div>
                  <h4 className="font-bold text-slate-400 mb-2 uppercase tracking-wider">Accumulated Forensic Scope</h4>
                  <ul className="space-y-3 bg-slate-950 p-4 rounded border border-slate-850/60 font-mono">
                    <li className="flex justify-between"><span className="text-slate-500">EVIDENCE PACKAGES:</span> <span className="text-slate-300">{evidenceList.length}</span></li>
                    <li className="flex justify-between"><span className="text-slate-500">PIPELINE RUNS:</span> <span className="text-slate-300">{analysesList.length}</span></li>
                    <li className="flex justify-between"><span className="text-slate-500">NORMALIZED IOCS:</span> <span className="text-cyan-400 font-bold">{indicatorsList.length}</span></li>
                    <li className="flex justify-between"><span className="text-slate-500">CORRELATIONS:</span> <span className="text-amber-400 font-bold">{correlationsList.length}</span></li>
                    <li className="flex justify-between"><span className="text-slate-500">THREAT INTEL FEEDS:</span> <span className="text-slate-300">{threatIntelList.length}</span></li>
                  </ul>
                </div>
              </div>

              {/* Risk Assessment Summary Preview Card */}
              {riskAssessment && (
                <div className="bg-slate-950 border border-slate-800 rounded p-5 space-y-3 font-mono">
                  <div className="flex justify-between items-center border-b border-slate-850/60 pb-2">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-cyan-400" />
                      <span className="font-bold text-slate-200 text-xs uppercase">Deterministic Risk & Explainability Summary</span>
                    </div>
                    <button 
                      onClick={() => setActiveTab('risk_assessment')}
                      className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-bold"
                    >
                      View Full Breakdown <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed font-sans">{riskAssessment.summary}</p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 2. UPLOADED EVIDENCE & EVIDENCE DETAILS TAB */}
          {/* ================================================================= */}
          {activeTab === 'evidence' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Evidence Packages & Provenance</h3>
                <span className="text-[10px] font-mono text-slate-500">{evidenceList.length} Files</span>
              </div>
              
              {/* Upload Form */}
              <form onSubmit={handleFileUpload} className="bg-slate-950 border border-slate-850 p-5 rounded space-y-3">
                <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
                  <div>
                    <h4 className="font-bold text-xs text-slate-300 uppercase tracking-wider">Add Evidence Package</h4>
                    <p className="text-[11px] text-slate-500">Upload APK package or Wireshark network capture (.pcap, .pcapng). File signatures are verified via magic bytes.</p>
                  </div>

                  <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
                    <input
                      type="file"
                      id="evidence-upload-input"
                      required
                      onChange={(e) => setSelectedFile(e.target.files ? e.target.files[0] : null)}
                      className="w-full sm:w-64 bg-slate-900 border border-slate-800 text-xs px-3 py-2 rounded text-slate-400 file:mr-4 file:py-1 file:px-2.5 file:rounded file:border-0 file:bg-cyan-950/40 file:text-cyan-400 file:text-xs file:font-bold hover:file:bg-cyan-900/30 cursor-pointer"
                    />
                    <button
                      type="submit"
                      disabled={uploadLoading || !selectedFile}
                      className="flex items-center justify-center gap-2 w-full sm:w-auto px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-slate-950 text-xs font-bold uppercase tracking-wider rounded transition-all shrink-0"
                    >
                      {uploadLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-4 w-4" />}
                      Upload File
                    </button>
                  </div>
                </div>

                {uploadProgress !== null && (
                  <div className="w-full bg-slate-900 border border-slate-800 p-3 rounded space-y-2">
                    <div className="flex justify-between text-xs font-mono text-cyan-400 font-bold">
                      <span>UPLOADING WITH AXIOS PROGRESS TRACKING...</span>
                      <span>{uploadProgress}%</span>
                    </div>
                    <div className="w-full bg-slate-800 h-2 rounded overflow-hidden">
                      <div 
                        className="bg-cyan-500 h-full rounded transition-all duration-200" 
                        style={{ width: `${uploadProgress}%` }}
                      />
                    </div>
                  </div>
                )}
                {uploadError && <p className="text-xs text-rose-400 font-semibold bg-rose-950/20 border border-rose-900/40 p-3 rounded">{uploadError}</p>}
              </form>

              {/* Evidence table */}
              {evidenceList.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-850 text-slate-400 uppercase tracking-wider font-mono">
                        <th className="py-3">File Name</th>
                        <th className="py-3">Format</th>
                        <th className="py-3">SHA-256 Hash</th>
                        <th className="py-3">Size</th>
                        <th className="py-3">Uploaded</th>
                        <th className="py-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850/40 font-mono text-slate-300">
                      {evidenceList.map((e) => (
                        <tr key={e.evidence_id} className="hover:bg-slate-800/20 transition-colors">
                          <td className="py-3.5 font-bold text-slate-200">
                            <button
                              onClick={() => setInspectEvidence(e)}
                              className="text-cyan-400 hover:underline text-left flex items-center gap-1.5"
                            >
                              <FileCode className="h-3.5 w-3.5" />
                              {e.file_name}
                            </button>
                          </td>
                          <td className="py-3.5">
                            <span className="px-2 py-0.5 border border-cyan-800/40 bg-cyan-950/20 text-cyan-400 text-[10px] rounded font-bold">
                              {e.file_type}
                            </span>
                          </td>
                          <td className="py-3.5 text-slate-400 text-[10px] truncate max-w-xs select-all" title={e.sha256}>
                            {e.sha256}
                          </td>
                          <td className="py-3.5 text-slate-400">{(e.file_size / 1024 / 1024).toFixed(2)} MB</td>
                          <td className="py-3.5 text-slate-500">{new Date(e.uploaded_at).toLocaleDateString()}</td>
                          <td className="py-3.5 text-right space-x-2">
                            <button
                              onClick={() => setInspectEvidence(e)}
                              title="Inspect Evidence Details"
                              className="text-slate-400 hover:text-cyan-400 p-1.5 rounded transition-colors inline-block"
                            >
                              <ExternalLink className="h-4 w-4" />
                            </button>
                            <button
                              onClick={() => handleDeleteEvidence(e.evidence_id)}
                              title="Delete Evidence"
                              className="text-rose-500 hover:text-rose-400 p-1.5 rounded transition-colors inline-block"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-16 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
                  <FileCode className="h-8 w-8 text-slate-700 mx-auto mb-2" />
                  <p className="text-xs text-slate-500 uppercase tracking-wider">No evidence uploaded yet. Add packages above to begin.</p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 3. ANALYSIS RUNS TAB */}
          {/* ================================================================= */}
          {activeTab === 'analysis' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Analysis Execution Pipeline</h3>
                <span className="text-[10px] font-mono text-slate-500">{analysesList.length} Jobs</span>
              </div>

              {/* Trigger Analysis Form */}
              <form onSubmit={handleTriggerAnalysis} className="bg-slate-950 border border-slate-850 p-5 rounded space-y-3">
                <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
                  <div>
                    <h4 className="font-bold text-xs text-slate-300 uppercase tracking-wider">Execute Forensic Parser</h4>
                    <p className="text-[11px] text-slate-500">Triggers MobSF/Androguard for APK or Scapy/tshark for network PCAP files.</p>
                  </div>

                  <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
                    <select
                      value={runEvidenceId}
                      onChange={(e) => setRunEvidenceId(e.target.value)}
                      className="w-full sm:w-56 bg-slate-900 border border-slate-800 px-3 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-cyan-500 cursor-pointer"
                    >
                      <option value="">SELECT EVIDENCE FILE...</option>
                      {evidenceList.map(ev => (
                        <option key={ev.evidence_id} value={ev.evidence_id}>{ev.file_name} ({ev.file_type})</option>
                      ))}
                    </select>

                    <select
                      value={runType}
                      onChange={(e) => setRunType(e.target.value as 'APK' | 'PCAP')}
                      className="w-full sm:w-28 bg-slate-900 border border-slate-800 px-3 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-cyan-500 cursor-pointer"
                    >
                      <option value="APK">APK STATIC</option>
                      <option value="PCAP">PCAP NET</option>
                    </select>

                    <button
                      type="submit"
                      disabled={runLoading || !runEvidenceId}
                      className="flex items-center justify-center gap-2 w-full sm:w-auto px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-slate-950 text-xs font-bold uppercase tracking-wider rounded transition-all shrink-0"
                    >
                      {runLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-4 w-4" />}
                      Execute
                    </button>
                  </div>
                </div>
                {runError && <p className="text-xs text-rose-400 font-semibold bg-rose-950/20 border border-rose-900/40 p-3 rounded">{runError}</p>}
              </form>

              {/* Analysis runs listing */}
              {analysesList.length > 0 ? (
                <div className="space-y-4">
                  {analysesList.map((run) => (
                    <div key={run.analysis_id} className="bg-slate-950 border border-slate-850 rounded p-5 space-y-4 font-mono text-xs">
                      <div className="flex justify-between items-start gap-4 border-b border-slate-850/60 pb-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-slate-200">Run ID: {run.analysis_id.slice(0, 8)}...</span>
                            <span className="text-[10px] text-slate-500 uppercase">({run.analysis_type} Run)</span>
                          </div>
                          <span className="text-[10px] text-slate-500 block mt-1">Started: {new Date(run.started_at).toLocaleString()}</span>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-slate-400">Stage: <strong className="text-cyan-400">{run.current_stage}</strong></span>
                          <span className={`px-2 py-0.5 text-[9px] font-bold border rounded ${
                            run.status === 'COMPLETED' ? 'border-emerald-800/40 bg-emerald-950/20 text-emerald-400' :
                            run.status === 'PARTIAL' ? 'border-amber-800/40 bg-amber-950/20 text-amber-400' :
                            run.status === 'FAILED' ? 'border-rose-800/40 bg-rose-950/20 text-rose-500' :
                            'border-slate-800 text-slate-500 animate-pulse'
                          }`}>
                            {run.status}
                          </span>
                        </div>
                      </div>

                      {/* Providers breakdown */}
                      <div>
                        <h4 className="font-bold text-slate-400 text-[10px] uppercase mb-2 tracking-wide">Analysis Providers</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {Object.entries(run.provider_results || {}).map(([prov, record]) => (
                            <div key={prov} className="bg-slate-900 border border-slate-850 p-3 rounded flex justify-between items-center text-[11px]">
                              <div>
                                <span className="font-bold text-slate-300 uppercase">{prov}</span>
                                <span className="text-[10px] text-slate-500 block mt-0.5">v{record.provider_version || 'unknown'}</span>
                              </div>
                              <span className={`px-2 py-0.5 text-[9px] font-bold border rounded ${
                                record.status === 'COMPLETED' ? 'border-emerald-800/20 bg-emerald-950/10 text-emerald-400' :
                                record.status === 'DISABLED' ? 'border-slate-800 bg-slate-800/20 text-slate-600' :
                                record.status === 'UNAVAILABLE' ? 'border-amber-800/20 bg-amber-950/10 text-amber-500' :
                                'border-rose-800/20 bg-rose-950/10 text-rose-500'
                              }`}>
                                {record.status}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-16 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
                  <p className="text-xs text-slate-500 uppercase tracking-wider">No analysis jobs executed yet.</p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 4. APK FINDINGS TAB */}
          {/* ================================================================= */}
          {activeTab === 'apk_findings' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Static Android APK Findings</h3>
                <span className="text-[10px] font-mono text-slate-500">{apkObservations.length} Observations</span>
              </div>

              {apkObservations.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-850 text-slate-400 uppercase tracking-wider font-mono">
                        <th className="py-3">Observation Type</th>
                        <th className="py-3">Value / Detail</th>
                        <th className="py-3">Confidence</th>
                        <th className="py-3">Evidence ID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850/40 font-mono text-slate-300">
                      {apkObservations.map((obs) => (
                        <tr key={obs.observation_id} className="hover:bg-slate-800/20 transition-colors">
                          <td className="py-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              obs.observation_type.includes('SUSPICIOUS') ? 'bg-amber-950/40 border-amber-800 text-amber-400' :
                              obs.observation_type.includes('PERMISSION') ? 'bg-purple-950/40 border-purple-800 text-purple-400' :
                              'bg-slate-800 border-slate-700 text-slate-300'
                            }`}>
                              {obs.observation_type}
                            </span>
                          </td>
                          <td className="py-3 font-bold text-slate-100 select-all max-w-md truncate" title={obs.value}>
                            {obs.value}
                          </td>
                          <td className="py-3 text-slate-400">{obs.confidence}</td>
                          <td className="py-3 text-slate-500 text-[10px] truncate max-w-xs">{obs.evidence_id}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-16 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
                  <FileCheck2 className="h-8 w-8 text-slate-700 mx-auto mb-2" />
                  <p className="text-xs text-slate-500 uppercase tracking-wider">No APK observations recorded. Run an APK analysis job to inspect findings.</p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 5. NETWORK FINDINGS TAB */}
          {/* ================================================================= */}
          {activeTab === 'network_findings' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Network PCAP Traffic Findings</h3>
                <span className="text-[10px] font-mono text-slate-500">{networkObservations.length} Observations</span>
              </div>

              {networkObservations.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-850 text-slate-400 uppercase tracking-wider font-mono">
                        <th className="py-3">Type</th>
                        <th className="py-3">Observed Value</th>
                        <th className="py-3">Timestamp</th>
                        <th className="py-3">Metadata</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850/40 font-mono text-slate-300">
                      {networkObservations.map((obs) => (
                        <tr key={obs.observation_id} className="hover:bg-slate-800/20 transition-colors">
                          <td className="py-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              obs.observation_type.includes('REPEATED') ? 'bg-rose-950/40 border-rose-800 text-rose-400' :
                              obs.observation_type.includes('DNS') ? 'bg-cyan-950/40 border-cyan-800 text-cyan-400' :
                              'bg-sky-950/40 border-sky-800 text-sky-400'
                            }`}>
                              {obs.observation_type}
                            </span>
                          </td>
                          <td className="py-3 font-bold text-cyan-300 select-all max-w-sm truncate" title={obs.value}>
                            {obs.value}
                          </td>
                          <td className="py-3 text-slate-400 text-[10px]">
                            {obs.timestamp ? new Date(obs.timestamp).toLocaleTimeString() : 'Unspecified'}
                          </td>
                          <td className="py-3 text-slate-500 text-[10px] truncate max-w-xs">
                            {JSON.stringify(obs.metadata || {})}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-16 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
                  <Radio className="h-8 w-8 text-slate-700 mx-auto mb-2" />
                  <p className="text-xs text-slate-500 uppercase tracking-wider">No PCAP network observations recorded. Run a PCAP analysis job to view traffic findings.</p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 6. INDICATORS (IOCS) TAB */}
          {/* ================================================================= */}
          {activeTab === 'indicators' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-slate-850 pb-2">
                <div>
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Normalized Indicators of Compromise</h3>
                  <p className="text-[11px] text-slate-500">Deduplicated across static and network evidence sources</p>
                </div>
                <div className="relative w-full sm:w-56">
                  <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search IOCs..."
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 pl-8 pr-3 py-1.5 text-xs rounded text-slate-300 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              {indicatorsList.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-850 text-slate-400 uppercase tracking-wider font-mono">
                        <th className="py-3">Type</th>
                        <th className="py-3">Normalized Value</th>
                        <th className="py-3">Original Value</th>
                        <th className="py-3">Extracted Date</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850/40 font-mono text-slate-300">
                      {indicatorsList
                        .filter(i => !searchFilter || i.value.toLowerCase().includes(searchFilter.toLowerCase()) || i.type.toLowerCase().includes(searchFilter.toLowerCase()))
                        .map((ind) => (
                          <tr key={ind.indicator_id} className="hover:bg-slate-800/20 transition-colors">
                            <td className="py-3">
                              <span className="px-2 py-0.5 border border-slate-700 bg-slate-800 text-slate-300 text-[10px] rounded font-bold uppercase">
                                {ind.type}
                              </span>
                            </td>
                            <td className="py-3 font-bold text-cyan-400 select-all max-w-sm truncate" title={ind.normalized_value}>
                              {ind.normalized_value}
                            </td>
                            <td className="py-3 text-slate-400 select-all max-w-xs truncate" title={ind.value}>
                              {ind.value}
                            </td>
                            <td className="py-3 text-slate-500 text-[10px]">{new Date(ind.created_at).toLocaleDateString()}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-16 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
                  <ShieldAlert className="h-8 w-8 text-slate-700 mx-auto mb-2" />
                  <p className="text-xs text-slate-500 uppercase tracking-wider">No indicators extracted yet.</p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 7. CORRELATIONS TAB */}
          {/* ================================================================= */}
          {activeTab === 'correlations' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <div>
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Deterministic Evidence Correlations</h3>
                  <p className="text-[11px] text-slate-500">Cross-evidence corroborated relationships (Rules 1-7)</p>
                </div>
                <span className="text-[10px] font-mono text-slate-500">{correlationsList.length} Rules Matched</span>
              </div>

              {correlationsList.length > 0 ? (
                <div className="space-y-3">
                  {correlationsList.map((corr) => (
                    <div key={corr.correlation_id} className="bg-slate-950 border border-slate-850 p-4 rounded space-y-2 font-mono text-xs">
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded font-bold text-[10px] bg-amber-950/60 border border-amber-700 text-amber-300">
                            {corr.relationship_type}
                          </span>
                          <span className="text-[10px] text-slate-500">ID: {corr.correlation_id.slice(0, 8)}...</span>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          corr.strength === 'STRONG' ? 'bg-emerald-950/40 border-emerald-700 text-emerald-400' :
                          corr.strength === 'MODERATE' ? 'bg-amber-950/40 border-amber-700 text-amber-400' :
                          'bg-slate-800 border-slate-700 text-slate-400'
                        }`}>
                          {corr.strength} STRENGTH
                        </span>
                      </div>

                      <p className="text-slate-200 font-sans text-xs bg-slate-900/60 p-2.5 rounded border border-slate-850 leading-relaxed">
                        {corr.reason}
                      </p>

                      <div className="flex flex-wrap gap-4 text-[10px] text-slate-500 pt-1">
                        <span>Source Obs: {corr.source_observation_ids?.length || 0}</span>
                        <span>Target Obs: {corr.target_observation_ids?.length || 0}</span>
                        <span>Evidence Files: {corr.supporting_evidence_ids?.length || 0}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-16 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
                  <Layers className="h-8 w-8 text-slate-700 mx-auto mb-2" />
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-widest">No Correlations Identified</h4>
                  <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
                    Deterministic correlations require both APK and PCAP evidence with shared domains, IPs, or periodic communication flows.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 8. THREAT INTELLIGENCE TAB */}
          {/* ================================================================= */}
          {activeTab === 'threat_intel' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-slate-850 pb-2">
                <div>
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">External Threat Intelligence Feeds</h3>
                  <p className="text-[11px] text-slate-500">VirusTotal, URLhaus, AbuseIPDB, AlienVault OTX</p>
                </div>
                <button
                  onClick={handleTriggerEnrichment}
                  disabled={enriching}
                  className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-slate-950 text-xs font-bold uppercase rounded transition-all"
                >
                  {enriching ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                  Enrich Case Indicators
                </button>
              </div>

              {threatIntelList.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-slate-850 text-slate-400 uppercase tracking-wider font-mono">
                        <th className="py-3">Provider</th>
                        <th className="py-3">Indicator</th>
                        <th className="py-3">Verdict</th>
                        <th className="py-3">Score</th>
                        <th className="py-3">Categories</th>
                        <th className="py-3">Checked</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850/40 font-mono text-slate-300">
                      {threatIntelList.map((ti) => (
                        <tr key={ti.threat_intel_id} className="hover:bg-slate-800/20 transition-colors">
                          <td className="py-3.5 font-bold text-slate-200">{ti.provider}</td>
                          <td className="py-3.5 font-bold text-cyan-400 select-all max-w-xs truncate" title={ti.indicator}>
                            {ti.indicator}
                          </td>
                          <td className="py-3.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              ti.verdict === 'MALICIOUS' ? 'bg-rose-950/60 border-rose-700 text-rose-400' :
                              ti.verdict === 'SUSPICIOUS' ? 'bg-amber-950/60 border-amber-700 text-amber-400' :
                              ti.verdict === 'BENIGN' ? 'bg-emerald-950/60 border-emerald-700 text-emerald-400' :
                              'bg-slate-800 border-slate-700 text-slate-400'
                            }`}>
                              {ti.verdict}
                            </span>
                          </td>
                          <td className="py-3.5 text-slate-400">{ti.score ?? 'N/A'}</td>
                          <td className="py-3.5 text-slate-400 text-[10px] max-w-xs truncate">
                            {ti.categories?.length > 0 ? ti.categories.join(', ') : 'None'}
                          </td>
                          <td className="py-3.5 text-slate-500 text-[10px]">{new Date(ti.checked_at).toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-16 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
                  <Globe className="h-8 w-8 text-slate-700 mx-auto mb-2" />
                  <h4 className="text-xs font-bold text-slate-300 uppercase tracking-widest">No Threat Intel Records</h4>
                  <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
                    Click "Enrich Case Indicators" above to query configured external threat intelligence feeds for public domains and IPs.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 9. RISK ASSESSMENT & EXPLAINABILITY TAB */}
          {/* ================================================================= */}
          {activeTab === 'risk_assessment' && (
            <div className="space-y-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-slate-850 pb-2">
                <div>
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Deterministic Risk & Explainability Engine</h3>
                  <p className="text-[11px] text-slate-500">Evidence-weighted assessment strictly separating observed facts from inferences</p>
                </div>
                <button
                  onClick={handleRecalculateRisk}
                  disabled={assessing}
                  className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-bold uppercase rounded border border-slate-700 transition-all"
                >
                  {assessing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                  Recalculate Assessment
                </button>
              </div>

              {riskAssessment ? (
                <div className="space-y-6">
                  {/* Executive Metric Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono">
                    <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-500 uppercase block">DETERMINISTIC RISK LEVEL</span>
                      <span className={`text-2xl font-bold ${
                        riskAssessment.risk_level === 'CRITICAL' ? 'text-rose-500' :
                        riskAssessment.risk_level === 'HIGH' ? 'text-amber-500' :
                        riskAssessment.risk_level === 'MEDIUM' ? 'text-yellow-400' :
                        'text-emerald-400'
                      }`}>
                        {riskAssessment.risk_level}
                      </span>
                    </div>
                    <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-500 uppercase block">EVIDENCE STRENGTH</span>
                      <span className="text-2xl font-bold text-slate-100">{riskAssessment.evidence_strength}</span>
                    </div>
                    <div className="bg-slate-950 p-4 rounded border border-slate-800 space-y-1">
                      <span className="text-[10px] text-slate-500 uppercase block">CONFIDENCE GAUGE</span>
                      <span className="text-2xl font-bold text-cyan-400">{(riskAssessment.confidence * 100).toFixed(0)}%</span>
                      <span className="text-[9px] text-slate-600 block">(calibrated, never 100%)</span>
                    </div>
                  </div>

                  {/* Summary */}
                  <div className="bg-slate-950 border border-slate-850 p-4 rounded space-y-2">
                    <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Synthesis Summary</h4>
                    <p className="text-xs text-slate-300 leading-relaxed font-sans">{riskAssessment.summary}</p>
                  </div>

                  {/* OBSERVED FACTS vs INFERENCES (Side-by-side comparison) */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Observed Facts */}
                    <div className="bg-slate-950 border border-cyan-900/30 p-4 rounded space-y-3">
                      <div className="flex items-center gap-2 border-b border-slate-850 pb-2">
                        <CheckCircle2 className="h-4 w-4 text-cyan-400" />
                        <h4 className="text-xs font-bold text-cyan-300 uppercase tracking-wider font-mono">Observed Ground-Truth Facts</h4>
                      </div>
                      <ul className="space-y-2 text-xs text-slate-300 list-disc list-inside">
                        {riskAssessment.observed_facts?.length > 0 ? (
                          riskAssessment.observed_facts.map((fact, idx) => (
                            <li key={idx} className="leading-relaxed">{fact}</li>
                          ))
                        ) : (
                          <li className="text-slate-500">No static or network facts recorded.</li>
                        )}
                      </ul>
                    </div>

                    {/* Inferences */}
                    <div className="bg-slate-950 border border-amber-900/30 p-4 rounded space-y-3">
                      <div className="flex items-center gap-2 border-b border-slate-850 pb-2">
                        <Layers className="h-4 w-4 text-amber-400" />
                        <h4 className="text-xs font-bold text-amber-300 uppercase tracking-wider font-mono">Analytical Inferences</h4>
                      </div>
                      <ul className="space-y-2 text-xs text-slate-300 list-disc list-inside">
                        {riskAssessment.inferences?.length > 0 ? (
                          riskAssessment.inferences.map((inf, idx) => (
                            <li key={idx} className="leading-relaxed">{inf}</li>
                          ))
                        ) : (
                          <li className="text-slate-500">No multi-source cross-correlations established.</li>
                        )}
                      </ul>
                    </div>
                  </div>

                  {/* Possible Interpretations & Uncertainty */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-slate-950 border border-slate-800 p-4 rounded space-y-2">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-2">
                        <HelpCircle className="h-3.5 w-3.5 text-slate-400" /> Possible Interpretations
                      </h4>
                      <div className="space-y-1.5 text-xs text-slate-300">
                        {riskAssessment.possible_interpretations?.map((interp, idx) => (
                          <p key={idx} className="leading-relaxed">&bull; {interp}</p>
                        ))}
                      </div>
                    </div>

                    <div className="bg-slate-950 border border-slate-800 p-4 rounded space-y-2">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono flex items-center gap-2">
                        <AlertTriangle className="h-3.5 w-3.5 text-amber-400" /> Documented Uncertainty
                      </h4>
                      <div className="space-y-1.5 text-xs text-slate-400">
                        {riskAssessment.uncertainty?.map((u, idx) => (
                          <p key={idx} className="leading-relaxed">&bull; {u}</p>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Actionable Analyst Guidance */}
                  <div className="bg-slate-950 border border-slate-800 p-4 rounded space-y-2">
                    <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider font-mono">Actionable Analyst Guidance</h4>
                    <div className="space-y-1.5 text-xs text-cyan-300 font-mono">
                      {riskAssessment.analyst_guidance?.map((guide, idx) => (
                        <div key={idx} className="flex items-start gap-2">
                          <span className="text-cyan-500">&gt;</span>
                          <p className="leading-relaxed">{guide}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="py-16 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
                  <ShieldQuestion className="h-8 w-8 text-slate-700 mx-auto mb-2" />
                  <p className="text-xs text-slate-500 uppercase tracking-wider">No risk assessment generated yet.</p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 10. ATTACK GRAPH TAB */}
          {/* ================================================================= */}
          {activeTab === 'attack_graph' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <div>
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Interactive Attack Chain Provenance Graph</h3>
                  <p className="text-[11px] text-slate-500">React Flow canvas. Click any node or edge to inspect supporting evidence references.</p>
                </div>
                <span className="text-[10px] font-mono text-purple-400 font-bold">
                  {graphData.nodes.length} Nodes &bull; {graphData.edges.length} Edges
                </span>
              </div>

              <AttackGraphCanvas 
                nodesData={graphData.nodes} 
                edgesData={graphData.edges} 
                height="560px" 
              />
            </div>
          )}

          {/* ================================================================= */}
          {/* 11. TIMELINE TAB */}
          {/* ================================================================= */}
          {activeTab === 'timeline' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <div>
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">Forensic Chronological Timeline</h3>
                  <p className="text-[11px] text-slate-500">Events rendered strictly with authentic observation timestamps (no fabricated dates)</p>
                </div>
                <Clock className="h-4 w-4 text-cyan-400" />
              </div>

              {(() => {
                interface TimelineItem {
                  title: string;
                  desc: string;
                  date: Date;
                  type: 'CASE' | 'EVIDENCE' | 'RUN' | 'NETWORK' | 'INTEL';
                }

                const events: TimelineItem[] = [
                  { 
                    title: 'Case File Created', 
                    desc: 'Investigation formally created on the MongoDB persistence layer.', 
                    date: new Date(caseObj.created_at),
                    type: 'CASE'
                  }
                ];

                evidenceList.forEach(e => {
                  events.push({
                    title: `Evidence Uploaded: ${e.file_name}`,
                    desc: `Format: ${e.file_type} | SHA-256: ${e.sha256.slice(0, 16)}...`,
                    date: new Date(e.uploaded_at || e.created_at),
                    type: 'EVIDENCE'
                  });
                });

                analysesList.forEach(run => {
                  events.push({
                    title: `Analysis Executed (${run.analysis_type})`,
                    desc: `Job ID: ${run.analysis_id.slice(0, 8)}... | Status: ${run.status}`,
                    date: new Date(run.started_at || run.created_at),
                    type: 'RUN'
                  });
                });

                // Network Observations with valid timestamps
                networkObservations.forEach(obs => {
                  if (obs.timestamp) {
                    events.push({
                      title: `Network Event: ${obs.observation_type}`,
                      desc: `Observed: ${obs.value}`,
                      date: new Date(obs.timestamp),
                      type: 'NETWORK'
                    });
                  }
                });

                // Threat Intel checks
                threatIntelList.forEach(ti => {
                  if (ti.checked_at) {
                    events.push({
                      title: `Threat Intel Query: ${ti.provider}`,
                      desc: `Indicator: ${ti.indicator} | Verdict: ${ti.verdict}`,
                      date: new Date(ti.checked_at),
                      type: 'INTEL'
                    });
                  }
                });

                // Sort chronological descending
                events.sort((a, b) => b.date.getTime() - a.date.getTime());

                return (
                  <div className="space-y-6 pl-4 border-l border-slate-850 relative font-mono text-xs">
                    {events.map((ev, i) => (
                      <div key={i} className="relative space-y-1">
                        <span className={`absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full border border-slate-900 ${
                          ev.type === 'NETWORK' ? 'bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.6)]' :
                          ev.type === 'INTEL' ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.6)]' :
                          ev.type === 'EVIDENCE' ? 'bg-emerald-400' :
                          'bg-slate-500'
                        }`}></span>
                        <div className="flex items-center gap-2">
                          <h4 className="font-bold text-slate-200">{ev.title}</h4>
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-950 border border-slate-800 text-slate-400">
                            {ev.type}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 font-sans">{ev.desc}</p>
                        <span className="text-[10px] text-slate-500 block pt-1">{ev.date.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </div>
          )}

          {/* ================================================================= */}
          {/* 12. REPORTS TAB */}
          {/* ================================================================= */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-slate-850 pb-2">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                  Case Investigation Reports & Exports
                </h3>
                <span className="text-[10px] font-mono text-cyan-400">
                  {reportsList.length} Generated Dossier(s)
                </span>
              </div>
              
              {/* Report Generator Box */}
              <div className="bg-slate-950 border border-slate-850 p-6 rounded space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Compile New Investigation Dossier</h4>
                  <p className="text-[11px] text-slate-500 mt-0.5">
                    Renders all 13 forensic sections directly from stored database records, with strict separation between observed facts and inferences.
                  </p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="md:col-span-2">
                    <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">
                      Dossier Title
                    </label>
                    <input
                      type="text"
                      value={reportTitle}
                      onChange={(e) => setReportTitle(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-800 px-3 py-2 text-xs text-slate-200 rounded focus:outline-none focus:border-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-1">
                      Output Format
                    </label>
                    <select
                      value={reportFormat}
                      onChange={(e) => setReportFormat(e.target.value as any)}
                      className="w-full bg-slate-900 border border-slate-800 px-3 py-2 text-xs text-slate-200 rounded focus:outline-none focus:border-cyan-500 cursor-pointer"
                    >
                      <option value="BOTH">HTML + PDF Export</option>
                      <option value="HTML">Interactive HTML Only</option>
                      <option value="PDF">ReportLab PDF Dossier Only</option>
                    </select>
                  </div>
                </div>

                <div className="pt-2 flex justify-end">
                  <button
                    disabled={generatingReport}
                    onClick={async () => {
                      try {
                        setGeneratingReport(true);
                        await apiService.generateReport(caseId, reportFormat, reportTitle);
                        const updated = await apiService.getReportsForCase(caseId);
                        setReportsList(updated.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()));
                      } catch (err: any) {
                        alert('Report generation failed: ' + (err.response?.data?.detail || err.message));
                      } finally {
                        setGeneratingReport(false);
                      }
                    }}
                    className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-slate-950 disabled:text-slate-500 text-xs font-bold uppercase tracking-wider rounded transition-colors"
                  >
                    {generatingReport ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span>Compiling Dossier...</span>
                      </>
                    ) : (
                      <>
                        <FileText className="h-4 w-4" />
                        <span>Generate Case Report</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Reports History */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Available Case Reports</h4>
                
                {reportsList.length === 0 ? (
                  <div className="py-10 text-center border border-dashed border-slate-850 rounded bg-slate-950/20">
                    <FileText className="h-8 w-8 text-slate-700 mx-auto mb-2" />
                    <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">No Reports Generated For This Case</p>
                    <p className="text-[11px] text-slate-500 mt-1 max-w-sm mx-auto">
                      Click "Generate Case Report" above to compile a reproducible report containing real evidence, attack chain, and risk assessment findings.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {reportsList.map((rep) => (
                      <div
                        key={rep.report_id}
                        className="p-3 bg-slate-950 border border-slate-850 rounded flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 hover:border-slate-700 transition-colors"
                      >
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-slate-200">{rep.title}</span>
                            <span className="text-[9px] font-mono px-1.5 py-0.5 bg-cyan-950/50 border border-cyan-800/40 text-cyan-400 rounded uppercase">
                              {rep.report_format}
                            </span>
                            <span className="text-[9px] font-mono px-1.5 py-0.5 bg-emerald-950/50 border border-emerald-800/40 text-emerald-400 rounded">
                              {rep.status}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500 mt-0.5">
                            <span>ID: {rep.report_id.slice(0, 8)}...</span>
                            <span>&bull;</span>
                            <span>{rep.generated_at ? new Date(rep.generated_at).toLocaleString() : 'N/A'}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          {(rep.report_format === 'HTML' || rep.report_format === 'BOTH') && rep.html_path && (
                            <a
                              href={apiService.getReportDownloadUrl(caseId, rep.report_id, 'html')}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-750 text-cyan-400 hover:text-cyan-300 text-xs font-mono rounded transition-colors"
                            >
                              <ExternalLink className="h-3 w-3" />
                              <span>View HTML</span>
                            </a>
                          )}

                          {(rep.report_format === 'PDF' || rep.report_format === 'BOTH') && rep.pdf_path && (
                            <a
                              href={apiService.getReportDownloadUrl(caseId, rep.report_id, 'pdf')}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 px-2.5 py-1.5 bg-cyan-950/50 hover:bg-cyan-900/50 border border-cyan-800/50 text-cyan-300 text-xs font-mono rounded transition-colors"
                            >
                              <Download className="h-3 w-3" />
                              <span>Download PDF</span>
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

        </div>
      </div>

      {/* ===================================================================== */}
      {/* EVIDENCE DRILL-DOWN MODAL */}
      {/* ===================================================================== */}
      {inspectEvidence && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-cyan-800/80 rounded-lg max-w-2xl w-full p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex justify-between items-start border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-bold text-cyan-400 uppercase tracking-wider block">Evidence File Details</span>
                <h3 className="text-base font-bold text-slate-100">{inspectEvidence.file_name}</h3>
              </div>
              <button 
                onClick={() => setInspectEvidence(null)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                &times;
              </button>
            </div>

            <div className="space-y-2">
              <div className="grid grid-cols-2 gap-3 bg-slate-950 p-3 rounded border border-slate-800">
                <div>
                  <span className="text-slate-500 text-[10px] block">EVIDENCE ID</span>
                  <span className="text-slate-300 select-all">{inspectEvidence.evidence_id}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">FORMAT</span>
                  <span className="text-cyan-400 font-bold">{inspectEvidence.file_type}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">FILE SIZE</span>
                  <span className="text-slate-300">{(inspectEvidence.file_size / 1024 / 1024).toFixed(2)} MB</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] block">UPLOAD TIMESTAMP</span>
                  <span className="text-slate-300">{new Date(inspectEvidence.uploaded_at).toLocaleString()}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-500 text-[10px] block">SHA-256 HASH PROVENANCE</span>
                <p className="bg-slate-950 p-2.5 rounded border border-slate-800 text-slate-300 select-all break-all text-[11px]">
                  {inspectEvidence.sha256}
                </p>
              </div>

              <div>
                <span className="text-slate-500 text-[10px] block">ASSOCIATED OBSERVATIONS ({observationsList.filter(o => o.evidence_id === inspectEvidence.evidence_id).length})</span>
                <div className="bg-slate-950 p-2.5 rounded border border-slate-800 max-h-48 overflow-y-auto space-y-1.5">
                  {observationsList.filter(o => o.evidence_id === inspectEvidence.evidence_id).map((obs, idx) => (
                    <div key={idx} className="flex justify-between items-center text-[10px] border-b border-slate-850/50 pb-1">
                      <span className="text-cyan-400">{obs.observation_type}:</span>
                      <span className="text-slate-300 truncate max-w-xs">{obs.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setInspectEvidence(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold uppercase rounded"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default InvestigationDetails;
