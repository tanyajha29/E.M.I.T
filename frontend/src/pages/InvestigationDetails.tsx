import React, { useEffect, useState, useCallback } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
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
import { AnalysisRunPanel } from '../components/AnalysisRunPanel';
import { 
  Loader2, 
  FileCode, 
  Cpu, 
  ShieldAlert, 
  Layers, 
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
  Radio,
  FileCheck2,
  ShieldQuestion,
  ChevronRight,
  Download,
  Copy,
  Check,
  X,
  Shield
} from 'lucide-react';
import { StatusBadge } from '../components/ui/StatusBadge';
import { RiskBadge } from '../components/ui/RiskBadge';
import { LoadingSkeleton } from '../components/ui/LoadingSkeleton';
import { ErrorState } from '../components/ui/ErrorState';
import { EmptyState } from '../components/ui/EmptyState';
import { useUser } from '../context/UserContext';

export const InvestigationDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const caseId = id || '';
  const navigate = useNavigate();
  const { currentUser, filterMode, setFilterMode, isCaseAssigned } = useUser();
  const [deletingCase, setDeletingCase] = useState(false);
  const [deletingRunId, setDeletingRunId] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<
    'overview' | 'evidence' | 'analysis' | 'apk_findings' | 'network_findings' | 
    'indicators' | 'correlations' | 'threat_intel' | 'risk_assessment' | 'attack_graph' | 'reports'
  >('overview');
  
  // Data State
  const [caseObj, setCaseObj] = useState<Case | null>(null);
  const [evidenceList, setEvidenceList] = useState<EvidenceFile[]>([]);
  const [analysesList, setAnalysesList] = useState<AnalysisRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
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
  const [reportSuccess, setReportSuccess] = useState<string | null>(null);

  // Selected Evidence for Drill-down Drawer
  const [inspectEvidence, setInspectEvidence] = useState<EvidenceFile | null>(null);
  const [selectedIoc, setSelectedIoc] = useState<Indicator | null>(null);

  // Copy feedback state
  const [copiedId, setCopiedId] = useState<string | null>(null);

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
  const [iocFilter, setIocFilter] = useState('');
  const [iocTypeFilter, setIocTypeFilter] = useState('ALL');

  const copyToClipboard = (text: string, idStr: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(idStr);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const loadCaseData = useCallback(async (showLoading = true) => {
    if (!caseId) return;
    try {
      if (showLoading) {
        setLoading(true);
      }
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
      setEvidenceList(Array.isArray(evidenceData) ? evidenceData : []);
      const runs = Array.isArray(analysesData) ? analysesData : [];
      setAnalysesList(runs);

      // Auto-select active running analysis or latest run
      setSelectedRunId(prevSelected => {
        if (prevSelected && runs.some(r => r.analysis_id === prevSelected)) {
          return prevSelected;
        }
        const activeRun = runs.find(r => 
          ['PENDING', 'STARTING', 'RUNNING', 'ANALYZING', 'NORMALIZING', 'CORRELATING', 'BUILDING_GRAPH'].includes((r.status || '').toUpperCase())
        );
        if (activeRun) return activeRun.analysis_id;
        if (runs.length > 0) return runs[0].analysis_id;
        return null;
      });

      setIndicatorsList(Array.isArray(indicatorsData) ? indicatorsData : []);
      setObservationsList(Array.isArray(obsData) ? obsData : []);
      setCorrelationsList(Array.isArray(corrData) ? corrData : []);
      setThreatIntelList(Array.isArray(threatData) ? threatData : []);
      setRiskAssessment(riskData);
      setGraphData(graphRes && typeof graphRes === 'object' && Array.isArray(graphRes.nodes) ? graphRes : { nodes: [], edges: [] });
      setReportsList(Array.isArray(repData) ? repData.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()) : []);
    } catch (err) {
      console.error('Failed to load investigation details:', err);
      setError(true);
    } finally {
      if (showLoading) {
        setLoading(false);
      }
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
    if (!selectedFile) {
      setUploadError('Please choose an APK or PCAP file to upload');
      return;
    }

    try {
      setUploadLoading(true);
      setUploadError(null);
      setUploadProgress(0);

      await apiService.uploadEvidence(caseId, selectedFile, (percent) => {
        setUploadProgress(percent);
      });

      setSelectedFile(null);
      setUploadProgress(null);
      await loadCaseData();
    } catch (err: any) {
      console.error('Upload failed:', err);
      setUploadError(err.response?.data?.detail || 'File ingest and cryptographic hashing failed.');
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

  const handleDeleteCase = async () => {
    if (!caseObj) return;
    if (!window.confirm(`Are you sure you want to permanently delete investigation dossier "${caseObj.name}"?\n\nThis will remove all evidence files, pipeline runs, IOCs, observations, and generated reports.`)) {
      return;
    }
    try {
      setDeletingCase(true);
      await apiService.deleteCase(caseId);
      navigate('/investigations');
    } catch (err: any) {
      console.error('Delete case failed:', err);
      alert(err.response?.data?.detail || 'Failed to delete case.');
      setDeletingCase(false);
    }
  };

  const handleDeleteAnalysisRun = async (analysisId: string) => {
    if (!window.confirm('Are you sure you want to permanently delete this analysis execution run and its provider results? This action cannot be undone.')) {
      return;
    }
    try {
      setDeletingRunId(analysisId);
      await apiService.deleteAnalysisRun(caseId, analysisId);
      setAnalysesList(prev => prev.filter(r => r.analysis_id !== analysisId));
      if (selectedRunId === analysisId) {
        setSelectedRunId(null);
      }
      await loadCaseData();
    } catch (err: any) {
      console.error('Delete analysis run failed:', err);
      alert(err.response?.data?.detail || 'Failed to delete analysis run.');
    } finally {
      setDeletingRunId(null);
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
      const newRun = await apiService.triggerAnalysis(caseId, runEvidenceId, runType);
      setRunEvidenceId('');
      if (newRun && newRun.analysis_id) {
        setAnalysesList(prev => [newRun, ...prev.filter(r => r.analysis_id !== newRun.analysis_id)]);
        setSelectedRunId(newRun.analysis_id);
      } else {
        await loadCaseData();
      }
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
      setThreatIntelList(Array.isArray(enriched) ? enriched : []);
      const [updatedRisk, updatedGraph] = await Promise.all([
        apiService.getRiskAssessmentForCase(caseId).catch(() => null),
        apiService.getGraphForCase(caseId).catch(() => ({ nodes: [], edges: [] }))
      ]);
      setRiskAssessment(updatedRisk);
      setGraphData(updatedGraph && typeof updatedGraph === 'object' && Array.isArray(updatedGraph.nodes) ? updatedGraph : { nodes: [], edges: [] });
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

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setGeneratingReport(true);
      setReportSuccess(null);
      await apiService.generateReport(caseId, reportFormat, reportTitle);
      setReportSuccess('Forensic Dossier successfully compiled and stored.');
      const reps = await apiService.getReportsForCase(caseId);
      setReportsList(Array.isArray(reps) ? reps.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()) : []);
    } catch (err: any) {
      console.error('Report compilation failed:', err);
      alert('Report generation failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setGeneratingReport(false);
    }
  };

  // Filtered views
  const apkObservations = (observationsList || []).filter(o => o && o.source === 'APK');
  const networkObservations = (observationsList || []).filter(o => o && o.source === 'PCAP');

  const filteredIocs = (indicatorsList || []).filter(ioc => {
    if (!ioc) return false;
    const val = String(ioc.value || '').toLowerCase();
    const norm = String(ioc.normalized_value || '').toLowerCase();
    const query = iocFilter.toLowerCase();
    const matchSearch = !iocFilter || val.includes(query) || norm.includes(query);
    const matchType = iocTypeFilter === 'ALL' || String(ioc.type || '').toUpperCase() === iocTypeFilter;
    return matchSearch && matchType;
  });

  const iocTypes = Array.from(new Set((indicatorsList || []).filter(Boolean).map(i => String(i.type || '').toUpperCase())));

  if (loading) {
    return (
      <div className="space-y-6 font-mono text-white">
        <div>
          <div className="h-6 w-60 bg-[#181818] rounded animate-pulse mb-2" />
          <div className="h-4 w-96 bg-[#181818] rounded animate-pulse" />
        </div>
        <LoadingSkeleton type="metrics" />
        <LoadingSkeleton type="table" rows={6} />
      </div>
    );
  }

  // Frontend Restricted Guard: If in My Cases filter mode and this case is not assigned to current investigator
  const isAssigned = isCaseAssigned(caseId);
  if (!isAssigned && filterMode === 'MY_CASES') {
    return (
      <div className="font-mono text-xs flex flex-col items-center justify-center min-h-[60vh] p-6 text-center space-y-4 text-white">
        <div className="p-4 rounded-full bg-[#FF3333]/15 border border-[#FF3333]/40 text-[#FF3333] shadow-[0_0_20px_rgba(255,51,51,0.25)]">
          <ShieldAlert className="h-10 w-10 animate-pulse" />
        </div>
        <div>
          <h2 className="text-base font-bold uppercase tracking-wider text-white">
            Access Restricted / Case Unassigned
          </h2>
          <p className="text-xs text-[#AAAAAA] mt-1 max-w-md">
            This investigation dossier (<code className="text-[#FF8800]">{caseId}</code>) is not currently assigned to Investigator <strong className="text-white">{currentUser.name}</strong> ({currentUser.badgeId}).
          </p>
        </div>
        <div className="p-4 rounded bg-[#101010] border border-[#222222] max-w-md text-left text-[11px] text-[#AAAAAA] space-y-2">
          <div className="flex justify-between">
            <span className="text-[#666666]">Active Session:</span>
            <span className="text-white font-bold">{currentUser.name} [{currentUser.role}]</span>
          </div>
          <div className="flex justify-between">
            <span className="text-[#666666]">Enforcement Policy:</span>
            <span className="text-[#00FF00]">STRICT ANALYST COMPARTMENTALIZATION</span>
          </div>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => setFilterMode('ALL_CASES')}
            className="px-4 py-2 bg-[#181818] hover:bg-[#222222] border border-[#00FF00]/40 rounded text-xs text-[#00FF00] font-bold uppercase tracking-wider transition-colors"
          >
            Switch to All Cases Mode
          </button>
          <Link
            to="/investigations"
            className="px-4 py-2 bg-[#222222] hover:bg-[#333333] border border-[#333333] rounded text-xs text-white uppercase font-bold transition-colors"
          >
            Return to Dossiers
          </Link>
        </div>
      </div>
    );
  }

  if (error || !caseObj) {
    return (
      <ErrorState
        title="Investigation Dossier Unavailable"
        message="Unable to locate investigation case file. It may have been deleted or the identifier is invalid."
        onRetry={loadCaseData}
      />
    );
  }

  return (
    <div className="space-y-6 font-mono text-xs text-white">
      {/* ===================================================================== */}
      {/* CASE WORKSPACE HEADER */}
      {/* ===================================================================== */}
      <div className="bg-[#101010] border border-[#222222] rounded p-5">
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-[11px] text-[#666666]">
              <span className="uppercase tracking-wider">CASE DOSSIER</span>
              <span>/</span>
              <span className="text-[#AAAAAA] select-all">{caseObj.case_id}</span>
              <button
                onClick={() => copyToClipboard(caseObj.case_id, 'case_id')}
                className="p-1 hover:text-[#00FF00] text-[#666666] transition-colors"
                title="Copy Case UUID"
              >
                {copiedId === 'case_id' ? <Check className="h-3 w-3 text-[#00FF00]" /> : <Copy className="h-3 w-3" />}
              </button>
            </div>
            <div className="flex items-center gap-3">
              <h2 className="text-lg font-bold text-white uppercase tracking-wider">{caseObj.name}</h2>
              {isAssigned && (
                <span className="px-2 py-0.5 rounded border border-[#00FF00]/40 bg-[#00FF00]/10 text-[#00FF00] text-[10px] font-bold">
                  ASSIGNED TO YOU
                </span>
              )}
            </div>
            <p className="text-xs text-[#AAAAAA] max-w-3xl leading-relaxed">
              {caseObj.description || 'No formal scope or description documented for this investigation.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            {/* Real Risk Assessment Badge */}
            {riskAssessment ? (
              <RiskBadge level={riskAssessment.risk_level} confidence={riskAssessment.confidence} />
            ) : (
              <span className="px-2.5 py-1 rounded border border-[#BB88FF]/40 bg-[#BB88FF]/10 text-[#BB88FF] text-[10px] font-bold uppercase tracking-wider">
                LOW RISK
              </span>
            )}

            {/* Case Status Selector */}
            <div className="flex items-center gap-2 bg-[#0A0A0A] border border-[#222222] px-3 py-1.5 rounded">
              <span className="text-[10px] text-[#666666] uppercase tracking-wider font-bold">STATUS:</span>
              <select
                value={caseObj.status}
                onChange={(e) => handleStatusChange(e.target.value as CaseStatus)}
                className="bg-transparent text-[#00FF00] font-bold focus:outline-none cursor-pointer text-xs"
              >
                <option value="OPEN" className="bg-[#101010] text-white">OPEN</option>
                <option value="ANALYZING" className="bg-[#101010] text-[#FF8800]">ANALYZING</option>
                <option value="COMPLETED" className="bg-[#101010] text-[#00FF00]">COMPLETED</option>
                <option value="ARCHIVED" className="bg-[#101010] text-[#AAAAAA]">ARCHIVED</option>
              </select>
            </div>

            {/* Refresh Case Trigger */}
            <button
              onClick={() => loadCaseData(true)}
              title="Refresh case data from backend"
              className="p-2 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 rounded text-[#AAAAAA] hover:text-[#00FF00] transition-colors"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>

            {/* Delete Case Trigger */}
            <button
              onClick={handleDeleteCase}
              disabled={deletingCase}
              title="Delete Entire Investigation Dossier"
              className="p-2 bg-[#181818] hover:bg-[#FF3333]/20 border border-[#222222] hover:border-[#FF3333]/50 rounded text-[#AAAAAA] hover:text-[#FF3333] transition-colors"
            >
              {deletingCase ? <Loader2 className="h-3.5 w-3.5 animate-spin text-[#FF3333]" /> : <Trash2 className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>

        {/* Interactive Summary Tiles Strip (Console themed) */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-5 pt-4 border-t border-[#222222] text-xs">
          <button
            onClick={() => setActiveTab('evidence')}
            className={`p-3 rounded border text-left transition-all ${
              activeTab === 'evidence' 
                ? 'bg-[#181818] border-[#00FF00] shadow-[0_0_10px_rgba(0,255,0,0.2)]' 
                : 'bg-[#0A0A0A] border-[#222222] hover:bg-[#141414] hover:border-[#333333]'
            }`}
          >
            <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">EVIDENCE</span>
            <span className="font-bold text-sm text-[#00FF00]">{evidenceList.length} files</span>
          </button>

          <button
            onClick={() => setActiveTab('analysis')}
            className={`p-3 rounded border text-left transition-all ${
              activeTab === 'analysis' 
                ? 'bg-[#181818] border-[#FF8800] shadow-[0_0_10px_rgba(255,136,0,0.2)]' 
                : 'bg-[#0A0A0A] border-[#222222] hover:bg-[#141414] hover:border-[#333333]'
            }`}
          >
            <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">ANALYSIS</span>
            <span className="font-bold text-sm text-[#FF8800]">{analysesList.length} runs</span>
          </button>

          <button
            onClick={() => setActiveTab('indicators')}
            className={`p-3 rounded border text-left transition-all ${
              activeTab === 'indicators' 
                ? 'bg-[#181818] border-[#BB88FF] shadow-[0_0_10px_rgba(187,136,255,0.2)]' 
                : 'bg-[#0A0A0A] border-[#222222] hover:bg-[#141414] hover:border-[#333333]'
            }`}
          >
            <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">INDICATORS</span>
            <span className="font-bold text-sm text-[#BB88FF]">{indicatorsList.length} IOCs</span>
          </button>

          <button
            onClick={() => setActiveTab('apk_findings')}
            className={`p-3 rounded border text-left transition-all ${
              activeTab === 'apk_findings' || activeTab === 'network_findings' 
                ? 'bg-[#181818] border-[#00FF00] shadow-[0_0_10px_rgba(0,255,0,0.2)]' 
                : 'bg-[#0A0A0A] border-[#222222] hover:bg-[#141414] hover:border-[#333333]'
            }`}
          >
            <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">OBSERVATIONS</span>
            <span className="font-bold text-sm text-white">{observationsList.length} items</span>
          </button>

          <button
            onClick={() => setActiveTab('attack_graph')}
            className={`p-3 rounded border text-left transition-all ${
              activeTab === 'attack_graph' 
                ? 'bg-[#181818] border-[#00FF00] shadow-[0_0_10px_rgba(0,255,0,0.2)]' 
                : 'bg-[#0A0A0A] border-[#222222] hover:bg-[#141414] hover:border-[#333333]'
            }`}
          >
            <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">GRAPH NODES</span>
            <span className="font-bold text-sm text-[#00FF00]">{graphData.nodes.length} entities</span>
          </button>

          <button
            onClick={() => setActiveTab('risk_assessment')}
            className={`p-3 rounded border text-left transition-all ${
              activeTab === 'risk_assessment' 
                ? 'bg-[#181818] border-[#BB88FF] shadow-[0_0_10px_rgba(187,136,255,0.2)]' 
                : 'bg-[#0A0A0A] border-[#222222] hover:bg-[#141414] hover:border-[#333333]'
            }`}
          >
            <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">RISK POSTURE</span>
            <span className={`font-bold text-sm uppercase ${
              riskAssessment?.risk_level === 'CRITICAL' || riskAssessment?.risk_level === 'HIGH'
                ? 'text-[#FF8800]'
                : 'text-[#BB88FF]'
            }`}>
              {riskAssessment?.risk_level || 'LOW'}
            </span>
          </button>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* WORKBENCH LAYOUT: SIDEBAR NAV + CONTENT VIEW */}
      {/* ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        {/* Navigation Sidebar (Console Themed) */}
        <div className="bg-[#101010] border border-[#222222] rounded p-2.5 flex flex-col space-y-1">
          {[
            { id: 'overview', name: '01 Overview', icon: Calendar, badge: null },
            { id: 'evidence', name: '02 Evidence', icon: FileCode, badge: evidenceList.length },
            { id: 'analysis', name: '03 Analysis', icon: Cpu, badge: analysesList.length },
            { id: 'apk_findings', name: '04 APK Findings', icon: FileCheck2, badge: apkObservations.length },
            { id: 'network_findings', name: '05 Network Findings', icon: Radio, badge: networkObservations.length },
            { id: 'indicators', name: '06 Indicators (IOCs)', icon: ShieldAlert, badge: indicatorsList.length },
            { id: 'correlations', name: '07 Correlations', icon: Layers, badge: correlationsList.length },
            { id: 'threat_intel', name: '08 Threat Intel', icon: Globe, badge: threatIntelList.length },
            { id: 'risk_assessment', name: '09 Risk Assessment', icon: ShieldQuestion, badge: riskAssessment?.risk_level || 'LOW' },
            { id: 'attack_graph', name: '10 Attack Graph', icon: Share2, badge: graphData.nodes.length },
            { id: 'reports', name: '11 Reports', icon: FileText, badge: reportsList.length },
          ].map((tab) => {
            const Icon = tab.icon;
            const isTabActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center justify-between px-3 py-2.5 rounded text-left transition-all ${
                  isTabActive
                    ? 'bg-[#181818] text-[#00FF00] font-bold border-l-2 border-[#00FF00] pl-2.5 shadow-[0_0_10px_rgba(0,255,0,0.1)]'
                    : 'text-[#AAAAAA] hover:bg-[#141414] hover:text-white border-l-2 border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Icon className={`h-4 w-4 shrink-0 ${isTabActive ? 'text-[#00FF00]' : 'text-[#666666]'}`} />
                  <span className="truncate tracking-wider uppercase text-[11px]">{tab.name}</span>
                </div>
                {tab.badge !== null && tab.badge !== undefined && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                    isTabActive 
                      ? 'border-[#00FF00]/40 bg-[#00FF00]/10 text-[#00FF00]' 
                      : 'border-[#222222] bg-[#0A0A0A] text-[#666666]'
                  }`}>
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Tab View Container (Console Themed) */}
        <div className="lg:col-span-3 bg-[#101010] border border-[#222222] rounded p-6 min-h-[640px]">
          
          {/* ================================================================= */}
          {/* 01. OVERVIEW TAB */}
          {/* ================================================================= */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <Shield className="h-4 w-4 text-[#00FF00]" />
                  <span>Investigation Case Overview</span>
                </h3>
                <span className="text-[10px] text-[#666666]">E.M.I.T. FORENSIC STATE</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <h4 className="font-bold text-[#AAAAAA] uppercase tracking-wider text-[11px]">Dossier Identification</h4>
                  <ul className="space-y-2.5 bg-[#0A0A0A] p-4 rounded border border-[#222222] text-xs">
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">CASE ID:</span>
                      <span className="text-white font-bold select-all">{caseObj.case_id}</span>
                    </li>
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">OPERATIONAL STATUS:</span>
                      <StatusBadge status={caseObj.status} size="sm" />
                    </li>
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">REGISTERED:</span>
                      <span className="text-[#AAAAAA]">{new Date(caseObj.created_at).toLocaleString()}</span>
                    </li>
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">LAST UPDATE:</span>
                      <span className="text-[#AAAAAA]">{new Date(caseObj.updated_at).toLocaleString()}</span>
                    </li>
                  </ul>
                </div>

                <div className="space-y-2">
                  <h4 className="font-bold text-[#AAAAAA] uppercase tracking-wider text-[11px]">Telemetry Aggregate</h4>
                  <ul className="space-y-2.5 bg-[#0A0A0A] p-4 rounded border border-[#222222] text-xs">
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">EVIDENCE PACKAGES:</span>
                      <span className="text-[#00FF00] font-bold">{evidenceList.length} files</span>
                    </li>
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">PIPELINE RUNS:</span>
                      <span className="text-[#FF8800] font-bold">{analysesList.length} executions</span>
                    </li>
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">NORMALIZED IOCS:</span>
                      <span className="text-[#BB88FF] font-bold">{indicatorsList.length} items</span>
                    </li>
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">OBSERVED CORRELATIONS:</span>
                      <span className="text-[#00FF00] font-bold">{correlationsList.length} links</span>
                    </li>
                    <li className="flex justify-between items-center">
                      <span className="text-[#666666]">THREAT INTEL QUERIES:</span>
                      <span className="text-white font-bold">{threatIntelList.length} records</span>
                    </li>
                  </ul>
                </div>
              </div>

              {/* Risk Assessment Summary */}
              {riskAssessment && (
                <div className="bg-[#0A0A0A] border border-[#222222] rounded p-5 space-y-3">
                  <div className="flex justify-between items-center border-b border-[#222222] pb-2">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-[#FF8800]" />
                      <span className="font-bold text-white text-xs uppercase tracking-wider">
                        Risk Assessment Summary & Guidance
                      </span>
                    </div>
                    <button
                      onClick={() => setActiveTab('risk_assessment')}
                      className="text-[11px] text-[#00FF00] hover:underline flex items-center gap-1 font-bold"
                    >
                      <span>Full Assessment</span>
                      <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>
                  <p className="text-xs text-[#AAAAAA] leading-relaxed">
                    {riskAssessment.summary || 'No narrative summary provided by the risk engine.'}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 02. EVIDENCE TAB */}
          {/* ================================================================= */}
          {activeTab === 'evidence' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <FileCode className="h-4 w-4 text-[#00FF00]" />
                  <span>Evidence Ingestion & Provenance</span>
                </h3>
                <span className="text-[10px] text-[#666666]">{evidenceList.length} REGISTERED PACKAGES</span>
              </div>

              {/* Upload Drop Zone / Form */}
              <form onSubmit={handleFileUpload} className="bg-[#0A0A0A] border border-[#222222] p-5 rounded space-y-4">
                <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
                  <div>
                    <h4 className="font-bold text-white uppercase tracking-wider text-xs">
                      Ingest Forensic Evidence Package
                    </h4>
                    <p className="text-[11px] text-[#AAAAAA] mt-0.5">
                      Accepts Android APK binaries (.apk) or PCAP packet captures (.pcap, .pcapng). File signatures verified via magic bytes.
                    </p>
                  </div>

                  <div className="flex flex-col sm:flex-row items-center gap-3 w-full md:w-auto">
                    <input
                      type="file"
                      id="evidence-upload-input"
                      required
                      onChange={(e) => setSelectedFile(e.target.files ? e.target.files[0] : null)}
                      className="w-full sm:w-64 bg-[#101010] border border-[#222222] text-xs px-3 py-1.5 rounded text-white file:mr-3 file:py-1 file:px-2.5 file:rounded file:border-0 file:bg-[#181818] file:text-[#00FF00] file:text-xs file:font-bold hover:file:bg-[#222222] cursor-pointer"
                    />
                    <button
                      type="submit"
                      disabled={uploadLoading || !selectedFile}
                      className="inline-flex items-center justify-center gap-2 w-full sm:w-auto px-4 py-2 bg-[#00FF00] hover:bg-[#00DD00] disabled:opacity-50 text-black rounded font-bold uppercase tracking-wider transition-all shrink-0 shadow-[0_0_12px_rgba(0,255,0,0.3)]"
                    >
                      {uploadLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
                      <span>Ingest Evidence</span>
                    </button>
                  </div>
                </div>

                {uploadProgress !== null && (
                  <div className="w-full bg-[#101010] border border-[#222222] p-3 rounded space-y-2">
                    <div className="flex justify-between text-xs text-[#00FF00] font-bold">
                      <span>STREAMING EVIDENCE BUFFER...</span>
                      <span>{uploadProgress}%</span>
                    </div>
                    <div className="w-full bg-[#000000] h-2 rounded overflow-hidden">
                      <div 
                        className="bg-[#00FF00] h-full rounded transition-all duration-200" 
                        style={{ width: `${uploadProgress}%` }}
                      />
                    </div>
                  </div>
                )}

                {uploadError && (
                  <div className="p-3 bg-[#FF3333]/10 border border-[#FF3333]/40 text-[#FF3333] rounded text-xs font-semibold">
                    {uploadError}
                  </div>
                )}
              </form>

              {/* Evidence Cards List */}
              {evidenceList.length > 0 ? (
                <div className="space-y-3">
                  {evidenceList.map((e) => (
                    <div
                      key={e.evidence_id}
                      className="p-4 bg-[#0A0A0A] hover:bg-[#141414] border border-[#222222] rounded flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 transition-colors"
                    >
                      <div className="space-y-1.5 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-bold text-white text-xs truncate max-w-sm sm:max-w-md">
                            {e.file_name}
                          </span>
                          <span className="px-2 py-0.5 rounded border border-[#00FF00]/40 bg-[#181818] text-[10px] font-bold text-[#00FF00]">
                            {e.file_type || 'BINARY'}
                          </span>
                          <span className="text-[#666666] text-[11px]">
                            {e.file_size ? `${(e.file_size / 1024).toFixed(1)} KB` : '—'}
                          </span>
                        </div>

                        {/* Hash with copy action */}
                        <div className="flex items-center gap-2 text-[11px] text-[#AAAAAA]">
                          <span className="text-[#666666]">SHA256:</span>
                          <span className="text-white font-mono truncate max-w-xs sm:max-w-md select-all">
                            {e.sha256 || '—'}
                          </span>
                          {e.sha256 && (
                            <button
                              onClick={() => copyToClipboard(e.sha256, e.evidence_id)}
                              className="p-1 text-[#666666] hover:text-[#00FF00]"
                              title="Copy SHA-256 Hash"
                            >
                              {copiedId === e.evidence_id ? <Check className="h-3 w-3 text-[#00FF00]" /> : <Copy className="h-3 w-3" />}
                            </button>
                          )}
                        </div>

                        <div className="text-[10px] text-[#666666]">
                          Uploaded: {e.uploaded_at ? new Date(e.uploaded_at).toLocaleString() : '—'}
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => setInspectEvidence(e)}
                          className="px-3 py-1.5 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 rounded text-[#AAAAAA] hover:text-[#00FF00] font-bold transition-colors"
                        >
                          Inspect
                        </button>
                        <button
                          onClick={() => handleDeleteEvidence(e.evidence_id)}
                          className="p-2 text-[#666666] hover:text-[#FF3333] border border-[#222222] hover:border-[#FF3333]/50 rounded transition-colors"
                          title="Delete Evidence Package"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No Evidence Ingested"
                  description="Use the upload console above to register APK or PCAP evidence files for analysis."
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 03. ANALYSIS TAB */}
          {/* ================================================================= */}
          {activeTab === 'analysis' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-[#FF8800]" />
                  <span>Forensic Analysis Pipelines & Provider Engine</span>
                </h3>
                <span className="text-[10px] text-[#666666]">{analysesList.length} PIPELINE EXECUTIONS</span>
              </div>

              {/* Active / Selected Analysis Run Execution Console */}
              {(() => {
                const selectedRun = analysesList.find(r => r.analysis_id === selectedRunId) || (analysesList.length > 0 ? analysesList[0] : null);
                const activeRunningRun = analysesList.find(r => 
                  ['PENDING', 'STARTING', 'RUNNING', 'ANALYZING', 'NORMALIZING', 'CORRELATING', 'BUILDING_GRAPH'].includes((r.status || '').toUpperCase())
                );
                const isAnyAnalysisActive = !!activeRunningRun;
                const targetEvidence = selectedRun ? evidenceList.find(e => e.evidence_id === selectedRun.evidence_id) : null;

                return (
                  <div className="space-y-6">
                    {/* Trigger Analysis Form */}
                    <form onSubmit={handleTriggerAnalysis} className="bg-[#0A0A0A] border border-[#222222] p-5 rounded space-y-4">
                      <div>
                        <h4 className="font-bold text-white uppercase tracking-wider text-xs">
                          Trigger Pipeline Execution
                        </h4>
                        <p className="text-[11px] text-[#AAAAAA] mt-0.5">
                          Select an ingested evidence package to run containerized static decompilation (MobSF, Androguard, JADX, APKTool) or packet inspection (TShark, Scapy).
                        </p>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div className="sm:col-span-2">
                          <label className="block text-[10px] text-[#666666] uppercase font-bold mb-1">
                            Evidence Package
                          </label>
                          <select
                            value={runEvidenceId}
                            disabled={runLoading || isAnyAnalysisActive}
                            onChange={(e) => setRunEvidenceId(e.target.value)}
                            className="w-full bg-[#101010] border border-[#222222] px-3 py-2 text-xs text-white rounded focus:outline-none focus:border-[#00FF00] cursor-pointer disabled:opacity-50"
                          >
                            <option value="">SELECT EVIDENCE TARGET...</option>
                            {evidenceList.map((e) => (
                              <option key={e.evidence_id} value={e.evidence_id}>
                                {e.file_name} ({e.file_type})
                              </option>
                            ))}
                          </select>
                        </div>

                        <div>
                          <label className="block text-[10px] text-[#666666] uppercase font-bold mb-1">
                            Analysis Pipeline
                          </label>
                          <select
                            value={runType}
                            disabled={runLoading || isAnyAnalysisActive}
                            onChange={(e) => setRunType(e.target.value as any)}
                            className="w-full bg-[#101010] border border-[#222222] px-3 py-2 text-xs text-white rounded focus:outline-none focus:border-[#00FF00] cursor-pointer disabled:opacity-50"
                          >
                            <option value="APK">APK STATIC ANALYSIS</option>
                            <option value="PCAP">PCAP NETWORK FORENSICS</option>
                          </select>
                        </div>
                      </div>

                      {runError && (
                        <div className="p-3 bg-[#FF3333]/10 border border-[#FF3333]/40 text-[#FF3333] rounded text-xs">
                          {runError}
                        </div>
                      )}

                      <div className="flex justify-end items-center gap-3">
                        {isAnyAnalysisActive && (
                          <span className="text-[11px] text-[#00FF00] flex items-center gap-1.5 animate-pulse font-bold">
                            <Radio className="h-3.5 w-3.5" />
                            <span>Analysis run in progress...</span>
                          </span>
                        )}
                        <button
                          type="submit"
                          disabled={runLoading || isAnyAnalysisActive || !runEvidenceId}
                          className="inline-flex items-center gap-2 px-4 py-2 bg-[#00FF00] hover:bg-[#00DD00] disabled:opacity-50 text-black rounded font-bold uppercase tracking-wider transition-all shadow-[0_0_12px_rgba(0,255,0,0.3)] disabled:cursor-not-allowed"
                        >
                          {runLoading || isAnyAnalysisActive ? (
                            <>
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                              <span>Execution In Progress</span>
                            </>
                          ) : (
                            <>
                              <Play className="h-3.5 w-3.5" />
                              <span>Execute Analysis Pipeline</span>
                            </>
                          )}
                        </button>
                      </div>
                    </form>

                    {/* Historical Run Selector Tabs */}
                    {analysesList.length > 0 && (
                      <div className="space-y-3">
                        <div className="flex justify-between items-center">
                          <span className="text-[10px] font-bold text-[#666666] uppercase tracking-wider">
                            Investigation Execution History ({analysesList.length} Runs)
                          </span>
                          {selectedRun && (
                            <button
                              onClick={() => handleDeleteAnalysisRun(selectedRun.analysis_id)}
                              disabled={deletingRunId === selectedRun.analysis_id}
                              className="text-[10px] text-[#EF4444] hover:underline flex items-center gap-1"
                            >
                              <Trash2 className="h-3 w-3" />
                              <span>Delete Selected Run</span>
                            </button>
                          )}
                        </div>

                        <div className="flex items-center gap-2 overflow-x-auto pb-1">
                          {analysesList.map((run, runIdx) => {
                            const isSelected = selectedRun?.analysis_id === run.analysis_id;
                            const isRunActive = ['PENDING', 'STARTING', 'RUNNING', 'ANALYZING', 'NORMALIZING', 'CORRELATING', 'BUILDING_GRAPH'].includes((run.status || '').toUpperCase());

                            return (
                              <button
                                key={run.analysis_id || runIdx}
                                onClick={() => setSelectedRunId(run.analysis_id)}
                                className={`flex items-center gap-2 px-3 py-2 rounded text-xs font-mono border transition-all shrink-0 ${
                                  isSelected 
                                    ? 'bg-[#181818] border-[#00FF00] text-white shadow-[0_0_8px_rgba(0,255,0,0.2)]' 
                                    : 'bg-[#101010] border-[#222222] text-[#888888] hover:text-white hover:border-[#333333]'
                                }`}
                              >
                                {isRunActive ? (
                                  <Radio className="h-3 w-3 text-[#00FF00] animate-pulse" />
                                ) : run.status === 'COMPLETED' ? (
                                  <CheckCircle2 className="h-3 w-3 text-[#00FF00]" />
                                ) : (
                                  <span className="text-xs text-[#666666]">#</span>
                                )}
                                <span className="font-bold uppercase">
                                  Run {run.analysis_id ? run.analysis_id.slice(0, 8) : `#${runIdx + 1}`}
                                </span>
                                <span className="text-[10px] text-[#888888]">
                                  ({run.analysis_type})
                                </span>
                                <StatusBadge status={run.status} size="sm" />
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    )}

                    {/* Real-time SOC/DFIR Analysis Execution Panel */}
                    {selectedRun ? (
                      <AnalysisRunPanel
                        key={selectedRun.analysis_id}
                        caseId={caseId}
                        analysisRun={selectedRun}
                        evidenceFileName={targetEvidence?.file_name}
                        onRunCompleted={() => {
                          loadCaseData(false);
                        }}
                        onNavigateTab={(tabName) => setActiveTab(tabName as any)}
                      />
                    ) : (
                      <EmptyState
                        title="No Analysis Executions Logged"
                        description="Select an ingested evidence package above and click 'Execute Analysis Pipeline' to start forensic analysis."
                      />
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          {/* ================================================================= */}
          {/* 04. APK FINDINGS TAB */}
          {/* ================================================================= */}
          {activeTab === 'apk_findings' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <FileCheck2 className="h-4 w-4 text-[#00FF00]" />
                  <span>APK Static Analysis Findings</span>
                </h3>
                <span className="text-[10px] text-[#666666]">{apkObservations.length} ARTIFACTS</span>
              </div>

              {apkObservations.length > 0 ? (
                <div className="space-y-3">
                  {apkObservations.map((obs) => (
                    <div
                      key={obs.observation_id}
                      className="p-3.5 bg-[#0A0A0A] border border-[#222222] rounded flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 hover:border-[#333333] transition-colors"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 bg-[#181818] border border-[#00FF00]/40 text-[10px] font-bold text-[#00FF00] rounded uppercase">
                            {obs.observation_type}
                          </span>
                          <span className="text-white font-bold text-xs">{obs.value}</span>
                        </div>
                        <div className="text-[10px] text-[#666666]">
                          Source: {obs.source} &bull; Timestamp: {new Date(obs.timestamp).toLocaleString()}
                        </div>
                      </div>

                      <span className="text-[10px] font-mono px-2 py-1 rounded bg-[#101010] border border-[#222222] text-[#AAAAAA]">
                        Confidence: <strong className="text-[#00FF00]">{Math.round(obs.confidence * 100)}%</strong>
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No APK Findings Extracted"
                  description="Run an APK Static Analysis pipeline on uploaded evidence to extract permissions, activities, and embedded capabilities."
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 05. NETWORK FINDINGS TAB */}
          {/* ================================================================= */}
          {activeTab === 'network_findings' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <Radio className="h-4 w-4 text-[#FF8800]" />
                  <span>PCAP Network Telemetry Findings</span>
                </h3>
                <span className="text-[10px] text-[#666666]">{networkObservations.length} NETWORK ARTIFACTS</span>
              </div>

              {networkObservations.length > 0 ? (
                <div className="space-y-3">
                  {networkObservations.map((obs) => (
                    <div
                      key={obs.observation_id}
                      className="p-3.5 bg-[#0A0A0A] border border-[#222222] rounded flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 hover:border-[#333333] transition-colors"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 bg-[#181818] border border-[#FF8800]/40 text-[10px] font-bold text-[#FF8800] rounded uppercase">
                            {obs.observation_type}
                          </span>
                          <span className="text-white font-bold text-xs">{obs.value}</span>
                        </div>
                        <div className="text-[10px] text-[#666666]">
                          Source: {obs.source} &bull; Timestamp: {new Date(obs.timestamp).toLocaleString()}
                        </div>
                      </div>

                      <span className="text-[10px] font-mono px-2 py-1 rounded bg-[#101010] border border-[#222222] text-[#AAAAAA]">
                        Confidence: <strong className="text-[#FF8800]">{Math.round(obs.confidence * 100)}%</strong>
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No Network Findings Extracted"
                  description="Run a PCAP Network Forensics pipeline to parse packets, DNS queries, and TCP/UDP flows."
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 06. INDICATORS (IOCs) TAB */}
          {/* ================================================================= */}
          {activeTab === 'indicators' && (
            <div className="space-y-5">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-[#BB88FF]" />
                  <span>Extracted Indicators of Compromise</span>
                </h3>
                <span className="text-[10px] text-[#666666]">{indicatorsList.length} TOTAL IOCS</span>
              </div>

              {/* Filter Toolbar */}
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[#666666]" />
                  <input
                    type="text"
                    placeholder="Search IOC value or normalized form..."
                    value={iocFilter}
                    onChange={(e) => setIocFilter(e.target.value)}
                    className="w-full pl-8 pr-3 py-1.5 bg-[#0A0A0A] border border-[#222222] text-white text-xs rounded focus:outline-none focus:border-[#00FF00] placeholder:text-[#666666]"
                  />
                </div>

                <select
                  value={iocTypeFilter}
                  onChange={(e) => setIocTypeFilter(e.target.value)}
                  className="bg-[#0A0A0A] border border-[#222222] px-3 py-1.5 text-xs text-white rounded focus:outline-none focus:border-[#00FF00] cursor-pointer"
                >
                  <option value="ALL">ALL TYPES</option>
                  {iocTypes.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>

              {/* IOC Table */}
              {filteredIocs.length > 0 ? (
                <div className="border border-[#222222] rounded overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-[#222222] bg-[#050505] text-[#666666] uppercase tracking-wider text-[10px]">
                          <th className="py-2.5 px-3">Type</th>
                          <th className="py-2.5 px-3">Indicator Value</th>
                          <th className="py-2.5 px-3">Normalized Value</th>
                          <th className="py-2.5 px-3">First Seen</th>
                          <th className="py-2.5 px-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1A1A1A] text-[#AAAAAA]">
                        {filteredIocs.map((ioc) => (
                          <tr
                            key={ioc.indicator_id}
                            className="hover:bg-[#141414] transition-colors"
                          >
                            <td className="py-2.5 px-3">
                              <span className="px-2 py-0.5 rounded border border-[#BB88FF]/40 bg-[#181818] text-[10px] font-bold text-[#BB88FF] uppercase">
                                {ioc.type}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 font-semibold text-white select-all">
                              {ioc.value}
                            </td>
                            <td className="py-2.5 px-3 text-[#666666] select-all">
                              {ioc.normalized_value}
                            </td>
                            <td className="py-2.5 px-3 text-[#666666] text-[11px]">
                              {new Date(ioc.created_at).toLocaleString()}
                            </td>
                            <td className="py-2.5 px-3 text-right">
                              <button
                                onClick={() => setSelectedIoc(ioc)}
                                className="px-2.5 py-1 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 rounded text-[10px] text-[#AAAAAA] hover:text-[#00FF00] font-bold transition-colors"
                              >
                                Detail
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <EmptyState
                  title="No Matching Indicators Found"
                  description="No IOC entities match the current query filters."
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 07. CORRELATIONS TAB */}
          {/* ================================================================= */}
          {activeTab === 'correlations' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <Layers className="h-4 w-4 text-[#FF8800]" />
                  <span>Cross-Artifact Evidence Correlations</span>
                </h3>
                <span className="text-[10px] text-[#666666]">{correlationsList.length} CORRELATION RULES</span>
              </div>

              {correlationsList.length > 0 ? (
                <div className="space-y-3">
                  {correlationsList.map((corr) => (
                    <div
                      key={corr.correlation_id}
                      className="p-4 bg-[#0A0A0A] border border-[#222222] rounded space-y-2.5"
                    >
                      <div className="flex justify-between items-center">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded border border-[#FF8800]/40 bg-[#FF8800]/15 text-[#FF8800] text-[10px] font-bold uppercase">
                            {corr.relationship_type}
                          </span>
                          <span className="text-[11px] text-[#666666]">
                            Strength: <strong className="text-white">{corr.strength}</strong>
                          </span>
                        </div>
                        <span className="text-[10px] text-[#666666]">
                          {new Date(corr.created_at).toLocaleString()}
                        </span>
                      </div>

                      <p className="text-xs text-[#AAAAAA] leading-relaxed">
                        {corr.reason}
                      </p>

                      {corr.supporting_evidence_ids?.length > 0 && (
                        <div className="pt-2 border-t border-[#222222] flex items-center gap-2 text-[10px] text-[#666666] flex-wrap">
                          <span>SUPPORTING EVIDENCE:</span>
                          {corr.supporting_evidence_ids.map((id, idx) => (
                            <span key={idx} className="px-1.5 py-0.5 bg-[#181818] rounded border border-[#222222] text-white font-mono">
                              {id.slice(0, 8)}...
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No Correlations Detected"
                  description="Correlations are computed across APK static findings and PCAP network flows during analysis."
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 08. THREAT INTEL TAB */}
          {/* ================================================================= */}
          {activeTab === 'threat_intel' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-[#FF3333]" />
                  <h3 className="text-xs font-bold text-white uppercase tracking-widest">
                    External Threat Intelligence Feeds
                  </h3>
                  <span className="text-[10px] text-[#666666]">({threatIntelList.length} FEEDS)</span>
                </div>

                <button
                  onClick={handleTriggerEnrichment}
                  disabled={enriching}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-[#00FF00] hover:bg-[#00DD00] disabled:opacity-50 text-black rounded font-bold uppercase text-[11px] transition-all shadow-[0_0_10px_rgba(0,255,0,0.25)]"
                >
                  {enriching && <Loader2 className="h-3 w-3 animate-spin" />}
                  <span>Enrich Indicators</span>
                </button>
              </div>

              {threatIntelList.length > 0 ? (
                <div className="space-y-3">
                  {threatIntelList.map((intel) => (
                    <div
                      key={intel.threat_intel_id}
                      className="p-4 bg-[#0A0A0A] border border-[#222222] rounded space-y-2"
                    >
                      <div className="flex justify-between items-start">
                        <div>
                          <span className="font-bold text-white text-xs block select-all">
                            {intel.indicator}
                          </span>
                          <span className="text-[10px] text-[#666666]">
                            Provider: <strong className="text-[#AAAAAA]">{intel.provider}</strong> &bull; Type: {intel.indicator_type}
                          </span>
                        </div>

                        <StatusBadge status={intel.verdict} size="sm" />
                      </div>

                      {intel.categories && intel.categories.length > 0 && (
                        <div className="flex gap-1.5 flex-wrap pt-1">
                          {intel.categories.map((cat, idx) => (
                            <span key={idx} className="px-2 py-0.5 bg-[#181818] rounded border border-[#222222] text-[9px] text-[#AAAAAA]">
                              {cat}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No Threat Intel Feeds Active"
                  description="Click 'Enrich Indicators' above to query external intelligence sources for extracted IOCs."
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 09. RISK ASSESSMENT TAB */}
          {/* ================================================================= */}
          {activeTab === 'risk_assessment' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <ShieldQuestion className="h-4 w-4 text-[#BB88FF]" />
                  <span>Deterministic Risk Assessment Engine</span>
                </h3>

                <button
                  onClick={handleRecalculateRisk}
                  disabled={assessing}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-[#00FF00] hover:bg-[#00DD00] disabled:opacity-50 text-black rounded font-bold uppercase text-[11px] transition-all shadow-[0_0_10px_rgba(0,255,0,0.25)]"
                >
                  {assessing && <Loader2 className="h-3 w-3 animate-spin" />}
                  <span>Recalculate Risk</span>
                </button>
              </div>

              {riskAssessment ? (
                <div className="space-y-5">
                  {/* Score & Confidence Header Card */}
                  <div className="p-5 bg-[#0A0A0A] border border-[#222222] rounded grid grid-cols-1 sm:grid-cols-3 gap-4 items-center">
                    <div>
                      <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">
                        OVERALL RISK POSTURE
                      </span>
                      <RiskBadge level={riskAssessment.risk_level} confidence={riskAssessment.confidence} />
                    </div>

                    <div>
                      <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">
                        EVIDENCE STRENGTH
                      </span>
                      <span className="text-white font-bold text-sm uppercase">
                        {riskAssessment.evidence_strength || 'MODERATE'}
                      </span>
                    </div>

                    <div>
                      <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">
                        CONFIDENCE SCORE
                      </span>
                      <span className="text-[#00FF00] font-bold text-sm">
                        {Math.round(riskAssessment.confidence * 100)}% CONFIDENCE
                      </span>
                    </div>
                  </div>

                  {/* Summary Narrative */}
                  <div className="p-5 bg-[#0A0A0A] border border-[#222222] rounded space-y-2">
                    <span className="text-[10px] text-[#666666] uppercase font-bold block">
                      EXPLAINABLE RISK SUMMARY
                    </span>
                    <p className="text-xs text-[#AAAAAA] leading-relaxed">
                      {riskAssessment.summary}
                    </p>
                  </div>

                  {/* Facts vs Inferences Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Observed Facts */}
                    <div className="p-4 bg-[#0A0A0A] border border-[#222222] rounded space-y-2">
                      <span className="text-[10px] text-[#00FF00] uppercase font-bold block">
                        OBSERVED FACTS ({riskAssessment.observed_facts?.length || 0})
                      </span>
                      <ul className="space-y-1.5 text-[11px] text-[#AAAAAA] list-disc list-inside">
                        {riskAssessment.observed_facts?.map((fact, idx) => (
                          <li key={idx}>{fact}</li>
                        ))}
                      </ul>
                    </div>

                    {/* Inferences */}
                    <div className="p-4 bg-[#0A0A0A] border border-[#222222] rounded space-y-2">
                      <span className="text-[10px] text-[#FF8800] uppercase font-bold block">
                        DEDUCTIVE INFERENCES ({riskAssessment.inferences?.length || 0})
                      </span>
                      <ul className="space-y-1.5 text-[11px] text-[#AAAAAA] list-disc list-inside">
                        {riskAssessment.inferences?.map((inf, idx) => (
                          <li key={idx}>{inf}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ) : (
                <EmptyState
                  title="No Risk Assessment Available"
                  description="Run analysis and click 'Recalculate Risk' above to generate deterministic risk metrics."
                />
              )}
            </div>
          )}

          {/* ================================================================= */}
          {/* 10. ATTACK GRAPH TAB */}
          {/* ================================================================= */}
          {activeTab === 'attack_graph' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <div>
                  <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                    <Share2 className="h-4 w-4 text-[#00FF00]" />
                    <span>Provenance Attack Graph</span>
                  </h3>
                  <p className="text-[11px] text-[#AAAAAA] mt-0.5">
                    Interactive evidence-backed graph showing extracted entities and observed relationships.
                  </p>
                </div>
                <span className="text-[10px] text-[#666666]">
                  {graphData.nodes.length} NODES &bull; {graphData.edges.length} EDGES
                </span>
              </div>

              <div className="h-[650px] rounded border border-[#222222] overflow-hidden bg-[#000000]">
                <AttackGraphCanvas
                  nodesData={graphData.nodes}
                  edgesData={graphData.edges}
                  height="100%"
                />
              </div>
            </div>
          )}

          {/* ================================================================= */}
          {/* 11. REPORTS TAB */}
          {/* ================================================================= */}
          {activeTab === 'reports' && (
            <div className="space-y-6">
              <div className="flex justify-between items-center border-b border-[#222222] pb-2.5">
                <h3 className="text-xs font-bold text-white uppercase tracking-widest flex items-center gap-2">
                  <FileText className="h-4 w-4 text-[#00FF00]" />
                  <span>Forensic Dossier Reports Center</span>
                </h3>
                <span className="text-[10px] text-[#666666]">{reportsList.length} COMPILED DOSSIERS</span>
              </div>

              {/* Generator Form */}
              <form onSubmit={handleGenerateReport} className="bg-[#0A0A0A] border border-[#222222] p-5 rounded space-y-4">
                <div>
                  <h4 className="font-bold text-white uppercase tracking-wider text-xs">
                    Compile Investigation Dossier
                  </h4>
                  <p className="text-[11px] text-[#AAAAAA] mt-0.5">
                    Compiles evidence, static analysis, network findings, indicators, correlations, risk assessment, and attack chains into reproducible exports.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-2">
                    <label className="block text-[10px] text-[#666666] uppercase font-bold mb-1">
                      Report Title
                    </label>
                    <input
                      type="text"
                      value={reportTitle}
                      onChange={(e) => setReportTitle(e.target.value)}
                      className="w-full bg-[#101010] border border-[#222222] px-3 py-2 text-xs text-white rounded focus:outline-none focus:border-[#00FF00]"
                    />
                  </div>

                  <div>
                    <label className="block text-[10px] text-[#666666] uppercase font-bold mb-1">
                      Format Output
                    </label>
                    <select
                      value={reportFormat}
                      onChange={(e) => setReportFormat(e.target.value as any)}
                      className="w-full bg-[#101010] border border-[#222222] px-3 py-2 text-xs text-white rounded focus:outline-none focus:border-[#00FF00] cursor-pointer"
                    >
                      <option value="BOTH">HTML + PDF EXPORT</option>
                      <option value="HTML">HTML INTERACTIVE ONLY</option>
                      <option value="PDF">PDF DOSSIER ONLY</option>
                    </select>
                  </div>
                </div>

                {reportSuccess && (
                  <div className="p-3 bg-[#00FF00]/10 border border-[#00FF00]/40 text-[#00FF00] rounded text-xs flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4" />
                    <span>{reportSuccess}</span>
                  </div>
                )}

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={generatingReport}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-[#00FF00] hover:bg-[#00DD00] disabled:opacity-50 text-black rounded font-bold uppercase tracking-wider transition-all shadow-[0_0_12px_rgba(0,255,0,0.3)]"
                  >
                    {generatingReport ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileText className="h-3.5 w-3.5" />}
                    <span>Compile Forensic Report</span>
                  </button>
                </div>
              </form>

              {/* Generated Reports List */}
              {reportsList.length > 0 ? (
                <div className="space-y-3">
                  {reportsList.map((rep) => (
                    <div
                      key={rep.report_id}
                      className="p-4 bg-[#0A0A0A] border border-[#222222] rounded flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 hover:border-[#333333] transition-colors"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-bold text-white text-xs">{rep.title}</span>
                          <span className="px-2 py-0.5 rounded border border-[#222222] bg-[#181818] text-[10px] font-bold text-[#00FF00] uppercase">
                            {rep.report_format}
                          </span>
                          <StatusBadge status={rep.status} size="sm" />
                        </div>
                        <div className="text-[10px] text-[#666666]">
                          Generated: {rep.generated_at ? new Date(rep.generated_at).toLocaleString() : '—'} &bull; ID: {rep.report_id.slice(0, 8)}...
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {(rep.report_format === 'HTML' || rep.report_format === 'BOTH') && rep.html_path && (
                          <a
                            href={apiService.getReportDownloadUrl(caseId, rep.report_id, 'html')}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 text-[#00FF00] font-bold text-xs rounded transition-colors"
                          >
                            <ExternalLink className="h-3.5 w-3.5" />
                            <span>View HTML</span>
                          </a>
                        )}

                        {(rep.report_format === 'PDF' || rep.report_format === 'BOTH') && rep.pdf_path && (
                          <a
                            href={apiService.getReportDownloadUrl(caseId, rep.report_id, 'pdf')}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 text-white font-bold text-xs rounded transition-colors"
                          >
                            <Download className="h-3.5 w-3.5 text-[#00FF00]" />
                            <span>Download PDF</span>
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No Reports Generated Yet"
                  description="Click 'Compile Forensic Report' above to assemble an interactive HTML or PDF dossier."
                />
              )}
            </div>
          )}

        </div>
      </div>

      {/* ===================================================================== */}
      {/* EVIDENCE INSPECTOR DRAWER / MODAL */}
      {/* ===================================================================== */}
      {inspectEvidence && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#101010] border border-[#222222] rounded shadow-[0_0_40px_rgba(0,0,0,0.9)] relative font-mono text-xs text-white">
            <div className="flex items-center justify-between p-5 border-b border-[#222222]">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-[#00FF00]" />
                <h3 className="font-bold text-white uppercase tracking-wider">
                  Evidence File Provenance
                </h3>
              </div>
              <button 
                onClick={() => setInspectEvidence(null)}
                className="text-[#666666] hover:text-white p-1 rounded hover:bg-[#181818] transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-3">
              <div className="space-y-1">
                <span className="text-[10px] text-[#666666] uppercase font-bold">FILE NAME:</span>
                <span className="text-white font-bold block">{inspectEvidence.file_name}</span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] text-[#666666] uppercase font-bold">EVIDENCE ID:</span>
                <span className="text-[#AAAAAA] block select-all">{inspectEvidence.evidence_id}</span>
              </div>

              <div className="space-y-1">
                <span className="text-[10px] text-[#666666] uppercase font-bold">SHA-256 HASH:</span>
                <div className="flex items-center gap-2">
                  <span className="text-white block select-all truncate">{inspectEvidence.sha256 || '—'}</span>
                  {inspectEvidence.sha256 && (
                    <button
                      onClick={() => copyToClipboard(inspectEvidence.sha256, 'modal_sha')}
                      className="p-1 hover:text-[#00FF00] text-[#666666]"
                    >
                      {copiedId === 'modal_sha' ? <Check className="h-3 w-3 text-[#00FF00]" /> : <Copy className="h-3 w-3" />}
                    </button>
                  )}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-2">
                <div>
                  <span className="text-[10px] text-[#666666] uppercase font-bold block">FORMAT:</span>
                  <span className="text-[#00FF00] font-bold">{inspectEvidence.file_type || '—'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-[#666666] uppercase font-bold block">SIZE:</span>
                  <span className="text-white font-bold">
                    {inspectEvidence.file_size ? `${(inspectEvidence.file_size / 1024).toFixed(1)} KB` : '—'}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] text-[#666666] uppercase font-bold block">MIME TYPE:</span>
                  <span className="text-[#AAAAAA] font-bold">{inspectEvidence.mime_type || '—'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-[#666666] uppercase font-bold block">STORAGE:</span>
                  <span className="text-white font-bold">{inspectEvidence.storage_provider || 'Local'}</span>
                </div>
              </div>
            </div>

            <div className="p-4 border-t border-[#222222] flex justify-end">
              <button
                onClick={() => setInspectEvidence(null)}
                className="px-4 py-2 bg-[#181818] hover:bg-[#222222] border border-[#222222] rounded text-xs text-[#AAAAAA] hover:text-white font-bold uppercase"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* IOC INSPECTOR DRAWER / MODAL */}
      {/* ===================================================================== */}
      {selectedIoc && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-[#101010] border border-[#222222] rounded shadow-[0_0_40px_rgba(0,0,0,0.9)] relative font-mono text-xs text-white">
            <div className="flex items-center justify-between p-5 border-b border-[#222222]">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-[#BB88FF]" />
                <h3 className="font-bold text-white uppercase tracking-wider">
                  Indicator of Compromise (IOC)
                </h3>
              </div>
              <button 
                onClick={() => setSelectedIoc(null)}
                className="text-[#666666] hover:text-white p-1 rounded hover:bg-[#181818] transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-5 space-y-3">
              <div>
                <span className="text-[10px] text-[#666666] uppercase font-bold block">TYPE:</span>
                <span className="text-[#BB88FF] font-bold uppercase">{selectedIoc.type}</span>
              </div>

              <div>
                <span className="text-[10px] text-[#666666] uppercase font-bold block">RAW VALUE:</span>
                <span className="text-white font-bold block select-all break-all">{selectedIoc.value}</span>
              </div>

              <div>
                <span className="text-[10px] text-[#666666] uppercase font-bold block">NORMALIZED VALUE:</span>
                <span className="text-[#AAAAAA] font-bold block select-all break-all">{selectedIoc.normalized_value}</span>
              </div>

              <div>
                <span className="text-[10px] text-[#666666] uppercase font-bold block">FIRST SEEN:</span>
                <span className="text-[#666666]">{new Date(selectedIoc.created_at).toLocaleString()}</span>
              </div>

              {selectedIoc.metadata && Object.keys(selectedIoc.metadata).length > 0 && (
                <div className="pt-2">
                  <span className="text-[10px] text-[#666666] uppercase font-bold block mb-1">METADATA ATTRIBUTES:</span>
                  <div className="bg-[#0A0A0A] p-3 rounded border border-[#222222] text-[11px] space-y-1 max-h-36 overflow-y-auto">
                    {Object.entries(selectedIoc.metadata).map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-2">
                        <span className="text-[#666666] uppercase">{k}:</span>
                        <span className="text-white truncate">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="p-4 border-t border-[#222222] flex justify-end">
              <button
                onClick={() => setSelectedIoc(null)}
                className="px-4 py-2 bg-[#181818] hover:bg-[#222222] border border-[#222222] rounded text-xs text-[#AAAAAA] hover:text-white font-bold uppercase"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default InvestigationDetails;
