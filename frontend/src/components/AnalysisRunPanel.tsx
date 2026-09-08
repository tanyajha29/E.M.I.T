import React, { useEffect, useState, useRef, useMemo } from 'react';
import { 
  Check, 
  X, 
  AlertTriangle, 
  ChevronDown, 
  ChevronUp, 
  ShieldCheck,
  ShieldAlert,
  Radio,
  Clock,
  ArrowRight,
  Terminal,
  FileSearch,
  GitBranch,
  RefreshCw
} from 'lucide-react';
import { apiService, AnalysisRun, ProviderExecutionRecord, ProviderStatus } from '../services/api';

interface AnalysisRunPanelProps {
  caseId: string;
  analysisRun: AnalysisRun;
  evidenceFileName?: string;
  onRunCompleted?: (run: AnalysisRun) => void;
  onNavigateTab?: (tabName: string) => void;
}

// Format seconds into MM:SS or SS.Ss
const formatDuration = (seconds?: number | null): string => {
  if (seconds === undefined || seconds === null || isNaN(seconds) || seconds < 0) {
    return '—';
  }
  if (seconds >= 60) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }
  return `${seconds.toFixed(1)}s`;
};

// Calculate elapsed seconds from an ISO timestamp
const calculateElapsed = (startedAt?: string | null, completedAt?: string | null): number => {
  if (!startedAt) return 0;
  const start = new Date(startedAt).getTime();
  if (isNaN(start)) return 0;
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  if (isNaN(end)) return 0;
  return Math.max(0, (end - start) / 1000);
};

export const AnalysisRunPanel: React.FC<AnalysisRunPanelProps> = ({
  caseId,
  analysisRun: initialRun,
  evidenceFileName = 'Evidence Artifact',
  onRunCompleted,
  onNavigateTab
}) => {
  const [currentRun, setCurrentRun] = useState<AnalysisRun>(initialRun);
  const [expandedProviders, setExpandedProviders] = useState<Record<string, boolean>>({});
  const [nowTimestamp, setNowTimestamp] = useState<number>(Date.now());
  const pollingRef = useRef<number | null>(null);
  
  const isInitialTerminal = ['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes((initialRun.status || '').toUpperCase());
  const isCompletedRef = useRef<boolean>(isInitialTerminal);

  // Sync initial prop updates if the selected analysis ID changes
  useEffect(() => {
    setCurrentRun(initialRun);
    const terminal = ['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes((initialRun.status || '').toUpperCase());
    isCompletedRef.current = terminal;
  }, [initialRun.analysis_id]);

  const isTerminal = useMemo(() => {
    const s = (currentRun.status || '').toUpperCase();
    return ['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes(s);
  }, [currentRun.status]);

  // Live timer tick (updates every 500ms while active)
  useEffect(() => {
    if (isTerminal) return;
    const timer = setInterval(() => {
      setNowTimestamp(Date.now());
    }, 500);
    return () => clearInterval(timer);
  }, [isTerminal]);

  // Real-time backend polling engine (1500ms interval while active)
  useEffect(() => {
    if (isTerminal) {
      if (!isCompletedRef.current) {
        isCompletedRef.current = true;
        onRunCompleted?.(currentRun);
      }
      return;
    }

    let isSubscribed = true;

    const pollStatus = async () => {
      try {
        const updated = await apiService.getAnalysisStatus(caseId, currentRun.analysis_id);
        if (isSubscribed && updated) {
          setCurrentRun(updated);
          const updatedTerminal = ['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes((updated.status || '').toUpperCase());
          if (updatedTerminal && !isCompletedRef.current) {
            isCompletedRef.current = true;
            onRunCompleted?.(updated);
          }
        }
      } catch (err) {
        console.warn('Analysis status poll error (retrying):', err);
      }
    };

    // Polling interval only while active
    const intervalId = window.setInterval(pollStatus, 1500);
    pollingRef.current = intervalId;

    return () => {
      isSubscribed = false;
      window.clearInterval(intervalId);
    };
  }, [caseId, currentRun.analysis_id, isTerminal]);

  const toggleExpand = (providerKey: string) => {
    setExpandedProviders(prev => ({ ...prev, [providerKey]: !prev[providerKey] }));
  };

  // Provider map normalizer
  const providersMap = useMemo(() => {
    const raw = currentRun.provider_results || currentRun.providers || {};
    return raw;
  }, [currentRun.provider_results, currentRun.providers]);

  const providerEntries = useMemo(() => {
    return Object.entries(providersMap);
  }, [providersMap]);

  // Find currently active provider or stage
  const activeExecutingProvider = useMemo(() => {
    for (const [pName, rec] of providerEntries) {
      const status = (rec?.status || '').toUpperCase();
      if (status === 'EXECUTING' || status === 'STARTING' || status === 'RUNNING') {
        return { name: pName, record: rec };
      }
    }
    return null;
  }, [providerEntries]);

  // Overall live elapsed time
  const overallElapsedSeconds = useMemo(() => {
    if (currentRun.elapsed_seconds && isTerminal) {
      return currentRun.elapsed_seconds;
    }
    return calculateElapsed(currentRun.started_at, currentRun.completed_at);
  }, [currentRun.started_at, currentRun.completed_at, currentRun.elapsed_seconds, isTerminal, nowTimestamp]);

  // Deterministic progress calculation
  const progressPercent = useMemo(() => {
    if (typeof currentRun.progress_percent === 'number') {
      return Math.min(100, Math.max(0, currentRun.progress_percent));
    }
    if (isTerminal) return 100;
    return 10;
  }, [currentRun.progress_percent, isTerminal]);

  // Render provider status badge & visual indicator
  const renderProviderStatusVisual = (statusRaw?: string) => {
    const status = (statusRaw || 'PENDING').toUpperCase() as ProviderStatus;

    switch (status) {
      case 'COMPLETED':
        return {
          icon: <Check className="h-3.5 w-3.5 text-[#00FF00]" />,
          symbol: '✓',
          badgeClass: 'text-[#00FF00] bg-[#00FF00]/10 border-[#00FF00]/30',
          textColor: 'text-[#00FF00]',
          label: 'COMPLETED'
        };
      case 'EXECUTING':
      case 'RUNNING':
        return {
          icon: <Radio className="h-3.5 w-3.5 text-[#00FF00] animate-pulse" />,
          symbol: '◉',
          badgeClass: 'text-[#00FF00] bg-[#00FF00]/20 border-[#00FF00] shadow-[0_0_8px_rgba(0,255,0,0.3)] animate-pulse',
          textColor: 'text-[#00FF00]',
          label: 'EXECUTING'
        };
      case 'STARTING':
        return {
          icon: <RefreshCw className="h-3.5 w-3.5 text-[#F59E0B] animate-spin" />,
          symbol: '◌',
          badgeClass: 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/40 animate-pulse',
          textColor: 'text-[#F59E0B]',
          label: 'STARTING'
        };
      case 'FAILED':
        return {
          icon: <X className="h-3.5 w-3.5 text-[#EF4444]" />,
          symbol: '✕',
          badgeClass: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/40',
          textColor: 'text-[#EF4444]',
          label: 'FAILED'
        };
      case 'TIMEOUT':
        return {
          icon: <AlertTriangle className="h-3.5 w-3.5 text-[#F59E0B]" />,
          symbol: '!',
          badgeClass: 'text-[#F59E0B] bg-[#F59E0B]/15 border-[#F59E0B]/50',
          textColor: 'text-[#F59E0B]',
          label: 'TIMEOUT'
        };
      case 'SKIPPED':
        return {
          icon: <ArrowRight className="h-3.5 w-3.5 text-[#666666]" />,
          symbol: '→',
          badgeClass: 'text-[#888888] bg-[#181818] border-[#333333]',
          textColor: 'text-[#888888]',
          label: 'SKIPPED'
        };
      case 'DISABLED':
      case 'NOT_CONFIGURED':
      case 'UNAVAILABLE':
        return {
          icon: <span className="text-xs text-[#666666]">—</span>,
          symbol: '—',
          badgeClass: 'text-[#666666] bg-[#121212] border-[#222222]',
          textColor: 'text-[#666666]',
          label: status
        };
      case 'PENDING':
      default:
        return {
          icon: <span className="text-xs text-[#555555]">○</span>,
          symbol: '○',
          badgeClass: 'text-[#666666] bg-[#101010] border-[#222222]',
          textColor: 'text-[#666666]',
          label: 'PENDING'
        };
    }
  };

  // Pipeline stage status evaluation
  const getStageStatus = (stageName: 'INGEST' | 'ANALYZE' | 'NORMALIZE' | 'CORRELATE' | 'GRAPH') => {
    const curStage = (currentRun.current_stage || '').toUpperCase();
    const isDone = isTerminal;

    if (isDone) return 'DONE';

    if (stageName === 'INGEST') return 'DONE';
    if (stageName === 'ANALYZE') {
      if (['ANALYZING', 'STARTING', 'VALIDATING'].includes(curStage)) return 'ACTIVE';
      if (['NORMALIZING', 'CORRELATING', 'BUILDING_GRAPH', 'COMPLETED'].includes(curStage)) return 'DONE';
      return 'PENDING';
    }
    if (stageName === 'NORMALIZE') {
      if (curStage === 'NORMALIZING') return 'ACTIVE';
      if (['CORRELATING', 'BUILDING_GRAPH', 'COMPLETED'].includes(curStage)) return 'DONE';
      return 'PENDING';
    }
    if (stageName === 'CORRELATE') {
      if (curStage === 'CORRELATING') return 'ACTIVE';
      if (['BUILDING_GRAPH', 'COMPLETED'].includes(curStage)) return 'DONE';
      return 'PENDING';
    }
    if (stageName === 'GRAPH') {
      if (curStage === 'BUILDING_GRAPH') return 'ACTIVE';
      if (curStage === 'COMPLETED') return 'DONE';
      return 'PENDING';
    }
    return 'PENDING';
  };

  // Stage breadcrumb icon
  const renderBreadcrumbStage = (name: string, stageKey: 'INGEST' | 'ANALYZE' | 'NORMALIZE' | 'CORRELATE' | 'GRAPH', isLast = false) => {
    const st = getStageStatus(stageKey);
    return (
      <React.Fragment key={stageKey}>
        <div className="flex items-center gap-1.5 shrink-0">
          {st === 'DONE' && <span className="text-[#00FF00] font-bold">✓</span>}
          {st === 'ACTIVE' && <span className="text-[#00FF00] font-bold animate-pulse">●</span>}
          {st === 'PENDING' && <span className="text-[#555555]">○</span>}
          <span className={`text-[11px] font-bold tracking-wider ${
            st === 'DONE' ? 'text-[#00FF00]' : st === 'ACTIVE' ? 'text-white' : 'text-[#666666]'
          }`}>
            {name}
          </span>
        </div>
        {!isLast && <span className="text-[#333333] font-mono shrink-0">→</span>}
      </React.Fragment>
    );
  };

  return (
    <div className="bg-[#0A0A0A] border border-[#222222] rounded-lg overflow-hidden shadow-2xl font-mono text-xs text-white divide-y divide-[#1A1A1A]">
      {/* ================================================================= */}
      {/* 1. TOP STATUS BAR / HEADER */}
      {/* ================================================================= */}
      <div className="p-4 sm:p-5 bg-gradient-to-r from-[#101010] to-[#0A0A0A] flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5 flex-wrap">
            <div className={`h-2.5 w-2.5 rounded-full ${
              isTerminal 
                ? (currentRun.status === 'COMPLETED' ? 'bg-[#00FF00] shadow-[0_0_8px_#00FF00]' : 'bg-[#F59E0B]')
                : 'bg-[#00FF00] animate-ping'
            }`} />
            <span className="font-bold text-sm tracking-wider uppercase text-white">
              {isTerminal 
                ? (currentRun.status === 'COMPLETED' ? 'ANALYSIS COMPLETE' : `ANALYSIS ${currentRun.status}`)
                : 'ANALYSIS RUN IN PROGRESS'}
            </span>
            <span className="px-2 py-0.5 rounded bg-[#181818] border border-[#333333] text-[10px] font-bold text-[#AAAAAA]">
              {currentRun.analysis_id ? `RUN #${currentRun.analysis_id.slice(0, 8)}` : 'ORCHESTRATOR'}
            </span>
          </div>

          <div className="flex items-center gap-2 text-[#AAAAAA] text-[11px]">
            <span className="text-[#00FF00] font-bold">{currentRun.analysis_type} PIPELINE</span>
            <span>•</span>
            <span className="text-white truncate max-w-xs sm:max-w-md">{evidenceFileName}</span>
          </div>
        </div>

        {/* Progress & Live Clock */}
        <div className="flex items-center gap-5 w-full md:w-auto justify-between md:justify-end">
          <div className="text-right">
            <div className="text-[10px] text-[#666666] uppercase tracking-wider">OVERALL PROGRESS</div>
            <div className="text-base font-bold text-[#00FF00]">{progressPercent}%</div>
          </div>

          <div className="text-right border-l border-[#222222] pl-5">
            <div className="text-[10px] text-[#666666] uppercase tracking-wider flex items-center gap-1 justify-end">
              <Clock className="h-3 w-3 text-[#00FF00]" />
              <span>ELAPSED</span>
            </div>
            <div className="text-base font-bold text-white font-mono">
              {formatDuration(overallElapsedSeconds)}
            </div>
          </div>
        </div>
      </div>

      {/* Progress Bar Line */}
      <div className="w-full bg-[#181818] h-1.5 overflow-hidden">
        <div 
          className={`h-full transition-all duration-300 ease-out ${
            currentRun.status === 'FAILED' 
              ? 'bg-[#EF4444]' 
              : currentRun.status === 'PARTIAL' 
                ? 'bg-[#F59E0B]' 
                : 'bg-[#00FF00] shadow-[0_0_10px_#00FF00]'
          }`}
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      {/* ================================================================= */}
      {/* 2. PROVIDER EXECUTION ROWS */}
      {/* ================================================================= */}
      <div className="p-4 sm:p-5 space-y-3 bg-[#0D0D0D]">
        <div className="text-[10px] font-bold text-[#666666] uppercase tracking-wider flex justify-between items-center">
          <span>Containerized Forensic Analysis Providers</span>
          <span className="text-[10px] text-[#888888] font-normal">Deterministic Engine Execution</span>
        </div>

        <div className="space-y-2">
          {providerEntries.map(([pKey, rawRecord]) => {
            const record: ProviderExecutionRecord = rawRecord || { provider: pKey, status: 'PENDING' };
            const visual = renderProviderStatusVisual(record.status);
            const isExecuting = record.status === 'EXECUTING' || record.status === 'STARTING' || record.status === 'RUNNING';
            const isExpanded = !!expandedProviders[pKey];

            // Live provider duration
            const providerDuration = isExecuting 
              ? calculateElapsed(record.started_at, record.completed_at)
              : (typeof record.duration === 'number' ? record.duration : (record.duration_seconds || calculateElapsed(record.started_at, record.completed_at)));

            const executionMode = record.execution_mode || (['mobsf', 'jadx', 'apktool', 'tshark'].includes(pKey) ? 'CONTAINER' : 'HOST');
            const containerName = record.container_name || (executionMode === 'CONTAINER' ? 'emit-mobsf' : null);

            return (
              <div 
                key={pKey}
                className={`rounded border transition-all ${
                  isExecuting 
                    ? 'bg-[#121812] border-[#00FF00]/60 shadow-[0_0_15px_rgba(0,255,0,0.1)]' 
                    : record.status === 'COMPLETED'
                      ? 'bg-[#101010] border-[#222222] hover:border-[#333333]'
                      : record.status === 'FAILED'
                        ? 'bg-[#181010] border-[#EF4444]/40'
                        : record.status === 'TIMEOUT'
                          ? 'bg-[#181410] border-[#F59E0B]/40'
                          : 'bg-[#0E0E0E] border-[#1C1C1C]'
                }`}
              >
                <div className="p-3.5 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                  {/* Left: Status symbol + Provider Name + Description */}
                  <div className="flex items-start gap-3 flex-1 min-w-0">
                    <div className="pt-0.5 shrink-0">
                      <span className="font-bold text-sm">{visual.symbol}</span>
                    </div>

                    <div className="space-y-0.5 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-white text-xs uppercase tracking-wider">
                          {pKey}
                        </span>
                        {record.provider_version && (
                          <span className="text-[10px] text-[#666666] font-mono">
                            v{record.provider_version}
                          </span>
                        )}
                        {containerName && (
                          <span className="px-1.5 py-0.2 rounded bg-[#181818] border border-[#2A2A2A] text-[9px] text-[#AAAAAA] uppercase">
                            Docker • {containerName}
                          </span>
                        )}
                        {executionMode === 'HOST' && (
                          <span className="px-1.5 py-0.2 rounded bg-[#181818] border border-[#2A2A2A] text-[9px] text-[#888888] uppercase">
                            Host Process
                          </span>
                        )}
                      </div>

                      {/* Current activity / message */}
                      <p className={`text-[11px] truncate ${
                        isExecuting ? 'text-[#00FF00] font-bold animate-pulse' : record.error ? 'text-[#EF4444]' : 'text-[#888888]'
                      }`}>
                        {record.message || (isExecuting ? 'Executing analysis...' : record.status === 'COMPLETED' ? 'Analysis completed' : 'Awaiting orchestrator trigger')}
                      </p>
                    </div>
                  </div>

                  {/* Right: Status badge, Duration, Expand Details */}
                  <div className="flex items-center gap-3 self-end sm:self-center shrink-0">
                    <div className="text-right">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-bold uppercase ${visual.badgeClass}`}>
                        {visual.label}
                      </span>
                    </div>

                    <div className="w-14 text-right font-mono text-xs font-bold text-white">
                      {providerDuration > 0 ? formatDuration(providerDuration) : '—'}
                    </div>

                    {(record.error || (record.output_metadata && Object.keys(record.output_metadata).length > 0)) && (
                      <button
                        onClick={() => toggleExpand(pKey)}
                        className="p-1 rounded bg-[#181818] hover:bg-[#222222] text-[#888888] hover:text-white border border-[#282828] transition-colors"
                        title="View Diagnostic Details"
                      >
                        {isExpanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                      </button>
                    )}
                  </div>
                </div>

                {/* Technical Diagnostic Details Drawer */}
                {isExpanded && (
                  <div className="p-3 bg-[#080808] border-t border-[#1C1C1C] text-[10px] space-y-2">
                    {record.error && (
                      <div className="p-2.5 rounded bg-[#EF4444]/10 border border-[#EF4444]/30 text-[#EF4444] space-y-1">
                        <div className="font-bold flex items-center gap-1.5">
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                          <span>DIAGNOSTIC ERROR LOG</span>
                        </div>
                        <p className="font-mono text-[10px] break-words whitespace-pre-wrap">{record.error}</p>
                      </div>
                    )}

                    {record.output_metadata && Object.keys(record.output_metadata).length > 0 && (
                      <div className="space-y-1">
                        <span className="text-[#666666] font-bold uppercase tracking-wider block">Extracted Output Metadata</span>
                        <div className="bg-[#101010] p-2.5 rounded border border-[#222222] max-h-32 overflow-y-auto space-y-1 font-mono text-[9px]">
                          {Object.entries(record.output_metadata).map(([k, v]) => (
                            <div key={k} className="flex justify-between border-b border-[#1A1A1A] pb-0.5">
                              <span className="text-[#888888] uppercase">{k}:</span>
                              <span className="text-white truncate max-w-xs">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ================================================================= */}
      {/* 3. CURRENT STAGE PROMINENT PANEL */}
      {/* ================================================================= */}
      {!isTerminal && (
        <div className="p-4 sm:p-5 bg-gradient-to-br from-[#121812] to-[#0A0A0A] border-y border-[#00FF00]/20">
          <div className="text-[10px] font-bold text-[#00FF00] uppercase tracking-widest flex items-center gap-2 mb-2">
            <Radio className="h-3.5 w-3.5 text-[#00FF00] animate-pulse" />
            <span>CURRENT ACTIVE STAGE</span>
          </div>

          <div className="space-y-1">
            <h4 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <span className="text-[#00FF00]">●</span>
              <span>
                {activeExecutingProvider ? activeExecutingProvider.name.toUpperCase() : (currentRun.current_stage || 'ORCHESTRATING PIPELINE')}
              </span>
            </h4>
            <p className="text-xs text-[#AAAAAA]">
              {activeExecutingProvider?.name === 'mobsf' && 'Containerized Android Security Framework static vulnerability analysis.'}
              {activeExecutingProvider?.name === 'jadx' && 'Containerized DEX decompilation and Java AST extraction.'}
              {activeExecutingProvider?.name === 'apktool' && 'Containerized bytecode disassembly and Android manifest parsing.'}
              {activeExecutingProvider?.name === 'androguard' && 'Host-level Python DEX parser & permissions inspector.'}
              {activeExecutingProvider?.name === 'tshark' && 'Containerized Wireshark dissector packet frame analysis.'}
              {activeExecutingProvider?.name === 'scapy' && 'Host-level network packet stream reconstruction.'}
              {!activeExecutingProvider && (currentRun.current_stage === 'NORMALIZING' ? 'Normalizing provider findings into unified observation schemas.' : currentRun.current_stage === 'CORRELATING' ? 'Evaluating deterministic correlation engine rules across indicators.' : currentRun.current_stage === 'BUILDING_GRAPH' ? 'Reconstructing attack sequence chain and relationship graph.' : 'Initializing execution containers and sandbox environment...')}
            </p>
            <p className="text-[11px] text-[#00FF00] font-mono pt-1">
              {activeExecutingProvider?.record?.message || (currentRun.current_stage === 'NORMALIZING' ? 'Ingesting findings to observations...' : currentRun.current_stage === 'CORRELATING' ? 'Correlating indicators...' : currentRun.current_stage === 'BUILDING_GRAPH' ? 'Building graph nodes & edges...' : 'Pipeline active...')}
            </p>
          </div>
        </div>
      )}

      {/* ================================================================= */}
      {/* 4. PIPELINE STEP BREADCRUMBS TRACKER */}
      {/* ================================================================= */}
      <div className="p-3 sm:p-4 bg-[#0A0A0A] flex items-center justify-between overflow-x-auto gap-3">
        <div className="flex items-center gap-3 shrink-0">
          {renderBreadcrumbStage('INGEST', 'INGEST')}
          {renderBreadcrumbStage('ANALYZE', 'ANALYZE')}
          {renderBreadcrumbStage('NORMALIZE', 'NORMALIZE')}
          {renderBreadcrumbStage('CORRELATE', 'CORRELATE')}
          {renderBreadcrumbStage('GRAPH', 'GRAPH', true)}
        </div>

        <div className="text-[10px] text-[#666666] shrink-0 uppercase tracking-wider hidden sm:block">
          STATUS: <strong className={isTerminal ? (currentRun.status === 'COMPLETED' ? 'text-[#00FF00]' : 'text-[#F59E0B]') : 'text-[#00FF00] animate-pulse'}>{currentRun.status}</strong>
        </div>
      </div>

      {/* ================================================================= */}
      {/* 5. COMPLETION SUMMARY & SOC ACTION BUTTONS */}
      {/* ================================================================= */}
      {isTerminal && (
        <div className="p-4 sm:p-5 bg-gradient-to-r from-[#101510] to-[#0A0A0A] space-y-4">
          <div className="flex items-start gap-3">
            <div className={`p-2 rounded-full shrink-0 ${
              currentRun.status === 'COMPLETED' 
                ? 'bg-[#00FF00]/15 text-[#00FF00] border border-[#00FF00]/40' 
                : currentRun.status === 'PARTIAL'
                  ? 'bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/40'
                  : 'bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/40'
            }`}>
              {currentRun.status === 'COMPLETED' ? (
                <ShieldCheck className="h-5 w-5" />
              ) : currentRun.status === 'PARTIAL' ? (
                <AlertTriangle className="h-5 w-5" />
              ) : (
                <ShieldAlert className="h-5 w-5" />
              )}
            </div>

            <div className="space-y-1">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                {currentRun.status === 'COMPLETED' && 'Analysis Completed Successfully'}
                {currentRun.status === 'PARTIAL' && 'Analysis Completed with Provider Warnings'}
                {currentRun.status === 'FAILED' && 'Analysis Pipeline Execution Failed'}
              </h4>
              <p className="text-[11px] text-[#AAAAAA]">
                {currentRun.status === 'COMPLETED' && 'Evidence findings, normalized observations, threat intelligence correlations, and attack chain graph have been reconstructed.'}
                {currentRun.status === 'PARTIAL' && 'Analysis completed with partial results. Available provider evidence has been normalized and is ready for review.'}
                {currentRun.status === 'FAILED' && 'The analysis pipeline could not produce forensic observations. Review diagnostic errors above.'}
              </p>
            </div>
          </div>

          {/* Quick SOC Navigation Actions */}
          <div className="flex flex-wrap gap-2.5 pt-1">
            <button
              onClick={() => onNavigateTab?.('observations')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-[#00FF00] hover:bg-[#00DD00] text-black font-bold uppercase text-[11px] rounded transition-all shadow-[0_0_12px_rgba(0,255,0,0.25)]"
            >
              <FileSearch className="h-3.5 w-3.5" />
              <span>View Results</span>
            </button>

            <button
              onClick={() => onNavigateTab?.('graph')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-[#181818] hover:bg-[#222222] text-[#00FF00] border border-[#00FF00]/40 rounded font-bold uppercase text-[11px] transition-colors"
            >
              <GitBranch className="h-3.5 w-3.5" />
              <span>Attack Graph</span>
            </button>

            <button
              onClick={() => onNavigateTab?.('reports')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 bg-[#181818] hover:bg-[#222222] text-white border border-[#333333] rounded font-bold uppercase text-[11px] transition-colors"
            >
              <Terminal className="h-3.5 w-3.5" />
              <span>View Reports</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default AnalysisRunPanel;
