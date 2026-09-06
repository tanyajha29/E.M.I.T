import React, { useEffect, useState, useCallback } from 'react';
import { apiService, Case, Report } from '../services/api';
import { Loader2, FileText, Download, ExternalLink, RefreshCw, CheckCircle2, ShieldAlert, Filter, Shield } from 'lucide-react';
import { StatusBadge } from '../components/ui/StatusBadge';
import { ErrorState } from '../components/ui/ErrorState';
import { EmptyState } from '../components/ui/EmptyState';
import { useUser } from '../context/UserContext';

export const Reports: React.FC = () => {
  const { currentUser, filterMode, setFilterMode, isCaseAssigned } = useUser();
  const [cases, setCases] = useState<Case[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [reports, setReports] = useState<Report[]>([]);
  
  const [format, setFormat] = useState<'BOTH' | 'HTML' | 'PDF'>('BOTH');
  const [reportTitle, setReportTitle] = useState('E.M.I.T. Forensic Investigation Dossier');
  
  const [loading, setLoading] = useState(true);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState(false);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    const fetchCases = async () => {
      try {
        setLoading(true);
        setError(false);
        const data = await apiService.getCases();
        setCases(data);
        if (data.length > 0) {
          // Select the first assigned case if in MY_CASES mode
          const assigned = data.filter(c => isCaseAssigned(c.case_id));
          setSelectedCaseId(assigned.length > 0 ? assigned[0].case_id : data[0].case_id);
        }
      } catch (err) {
        console.error('Failed to load cases in reports page:', err);
        setError(true);
      } finally {
        setLoading(false);
      }
    };

    fetchCases();
  }, [isCaseAssigned]);

  const fetchReports = useCallback(async (caseId: string) => {
    if (!caseId) {
      setReports([]);
      return;
    }
    try {
      setReportsLoading(true);
      const data = await apiService.getReportsForCase(caseId);
      setReports(data.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()));
    } catch (err) {
      console.error('Failed to fetch reports for case:', err);
      setReports([]);
    } finally {
      setReportsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports(selectedCaseId);
  }, [selectedCaseId, fetchReports]);

  const handleGenerateReport = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!selectedCaseId) return;
    try {
      setGenerating(true);
      setSuccessMessage(null);
      await apiService.generateReport(selectedCaseId, format, reportTitle);
      setSuccessMessage('Forensic Dossier successfully compiled and registered.');
      await fetchReports(selectedCaseId);
    } catch (err: any) {
      console.error('Report generation error:', err);
      alert('Report generation failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setGenerating(false);
    }
  };

  const isSelectedCaseAssigned = isCaseAssigned(selectedCaseId);
  const displayedCases = filterMode === 'MY_CASES'
    ? cases.filter(c => isCaseAssigned(c.case_id))
    : cases;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3 font-mono text-white">
        <Loader2 className="h-8 w-8 text-[#00FF00] animate-spin" />
        <span className="text-xs font-semibold tracking-wider text-[#AAAAAA] uppercase">
          Loading Forensic Report Center...
        </span>
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Report Center Inaccessible"
        message="Unable to initialize reporting modules. Check backend API logs."
      />
    );
  }

  return (
    <div className="space-y-6 max-w-5xl font-mono text-xs text-white">
      {/* Header & Case Selection Toolbar */}
      <div className="bg-[#101010] border border-[#222222] rounded p-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-[#00FF00]" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Forensic Reports & Dossiers
            </h3>
          </div>
          <p className="text-[11px] text-[#AAAAAA] mt-0.5">
            {filterMode === 'MY_CASES' 
              ? `Showing assigned reports for Investigator ${currentUser.name} (${currentUser.badgeId})`
              : 'Showing all platform forensic report files'}
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
        </div>
      </div>

      {/* Access Denied Guard for restricted cases */}
      {selectedCaseId && !isSelectedCaseAssigned && filterMode === 'MY_CASES' ? (
        <div className="p-8 border border-[#FF3333]/40 bg-[#101010] rounded text-center space-y-4">
          <div className="inline-flex p-3 rounded-full bg-[#FF3333]/10 border border-[#FF3333]/30 text-[#FF3333]">
            <ShieldAlert className="h-8 w-8 animate-pulse" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-white uppercase tracking-wider">
              Restricted Forensic Report Access
            </h4>
            <p className="text-xs text-[#AAAAAA] mt-1 max-w-md mx-auto">
              This dossier belongs to an investigation outside your assigned workspace scope. Switch to All Cases mode to review.
            </p>
          </div>
          <button
            onClick={() => setFilterMode('ALL_CASES')}
            className="px-4 py-2 bg-[#181818] hover:bg-[#222222] border border-[#00FF00]/40 rounded text-xs text-[#00FF00] font-bold uppercase transition-colors"
          >
            Switch to All Cases Mode
          </button>
        </div>
      ) : selectedCaseId ? (
        <div className="space-y-6">
          {/* Dossier Compiler Form */}
          <form onSubmit={handleGenerateReport} className="bg-[#101010] border border-[#222222] rounded p-5 space-y-4">
            <div className="flex justify-between items-start border-b border-[#222222] pb-3">
              <div>
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Compile New Investigation Dossier
                </h4>
                <p className="text-[11px] text-[#AAAAAA] mt-0.5">
                  Separates observed facts from deductions and external threat intelligence across all evidence artifacts.
                </p>
              </div>
              <span className="text-[10px] px-2 py-0.5 bg-[#0A0A0A] border border-[#222222] text-[#00FF00] rounded">
                CASE ID: {selectedCaseId.slice(0, 8)}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
              <div className="md:col-span-2">
                <label className="block text-[11px] font-bold text-white uppercase tracking-wider mb-1">
                  Report Title
                </label>
                <input
                  type="text"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  className="w-full bg-[#0A0A0A] border border-[#222222] px-3 py-2 text-xs text-white rounded focus:outline-none focus:border-[#00FF00] placeholder:text-[#666666]"
                  placeholder="E.M.I.T. Forensic Investigation Dossier"
                />
              </div>

              <div>
                <label htmlFor="format-select" className="block text-[11px] font-bold text-white uppercase tracking-wider mb-1">
                  Report Format
                </label>
                <select
                  id="format-select"
                  value={format}
                  onChange={(e) => setFormat(e.target.value as any)}
                  className="w-full bg-[#0A0A0A] border border-[#222222] px-3 py-2 text-xs text-white rounded focus:outline-none focus:border-[#00FF00] cursor-pointer"
                >
                  <option value="BOTH">HTML + PDF Dossier</option>
                  <option value="HTML">HTML Interactive</option>
                  <option value="PDF">PDF Document</option>
                </select>
              </div>
            </div>

            {successMessage && (
              <div className="flex items-center gap-2 p-3 bg-[#00FF00]/10 border border-[#00FF00]/40 rounded text-[#00FF00] text-xs">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>{successMessage}</span>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                type="submit"
                disabled={generating}
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#00FF00] hover:bg-[#00DD00] disabled:opacity-50 text-black text-xs font-bold uppercase tracking-wider rounded transition-all shadow-[0_0_12px_rgba(0,255,0,0.3)]"
              >
                {generating ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Compiling Forensic Dossier...</span>
                  </>
                ) : (
                  <>
                    <FileText className="h-4 w-4" />
                    <span>Compile Forensic Report</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Generated Reports History */}
          <div className="bg-[#101010] border border-[#222222] rounded p-5 space-y-4">
            <div className="flex justify-between items-center border-b border-[#222222] pb-3">
              <div className="flex items-center gap-2">
                <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                  Generated Reports History
                </h4>
                <span className="text-[10px] px-2 py-0.5 bg-[#0A0A0A] border border-[#222222] text-[#AAAAAA] rounded">
                  {reports.length}
                </span>
              </div>

              <button
                onClick={() => fetchReports(selectedCaseId)}
                className="p-1.5 bg-[#181818] hover:bg-[#222222] border border-[#222222] rounded text-[#AAAAAA] hover:text-white transition-colors"
                title="Refresh Report List"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${reportsLoading ? 'animate-spin text-[#00FF00]' : ''}`} />
              </button>
            </div>

            {reportsLoading ? (
              <div className="py-12 flex flex-col items-center justify-center gap-2">
                <Loader2 className="h-6 w-6 text-[#00FF00] animate-spin" />
                <span className="text-xs text-[#AAAAAA]">Retrieving case reports...</span>
              </div>
            ) : reports.length === 0 ? (
              <EmptyState
                icon={FileText}
                title="No Reports Generated Yet"
                description="Click 'Compile Forensic Report' above to assemble an interactive HTML dossier or PDF document."
              />
            ) : (
              <div className="space-y-3">
                {reports.map((rep) => (
                  <div
                    key={rep.report_id}
                    className="p-4 bg-[#0A0A0A] border border-[#222222] rounded flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 hover:border-[#00FF00]/40 transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-bold text-white">{rep.title}</span>
                        <span className="text-[10px] px-2 py-0.5 bg-[#181818] border border-[#222222] text-[#00FF00] rounded uppercase font-bold">
                          {rep.report_format}
                        </span>
                        <StatusBadge status={rep.status} size="sm" />
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-[#666666]">
                        <span>ID: {rep.report_id.slice(0, 8)}...</span>
                        <span>&bull;</span>
                        <span>Generated: {rep.generated_at ? new Date(rep.generated_at).toLocaleString() : 'N/A'}</span>
                        {rep.metadata?.risk_level && (
                          <>
                            <span>&bull;</span>
                            <span className="text-[#FF8800] font-semibold">Risk: {rep.metadata.risk_level}</span>
                          </>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 w-full sm:w-auto">
                      {(rep.report_format === 'HTML' || rep.report_format === 'BOTH') && rep.html_path && (
                        <a
                          href={apiService.getReportDownloadUrl(selectedCaseId, rep.report_id, 'html')}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#00FF00]/40 text-[#00FF00] text-xs rounded transition-colors"
                        >
                          <ExternalLink className="h-3.5 w-3.5" />
                          <span>View HTML</span>
                        </a>
                      )}

                      {(rep.report_format === 'PDF' || rep.report_format === 'BOTH') && rep.pdf_path && (
                        <a
                          href={apiService.getReportDownloadUrl(selectedCaseId, rep.report_id, 'pdf')}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#181818] hover:bg-[#222222] border border-[#222222] hover:border-[#BB88FF]/40 text-[#BB88FF] text-xs rounded transition-colors"
                        >
                          <Download className="h-3.5 w-3.5" />
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
      ) : (
        <EmptyState
          title="No Case Dossier Selected"
          description="Select an active investigation case from the dropdown above to manage and compile forensic reports."
        />
      )}
    </div>
  );
};

export default Reports;
