import React, { useEffect, useState, useCallback } from 'react';
import { apiService, Case, Report } from '../services/api';
import { Loader2, AlertTriangle, FileText, Download, ExternalLink, RefreshCw, CheckCircle2 } from 'lucide-react';

export const Reports: React.FC = () => {
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
          setSelectedCaseId(data[0].case_id);
        }
      } catch (err) {
        console.error('Failed to load cases in reports page:', err);
        setError(true);
      } finally {
        setLoading(false);
      }
    };

    fetchCases();
  }, []);

  const fetchReports = useCallback(async (caseId: string) => {
    if (!caseId) {
      setReports([]);
      return;
    }
    try {
      setReportsLoading(true);
      const data = await apiService.getReportsForCase(caseId);
      // sort descending by created_at
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

  const handleGenerateReport = async () => {
    if (!selectedCaseId) return;
    try {
      setGenerating(true);
      setSuccessMessage(null);
      await apiService.generateReport(selectedCaseId, format, reportTitle);
      setSuccessMessage('Forensic Report successfully generated and stored.');
      await fetchReports(selectedCaseId);
    } catch (err: any) {
      console.error('Report generation error:', err);
      alert('Report generation failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setGenerating(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
        <span className="text-sm font-semibold tracking-wider text-slate-400 uppercase">Loading Report Center...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="border border-rose-950 bg-rose-950/20 p-6 rounded flex items-start gap-4">
        <AlertTriangle className="h-6 w-6 text-rose-500 shrink-0 mt-0.5" />
        <div>
          <h3 className="text-md font-bold text-rose-400 uppercase tracking-wider">Reports Unavailable</h3>
          <p className="text-sm text-slate-400 mt-1">Unable to initialize reporting modules. Check backend API logs.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Selection toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Executive Investigation Reports</h3>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">Generate, view, and export reproducible forensic dossiers directly from stored investigation data.</p>
        </div>

        <div className="w-full sm:w-auto">
          <select
            value={selectedCaseId}
            onChange={(e) => setSelectedCaseId(e.target.value)}
            className="w-full sm:w-72 bg-slate-950 border border-slate-800 px-3 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="">SELECT INVESTIGATION CASE...</option>
            {cases.map(c => (
              <option key={c.case_id} value={c.case_id}>{c.name}</option>
            ))}
          </select>
        </div>
      </div>

      {selectedCaseId ? (
        <div className="space-y-6">
          {/* Generator Card */}
          <div className="bg-slate-900 border border-slate-800 rounded p-6 space-y-4">
            <div className="flex justify-between items-start border-b border-slate-800 pb-3">
              <div>
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Compile New Investigation Report</h4>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Renders all 13 forensic sections, separating observed evidence from inferences and external threat intelligence.
                </p>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 bg-cyan-950/60 border border-cyan-800 text-cyan-400 rounded">
                CASE ID: {selectedCaseId.slice(0, 8)}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
              <div className="md:col-span-2">
                <label className="block text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">
                  Report Title
                </label>
                <input
                  type="text"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-200 rounded focus:outline-none focus:border-cyan-500"
                  placeholder="E.M.I.T. Forensic Investigation Dossier"
                />
              </div>

              <div>
                <label className="block text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">
                  Output Format
                </label>
                <select
                  value={format}
                  onChange={(e) => setFormat(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-200 rounded focus:outline-none focus:border-cyan-500 cursor-pointer"
                >
                  <option value="BOTH">HTML + PDF Export (Recommended)</option>
                  <option value="HTML">Interactive HTML Only</option>
                  <option value="PDF">ReportLab PDF Dossier Only</option>
                </select>
              </div>
            </div>

            {successMessage && (
              <div className="flex items-center gap-2 p-3 bg-emerald-950/30 border border-emerald-800/40 rounded text-emerald-400 text-xs">
                <CheckCircle2 className="h-4 w-4 shrink-0" />
                <span>{successMessage}</span>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                onClick={handleGenerateReport}
                disabled={generating}
                className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-slate-950 disabled:text-slate-500 text-xs font-bold uppercase tracking-wider rounded transition-colors"
              >
                {generating ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Compiling Forensic Dossier...</span>
                  </>
                ) : (
                  <>
                    <FileText className="h-4 w-4" />
                    <span>Generate Forensic Report</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Generated Reports List */}
          <div className="bg-slate-900 border border-slate-800 rounded p-6 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <h4 className="text-xs font-bold text-slate-200 uppercase tracking-wider">Generated Reports History</h4>
                <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-800 text-slate-400 rounded">
                  {reports.length}
                </span>
              </div>
              <button
                onClick={() => fetchReports(selectedCaseId)}
                className="p-1.5 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
                title="Refresh Report List"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${reportsLoading ? 'animate-spin' : ''}`} />
              </button>
            </div>

            {reportsLoading ? (
              <div className="py-12 flex flex-col items-center justify-center gap-2">
                <Loader2 className="h-6 w-6 text-cyan-400 animate-spin" />
                <span className="text-xs text-slate-500">Retrieving case reports...</span>
              </div>
            ) : reports.length === 0 ? (
              <div className="py-12 text-center border border-dashed border-slate-800 rounded bg-slate-950/20">
                <FileText className="h-8 w-8 text-slate-600 mx-auto mb-2" />
                <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">No Reports Generated Yet</p>
                <p className="text-[11px] text-slate-500 mt-1 max-w-sm mx-auto">
                  Click "Generate Forensic Report" above to compile a reproducible report containing real evidence, attack chain, and risk assessment findings.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {reports.map((rep) => (
                  <div
                    key={rep.report_id}
                    className="p-4 bg-slate-950 border border-slate-800 rounded flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 hover:border-slate-700 transition-colors"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-slate-200">{rep.title}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-cyan-950/50 border border-cyan-800/40 text-cyan-400 rounded uppercase">
                          {rep.report_format}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-emerald-950/50 border border-emerald-800/40 text-emerald-400 rounded">
                          {rep.status}
                        </span>
                      </div>
                      <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500">
                        <span>ID: {rep.report_id.slice(0, 8)}...</span>
                        <span>&bull;</span>
                        <span>Generated: {rep.generated_at ? new Date(rep.generated_at).toLocaleString() : 'N/A'}</span>
                        {rep.metadata?.risk_level && (
                          <>
                            <span>&bull;</span>
                            <span className="text-amber-400 font-semibold">Risk: {rep.metadata.risk_level}</span>
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
                          className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-400 hover:text-cyan-300 text-xs font-mono rounded transition-colors"
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
                          className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-700/60 text-cyan-300 text-xs font-mono rounded transition-colors"
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
        <div className="py-20 text-center border border-dashed border-slate-800 rounded bg-slate-950/10">
          <p className="text-xs text-slate-500 uppercase tracking-widest">Select a case file above to access reporting options</p>
        </div>
      )}
    </div>
  );
};

export default Reports;
