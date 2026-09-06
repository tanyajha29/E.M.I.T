import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiService, Case } from '../services/api';
import { 
  Plus, 
  Search, 
  SlidersHorizontal, 
  FolderOpen, 
  Loader2,
  X,
  ArrowRight,
  Calendar,
  Shield,
  Filter
} from 'lucide-react';
import { StatusBadge } from '../components/ui/StatusBadge';
import { LoadingSkeleton } from '../components/ui/LoadingSkeleton';
import { ErrorState } from '../components/ui/ErrorState';
import { EmptyState } from '../components/ui/EmptyState';
import { useUser } from '../context/UserContext';

export const Investigations: React.FC = () => {
  const { currentUser, filterMode, setFilterMode, isCaseAssigned } = useUser();
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  // Search & Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'name' | 'date'>('date');

  // Modal State
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newCaseName, setNewCaseName] = useState('');
  const [newCaseDesc, setNewCaseDesc] = useState('');
  const [modalLoading, setModalLoading] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const fetchCases = async () => {
    try {
      setLoading(true);
      setError(false);
      const data = await apiService.getCases();
      setCases(data);
    } catch (err) {
      console.error('Failed to load cases:', err);
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCaseName.trim()) {
      setModalError('Case name is required.');
      return;
    }

    try {
      setModalLoading(true);
      setModalError(null);
      await apiService.createCase({
        name: newCaseName.trim(),
        description: newCaseDesc.trim()
      });
      // Reset & Refresh
      setNewCaseName('');
      setNewCaseDesc('');
      setIsModalOpen(false);
      await fetchCases();
    } catch (err: any) {
      console.error('Create case failed:', err);
      setModalError(err.response?.data?.detail || 'Unable to register case dossier. Try again.');
    } finally {
      setModalLoading(false);
    }
  };

  // User-scoped cases
  const scopedCases = filterMode === 'MY_CASES'
    ? cases.filter(c => isCaseAssigned(c.case_id))
    : cases;

  // Filter & Sort cases list
  const filteredCases = scopedCases
    .filter(c => {
      const matchSearch = c.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
        c.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        c.case_id.toLowerCase().includes(searchTerm.toLowerCase());
      const matchStatus = statusFilter === 'ALL' || c.status === statusFilter;
      return matchSearch && matchStatus;
    })
    .sort((a, b) => {
      if (sortBy === 'name') {
        return a.name.localeCompare(b.name);
      } else {
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      }
    });

  if (loading) {
    return (
      <div className="space-y-6 font-mono">
        <div className="flex justify-between items-center">
          <div className="h-6 w-48 bg-[#181818] rounded animate-pulse" />
          <div className="h-4 w-72 bg-[#181818] rounded animate-pulse" />
        </div>
        <LoadingSkeleton type="card" rows={6} />
      </div>
    );
  }

  if (error) {
    return (
      <ErrorState
        title="Investigations Store Inaccessible"
        message="Could not retrieve forensic case files from the E.M.I.T. server. Verify backend connectivity."
        onRetry={fetchCases}
      />
    );
  }

  return (
    <div className="space-y-6 font-mono text-white">
      {/* Header and Primary Action */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 p-4 rounded bg-[#101010] border border-[#222222]">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-[#00FF00]" />
            <h2 className="text-base font-bold tracking-wider uppercase text-white">
              Forensic Investigations Dossier
            </h2>
          </div>
          <p className="text-xs text-[#AAAAAA] mt-1">
            {filterMode === 'MY_CASES' ? (
              <span className="text-[#00FF00]">
                (Showing only your assigned investigations — Investigator: {currentUser.name})
              </span>
            ) : (
              <span>(Showing all system investigations)</span>
            )}
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
            onClick={() => {
              setModalError(null);
              setIsModalOpen(true);
            }}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 bg-[#00FF00] hover:bg-[#00DD00] text-black text-xs font-bold uppercase tracking-wider rounded transition-all shadow-[0_0_12px_rgba(0,255,0,0.3)]"
          >
            <Plus className="h-4 w-4" />
            <span>New Investigation</span>
          </button>
        </div>
      </div>

      {/* Filters & Search Toolbar */}
      <div className="bg-[#101010] border border-[#222222] rounded p-4 flex flex-col md:flex-row gap-4 items-center justify-between text-xs">
        {/* Search */}
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-[#666666]" />
          <input
            type="text"
            placeholder="Search case name, description, or UUID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#0A0A0A] border border-[#222222] text-white text-xs rounded focus:outline-none focus:border-[#00FF00] transition-colors placeholder:text-[#666666]"
          />
        </div>

        {/* Filter Controls */}
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
              <option value="OPEN">OPEN</option>
              <option value="ANALYZING">ANALYZING</option>
              <option value="COMPLETED">COMPLETED</option>
            </select>
          </div>

          {/* Sort By */}
          <div className="w-full sm:w-auto">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as 'name' | 'date')}
              className="w-full sm:w-40 bg-[#0A0A0A] border border-[#222222] px-2.5 py-2 text-white text-xs rounded focus:outline-none focus:border-[#00FF00] cursor-pointer"
            >
              <option value="date">SORT BY CREATED</option>
              <option value="name">SORT BY NAME</option>
            </select>
          </div>
        </div>
      </div>

      {/* Grid of Case Dossier Cards (Styled with Audit Case aesthetic from image_5.png) */}
      {filteredCases.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredCases.map((c) => {
            const isAssigned = isCaseAssigned(c.case_id);
            return (
              <div
                key={c.case_id}
                className="bg-[#101010] hover:bg-[#141414] border border-[#222222] hover:border-[#00FF00]/50 rounded p-5 flex flex-col justify-between transition-all duration-200 group shadow-sm hover:shadow-[0_0_15px_rgba(0,255,0,0.15)]"
              >
                <div>
                  {/* Header: ID & Status */}
                  <div className="flex justify-between items-start gap-3 pb-3 border-b border-[#1E1E1E]">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-[#666666] select-all tracking-wider">
                        {c.case_id.slice(0, 14)}...
                      </span>
                      {isAssigned && (
                        <span className="text-[9px] px-1.5 py-0.5 rounded border border-[#00FF00]/30 bg-[#00FF00]/10 text-[#00FF00] font-bold">
                          ASSIGNED
                        </span>
                      )}
                    </div>
                    <StatusBadge status={c.status} size="sm" />
                  </div>

                  {/* Case Name */}
                  <h3 className="font-bold text-white text-sm mt-3 group-hover:text-[#00FF00] transition-colors truncate">
                    <Link to={`/investigations/${c.case_id}`}>
                      {c.name}
                    </Link>
                  </h3>

                  {/* Description */}
                  <p className="text-xs text-[#AAAAAA] mt-2 line-clamp-3 h-12 leading-relaxed font-mono">
                    {c.description || 'No formal scope documented. Telemetry ingestion and graph correlation active.'}
                  </p>
                </div>

                {/* Footer strip: Timestamp & Open Action */}
                <div className="border-t border-[#1E1E1E] mt-5 pt-3.5 flex items-center justify-between text-[11px]">
                  <span className="text-[#666666] flex items-center gap-1.5">
                    <Calendar className="h-3 w-3 text-[#666666]" />
                    {new Date(c.created_at).toLocaleDateString()}
                  </span>
                  <Link
                    to={`/investigations/${c.case_id}`}
                    className="inline-flex items-center gap-1.5 text-[#00FF00] group-hover:underline font-bold uppercase tracking-wider transition-colors"
                  >
                    <span>OPEN DOSSIER</span>
                    <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </Link>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <EmptyState
          title="No Investigation Files Found"
          description={searchTerm || statusFilter !== 'ALL'
            ? "No case files match the current query filters. Try adjusting your search term."
            : filterMode === 'MY_CASES'
            ? "You have no assigned investigation dossiers. Switch to 'All Cases' or create a new case."
            : "No active cases registered yet. Click 'New Investigation' above to create one."}
          action={searchTerm || statusFilter !== 'ALL' ? {
            label: "Reset Filters",
            onClick: () => {
              setSearchTerm('');
              setStatusFilter('ALL');
            }
          } : undefined}
        />
      )}

      {/* New Case Creation Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-4 font-mono">
          <div className="w-full max-w-lg bg-[#101010] border border-[#222222] rounded shadow-2xl relative text-xs">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-[#222222] bg-[#0A0A0A]">
              <div className="flex items-center gap-2">
                <FolderOpen className="h-4 w-4 text-[#00FF00]" />
                <h3 className="font-bold text-white uppercase tracking-wider">
                  Register New Investigation Case
                </h3>
              </div>
              <button 
                onClick={() => setIsModalOpen(false)}
                className="text-[#666666] hover:text-white p-1 rounded hover:bg-[#181818] transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleCreateCase} className="p-5 space-y-4">
              {modalError && (
                <div className="p-3 border border-[#FF3333]/40 bg-[#FF3333]/10 text-[#FF3333] text-xs font-semibold rounded">
                  {modalError}
                </div>
              )}

              <div>
                <label className="block font-bold text-white uppercase tracking-wider mb-1.5">
                  Case Name <span className="text-[#FF3333]">*</span>
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Audit Case - Operation Chimera"
                  value={newCaseName}
                  onChange={(e) => setNewCaseName(e.target.value)}
                  className="w-full bg-[#0A0A0A] border border-[#222222] px-3 py-2 text-white text-xs rounded focus:outline-none focus:border-[#00FF00] transition-colors placeholder:text-[#666666]"
                />
              </div>

              <div>
                <label className="block font-bold text-white uppercase tracking-wider mb-1.5">
                  Investigative Scope & Description
                </label>
                <textarea
                  rows={4}
                  placeholder="Document target identifiers, evidence boundaries, and investigation objectives..."
                  value={newCaseDesc}
                  onChange={(e) => setNewCaseDesc(e.target.value)}
                  className="w-full bg-[#0A0A0A] border border-[#222222] px-3 py-2 text-white text-xs rounded focus:outline-none focus:border-[#00FF00] transition-colors resize-none placeholder:text-[#666666] font-mono"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-[#222222] mt-5">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  disabled={modalLoading}
                  className="px-4 py-2 border border-[#222222] text-[#AAAAAA] hover:text-white hover:bg-[#181818] rounded transition-colors uppercase font-bold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalLoading}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-[#00FF00] hover:bg-[#00DD00] disabled:opacity-50 text-black rounded font-bold uppercase tracking-wider transition-colors shadow-[0_0_12px_rgba(0,255,0,0.3)]"
                >
                  {modalLoading && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  <span>Register Dossier</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Investigations;

