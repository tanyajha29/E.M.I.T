import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { apiService, Case } from '../services/api';
import { 
  Plus, 
  Search, 
  SlidersHorizontal, 
  FolderOpen, 
  AlertTriangle, 
  Loader2,
  X
} from 'lucide-react';

const Investigations: React.FC = () => {
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
      setModalError('Case name is required');
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
      fetchCases();
    } catch (err: any) {
      console.error('Create case failed:', err);
      setModalError(err.response?.data?.detail || 'Unable to create case. Try again.');
    } finally {
      setModalLoading(false);
    }
  };

  // Filter & Sort cases list
  const filteredCases = cases
    .filter(c => {
      const matchSearch = c.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
        c.description.toLowerCase().includes(searchTerm.toLowerCase());
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
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-3">
        <Loader2 className="h-8 w-8 text-cyan-400 animate-spin" />
        <span className="text-sm font-semibold tracking-wider text-slate-400 uppercase">Resolving Cases...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="border border-red-950 bg-red-950/20 p-6 rounded flex items-start gap-4">
        <AlertTriangle className="h-6 w-6 text-red-500 shrink-0 mt-0.5" />
        <div>
          <h3 className="text-md font-bold text-red-400 uppercase tracking-wider">Loading Failed</h3>
          <p className="text-sm text-slate-400 mt-1">Could not retrieve cases from E.M.I.T. servers. Check server status.</p>
          <button 
            onClick={fetchCases}
            className="mt-4 px-4 py-2 border border-red-800 text-red-400 hover:bg-red-900/20 text-xs font-bold uppercase rounded transition-colors"
          >
            Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header and Action */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <p className="text-xs font-bold text-slate-500 uppercase tracking-widest">Active System Case Files</p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold uppercase tracking-wider rounded transition-colors"
        >
          <Plus className="h-4 w-4" /> New Case File
        </button>
      </div>

      {/* Filters toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 flex flex-col md:flex-row gap-4 items-center">
        {/* Search */}
        <div className="relative flex-1 w-full">
          <Search className="absolute left-3 top-2.5 h-4.5 w-4.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search by case file name or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded focus:outline-none focus:border-cyan-500 transition-colors placeholder:text-slate-600"
          />
        </div>

        {/* Status Select */}
        <div className="flex items-center gap-2 w-full md:w-auto">
          <SlidersHorizontal className="h-4 w-4 text-slate-500 shrink-0" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full md:w-40 bg-slate-950 border border-slate-800 px-3 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-cyan-500 transition-colors cursor-pointer"
          >
            <option value="ALL">ALL STATUSES</option>
            <option value="OPEN">OPEN</option>
            <option value="ANALYZING">ANALYZING</option>
            <option value="COMPLETED">COMPLETED</option>
            <option value="ARCHIVED">ARCHIVED</option>
          </select>
        </div>

        {/* Sort Select */}
        <div className="w-full md:w-auto">
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'name' | 'date')}
            className="w-full md:w-40 bg-slate-950 border border-slate-800 px-3 py-2 text-slate-300 text-xs rounded focus:outline-none focus:border-cyan-500 transition-colors cursor-pointer"
          >
            <option value="date">SORT BY CREATED</option>
            <option value="name">SORT BY NAME</option>
          </select>
        </div>
      </div>

      {/* Grid of Cases */}
      {filteredCases.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredCases.map((c) => (
            <div key={c.case_id} className="bg-slate-900 border border-slate-800 rounded p-6 flex flex-col justify-between hover:border-slate-700 transition-colors group">
              <div>
                <div className="flex justify-between items-start gap-4">
                  <h4 className="font-bold text-slate-100 text-md truncate group-hover:text-cyan-400 transition-colors">{c.name}</h4>
                  <span className={`px-2 py-0.5 border text-[9px] font-bold rounded uppercase tracking-wider shrink-0 ${
                    c.status === 'OPEN' 
                      ? 'border-cyan-800/40 bg-cyan-950/20 text-cyan-400'
                      : c.status === 'ANALYZING'
                        ? 'border-amber-800/40 bg-amber-950/20 text-amber-400 animate-pulse'
                        : c.status === 'COMPLETED'
                          ? 'border-emerald-800/40 bg-emerald-950/20 text-emerald-400'
                          : 'border-slate-750 bg-slate-800/45 text-slate-500'
                  }`}>
                    {c.status}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-3 line-clamp-3 h-12 leading-relaxed">
                  {c.description || 'No description provided.'}
                </p>
              </div>

              <div className="border-t border-slate-800/60 mt-6 pt-4 flex items-center justify-between text-[11px] text-slate-500">
                <span>Created: {new Date(c.created_at).toLocaleDateString()}</span>
                <Link
                  to={`/investigations/${c.case_id}`}
                  className="text-cyan-400 font-bold uppercase tracking-wider hover:underline"
                >
                  Open File &rarr;
                </Link>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="py-20 text-center border border-dashed border-slate-800 rounded bg-slate-900/10">
          <FolderOpen className="h-10 w-10 text-slate-700 mx-auto mb-3" />
          <p className="text-xs text-slate-500 uppercase tracking-widest">No matching investigations found</p>
        </div>
      )}

      {/* New Case Creation Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded shadow-2xl relative">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-slate-800">
              <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-widest">Create New Investigation Case</h3>
              <button 
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Form */}
            <form onSubmit={handleCreateCase} className="p-6 space-y-4">
              {modalError && (
                <div className="p-3 border border-red-900 bg-red-950/20 text-red-400 text-xs font-semibold rounded flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0" />
                  {modalError}
                </div>
              )}

              <div>
                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Case Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Operation Chimera AP-7"
                  value={newCaseName}
                  onChange={(e) => setNewCaseName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 px-4 py-2.5 text-slate-200 text-xs rounded focus:outline-none focus:border-cyan-500 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Description</label>
                <textarea
                  rows={4}
                  placeholder="Investigative scope, target identifiers, and evidence boundaries..."
                  value={newCaseDesc}
                  onChange={(e) => setNewCaseDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 px-4 py-2.5 text-slate-200 text-xs rounded focus:outline-none focus:border-cyan-500 transition-colors resize-none"
                />
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-850 mt-6">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  disabled={modalLoading}
                  className="px-4 py-2 border border-slate-800 text-slate-400 hover:bg-slate-800/40 text-xs font-bold uppercase rounded transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalLoading}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 disabled:text-slate-600 text-slate-950 text-xs font-bold uppercase tracking-wider rounded transition-all"
                >
                  {modalLoading && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  Open File
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
