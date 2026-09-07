import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { 
  LayoutDashboard, 
  FolderOpen, 
  Binary, 
  GitFork, 
  BarChart3, 
  Shield, 
  RefreshCw,
  Menu,
  X,
  UserCheck,
  Layers,
  Filter,
  LogOut
} from 'lucide-react';
import { apiService, HealthResponse, Case } from '../services/api';
import { StatusIndicator } from './ui/StatusIndicator';
import { useUser } from '../context/UserContext';
import { ErrorBoundary } from './ErrorBoundary';

interface LayoutProps {
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { currentUser, logout, filterMode, setFilterMode, isCaseAssigned } = useUser();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [cases, setCases] = useState<Case[]>([]);
  const [healthLoading, setHealthLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // Fetch live configurations to show real active details in header
  const fetchData = async (manual: boolean = false) => {
    if (manual) setRefreshing(true);
    try {
      const healthData = await apiService.getHealth();
      setHealth(healthData);
    } catch {
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }

    try {
      const caseList = await apiService.getCases();
      setCases(caseList);
    } catch {
      setCases([]);
    } finally {
      if (manual) setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchData();
    // Poll health status every 30 seconds
    const interval = setInterval(() => fetchData(false), 30000);
    return () => clearInterval(interval);
  }, []);

  const assignedCases = cases.filter(c => isCaseAssigned(c.case_id));
  const displayedCases = filterMode === 'MY_CASES' ? assignedCases : cases;
  const activeCasesCount = displayedCases.filter(c => c.status === 'OPEN' || c.status === 'ANALYZING').length;

  const menuItems: Array<{ name: string; path: string; icon: any; badge?: string }> = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Investigations', path: '/investigations', icon: FolderOpen },
    { name: 'Analysis', path: '/analysis', icon: Binary },
    { name: 'Attack Graph', path: '/attack-graph', icon: GitFork },
    { name: 'Reports', path: '/reports', icon: BarChart3 },
  ];

  // Derive database connection status safely
  const isDbConnected = health?.database?.status === 'connected';

  // Active page label for breadcrumb
  const currentMenuItem = menuItems.find(
    item => item.path === location.pathname || (item.path !== '/' && location.pathname.startsWith(item.path))
  );
  const pageTitle = currentMenuItem?.name || 'Workspace';

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#000000] text-white font-mono antialiased selection:bg-[#00FF00]/20 selection:text-[#00FF00]">
      {/* Mobile Drawer Backdrop */}
      {isMobileMenuOpen && (
        <div 
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Fixed Constant Sidebar */}
      <aside
        className={`fixed lg:static inset-y-0 left-0 z-50 w-64 h-full bg-[#101010] border-r border-[#222222] flex flex-col shrink-0 overflow-y-auto transition-transform duration-300 ease-in-out ${
          isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Title / Logo Header */}
        <div className="h-16 flex items-center justify-between px-5 border-b border-[#222222] bg-[#0A0A0A]">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded bg-[#141414] border border-[#00FF00]/40 flex items-center justify-center shadow-[0_0_12px_rgba(0,255,0,0.2)]">
              <Shield className="h-5 w-5 text-[#00FF00]" />
            </div>
            <div>
              <span className="text-base font-mono font-bold tracking-widest text-[#00FF00]">
                E.M.I.T.
              </span>
              <span className="block text-[9px] font-mono text-[#666666] tracking-widest uppercase">
                Forensic Console
              </span>
            </div>
          </div>
          <button
            onClick={() => setIsMobileMenuOpen(false)}
            className="lg:hidden p-1.5 text-[#666666] hover:text-white rounded border border-[#222222]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Section Label */}
        <div className="px-5 pt-5 pb-2">
          <span className="text-[10px] font-mono font-bold tracking-widest text-[#666666] uppercase">
            {currentUser.role === 'ADMIN' ? 'All Investigations (Admin)' : currentUser.role === 'VIEWER' ? 'Assigned Cases (Viewer)' : 'My Investigations'}
          </span>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 px-3 space-y-1.5">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path || 
              (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <Link
                key={item.name}
                to={item.path}
                onClick={() => setIsMobileMenuOpen(false)}
                className={`relative flex items-center justify-between px-3.5 py-2.5 rounded font-mono text-xs transition-all duration-150 group ${
                  isActive
                    ? 'bg-[#181818] text-white font-bold border border-[#00FF00]/50 shadow-[0_0_12px_rgba(0,255,0,0.15)]'
                    : 'text-[#AAAAAA] hover:text-white hover:bg-[#141414] border border-transparent'
                }`}
              >
                {/* Active neon green vertical bar indicator */}
                {isActive && (
                  <span className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-r bg-[#00FF00] shadow-[0_0_8px_#00FF00]" />
                )}

                <div className="flex items-center gap-3">
                  <Icon className={`h-4 w-4 transition-colors ${isActive ? 'text-[#00FF00]' : 'text-[#666666] group-hover:text-slate-300'}`} />
                  <span className="tracking-wider">{item.name}</span>
                </div>

                {item.badge && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[#00FF00]/40 bg-[#00FF00]/10 text-[#00FF00] font-bold">
                    {item.badge}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* User Session Info Card */}
        <div className="p-3 mx-3 mb-2 rounded bg-[#0D0D0D] border border-[#222222] text-[11px] space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-[9px] text-[#666666] uppercase tracking-wider font-bold">
              {currentUser.role}
            </span>
            <span className="text-[9px] px-1.5 py-0.2 rounded border border-[#00FF00]/30 bg-[#00FF00]/10 text-[#00FF00] font-bold">
              {currentUser.badgeId}
            </span>
          </div>
          <div className="font-bold text-white truncate">{currentUser.name}</div>
          {currentUser.email && (
            <div className="text-[10px] text-[#666666] truncate">{currentUser.email}</div>
          )}
          
          {/* Logout & Filter Scope */}
          <div className="pt-2 border-t border-[#1C1C1C] flex items-center justify-between">
            <button
              onClick={() => setFilterMode(filterMode === 'MY_CASES' ? 'ALL_CASES' : 'MY_CASES')}
              className="flex items-center gap-1 text-[10px] text-[#AAAAAA] hover:text-[#00FF00] transition-colors"
              title="Toggle Scope: My Assigned Cases vs All System Cases"
            >
              <Filter className="h-3 w-3 text-[#00FF00]" />
              <span>{filterMode === 'MY_CASES' ? 'My Scope' : 'All Scope'}</span>
            </button>
            <button
              onClick={async () => {
                await logout();
                navigate('/');
              }}
              className="flex items-center gap-1 text-[10px] text-red-400 hover:text-red-300 transition-colors"
              title="Sign Out"
            >
              <LogOut className="h-3 w-3" />
              <span>Sign Out</span>
            </button>
          </div>
        </div>

        {/* System Capabilities Footer */}
        <div className="p-4 border-t border-[#222222] bg-[#0A0A0A] space-y-2">
          <div className="flex items-center justify-between text-[10px] font-mono text-[#666666]">
            <span className="flex items-center gap-1.5">
              <Layers className="h-3 w-3 text-[#00FF00]" />
              <span>CORE PLATFORM</span>
            </span>
            <span className="text-[#AAAAAA] font-semibold">v1.0.0</span>
          </div>
          <div className="text-[9px] font-mono text-[#666666] uppercase tracking-wider bg-[#101010] p-1.5 rounded border border-[#222222] text-center">
            FORENSIC SOC WORKBENCH
          </div>
        </div>
      </aside>

      {/* Main Viewport Container */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden bg-[#000000]">
        {/* Top System Bar */}
        <header className="h-16 bg-[#101010] border-b border-[#222222] flex items-center justify-between px-4 sm:px-8 shrink-0 z-10">
          <div className="flex items-center gap-4">
            {/* Mobile Hamburger Toggle */}
            <button
              onClick={() => setIsMobileMenuOpen(true)}
              className="lg:hidden p-2 bg-[#181818] border border-[#222222] rounded text-slate-300 hover:text-white"
            >
              <Menu className="h-4 w-4" />
            </button>

            {/* Breadcrumb Path */}
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-[#00FF00] font-bold tracking-wider">E.M.I.T.</span>
              <span className="text-[#666666]">/</span>
              <h1 className="text-white font-bold tracking-wider uppercase">
                {pageTitle}
              </h1>
            </div>

            {/* Operational Status Strip (Desktop) */}
            <div className="hidden xl:flex items-center gap-4 text-xs border-l border-[#222222] pl-6">
              {/* API Online Status */}
              <StatusIndicator 
                status={health ? 'healthy' : (healthLoading ? 'neutral' : 'offline')}
                label={healthLoading ? 'CHECKING API...' : (health ? 'API ONLINE' : 'API OFFLINE')}
              />

              <span className="text-[#222222]">|</span>

              {/* MongoDB Status */}
              <StatusIndicator 
                status={isDbConnected ? 'healthy' : (healthLoading ? 'neutral' : 'offline')}
                label={healthLoading ? 'CHECKING DB...' : (isDbConnected ? 'MONGODB ACTIVE' : 'MONGODB OFFLINE')}
              />

              <span className="text-[#222222]">|</span>

              {/* Neutral Analysis Engine Indicator */}
              <span className="font-mono text-[11px] text-[#666666] uppercase tracking-wider">
                ENGINE: <span className="text-[#AAAAAA] font-semibold">CONTAINERIZED PIPELINE</span>
              </span>
            </div>
          </div>

          {/* Right Header Statuses */}
          <div className="flex items-center gap-3 sm:gap-4 font-mono">
            {/* Active Cases Indicator */}
            <div className="hidden sm:flex items-center gap-2 px-3 py-1 bg-[#181818] border border-[#222222] rounded text-xs">
              <span className="text-[#666666]">ACTIVE CASES:</span>
              <span className="text-[#00FF00] font-bold">{activeCasesCount}</span>
            </div>

            {/* User Session Badge */}
            <div className="flex items-center gap-1.5 px-3 py-1 bg-[#181818] border border-[#00FF00]/30 rounded text-xs text-[#00FF00] font-bold">
              <UserCheck className="h-3.5 w-3.5 text-[#00FF00]" />
              <span className="tracking-wider uppercase">{currentUser.name} [{currentUser.role}]</span>
            </div>

            {/* Top Bar Logout */}
            <button
              onClick={async () => {
                await logout();
                navigate('/signin');
              }}
              title="Sign Out of Session"
              className="p-2 bg-[#181818] hover:bg-rose-950/40 border border-[#222222] hover:border-rose-500/40 rounded text-[#AAAAAA] hover:text-rose-400 transition-colors"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>

            {/* Manual Refresh Action */}
            <button
              onClick={() => fetchData(true)}
              disabled={refreshing}
              title="Refresh System Status"
              className="p-2 bg-[#181818] hover:bg-[#222222] border border-[#222222] rounded text-[#AAAAAA] hover:text-white transition-colors"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? 'animate-spin text-[#00FF00]' : ''}`} />
            </button>
          </div>
        </header>

        {/* Main Content Area */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto bg-[#000000]">
          <ErrorBoundary fallbackTitle="Investigation View Error">
            {children}
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
};

export default Layout;
