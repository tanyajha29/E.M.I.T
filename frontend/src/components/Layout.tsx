import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  FolderOpen, 
  Binary, 
  GitFork, 
  BarChart3, 
  Terminal,
  Server,
  Database
} from 'lucide-react';
import { apiService, HealthResponse, Case } from '../services/api';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [cases, setCases] = useState<Case[]>([]);
  const [healthLoading, setHealthLoading] = useState(true);

  useEffect(() => {
    // Fetch live configurations to show real active details in header
    const fetchData = async () => {
      try {
        const healthData = await apiService.getHealth();
        setHealth(healthData);
      } catch (err) {
        setHealth(null);
      } finally {
        setHealthLoading(false);
      }

      try {
        const caseList = await apiService.getCases();
        setCases(caseList);
      } catch (err) {
        setCases([]);
      }
    };

    fetchData();
    // Poll health status every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  const menuItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard },
    { name: 'Investigations', path: '/investigations', icon: FolderOpen },
    { name: 'Analysis', path: '/analysis', icon: Binary },
    { name: 'Attack Graph', path: '/attack-graph', icon: GitFork },
    { name: 'Reports', path: '/reports', icon: BarChart3 },
  ];

  // Derive database connection status safely
  const isDbConnected = health?.database?.status === 'connected';
  const dbStatusText = healthLoading 
    ? 'Checking DB...' 
    : health 
      ? (isDbConnected ? 'MongoDB Active' : 'MongoDB Offline') 
      : 'Database status unavailable';

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100 font-mono text-sm selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
        {/* Title / Logo */}
        <div className="h-16 flex items-center px-6 border-b border-slate-800 gap-3">
          <Terminal className="h-6 w-6 text-cyan-400" />
          <span className="text-lg font-bold tracking-widest text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-teal-500">
            E.M.I.T.
          </span>
        </div>

        {/* Navigation Links */}
        <nav className="flex-1 px-4 py-6 space-y-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path || 
              (item.path !== '/' && location.pathname.startsWith(item.path));
            return (
              <Link
                key={item.name}
                to={item.path}
                className={`flex items-center px-4 py-3 rounded border transition-all gap-3 ${
                  isActive
                    ? 'bg-slate-850/50 text-cyan-400 border-cyan-500/80 shadow-[0_0_12px_rgba(6,182,212,0.1)]'
                    : 'text-slate-400 border-transparent hover:bg-slate-800/40 hover:text-slate-200'
                }`}
              >
                <Icon className="h-5 w-5" />
                <span className="font-semibold tracking-wider">{item.name}</span>
              </Link>
            );
          })}
        </nav>

        {/* Sidebar Footer */}
        <div className="p-4 border-t border-slate-800 text-[10px] text-slate-500 text-center uppercase tracking-widest">
          Sec platform v1.0.0
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col">
        {/* Header */}
        <header className="h-16 bg-slate-900 border-b border-slate-800 flex items-center px-8 justify-between">
          <div className="flex items-center gap-6">
            <h2 className="text-md font-bold tracking-widest text-cyan-400 uppercase">
              {menuItems.find(item => item.path === location.pathname || (item.path !== '/' && location.pathname.startsWith(item.path)))?.name || 'Workspace'}
            </h2>
            <div className="hidden lg:flex items-center gap-4 text-xs border-l border-slate-800 pl-6 text-slate-400">
              <span className="flex items-center gap-1.5">
                <Database className={`h-3.5 w-3.5 ${isDbConnected ? 'text-cyan-400' : 'text-rose-500'}`} />
                {dbStatusText}
              </span>
              <span className="text-slate-700">|</span>
              <span className="flex items-center gap-1.5">
                <FolderOpen className="h-3.5 w-3.5 text-cyan-400" />
                Active Cases: {cases.length}
              </span>
              <span className="text-slate-700">|</span>
              <span>Role: <strong className="text-cyan-400">Investigator</strong></span>
            </div>
          </div>
          
          <div className="flex items-center gap-3">
            <Server className={`h-4 w-4 ${health ? 'text-cyan-400 animate-pulse' : 'text-rose-500'}`} />
            <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">
              {health ? 'API ONLINE' : 'API OFFLINE'}
            </span>
          </div>
        </header>

        {/* Content Body */}
        <main className="flex-1 p-8 overflow-y-auto bg-slate-950">
          {children}
        </main>
      </div>
    </div>
  );
};

export default Layout;
