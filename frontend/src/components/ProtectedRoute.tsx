import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useUser } from '../context/UserContext';
import { UserRole } from '../services/api';
import { ShieldAlert, Terminal } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: UserRole[];
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, allowedRoles }) => {
  const { isAuthenticated, isLoading, user } = useUser();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#050505] flex flex-col items-center justify-center font-mono text-xs text-[#666666] space-y-4">
        <div className="h-10 w-10 rounded border border-[#00FF00]/40 bg-[#0A0A0A] flex items-center justify-center shadow-[0_0_15px_rgba(0,255,0,0.2)] animate-pulse">
          <Terminal className="h-5 w-5 text-[#00FF00]" />
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-block w-2 h-2 rounded-full bg-[#00FF00] animate-ping" />
          <span className="text-[#AAAAAA] tracking-widest uppercase">INITIALIZING SECURITY CONSOLE...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/signin" state={{ from: location }} replace />;
  }

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return (
      <div className="min-h-screen bg-[#050505] flex flex-col items-center justify-center font-mono p-6">
        <div className="max-w-md w-full p-8 rounded bg-[#0E0E0E] border border-[#FF0000]/40 shadow-[0_0_25px_rgba(255,0,0,0.15)] text-center space-y-4">
          <div className="h-12 w-12 mx-auto rounded-full bg-[#FF0000]/10 border border-[#FF0000]/40 flex items-center justify-center text-[#FF0000]">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <h2 className="text-base font-bold tracking-widest text-[#FF0000] uppercase">
            Access Denied
          </h2>
          <p className="text-xs text-[#888888] leading-relaxed">
            Your authenticated role (<span className="text-white font-bold">{user.role}</span>) does not have authorization to access this operational resource.
          </p>
          <div className="pt-4">
            <a
              href="/dashboard"
              className="inline-block px-5 py-2 rounded bg-[#161616] border border-[#333333] hover:border-[#00FF00] text-xs font-bold text-white hover:text-[#00FF00] transition-colors"
            >
              Return to Dashboard
            </a>
          </div>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};

export default ProtectedRoute;
