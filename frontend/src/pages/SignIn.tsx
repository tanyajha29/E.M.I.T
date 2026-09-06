import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Shield, Eye, EyeOff, Lock, Mail, AlertTriangle, CheckCircle2, ArrowLeft } from 'lucide-react';
import { useUser } from '../context/UserContext';

export const SignIn: React.FC = () => {
  const { login, sessionExpired, clearSessionExpired } = useUser();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSuccess, setIsSuccess] = useState(false);

  // Determine redirect target (defaults to /dashboard)
  const from = (location.state as any)?.from?.pathname || '/dashboard';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setErrorMessage('Please provide both email and password.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    clearSessionExpired();

    try {
      await login(email, password);
      setIsSuccess(true);
      setTimeout(() => {
        navigate(from, { replace: true });
      }, 500);
    } catch (err: any) {
      setIsLoading(false);
      const detail = err.response?.data?.detail;
      if (err.response?.status === 401) {
        setErrorMessage('Invalid investigator credentials. Please verify your email and password.');
      } else if (err.response?.status === 403) {
        setErrorMessage('Account has been suspended or disabled by administrator.');
      } else {
        setErrorMessage(detail || 'Authentication server unreachable. Verify backend connectivity.');
      }
    }
  };

  return (
    <div className="min-h-screen bg-[#000000] text-white font-mono flex flex-col justify-center items-center p-6 antialiased selection:bg-[#00FF00]/20 selection:text-[#00FF00]">
      {/* Background grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#111111_1px,transparent_1px),linear-gradient(to_bottom,#111111_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-30 pointer-events-none" />

      <div className="relative w-full max-w-md space-y-6">
        {/* Top Back Link */}
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-xs text-[#666666] hover:text-white transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Platform Overview</span>
        </Link>

        {/* Authentication Card */}
        <div className="rounded-lg bg-[#0A0A0A] border border-[#222222] shadow-[0_0_35px_rgba(0,0,0,0.8)] p-8 space-y-6">
          {/* Logo & Header */}
          <div className="text-center space-y-2">
            <div className="h-12 w-12 mx-auto rounded bg-[#111111] border border-[#00FF00]/40 flex items-center justify-center shadow-[0_0_15px_rgba(0,255,0,0.2)]">
              <Shield className="h-6 w-6 text-[#00FF00]" />
            </div>
            <h1 className="text-xl font-bold tracking-widest text-white">E.M.I.T.</h1>
            <p className="text-[10px] text-[#666666] tracking-widest uppercase">
              Forensic Analyst Authentication Gateway
            </p>
          </div>

          {/* Session Expired Notice */}
          {sessionExpired && (
            <div className="p-3 rounded bg-amber-500/10 border border-amber-500/40 text-amber-400 text-xs flex items-center gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Your session has expired or was revoked. Please sign in again.</span>
            </div>
          )}

          {/* Error Message */}
          {errorMessage && (
            <div className="p-3 rounded bg-red-500/10 border border-red-500/40 text-red-400 text-xs flex items-center gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Success Message */}
          {isSuccess && (
            <div className="p-3 rounded bg-[#00FF00]/10 border border-[#00FF00]/40 text-[#00FF00] text-xs flex items-center gap-2.5">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>AUTHENTICATED. Launching investigation workstation...</span>
            </div>
          )}

          {/* Sign In Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-[#888888] flex items-center justify-between">
                <span>Email Address</span>
                <span className="text-[#555555]">Required</span>
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-2.5 h-4 w-4 text-[#555555]" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@emit.local"
                  required
                  autoFocus
                  className="w-full pl-9 pr-3 py-2 rounded bg-[#111111] border border-[#222222] focus:border-[#00FF00] text-xs text-white placeholder-[#444444] outline-none transition-colors"
                />
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center justify-between text-[10px] uppercase tracking-wider text-[#888888]">
                <span>Password</span>
                <button
                  type="button"
                  onClick={() => alert('Password reset in enterprise air-gap environments requires database administrator intervention.')}
                  className="text-[#666666] hover:text-[#AAAAAA] transition-colors"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 h-4 w-4 text-[#555555]" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full pl-9 pr-10 py-2 rounded bg-[#111111] border border-[#222222] focus:border-[#00FF00] text-xs text-white placeholder-[#444444] outline-none transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-[#555555] hover:text-[#AAAAAA] transition-colors"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between pt-1">
              <label className="flex items-center gap-2 cursor-pointer text-xs text-[#888888]">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="rounded bg-[#111111] border-[#333333] text-[#00FF00] focus:ring-0"
                />
                <span className="text-[11px]">Remember session (24h)</span>
              </label>
            </div>

            <button
              type="submit"
              disabled={isLoading || isSuccess}
              className="w-full mt-2 py-2.5 rounded bg-[#00FF00] hover:bg-[#00DD00] disabled:bg-[#004400] disabled:text-[#888888] text-black font-bold text-xs tracking-widest uppercase transition-all shadow-[0_0_15px_rgba(0,255,0,0.25)] flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-black animate-ping" />
                  <span>AUTHENTICATING...</span>
                </>
              ) : (
                <span>SIGN IN</span>
              )}
            </button>
          </form>

          {/* Bottom Link */}
          <div className="pt-2 text-center text-xs text-[#666666] border-t border-[#181818]">
            <span>Need authorized access? </span>
            <Link to="/signup" className="text-[#00FF00] hover:underline font-bold">
              Create Investigator Account
            </Link>
          </div>
        </div>

        {/* Security badge footer */}
        <div className="text-center text-[10px] text-[#444444] space-y-1">
          <div>DEFENSIVE FORENSIC ACCESS ONLY &bull; AUDITED SESSION SINK</div>
        </div>
      </div>
    </div>
  );
};

export default SignIn;
