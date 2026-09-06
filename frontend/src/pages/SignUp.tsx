import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Eye, EyeOff, Lock, Mail, User as UserIcon, Check, X, AlertTriangle, ArrowLeft } from 'lucide-react';
import { useUser } from '../context/UserContext';

export const SignUp: React.FC = () => {
  const { signup } = useUser();
  const navigate = useNavigate();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [agreedTerms, setAgreedTerms] = useState(false);

  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Password Requirement Checks
  const hasMinLength = password.length >= 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\/]/.test(password);
  const passwordsMatch = password.length > 0 && password === confirmPassword;

  const isPasswordValid = hasMinLength && hasUppercase && hasLowercase && hasNumber && hasSpecial;
  const isFormValid = fullName.trim().length > 0 && email.trim().length > 0 && isPasswordValid && passwordsMatch && agreedTerms;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isPasswordValid) {
      setErrorMessage('Please satisfy all password complexity requirements.');
      return;
    }
    if (!passwordsMatch) {
      setErrorMessage('Passwords do not match.');
      return;
    }
    if (!agreedTerms) {
      setErrorMessage('You must confirm authorized defensive forensic usage.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      await signup(fullName, email, password);
      navigate('/dashboard', { replace: true });
    } catch (err: any) {
      setIsLoading(false);
      const detail = err.response?.data?.detail;
      if (err.response?.status === 409) {
        setErrorMessage('An account with this email address already exists. Please sign in instead.');
      } else {
        setErrorMessage(detail || 'Registration failed. Please verify the server is running.');
      }
    }
  };

  return (
    <div className="min-h-screen bg-[#000000] text-white font-mono flex flex-col justify-center items-center p-6 antialiased selection:bg-[#00FF00]/20 selection:text-[#00FF00]">
      {/* Background grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#111111_1px,transparent_1px),linear-gradient(to_bottom,#111111_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-30 pointer-events-none" />

      <div className="relative w-full max-w-lg space-y-6">
        {/* Top Back Link */}
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-xs text-[#666666] hover:text-white transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          <span>Back to Platform Overview</span>
        </Link>

        {/* Card */}
        <div className="rounded-lg bg-[#0A0A0A] border border-[#222222] shadow-[0_0_35px_rgba(0,0,0,0.8)] p-8 space-y-6">
          <div className="text-center space-y-2">
            <div className="h-12 w-12 mx-auto rounded bg-[#111111] border border-[#00FF00]/40 flex items-center justify-center shadow-[0_0_15px_rgba(0,255,0,0.2)]">
              <Shield className="h-6 w-6 text-[#00FF00]" />
            </div>
            <h1 className="text-xl font-bold tracking-widest text-white">E.M.I.T.</h1>
            <p className="text-[10px] text-[#666666] tracking-widest uppercase">
              Investigator Registration Portal
            </p>
          </div>

          {/* Error Notice */}
          {errorMessage && (
            <div className="p-3 rounded bg-red-500/10 border border-red-500/40 text-red-400 text-xs flex items-center gap-2.5">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Full Name */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-[#888888]">
                Analyst Full Name
              </label>
              <div className="relative">
                <UserIcon className="absolute left-3 top-2.5 h-4 w-4 text-[#555555]" />
                <input
                  type="text"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Alex Vance"
                  required
                  autoFocus
                  className="w-full pl-9 pr-3 py-2 rounded bg-[#111111] border border-[#222222] focus:border-[#00FF00] text-xs text-white placeholder-[#444444] outline-none transition-colors"
                />
              </div>
            </div>

            {/* Email */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-[#888888]">
                Enterprise Email
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-2.5 h-4 w-4 text-[#555555]" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="alex.vance@incident-response.org"
                  required
                  className="w-full pl-9 pr-3 py-2 rounded bg-[#111111] border border-[#222222] focus:border-[#00FF00] text-xs text-white placeholder-[#444444] outline-none transition-colors"
                />
              </div>
            </div>

            {/* Role Notice */}
            <div className="p-2.5 rounded bg-[#0D0D0D] border border-[#1A1A1A] flex items-center justify-between text-xs">
              <span className="text-[10px] uppercase tracking-wider text-[#666666]">Assigned Role</span>
              <span className="text-[10px] px-2 py-0.5 rounded border border-[#00FF00]/40 bg-[#00FF00]/10 text-[#00FF00] font-bold">
                INVESTIGATOR (DEFAULT)
              </span>
            </div>

            {/* Password */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-[#888888]">
                Password
              </label>
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

            {/* Confirm Password */}
            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-[#888888]">
                Confirm Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-2.5 h-4 w-4 text-[#555555]" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full pl-9 pr-3 py-2 rounded bg-[#111111] border border-[#222222] focus:border-[#00FF00] text-xs text-white placeholder-[#444444] outline-none transition-colors"
                />
              </div>
            </div>

            {/* Password Complexity Checklist */}
            <div className="p-3 rounded bg-[#0D0D0D] border border-[#1C1C1C] space-y-1.5 text-[11px]">
              <div className="text-[9px] uppercase tracking-wider text-[#666666] font-bold">
                Security Requirements
              </div>
              <div className="grid grid-cols-2 gap-1.5 text-[10px]">
                <div className={`flex items-center gap-1.5 ${hasMinLength ? 'text-[#00FF00]' : 'text-[#666666]'}`}>
                  {hasMinLength ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                  <span>&ge; 8 characters</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasUppercase ? 'text-[#00FF00]' : 'text-[#666666]'}`}>
                  {hasUppercase ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                  <span>Uppercase letter</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasLowercase ? 'text-[#00FF00]' : 'text-[#666666]'}`}>
                  {hasLowercase ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                  <span>Lowercase letter</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasNumber ? 'text-[#00FF00]' : 'text-[#666666]'}`}>
                  {hasNumber ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                  <span>Number (0-9)</span>
                </div>
                <div className={`flex items-center gap-1.5 ${hasSpecial ? 'text-[#00FF00]' : 'text-[#666666]'}`}>
                  {hasSpecial ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                  <span>Special character</span>
                </div>
                <div className={`flex items-center gap-1.5 ${passwordsMatch ? 'text-[#00FF00]' : 'text-[#666666]'}`}>
                  {passwordsMatch ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
                  <span>Passwords match</span>
                </div>
              </div>
            </div>

            {/* Ethical Authorization Notice Checkbox */}
            <div className="pt-1">
              <label className="flex items-start gap-2 cursor-pointer text-xs text-[#888888]">
                <input
                  type="checkbox"
                  checked={agreedTerms}
                  onChange={(e) => setAgreedTerms(e.target.checked)}
                  className="mt-0.5 rounded bg-[#111111] border-[#333333] text-[#00FF00] focus:ring-0"
                />
                <span className="text-[10px] leading-relaxed">
                  I confirm that I possess explicit legal authorization to ingest and analyze all mobile packages and packet captures submitted to this console.
                </span>
              </label>
            </div>

            <button
              type="submit"
              disabled={!isFormValid || isLoading}
              className="w-full mt-2 py-2.5 rounded bg-[#00FF00] hover:bg-[#00DD00] disabled:bg-[#003300] disabled:text-[#666666] text-black font-bold text-xs tracking-widest uppercase transition-all shadow-[0_0_15px_rgba(0,255,0,0.25)] flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-black animate-ping" />
                  <span>CREATING ACCOUNT...</span>
                </>
              ) : (
                <span>CREATE ACCOUNT</span>
              )}
            </button>
          </form>

          {/* Link to Sign In */}
          <div className="pt-2 text-center text-xs text-[#666666] border-t border-[#181818]">
            <span>Already have an account? </span>
            <Link to="/signin" className="text-[#00FF00] hover:underline font-bold">
              Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SignUp;
