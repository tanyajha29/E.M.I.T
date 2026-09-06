import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  Shield, FileCode2, Network, GitFork, 
  FileText, CheckCircle2, Lock, Cpu, Database, 
  ArrowRight, Layers, EyeOff, Server
} from 'lucide-react';
import { useUser } from '../context/UserContext';

const TELEMETRY_LINES = [
  { prefix: '[INGEST]', text: 'Artifact bank_update.apk ingested (SHA-256: 3a7b9c1d...)', color: 'text-[#00FF00]' },
  { prefix: '[PCAP]', text: 'Network trace session parsed: 1,428 frames, 8 TCP conversations', color: 'text-[#AAAAAA]' },
  { prefix: '[DISSECT]', text: 'TLS SNI detected: api.financial-sync.cc (Port 443)', color: 'text-amber-400' },
  { prefix: '[STATIC]', text: 'Androguard extracted string: api.financial-sync.cc in classes.dex', color: 'text-[#00FF00]' },
  { prefix: '[CORRELATE]', text: 'RULE 1: APK_NETWORK_OVERLAP confirmed between APK and PCAP', color: 'text-red-400 font-bold' },
  { prefix: '[DAG]', text: 'Attack graph edge established: APPLICATION -> DOMAIN -> IP', color: 'text-cyan-400' },
  { prefix: '[RISK]', text: 'Deterministic Score: 82 / 100 [CRITICAL THREAT TIER]', color: 'text-red-500 font-bold' },
  { prefix: '[REPORT]', text: 'Investigation dossier generated: report_2026_090.pdf (Verified)', color: 'text-[#00FF00]' },
];

export const LandingPage: React.FC = () => {
  const { isAuthenticated, logout } = useUser();
  const [activeTelemetryIndex, setActiveTelemetryIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveTelemetryIndex((prev) => (prev + 1) % TELEMETRY_LINES.length);
    }, 2400);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="min-h-screen bg-[#000000] text-white font-mono antialiased selection:bg-[#00FF00]/20 selection:text-[#00FF00]">
      {/* 1. Global Navigation Bar */}
      <header className="sticky top-0 z-50 border-b border-[#1A1A1A] bg-[#0A0A0A]/90 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded bg-[#111111] border border-[#00FF00]/40 flex items-center justify-center shadow-[0_0_12px_rgba(0,255,0,0.2)]">
              <Shield className="h-5 w-5 text-[#00FF00]" />
            </div>
            <div>
              <span className="text-base font-bold tracking-widest text-[#00FF00]">E.M.I.T.</span>
              <span className="hidden sm:inline-block ml-2 text-[10px] text-[#666666] tracking-widest uppercase">
                Forensic Console
              </span>
            </div>
          </div>

          <nav className="hidden md:flex items-center gap-6 text-xs text-[#888888]">
            <a href="#problem" className="hover:text-white transition-colors">Problem</a>
            <a href="#capabilities" className="hover:text-white transition-colors">Capabilities</a>
            <a href="#architecture" className="hover:text-white transition-colors">Architecture</a>
            <a href="#security" className="hover:text-white transition-colors">Security</a>
          </nav>

          <div className="flex items-center gap-3">
            {isAuthenticated ? (
              <>
                <Link
                  to="/dashboard"
                  className="px-4 py-2 rounded bg-[#00FF00] hover:bg-[#00DD00] text-black font-bold text-xs tracking-wider transition-colors flex items-center gap-2 shadow-[0_0_12px_rgba(0,255,0,0.25)]"
                >
                  <span>Open Console</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </Link>
                <button
                  onClick={() => logout()}
                  className="px-3 py-2 rounded border border-[#222222] hover:border-[#444444] text-xs text-[#888888] hover:text-white transition-colors"
                >
                  Sign Out
                </button>
              </>
            ) : (
              <>
                <Link
                  to="/signin"
                  className="px-3.5 py-1.5 rounded border border-[#222222] hover:border-[#444444] text-xs text-white hover:text-[#00FF00] transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  to="/signup"
                  className="px-4 py-1.5 rounded bg-[#00FF00] hover:bg-[#00DD00] text-black font-bold text-xs tracking-wider transition-colors shadow-[0_0_12px_rgba(0,255,0,0.2)]"
                >
                  Get Started
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* 2. Hero Section */}
      <section className="relative pt-20 pb-24 px-6 overflow-hidden border-b border-[#141414]">
        {/* Subtle grid background */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#111111_1px,transparent_1px),linear-gradient(to_bottom,#111111_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-40 pointer-events-none" />

        <div className="relative max-w-5xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[#00FF00]/30 bg-[#00FF00]/5 text-[11px] text-[#00FF00]">
            <span className="w-2 h-2 rounded-full bg-[#00FF00] animate-pulse" />
            <span>ENTERPRISE FORENSIC DFIR WORKSTATION</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white leading-tight">
            E.M.I.T.
            <span className="block text-xl sm:text-2xl font-normal text-[#888888] tracking-widest mt-3">
              Evidence-driven Malware & Intelligence Toolkit
            </span>
          </h1>

          <p className="max-w-2xl mx-auto text-xs sm:text-sm text-[#AAAAAA] leading-relaxed">
            Correlate Android application packages (APK) and network packet captures (PCAP) through a deterministic, evidence-weighted investigation platform built for cybersecurity analysts.
          </p>

          <div className="pt-4 flex flex-wrap items-center justify-center gap-4">
            <Link
              to={isAuthenticated ? "/dashboard" : "/signup"}
              className="px-6 py-3 rounded bg-[#00FF00] hover:bg-[#00DD00] text-black font-bold text-xs tracking-widest uppercase transition-all shadow-[0_0_18px_rgba(0,255,0,0.3)] flex items-center gap-2"
            >
              <span>Start Investigation</span>
              <ArrowRight className="h-4 w-4" />
            </Link>
            <a
              href="#capabilities"
              className="px-6 py-3 rounded border border-[#222222] hover:border-[#444444] bg-[#0A0A0A] hover:bg-[#111111] text-xs text-[#CCCCCC] hover:text-white tracking-widest uppercase transition-colors"
            >
              Explore Platform
            </a>
          </div>

          {/* Real-Time Telemetry Terminal readout */}
          <div className="pt-10 max-w-3xl mx-auto text-left">
            <div className="rounded-lg bg-[#0A0A0A] border border-[#222222] shadow-[0_0_30px_rgba(0,0,0,0.8)] overflow-hidden">
              <div className="px-4 py-2 border-b border-[#1A1A1A] bg-[#0E0E0E] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full bg-[#FF0000]/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-[#00FF00]/60" />
                  <span className="text-[10px] text-[#666666] ml-2">EMIT-ORCHESTRATOR // LIVE CORRELATION STREAM</span>
                </div>
                <span className="text-[9px] text-[#00FF00] font-bold">PASSIVE DEFENSE MODE</span>
              </div>
              <div className="p-4 space-y-2 text-[11px] font-mono min-h-[180px] bg-[#050505]">
                {TELEMETRY_LINES.slice(0, activeTelemetryIndex + 1).map((line, idx) => (
                  <div key={idx} className="flex items-start gap-2">
                    <span className="text-[#555555] select-none">$</span>
                    <span className={line.color}>
                      <span className="text-[#666666] mr-1">{line.prefix}</span>
                      {line.text}
                    </span>
                  </div>
                ))}
                <div className="flex items-center gap-1 text-[#00FF00]">
                  <span className="inline-block w-2 h-3.5 bg-[#00FF00] animate-pulse" />
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 3. The Real-World DFIR Problem */}
      <section id="problem" className="py-20 px-6 border-b border-[#141414] bg-[#050505]">
        <div className="max-w-5xl mx-auto space-y-12">
          <div className="text-center space-y-2">
            <span className="text-[10px] text-[#00FF00] tracking-widest uppercase font-bold">Investigation Bottleneck</span>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">The Operational Divide in Mobile DFIR</h2>
            <p className="text-xs text-[#888888] max-w-xl mx-auto">
              Why traditional malware sandboxing fails modern incident response requirements.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            <div className="p-6 rounded-lg bg-[#0A0A0A] border border-[#222222] space-y-3">
              <div className="flex items-center gap-2 text-red-400 font-bold text-xs uppercase">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                Traditional Fragmented Investigation
              </div>
              <ul className="space-y-2.5 text-xs text-[#888888] leading-relaxed">
                <li className="flex items-start gap-2">
                  <span className="text-red-400">&bull;</span>
                  Malware analysts decompile APKs in isolation (JADX, MobSF), while SOC analysts parse PCAP traces in Wireshark.
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-red-400">&bull;</span>
                  Correlating bytecode strings to ephemeral network flows requires manual, error-prone cross-referencing.
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-red-400">&bull;</span>
                  Opaque machine-learning threat scores lack verifiable proof, making them inadmissible in forensic audits.
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-red-400">&bull;</span>
                  Automated DNS lookups accidentally alert adversaries by leaking queries to malicious authoritative nameservers.
                </li>
              </ul>
            </div>

            <div className="p-6 rounded-lg bg-[#0A0A0A] border border-[#00FF00]/40 shadow-[0_0_15px_rgba(0,255,0,0.08)] space-y-3">
              <div className="flex items-center gap-2 text-[#00FF00] font-bold text-xs uppercase">
                <span className="w-2 h-2 rounded-full bg-[#00FF00]" />
                The E.M.I.T. Deterministic Approach
              </div>
              <ul className="space-y-2.5 text-xs text-[#CCCCCC] leading-relaxed">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-[#00FF00] shrink-0 mt-0.5" />
                  Common Evidence Model (CEM) normalizes heterogeneous findings into unified, typed indicators.
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-[#00FF00] shrink-0 mt-0.5" />
                  7 Deterministic Correlation Rules connect observed facts without probabilistic guesswork or hallucinations.
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-[#00FF00] shrink-0 mt-0.5" />
                  Evidence-weighted risk score (0–100) separates ground-truth empirical facts from deductive inferences.
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-[#00FF00] shrink-0 mt-0.5" />
                  Zero Host Execution: Untrusted APKs never run on host; PCAP dissection operates with strict <code className="text-[#00FF00]">-n</code> flag.
                </li>
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* 4. Core Capabilities */}
      <section id="capabilities" className="py-20 px-6 border-b border-[#141414]">
        <div className="max-w-5xl mx-auto space-y-12">
          <div className="text-center space-y-2">
            <span className="text-[10px] text-[#00FF00] tracking-widest uppercase font-bold">Tooling & Workflows</span>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">Core Forensic Capabilities</h2>
            <p className="text-xs text-[#888888] max-w-xl mx-auto">
              Five integrated modules engineered for high-assurance mobile threat analysis.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <div className="p-5 rounded-lg bg-[#0A0A0A] border border-[#222222] hover:border-[#00FF00]/50 transition-colors space-y-3">
              <div className="h-8 w-8 rounded bg-[#111111] border border-[#333333] flex items-center justify-center text-[#00FF00]">
                <FileCode2 className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wider">APK STATIC ANALYSIS</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Decompile DEX bytecode, extract Android permissions, audit broadcast receivers, and detect obfuscation or reflection with Androguard, MobSF, JADX, and APKTool.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#0A0A0A] border border-[#222222] hover:border-[#00FF00]/50 transition-colors space-y-3">
              <div className="h-8 w-8 rounded bg-[#111111] border border-[#333333] flex items-center justify-center text-[#00FF00]">
                <Network className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wider">NETWORK FORENSICS</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Dissect PCAP/PCAPNG packets with Scapy and TShark. Reconstruct TCP/UDP conversations, trace DNS lookups, extract TLS SNI, and discover periodic beaconing cycles.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#0A0A0A] border border-[#222222] hover:border-[#00FF00]/50 transition-colors space-y-3">
              <div className="h-8 w-8 rounded bg-[#111111] border border-[#333333] flex items-center justify-center text-[#00FF00]">
                <Layers className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wider">EVIDENCE CORRELATION</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Evaluate 7 deterministic rules linking hardcoded strings to live network flows, dangerous capabilities to exfiltration traffic, and indicators to external threat intelligence.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#0A0A0A] border border-[#222222] hover:border-[#00FF00]/50 transition-colors space-y-3">
              <div className="h-8 w-8 rounded bg-[#111111] border border-[#333333] flex items-center justify-center text-[#00FF00]">
                <GitFork className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wider">ATTACK GRAPH (DAG)</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Visualize multi-entity attack chains with Cytoscape.js. Filter by node type (APPLICATION, DOMAIN, IP, EVENT) with solid observed and dashed correlated edge provenance.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#0A0A0A] border border-[#222222] hover:border-[#00FF00]/50 transition-colors space-y-3">
              <div className="h-8 w-8 rounded bg-[#111111] border border-[#333333] flex items-center justify-center text-[#00FF00]">
                <FileText className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wider">FORENSIC DOSSIERS</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Compile court-admissible forensic dossiers with one click in dual interactive HTML and ReportLab PDF formats, incorporating evidence hashes and full audit provenance.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#0A0A0A] border border-[#222222] hover:border-[#00FF00]/50 transition-colors space-y-3">
              <div className="h-8 w-8 rounded bg-[#111111] border border-[#333333] flex items-center justify-center text-[#00FF00]">
                <Lock className="h-4 w-4" />
              </div>
              <h3 className="text-sm font-bold text-white tracking-wider">MULTI-TENANT RBAC</h3>
              <p className="text-xs text-[#888888] leading-relaxed">
                Strict case isolation guarantees investigators only access their own investigations. Role-based boundaries (Admin, Investigator, Viewer) prevent cross-tenant enumeration.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 5. Animated Architecture Flow */}
      <section id="architecture" className="py-20 px-6 border-b border-[#141414] bg-[#050505]">
        <div className="max-w-5xl mx-auto space-y-12">
          <div className="text-center space-y-2">
            <span className="text-[10px] text-[#00FF00] tracking-widest uppercase font-bold">Pipeline Architecture</span>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">End-to-End Forensic Processing</h2>
            <p className="text-xs text-[#888888] max-w-xl mx-auto">
              How raw evidence bytes progress from ingestion to definitive forensic intelligence.
            </p>
          </div>

          <div className="p-6 rounded-lg bg-[#0A0A0A] border border-[#222222] space-y-6">
            <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 text-center">
              <div className="p-3 rounded bg-[#111111] border border-[#222222]">
                <span className="text-[10px] text-[#666666] block">STAGE 1</span>
                <span className="text-xs font-bold text-white">Ingestion</span>
                <span className="text-[10px] text-[#00FF00] block mt-1">SHA-256 Custody</span>
              </div>
              <div className="p-3 rounded bg-[#111111] border border-[#222222]">
                <span className="text-[10px] text-[#666666] block">STAGE 2</span>
                <span className="text-xs font-bold text-white">Dissection</span>
                <span className="text-[10px] text-[#00FF00] block mt-1">Docker Isolation</span>
              </div>
              <div className="p-3 rounded bg-[#111111] border border-[#222222]">
                <span className="text-[10px] text-[#666666] block">STAGE 3</span>
                <span className="text-xs font-bold text-white">Normalization</span>
                <span className="text-[10px] text-[#00FF00] block mt-1">CEM Schema</span>
              </div>
              <div className="p-3 rounded bg-[#111111] border border-[#222222]">
                <span className="text-[10px] text-[#666666] block">STAGE 4</span>
                <span className="text-xs font-bold text-white">Correlation</span>
                <span className="text-[10px] text-[#00FF00] block mt-1">7 Strict Rules</span>
              </div>
              <div className="p-3 rounded bg-[#111111] border border-[#222222]">
                <span className="text-[10px] text-[#666666] block">STAGE 5</span>
                <span className="text-xs font-bold text-white">Synthesis</span>
                <span className="text-[10px] text-[#00FF00] block mt-1">DAG & Dossier</span>
              </div>
            </div>

            <div className="pt-2 text-xs text-[#888888] space-y-2 border-t border-[#1C1C1C]">
              <div className="flex items-center justify-between text-[11px]">
                <span className="text-white font-bold">ANALYSIS RUNTIME ENGINES:</span>
                <span className="text-[#00FF00]">CONTAINERIZED: emit-mobsf (PORT 8001:8000)</span>
              </div>
              <div className="grid sm:grid-cols-3 gap-2 pt-1 text-[10px]">
                <div className="p-2 rounded bg-[#0D0D0D] border border-[#1A1A1A]">
                  <span className="text-white font-bold">Static APK:</span> Androguard, MobSF, JADX, APKTool
                </div>
                <div className="p-2 rounded bg-[#0D0D0D] border border-[#1A1A1A]">
                  <span className="text-white font-bold">Network Traffic:</span> Scapy, TShark (-n DNS Safe)
                </div>
                <div className="p-2 rounded bg-[#0D0D0D] border border-[#1A1A1A]">
                  <span className="text-white font-bold">Threat Intelligence:</span> VT, AbuseIPDB, URLhaus, OTX
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 6. Security Principles */}
      <section id="security" className="py-20 px-6 border-b border-[#141414]">
        <div className="max-w-5xl mx-auto space-y-12">
          <div className="text-center space-y-2">
            <span className="text-[10px] text-[#00FF00] tracking-widest uppercase font-bold">Defensive Architecture</span>
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">Security & Privacy Guardrails</h2>
            <p className="text-xs text-[#888888] max-w-xl mx-auto">
              Hardened controls to guarantee investigator safety and preserve forensic chain of custody.
            </p>
          </div>

          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded bg-[#0A0A0A] border border-[#222222] space-y-2">
              <EyeOff className="h-5 w-5 text-[#00FF00]" />
              <div className="text-xs font-bold text-white">DNS Leak Prevention</div>
              <div className="text-[11px] text-[#888888]">
                TShark executes with the <code className="text-[#00FF00]">-n</code> flag, disabling live network resolution to prevent adversary reconnaissance detection.
              </div>
            </div>

            <div className="p-4 rounded bg-[#0A0A0A] border border-[#222222] space-y-2">
              <Cpu className="h-5 w-5 text-[#00FF00]" />
              <div className="text-xs font-bold text-white">Zero Host Execution</div>
              <div className="text-[11px] text-[#888888]">
                Untrusted APKs are never executed, emulated, or installed on the host. Decompilation is strictly static bytecode inspection.
              </div>
            </div>

            <div className="p-4 rounded bg-[#0A0A0A] border border-[#222222] space-y-2">
              <Server className="h-5 w-5 text-[#00FF00]" />
              <div className="text-xs font-bold text-white">Server-Side Session Revocation</div>
              <div className="text-[11px] text-[#888888]">
                Logout invalidates sessions immediately in MongoDB, guaranteeing already-issued tokens cannot be reused.
              </div>
            </div>

            <div className="p-4 rounded bg-[#0A0A0A] border border-[#222222] space-y-2">
              <Database className="h-5 w-5 text-[#00FF00]" />
              <div className="text-xs font-bold text-white">13 MongoDB Collections</div>
              <div className="text-[11px] text-[#888888]">
                Evidence files, IOCs, observations, and attack graph nodes are permanently persisted with compound unique indexing.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 7. Call To Action */}
      <section className="py-20 px-6 text-center space-y-6 bg-[#080808]">
        <div className="max-w-xl mx-auto space-y-4">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white">Ready to Investigate?</h2>
          <p className="text-xs text-[#888888] leading-relaxed">
            Deploy E.M.I.T. across your SOC or incident response team to streamline mobile artifact correlation.
          </p>
          <div className="pt-2 flex items-center justify-center gap-4">
            {isAuthenticated ? (
              <Link
                to="/dashboard"
                className="px-6 py-3 rounded bg-[#00FF00] hover:bg-[#00DD00] text-black font-bold text-xs tracking-wider uppercase transition-colors"
              >
                Access Forensic Console
              </Link>
            ) : (
              <>
                <Link
                  to="/signup"
                  className="px-6 py-3 rounded bg-[#00FF00] hover:bg-[#00DD00] text-black font-bold text-xs tracking-wider uppercase transition-colors"
                >
                  Create Account
                </Link>
                <Link
                  to="/signin"
                  className="px-6 py-3 rounded border border-[#333333] hover:border-[#666666] bg-[#111111] text-xs text-white tracking-wider uppercase transition-colors"
                >
                  Sign In
                </Link>
              </>
            )}
          </div>
        </div>
      </section>

      {/* 8. Footer */}
      <footer className="py-8 px-6 border-t border-[#141414] bg-[#050505] text-center text-[10px] text-[#555555] space-y-2">
        <div>E.M.I.T. Forensic Investigation Platform &mdash; Distributed under the Apache 2.0 License</div>
        <div>Engineered for authorized cybersecurity digital forensics and incident response.</div>
      </footer>
    </div>
  );
};

export default LandingPage;
