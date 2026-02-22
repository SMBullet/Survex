"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Shield, AlertCircle, Eye, EyeOff, Terminal, Scan, Globe, Zap } from "lucide-react";

const FEATURES = [
  { icon: <Globe className="h-4 w-4" />,    label: "28+ Modules",      sub: "Full recon pipeline" },
  { icon: <Zap className="h-4 w-4" />,      label: "Live Streaming",   sub: "Real-time log output" },
  { icon: <Scan className="h-4 w-4" />,     label: "Nuclei + WPScan",  sub: "CVE & CMS scanning" },
  { icon: <Terminal className="h-4 w-4" />, label: "REST API",         sub: "Fully automated" },
];

export default function LoginPage() {
  const { login, register } = useAuth();
  const router = useRouter();

  const [tab, setTab]           = useState<"login" | "register">("login");
  const [email, setEmail]       = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw]     = useState(false);
  const [error, setError]       = useState("");
  const [loading, setLoading]   = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (tab === "login") await login(email, password);
      else await register(email, password);
      router.push("/dashboard");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-[#0d0018]">

      {/* ── Left branding panel ─────────────────────────────────────── */}
      <div className="hidden lg:flex relative w-[52%] flex-col overflow-hidden bg-[#0f0020]">

        {/* Circuit grid background */}
        <div className="absolute inset-0 bg-circuit opacity-70" />

        {/* Radial glow — red */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_30%_60%,rgba(239,68,68,0.1)_0%,transparent_60%)]" />
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_80%_20%,rgba(251,191,36,0.05)_0%,transparent_50%)]" />

        {/* Bottom gradient line */}
        <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-red-500/40 to-transparent" />
        {/* Top gradient line */}
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-red-500/20 to-transparent" />

        {/* Content */}
        <div className="relative z-10 flex flex-1 flex-col justify-between p-12">

          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-red-500/40 bg-red-500/10 glow-sm-red">
              <Shield className="h-5 w-5 text-red-400" />
            </div>
            <div>
              <p className="text-[15px] font-bold tracking-widest text-white">SURVEX</p>
              <p className="text-[9px] tracking-widest text-red-500/50 font-semibold">ATTACK SURFACE MANAGEMENT</p>
            </div>
          </div>

          {/* Main copy */}
          <div className="space-y-6">
            <div className="space-y-3">
              <div className="inline-flex items-center gap-2 rounded-full border border-red-500/25 bg-red-500/8 px-3 py-1">
                <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
                <span className="text-[11px] font-medium text-red-400 tracking-widest">THREAT INTELLIGENCE PLATFORM</span>
              </div>
              <h1 className="text-[42px] font-bold leading-[1.1] tracking-tight text-white animate-flicker">
                Know your<br />
                <span className="bg-gradient-to-r from-red-400 via-orange-400 to-amber-400 bg-clip-text text-transparent">
                  attack surface.
                </span>
              </h1>
              <p className="text-[15px] leading-relaxed text-zinc-400 max-w-sm">
                Enumerate subdomains, scan ports, detect vulnerabilities,
                and monitor your external exposure — all in one platform.
              </p>
            </div>

            {/* Feature grid */}
            <div className="grid grid-cols-2 gap-2.5">
              {FEATURES.map(f => (
                <div key={f.label} className="flex items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3.5 hover:border-red-500/20 hover:bg-red-500/4 transition-all">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-red-500/20 bg-red-500/8 text-red-400">
                    {f.icon}
                  </div>
                  <div>
                    <p className="text-[12px] font-semibold text-white">{f.label}</p>
                    <p className="text-[11px] text-zinc-500">{f.sub}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Footer */}
          <p className="text-[11px] text-zinc-700">
            Use responsibly. Only scan systems you own or have written permission to test.
          </p>
        </div>
      </div>

      {/* ── Right auth panel ─────────────────────────────────────────── */}
      <div className="flex flex-1 flex-col items-center justify-center px-6 py-12 bg-[#0d0018]">

        {/* Subtle background */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_70%_50%,rgba(139,0,30,0.06)_0%,transparent_60%)] pointer-events-none" />

        <div className="relative w-full max-w-[360px] space-y-8">

          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-red-500/30 bg-red-500/10">
              <Shield className="h-4 w-4 text-red-400" />
            </div>
            <span className="text-[15px] font-bold tracking-widest text-white">SURVEX</span>
          </div>

          {/* Header */}
          <div>
            <h2 className="text-2xl font-bold text-white">
              {tab === "login" ? "Welcome back" : "Create account"}
            </h2>
            <p className="text-sm text-zinc-500 mt-1">
              {tab === "login" ? "Sign in to your workspace" : "Start monitoring your attack surface"}
            </p>
          </div>

          {/* Tab switcher */}
          <div className="flex gap-1 rounded-lg border border-white/[0.07] bg-white/[0.03] p-1">
            {(["login", "register"] as const).map(t => (
              <button
                key={t}
                type="button"
                onClick={() => { setTab(t); setError(""); }}
                className={`flex-1 rounded-md py-2 text-[13px] font-medium transition-all ${
                  tab === t
                    ? "bg-red-500/15 text-red-400 border border-red-500/25"
                    : "text-zinc-500 hover:text-zinc-300"
                }`}
              >
                {t === "login" ? "Sign In" : "Register"}
              </button>
            ))}
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label className="text-[12px] font-medium text-zinc-400 uppercase tracking-wider">Email</Label>
              <Input
                type="email"
                placeholder="operator@example.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="bg-white/[0.04] border-white/[0.08] text-white placeholder:text-zinc-600 focus:border-red-500/50 focus:ring-red-500/20 h-10"
                autoComplete="email"
                required
              />
            </div>

            <div className="space-y-1.5">
              <Label className="text-[12px] font-medium text-zinc-400 uppercase tracking-wider">Password</Label>
              <div className="relative">
                <Input
                  type={showPw ? "text" : "password"}
                  placeholder={tab === "register" ? "Minimum 8 characters" : "••••••••"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="bg-white/[0.04] border-white/[0.08] text-white placeholder:text-zinc-600 focus:border-red-500/50 focus:ring-red-500/20 h-10 pr-10"
                  autoComplete={tab === "login" ? "current-password" : "new-password"}
                  required
                  minLength={tab === "register" ? 8 : 1}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-300 transition-colors"
                >
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2.5 rounded-lg border border-red-500/20 bg-red-500/8 px-3.5 py-2.5 text-sm text-red-400">
                <AlertCircle className="h-4 w-4 shrink-0" />
                {error}
              </div>
            )}

            <Button
              type="submit"
              disabled={loading}
              className="w-full h-10 bg-red-600 hover:bg-red-500 text-white font-semibold transition-all glow-sm-red"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="h-3.5 w-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                  {tab === "login" ? "Signing in…" : "Creating account…"}
                </span>
              ) : (
                tab === "login" ? "Sign In" : "Create Account"
              )}
            </Button>
          </form>

          <p className="text-center text-[11px] text-zinc-700">
            Authorized access only. All activity is logged.
          </p>
        </div>
      </div>
    </div>
  );
}
