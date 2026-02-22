"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Shield, AlertCircle, Eye, EyeOff, Terminal, Scan, Globe, Zap, Loader2 } from "lucide-react";

const FEATURES = [
  { icon: <Globe    className="h-4 w-4" />, label: "28+ Modules",     sub: "Full recon pipeline"   },
  { icon: <Zap      className="h-4 w-4" />, label: "Live Streaming",  sub: "Real-time log output"  },
  { icon: <Scan     className="h-4 w-4" />, label: "Nuclei + CVEs",   sub: "Vulnerability scanning"},
  { icon: <Terminal className="h-4 w-4" />, label: "REST API",        sub: "Fully automated"       },
];

export default function LoginPage() {
  const { login, register } = useAuth();
  const router = useRouter();

  const [tab,      setTab]      = useState<"login" | "register">("login");
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [showPw,   setShowPw]   = useState(false);
  const [error,    setError]    = useState("");
  const [loading,  setLoading]  = useState(false);

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
    <div className="flex min-h-screen bg-background">

      {/* ── Left branding panel ─────────────────────────────────────────── */}
      <div className="hidden lg:flex relative w-[52%] flex-col overflow-hidden bg-card border-r border-border">

        {/* Subtle pattern */}
        <div className="absolute inset-0 bg-dots opacity-60" />

        {/* Warm gradient overlay */}
        <div className="absolute inset-0 bg-gradient-to-br from-primary/4 via-transparent to-transparent" />

        {/* Content */}
        <div className="relative z-10 flex flex-1 flex-col justify-between p-12">

          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 border border-primary/20">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div>
              <p className="text-[15px] font-bold tracking-widest text-foreground">SURVEX</p>
              <p className="text-[9px] tracking-widest text-muted-foreground/50 font-semibold">ATTACK SURFACE MANAGEMENT</p>
            </div>
          </div>

          {/* Main copy */}
          <div className="space-y-8">
            <div className="space-y-4">
              <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/8 px-3 py-1">
                <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                <span className="text-[11px] font-semibold text-primary tracking-widest">THREAT INTELLIGENCE PLATFORM</span>
              </div>
              <h1 className="text-[40px] font-bold leading-[1.1] tracking-tight text-foreground">
                Know your<br />
                <span className="text-primary">attack surface.</span>
              </h1>
              <p className="text-[15px] leading-relaxed text-muted-foreground max-w-sm">
                Enumerate subdomains, scan ports, detect vulnerabilities,
                and monitor your external exposure — all in one platform.
              </p>
            </div>

            {/* Feature grid */}
            <div className="grid grid-cols-2 gap-3">
              {FEATURES.map(f => (
                <div
                  key={f.label}
                  className="flex items-center gap-3 rounded-xl border border-border bg-background/50 p-3.5 hover:border-primary/20 hover:bg-primary/4 transition-all"
                >
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 border border-primary/15 text-primary">
                    {f.icon}
                  </div>
                  <div>
                    <p className="text-[12px] font-semibold text-foreground">{f.label}</p>
                    <p className="text-[11px] text-muted-foreground">{f.sub}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <p className="text-[11px] text-muted-foreground/40">
            Use responsibly. Only scan systems you own or have written permission to test.
          </p>
        </div>
      </div>

      {/* ── Right auth panel ─────────────────────────────────────────────── */}
      <div className="flex flex-1 flex-col items-center justify-center px-6 py-12">
        <div className="w-full max-w-[360px] space-y-7">

          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-primary/10 border border-primary/20">
              <Shield className="h-4 w-4 text-primary" />
            </div>
            <span className="text-[15px] font-bold tracking-widest text-foreground">SURVEX</span>
          </div>

          {/* Heading */}
          <div>
            <h2 className="text-2xl font-bold text-foreground">
              {tab === "login" ? "Welcome back" : "Create account"}
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              {tab === "login" ? "Sign in to your workspace" : "Start monitoring your attack surface"}
            </p>
          </div>

          {/* Tab switcher */}
          <div className="flex gap-1 rounded-lg border border-border bg-muted/40 p-1">
            {(["login", "register"] as const).map(t => (
              <button
                key={t}
                type="button"
                onClick={() => { setTab(t); setError(""); }}
                className={`flex-1 rounded-md py-2 text-[13px] font-medium transition-all ${
                  tab === t
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {t === "login" ? "Sign In" : "Register"}
              </button>
            ))}
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label className="text-[12px] font-medium text-muted-foreground uppercase tracking-wider">Email</Label>
              <Input
                type="email"
                placeholder="operator@example.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="h-10 bg-card border-border placeholder:text-muted-foreground/40 focus:border-primary/50 focus:ring-primary/20"
                autoComplete="email"
                required
              />
            </div>

            <div className="space-y-1.5">
              <Label className="text-[12px] font-medium text-muted-foreground uppercase tracking-wider">Password</Label>
              <div className="relative">
                <Input
                  type={showPw ? "text" : "password"}
                  placeholder={tab === "register" ? "Minimum 8 characters" : "••••••••"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="h-10 bg-card border-border placeholder:text-muted-foreground/40 focus:border-primary/50 focus:ring-primary/20 pr-10"
                  autoComplete={tab === "login" ? "current-password" : "new-password"}
                  required
                  minLength={tab === "register" ? 8 : 1}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground/40 hover:text-muted-foreground transition-colors"
                >
                  {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-center gap-2.5 rounded-lg border border-destructive/20 bg-destructive/8 px-3.5 py-2.5 text-sm text-destructive">
                <AlertCircle className="h-4 w-4 shrink-0" />
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 h-10 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-60 text-primary-foreground font-semibold text-sm transition-colors"
            >
              {loading ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  {tab === "login" ? "Signing in…" : "Creating account…"}
                </>
              ) : (
                tab === "login" ? "Sign In" : "Create Account"
              )}
            </button>
          </form>

          <p className="text-center text-[11px] text-muted-foreground/40">
            Authorized access only. All activity is logged.
          </p>
        </div>
      </div>
    </div>
  );
}
