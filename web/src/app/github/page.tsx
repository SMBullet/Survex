"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, CloudScanJob, CloudFinding } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import {
  Github, Search, Key, AlertCircle, ChevronRight,
  Eye, Lock, Code, Globe, Loader2, Shield,
  CheckCircle, Clock, XCircle, Play,
} from "lucide-react";

const WHAT_IT_FINDS = [
  { icon: <Key className="h-4 w-4" />,    label: "API Keys & Tokens",     desc: "Hardcoded credentials, API keys, access tokens in public repos" },
  { icon: <Lock className="h-4 w-4" />,   label: "Secrets & Passwords",   desc: "Passwords, private keys, connection strings accidentally committed" },
  { icon: <Code className="h-4 w-4" />,   label: "Source Code Leaks",     desc: "Internal configs, .env files, infrastructure-as-code with secrets" },
  { icon: <Globe className="h-4 w-4" />,  label: "Internal Endpoints",    desc: "Internal hostnames, IP ranges, staging/dev URLs exposed in code" },
  { icon: <Eye className="h-4 w-4" />,    label: "Employee Accounts",     desc: "Developer repositories that reference your domains or brand" },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  low:      "text-blue-400 bg-blue-500/10 border-blue-500/20",
  info:     "text-muted-foreground bg-muted/30 border-border",
};

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { icon: React.ReactNode; cls: string }> = {
    queued:  { icon: <Clock className="h-3 w-3" />,   cls: "text-muted-foreground" },
    running: { icon: <Loader2 className="h-3 w-3 animate-spin" />, cls: "text-blue-400" },
    done:    { icon: <CheckCircle className="h-3 w-3" />, cls: "text-green-400" },
    failed:  { icon: <XCircle className="h-3 w-3" />, cls: "text-red-400" },
  };
  const s = map[status] ?? map.queued;
  return (
    <span className={`flex items-center gap-1 text-xs font-medium ${s.cls}`}>
      {s.icon}{status}
    </span>
  );
}

function FindingsTable({ findings }: { findings: CloudFinding[] }) {
  if (!findings.length) return (
    <p className="text-center text-muted-foreground text-sm py-8">No findings — organization looks clean.</p>
  );
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[12px]">
        <thead>
          <tr className="border-b border-border text-left text-muted-foreground/60 text-[11px] uppercase tracking-widest">
            <th className="pb-2 pr-3 font-semibold">Severity</th>
            <th className="pb-2 pr-3 font-semibold">Service</th>
            <th className="pb-2 pr-3 font-semibold">Resource</th>
            <th className="pb-2 pr-3 font-semibold">Check</th>
            <th className="pb-2 font-semibold">Remediation</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {findings.map((f, i) => (
            <tr key={i} className="hover:bg-muted/20 transition-colors">
              <td className="py-2 pr-3">
                <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase ${SEVERITY_COLORS[f.severity] ?? SEVERITY_COLORS.info}`}>
                  {f.severity}
                </span>
              </td>
              <td className="py-2 pr-3 font-medium text-foreground/80">{f.service}</td>
              <td className="py-2 pr-3 font-mono text-foreground/70 max-w-[140px] truncate" title={f.resource}>{f.resource}</td>
              <td className="py-2 pr-3 text-foreground/70">
                <p className="font-medium text-foreground/80">{f.check}</p>
                <p className="text-muted-foreground/60 mt-0.5 leading-relaxed">{f.detail}</p>
              </td>
              <td className="py-2 text-muted-foreground/60 max-w-[200px] leading-relaxed">{f.remediation}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function GitHubPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [tab, setTab] = useState<"exposure" | "review">("exposure");

  // ── Exposure scan state ──────────────────────────────────────────────────────
  const [targets, setTargets]       = useState("");
  const [client, setClient]         = useState("");
  const [expToken, setExpToken]     = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState("");

  // ── Config review state ──────────────────────────────────────────────────────
  const [revToken, setRevToken]   = useState("");
  const [org, setOrg]             = useState("");
  const [repos, setRepos]         = useState("");
  const [scanning, setScanning]   = useState(false);
  const [scanError, setScanError] = useState("");
  const [currentJob, setCurrentJob] = useState<CloudScanJob | null>(null);
  const [recentScans, setRecentScans] = useState<CloudScanJob[]>([]);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);

  // Pre-fill token from saved github credentials
  useEffect(() => {
    if (!user) return;
    api.cloud.getCredentials().then(all => {
      if (all.github?.token) {
        setRevToken(all.github.token);
        setOrg(all.github.org ?? "");
      }
    }).catch(() => {});
    api.cloud.listScans("github", 5).then(setRecentScans).catch(() => {});
  }, [user]);

  const pollJob = useCallback((id: string) => {
    const interval = setInterval(async () => {
      try {
        const job = await api.cloud.getScan(id);
        setCurrentJob(job);
        if (job.status === "done" || job.status === "failed") {
          clearInterval(interval);
          setScanning(false);
          api.cloud.listScans("github", 5).then(setRecentScans).catch(() => {});
        }
      } catch {
        clearInterval(interval);
        setScanning(false);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  if (loading || !user) return null;

  // Exposure scan handler
  const handleExposureSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const targetList = targets.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (!targetList.length) { setError("Enter at least one domain to search."); return; }
    setSubmitting(true);
    try {
      const job = await api.scans.create({
        client: client || targetList[0],
        targets: targetList,
        modules: ["github"],
        options: { no_subs: true, github_token: expToken } as Record<string, unknown>,
      });
      router.push(`/scans/detail?id=${job.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setSubmitting(false);
    }
  };

  // Config review handler
  const handleReviewScan = async () => {
    setScanError("");
    setScanning(true);
    setCurrentJob(null);
    try {
      const opts: Record<string, string> = { token: revToken };
      if (org) opts.org = org;
      if (repos) opts.repos = repos;
      const { id } = await api.cloud.createScan("github", opts);
      const job = await api.cloud.getScan(id);
      setCurrentJob(job);
      pollJob(id);
    } catch (e: unknown) {
      setScanError(e instanceof Error ? e.message : "Failed to start review");
      setScanning(false);
    }
  };

  return (
    <AppShell>
      <main className="min-h-screen bg-background bg-dots">
        <div className="mx-auto max-w-3xl px-6 py-8 space-y-6">

          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground/60">
            <span className="hover:text-muted-foreground cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
            <ChevronRight className="h-3 w-3" />
            <span className="text-muted-foreground">GitHub</span>
          </div>

          {/* Header */}
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-card">
              <Github className="h-5 w-5 text-foreground/80" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground tracking-tight">GitHub</h1>
              <p className="text-[12px] text-muted-foreground/60">Exposure scan and organization security review.</p>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 rounded-lg border border-border bg-muted/20 p-1">
            {(["exposure", "review"] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`flex-1 rounded-md px-4 py-2 text-[13px] font-semibold transition-all ${
                  tab === t
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {t === "exposure" ? (
                  <span className="flex items-center justify-center gap-2"><Search className="h-3.5 w-3.5" />Exposure Scan</span>
                ) : (
                  <span className="flex items-center justify-center gap-2"><Shield className="h-3.5 w-3.5" />Config Review</span>
                )}
              </button>
            ))}
          </div>

          {/* ── Exposure Scan Tab ─────────────────────────────────────────────── */}
          {tab === "exposure" && (
            <>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {WHAT_IT_FINDS.map(item => (
                  <div key={item.label} className="flex gap-3 rounded-lg border border-border bg-card/90 p-3 hover:border-red-500/15 hover:bg-red-500/4 transition-all">
                    <span className="shrink-0 text-muted-foreground/60 mt-0.5">{item.icon}</span>
                    <div>
                      <p className="text-[13px] font-medium text-foreground/80">{item.label}</p>
                      <p className="text-[11px] text-muted-foreground/60 mt-0.5 leading-relaxed">{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>

              <form onSubmit={handleExposureSubmit} className="space-y-4">
                <section className="rounded-xl border border-border bg-card overflow-hidden">
                  <div className="flex items-center gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
                    <Search className="h-4 w-4 text-red-400" />
                    <span className="text-[13px] font-semibold text-foreground">Search Parameters</span>
                  </div>
                  <div className="p-5 space-y-4">
                    <div className="space-y-1.5">
                      <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                        Target Domains <span className="text-red-500">*</span>
                      </label>
                      <textarea
                        placeholder={"example.com\nacme-corp.com\nmycompany.io"}
                        rows={4}
                        value={targets}
                        onChange={e => setTargets(e.target.value)}
                        className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[13px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all resize-none"
                        required
                      />
                      <p className="text-[11px] text-muted-foreground/40">One domain per line. Survex searches GitHub for code referencing these domains.</p>
                    </div>
                    <div className="grid gap-4 sm:grid-cols-2">
                      <div className="space-y-1.5">
                        <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                          Client Name <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(optional)</span>
                        </label>
                        <input type="text" placeholder="acme-corp" value={client} onChange={e => setClient(e.target.value)}
                          className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 text-[13px] text-foreground/80 placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all" />
                      </div>
                      <div className="space-y-1.5">
                        <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                          GitHub Token <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(recommended)</span>
                        </label>
                        <input type="password" placeholder="ghp_…" value={expToken} onChange={e => setExpToken(e.target.value)}
                          className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[13px] text-foreground/80 placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all" />
                      </div>
                    </div>
                  </div>
                </section>

                {error && (
                  <div className="flex items-center gap-2.5 rounded-lg border border-red-500/20 bg-red-500/8 px-4 py-3 text-sm text-red-400">
                    <AlertCircle className="h-4 w-4 shrink-0" />{error}
                  </div>
                )}

                <div className="flex gap-3">
                  <button type="submit" disabled={submitting}
                    className="flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 px-6 py-2.5 text-sm font-semibold text-primary-foreground transition-all">
                    {submitting ? <><Loader2 className="h-3.5 w-3.5 animate-spin" />Starting…</> : <><Search className="h-4 w-4" />Search GitHub<ChevronRight className="h-4 w-4" /></>}
                  </button>
                  <button type="button" onClick={() => router.push("/dashboard")}
                    className="rounded-lg border border-border px-5 py-2.5 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all">
                    Cancel
                  </button>
                </div>
              </form>
            </>
          )}

          {/* ── Config Review Tab ─────────────────────────────────────────────── */}
          {tab === "review" && (
            <>
              <section className="rounded-xl border border-border bg-card overflow-hidden">
                <div className="flex items-center gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
                  <Shield className="h-4 w-4 text-primary" />
                  <span className="text-[13px] font-semibold text-foreground">Review Parameters</span>
                </div>
                <div className="p-5 space-y-4">
                  <div className="space-y-1.5">
                    <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                      GitHub Token <span className="text-red-500">*</span>
                    </label>
                    <input type="password" placeholder="ghp_… (needs read:org and repo scopes)"
                      value={revToken} onChange={e => setRevToken(e.target.value)}
                      className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[13px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all" />
                    <p className="text-[11px] text-muted-foreground/40">Required scopes: <span className="font-mono">read:org</span>, <span className="font-mono">repo</span>. Pre-filled from saved credentials if available.</p>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                        Organization <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(optional)</span>
                      </label>
                      <input type="text" placeholder="my-org (scans all accessible orgs if blank)"
                        value={org} onChange={e => setOrg(e.target.value)}
                        className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 text-[13px] text-foreground/80 placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all" />
                    </div>
                    <div className="space-y-1.5">
                      <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                        Repos to Include <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(optional)</span>
                      </label>
                      <input type="text" placeholder="repo1, repo2 (comma-separated, or blank for all)"
                        value={repos} onChange={e => setRepos(e.target.value)}
                        className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 text-[13px] text-foreground/80 placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all" />
                    </div>
                  </div>
                </div>
              </section>

              {/* What it checks */}
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 text-[12px]">
                {[
                  "2FA enforcement", "Branch protection", "Force push allowed",
                  "Required PR reviews", "Secret scanning", "Dependabot alerts",
                  "Actions write permissions", "Webhook HTTPS", "Webhook secrets",
                ].map(item => (
                  <div key={item} className="flex items-center gap-2 rounded-lg border border-border bg-card/50 px-3 py-2">
                    <Shield className="h-3 w-3 shrink-0 text-primary/60" />
                    <span className="text-muted-foreground/70">{item}</span>
                  </div>
                ))}
              </div>

              <div className="flex items-center gap-4">
                <button onClick={handleReviewScan} disabled={scanning || !revToken}
                  className="flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 px-6 py-2.5 text-sm font-semibold text-primary-foreground transition-all">
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                  {scanning ? "Scanning…" : "Start Config Review"}
                </button>
                {scanError && <div className="flex items-center gap-2 text-sm text-red-400"><AlertCircle className="h-4 w-4 shrink-0" />{scanError}</div>}
              </div>

              {currentJob && (
                <section className="rounded-xl border border-border bg-card overflow-hidden">
                  <div className="flex items-center justify-between border-b border-border bg-muted/20 px-5 py-3">
                    <div className="flex items-center gap-2.5">
                      <Github className="h-4 w-4 text-foreground/60" />
                      <span className="text-[13px] font-semibold text-foreground">Review Results</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <StatusBadge status={currentJob.status} />
                      {currentJob.result?.summary && (
                        <div className="flex items-center gap-2 text-[11px]">
                          {["critical","high","medium","low","info"].map(sev =>
                            (currentJob.result!.summary[sev] ?? 0) > 0 ? (
                              <span key={sev} className={`rounded border px-1.5 py-0.5 font-semibold uppercase ${SEVERITY_COLORS[sev]}`}>
                                {currentJob.result!.summary[sev]} {sev}
                              </span>
                            ) : null
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="p-5">
                    {currentJob.status === "running" || currentJob.status === "queued" ? (
                      <div className="flex items-center justify-center gap-3 py-12 text-muted-foreground">
                        <Loader2 className="h-5 w-5 animate-spin" /><span className="text-sm">Reviewing GitHub org…</span>
                      </div>
                    ) : currentJob.status === "failed" ? (
                      <div className="flex items-center gap-2 text-red-400 text-sm py-4">
                        <XCircle className="h-4 w-4 shrink-0" />{currentJob.error ?? "Review failed"}
                      </div>
                    ) : currentJob.result ? <FindingsTable findings={currentJob.result.findings} /> : null}
                  </div>
                </section>
              )}

              {recentScans.length > 0 && !currentJob && (
                <section className="rounded-xl border border-border bg-card overflow-hidden">
                  <div className="flex items-center gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
                    <Clock className="h-4 w-4 text-muted-foreground/60" />
                    <span className="text-[13px] font-semibold text-foreground">Recent Reviews</span>
                  </div>
                  <div className="divide-y divide-border">
                    {recentScans.map(job => (
                      <button key={job.id} onClick={() => setCurrentJob(job)}
                        className="w-full flex items-center justify-between px-5 py-3 hover:bg-muted/20 transition-colors text-left">
                        <div className="flex items-center gap-3">
                          <StatusBadge status={job.status} />
                          <span className="text-[12px] text-muted-foreground/60">{new Date(job.created_at).toLocaleString()}</span>
                        </div>
                        {job.result?.summary && (
                          <div className="flex items-center gap-2 text-[11px]">
                            {["critical","high","medium"].map(sev =>
                              (job.result!.summary[sev] ?? 0) > 0 ? (
                                <span key={sev} className={`rounded border px-1.5 py-0.5 font-semibold uppercase ${SEVERITY_COLORS[sev]}`}>
                                  {job.result!.summary[sev]} {sev}
                                </span>
                              ) : null
                            )}
                          </div>
                        )}
                      </button>
                    ))}
                  </div>
                </section>
              )}
            </>
          )}

          <p className="text-[11px] text-muted-foreground/40 border-t border-border pt-4">
            <span className="font-bold text-muted-foreground/60">Note:</span> Exposure scan uses the GitHub code search API.
            Config review requires a token with <span className="font-mono">read:org</span> and <span className="font-mono">repo</span> scopes.
          </p>
        </div>
      </main>
    </AppShell>
  );
}
