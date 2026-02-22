"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, CloudScanJob, CloudFinding } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import {
  GitBranch, ChevronRight, Key, Shield, AlertCircle,
  Loader2, Play, CheckCircle, Clock, XCircle,
} from "lucide-react";

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

export default function GitLabPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [token, setToken]     = useState("");
  const [glURL, setGlURL]     = useState("https://gitlab.com");
  const [group, setGroup]     = useState("");

  const [scanning, setScanning]     = useState(false);
  const [scanError, setScanError]   = useState("");
  const [currentJob, setCurrentJob] = useState<CloudScanJob | null>(null);
  const [recentScans, setRecentScans] = useState<CloudScanJob[]>([]);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);

  useEffect(() => {
    if (!user) return;
    api.cloud.getCredentials().then(all => {
      if (all.gitlab) {
        setToken(all.gitlab.token ?? "");
        setGlURL(all.gitlab.url ?? "https://gitlab.com");
        setGroup(all.gitlab.group ?? "");
      }
    }).catch(() => {});
    api.cloud.listScans("gitlab", 5).then(setRecentScans).catch(() => {});
  }, [user]);

  const pollJob = useCallback((id: string) => {
    const interval = setInterval(async () => {
      try {
        const job = await api.cloud.getScan(id);
        setCurrentJob(job);
        if (job.status === "done" || job.status === "failed") {
          clearInterval(interval);
          setScanning(false);
          api.cloud.listScans("gitlab", 5).then(setRecentScans).catch(() => {});
        }
      } catch {
        clearInterval(interval);
        setScanning(false);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  if (loading || !user) return null;

  const handleScan = async () => {
    setScanError("");
    setScanning(true);
    setCurrentJob(null);
    try {
      const opts: Record<string, string> = { token, url: glURL };
      if (group) opts.group = group;
      const { id } = await api.cloud.createScan("gitlab", opts);
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
            <span className="text-muted-foreground">GitLab Config Review</span>
          </div>

          {/* Header */}
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-orange-500/20 bg-orange-500/8">
              <GitBranch className="h-5 w-5 text-orange-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground tracking-tight">GitLab Configuration Review</h1>
              <p className="text-[12px] text-muted-foreground/60">
                Audit groups, projects, branch protection, CI/CD variables, and webhooks for security misconfigurations.
              </p>
            </div>
          </div>

          {/* What it checks */}
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 text-[12px]">
            {[
              "2FA enforcement", "Branch protection", "Force push allowed",
              "MR approvals required", "CI/CD variable exposure", "Webhook HTTPS",
              "Webhook SSL verification", "Public container registry", "IP restrictions",
            ].map(item => (
              <div key={item} className="flex items-center gap-2 rounded-lg border border-border bg-card/50 px-3 py-2">
                <Shield className="h-3 w-3 shrink-0 text-orange-400/60" />
                <span className="text-muted-foreground/70">{item}</span>
              </div>
            ))}
          </div>

          {/* Form */}
          <section className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="flex items-center gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
              <Key className="h-4 w-4 text-orange-400" />
              <span className="text-[13px] font-semibold text-foreground">Review Parameters</span>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                    Access Token <span className="text-red-500">*</span>
                  </label>
                  <input type="password" placeholder="glpat-…"
                    value={token} onChange={e => setToken(e.target.value)}
                    className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[13px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all" />
                  <p className="text-[11px] text-muted-foreground/40">Personal access token or Group access token with <span className="font-mono">read_api</span> scope.</p>
                </div>
                <div className="space-y-1.5">
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                    GitLab URL <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(optional)</span>
                  </label>
                  <input type="text" placeholder="https://gitlab.com"
                    value={glURL} onChange={e => setGlURL(e.target.value)}
                    className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[13px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all" />
                  <p className="text-[11px] text-muted-foreground/40">Leave as-is for gitlab.com, or enter your self-hosted instance URL.</p>
                </div>
              </div>
              <div className="space-y-1.5 max-w-sm">
                <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                  Group Path <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(optional)</span>
                </label>
                <input type="text" placeholder="my-group (scans all accessible groups if blank)"
                  value={group} onChange={e => setGroup(e.target.value)}
                  className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 text-[13px] text-foreground/80 placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all" />
              </div>
            </div>
          </section>

          <div className="flex items-center gap-4">
            <button onClick={handleScan} disabled={scanning || !token}
              className="flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 px-6 py-2.5 text-sm font-semibold text-primary-foreground transition-all">
              {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {scanning ? "Scanning…" : "Start Config Review"}
            </button>
            <button onClick={() => router.push("/dashboard")}
              className="rounded-lg border border-border px-5 py-2.5 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all">
              Cancel
            </button>
            {scanError && <div className="flex items-center gap-2 text-sm text-red-400"><AlertCircle className="h-4 w-4 shrink-0" />{scanError}</div>}
          </div>

          {currentJob && (
            <section className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="flex items-center justify-between border-b border-border bg-muted/20 px-5 py-3">
                <div className="flex items-center gap-2.5">
                  <GitBranch className="h-4 w-4 text-orange-400" />
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
                    <Loader2 className="h-5 w-5 animate-spin" /><span className="text-sm">Reviewing GitLab groups…</span>
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

          <p className="text-[11px] text-muted-foreground/40 border-t border-border pt-4">
            <span className="font-bold text-muted-foreground/60">Note:</span> Token must have <span className="font-mono">read_api</span> scope.
            For approval rules, a GitLab Premium or higher license is required.
          </p>
        </div>
      </main>
    </AppShell>
  );
}
