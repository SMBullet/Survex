"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, CloudScanJob, CloudFinding } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import {
  Cpu, ChevronRight, Key, Shield, AlertCircle,
  Loader2, Play, Trash2, CheckCircle, Clock, XCircle,
} from "lucide-react";
import Link from "next/link";

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
    <p className="text-center text-muted-foreground text-sm py-8">No findings — environment looks clean.</p>
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

export default function GCPPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [saJSON, setSaJSON] = useState("");
  const [projectID, setProjectID] = useState("");
  const [savingCreds, setSavingCreds] = useState(false);
  const [credsError, setCredsError] = useState("");
  const [credsSaved, setCredsSaved] = useState(false);

  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [currentJob, setCurrentJob] = useState<CloudScanJob | null>(null);
  const [recentScans, setRecentScans] = useState<CloudScanJob[]>([]);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);

  useEffect(() => {
    if (!user) return;
    api.cloud.getCredentials().then(all => {
      if (all.gcp) {
        setSaJSON(all.gcp.service_account_json ?? "");
        setProjectID(all.gcp.project_id ?? "");
      }
    }).catch(() => {});
    api.cloud.listScans("gcp", 5).then(setRecentScans).catch(() => {});
  }, [user]);

  const pollJob = useCallback((id: string) => {
    const interval = setInterval(async () => {
      try {
        const job = await api.cloud.getScan(id);
        setCurrentJob(job);
        if (job.status === "done" || job.status === "failed") {
          clearInterval(interval);
          setScanning(false);
          api.cloud.listScans("gcp", 5).then(setRecentScans).catch(() => {});
        }
      } catch {
        clearInterval(interval);
        setScanning(false);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  if (loading || !user) return null;

  const handleSaveCreds = async () => {
    setSavingCreds(true);
    setCredsError("");
    setCredsSaved(false);
    try {
      const data: Record<string, string> = { service_account_json: saJSON };
      if (projectID) data.project_id = projectID;
      await api.cloud.saveCredentials("gcp", data);
      setCredsSaved(true);
      setTimeout(() => setCredsSaved(false), 3000);
    } catch (e: unknown) {
      setCredsError(e instanceof Error ? e.message : "Failed to save");
    } finally {
      setSavingCreds(false);
    }
  };

  const handleClearCreds = async () => {
    await api.cloud.deleteCredentials("gcp").catch(() => {});
    setSaJSON("");
    setProjectID("");
  };

  const handleScan = async () => {
    setScanError("");
    setScanning(true);
    setCurrentJob(null);
    try {
      const opts: Record<string, string> = { service_account_json: saJSON };
      if (projectID) opts.project_id = projectID;
      const { id } = await api.cloud.createScan("gcp", opts);
      const job = await api.cloud.getScan(id);
      setCurrentJob(job);
      pollJob(id);
    } catch (e: unknown) {
      setScanError(e instanceof Error ? e.message : "Failed to start scan");
      setScanning(false);
    }
  };

  return (
    <AppShell>
      <main className="min-h-screen bg-background bg-dots">
        <div className="mx-auto max-w-4xl px-6 py-8 space-y-6">

          <div className="flex items-center gap-2 text-xs text-muted-foreground/60">
            <Link href="/cloud" className="hover:text-muted-foreground transition-colors">Cloud</Link>
            <ChevronRight className="h-3 w-3" />
            <span className="text-muted-foreground">GCP Configuration Review</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-violet-500/20 bg-violet-500/8">
              <Cpu className="h-5 w-5 text-violet-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground tracking-tight">GCP Configuration Review</h1>
              <p className="text-[12px] text-muted-foreground/60">Audit GCS, Compute, BigQuery, Cloud SQL, Cloud Functions, and IAM.</p>
            </div>
          </div>

          {/* Credentials */}
          <section className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="flex items-center gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
              <Key className="h-4 w-4 text-violet-400" />
              <span className="text-[13px] font-semibold text-foreground">Service Account Credentials</span>
              <span className="ml-auto text-[11px] text-muted-foreground/50">Stored in Survex — never leaves your server</span>
            </div>
            <div className="p-5 space-y-4">
              <div className="space-y-1.5">
                <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                  Service Account JSON <span className="text-red-500">*</span>
                </label>
                <textarea
                  rows={8}
                  placeholder={`{\n  "type": "service_account",\n  "project_id": "my-project",\n  "private_key_id": "...",\n  ...\n}`}
                  value={saJSON}
                  onChange={e => setSaJSON(e.target.value)}
                  className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[12px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all resize-none"
                />
                <p className="text-[11px] text-muted-foreground/40">
                  Paste the full contents of your service account JSON key file. The key needs Cloud Viewer roles.
                </p>
              </div>
              <div className="space-y-1.5 max-w-sm">
                <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                  Project ID <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(optional — auto-detected from JSON)</span>
                </label>
                <input
                  type="text"
                  placeholder="my-gcp-project"
                  value={projectID}
                  onChange={e => setProjectID(e.target.value)}
                  className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[12px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all"
                />
              </div>
            </div>
            {credsError && (
              <div className="mx-5 mb-4 flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/8 px-4 py-2.5 text-sm text-red-400">
                <AlertCircle className="h-4 w-4 shrink-0" />{credsError}
              </div>
            )}
            <div className="flex items-center gap-3 px-5 pb-5">
              <button onClick={handleSaveCreds} disabled={savingCreds}
                className="flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 px-4 py-2 text-sm font-semibold text-primary-foreground transition-all">
                {savingCreds ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Key className="h-3.5 w-3.5" />}
                {credsSaved ? "Saved!" : "Save Credentials"}
              </button>
              <button onClick={handleClearCreds}
                className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all">
                <Trash2 className="h-3.5 w-3.5" />Clear
              </button>
            </div>
          </section>

          <div className="flex items-center gap-4">
            <button onClick={handleScan} disabled={scanning}
              className="flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 px-6 py-2.5 text-sm font-semibold text-primary-foreground transition-all">
              {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {scanning ? "Scanning…" : "Run GCP Review"}
            </button>
            {scanError && <div className="flex items-center gap-2 text-sm text-red-400"><AlertCircle className="h-4 w-4 shrink-0" />{scanError}</div>}
          </div>

          {currentJob && (
            <section className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="flex items-center justify-between border-b border-border bg-muted/20 px-5 py-3">
                <div className="flex items-center gap-2.5">
                  <Shield className="h-4 w-4 text-violet-400" />
                  <span className="text-[13px] font-semibold text-foreground">Scan Results</span>
                  {currentJob.result?.account_id && (
                    <span className="text-[11px] text-muted-foreground/50 font-mono">project: {currentJob.result.account_id}</span>
                  )}
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
                    <Loader2 className="h-5 w-5 animate-spin" /><span className="text-sm">Scanning GCP project…</span>
                  </div>
                ) : currentJob.status === "failed" ? (
                  <div className="flex items-center gap-2 text-red-400 text-sm py-4">
                    <XCircle className="h-4 w-4 shrink-0" />{currentJob.error ?? "Scan failed"}
                  </div>
                ) : currentJob.result ? <FindingsTable findings={currentJob.result.findings} /> : null}
              </div>
            </section>
          )}

          {recentScans.length > 0 && !currentJob && (
            <section className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="flex items-center gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
                <Clock className="h-4 w-4 text-muted-foreground/60" />
                <span className="text-[13px] font-semibold text-foreground">Recent Scans</span>
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
        </div>
      </main>
    </AppShell>
  );
}
