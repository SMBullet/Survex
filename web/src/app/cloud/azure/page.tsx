"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, CloudScanJob, CloudFinding, CloudAsset } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import {
  Cloud, ChevronRight, Key, Shield, AlertCircle,
  Loader2, Play, Trash2, CheckCircle, Clock, XCircle, Globe, ScanSearch,
} from "lucide-react";
import Link from "next/link";

type ScanMode = "both" | "discovery" | "audit";

const AZURE_FIELDS = [
  { key: "tenant_id",       label: "Tenant ID",       type: "text",     placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", required: true },
  { key: "client_id",       label: "Client ID",       type: "text",     placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", required: true },
  { key: "client_secret",   label: "Client Secret",   type: "password", placeholder: "Service principal secret", required: true },
  { key: "subscription_id", label: "Subscription ID", type: "text",     placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", required: true },
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

function AssetsTable({ assets }: { assets: CloudAsset[] }) {
  if (!assets.length) return (
    <p className="text-center text-muted-foreground text-sm py-8">No assets discovered.</p>
  );
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[12px]">
        <thead>
          <tr className="border-b border-border text-left text-muted-foreground/60 text-[11px] uppercase tracking-widest">
            <th className="pb-2 pr-3 font-semibold">Host / DNS</th>
            <th className="pb-2 pr-3 font-semibold">IP</th>
            <th className="pb-2 font-semibold">Visibility</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {assets.map((a, i) => (
            <tr key={i} className="hover:bg-muted/20 transition-colors">
              <td className="py-2 pr-3 font-mono text-foreground/80 max-w-[260px] truncate" title={a.host}>{a.host || "—"}</td>
              <td className="py-2 pr-3 font-mono text-muted-foreground/70">{a.ip || "—"}</td>
              <td className="py-2">
                <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-semibold uppercase ${a.public ? "text-blue-400 bg-blue-500/10 border-blue-500/20" : "text-muted-foreground bg-muted/30 border-border"}`}>
                  {a.public ? "public" : "private"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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

function JobResults({ job, mode }: { job: CloudScanJob; mode: ScanMode }) {
  const isActive = job.status === "running" || job.status === "queued";
  const loadingText =
    mode === "discovery" ? "Running cloudlist — enumerating Azure assets…" :
    mode === "audit"     ? "Running prowler — auditing Azure security posture…" :
                           "Running cloudlist + prowler against Azure…";

  if (isActive) return (
    <div className="flex items-center justify-center gap-3 py-12 text-muted-foreground">
      <Loader2 className="h-5 w-5 animate-spin" /><span className="text-sm">{loadingText}</span>
    </div>
  );
  if (job.status === "failed") return (
    <div className="flex items-center gap-2 text-red-400 text-sm py-4">
      <XCircle className="h-4 w-4 shrink-0" />{job.error ?? "Scan failed"}
    </div>
  );
  if (!job.result) return null;
  return (
    <>
      {mode !== "audit" && (
        <section className="rounded-xl border border-border bg-card overflow-hidden">
          <div className="flex items-center justify-between border-b border-border bg-muted/20 px-5 py-3">
            <div className="flex items-center gap-2.5">
              <Globe className="h-4 w-4 text-blue-400" />
              <span className="text-[13px] font-semibold text-foreground">Discovered Assets</span>
            </div>
            <span className="text-[11px] text-muted-foreground/60">{(job.result.assets ?? []).length} assets via cloudlist</span>
          </div>
          <div className="p-5"><AssetsTable assets={job.result.assets ?? []} /></div>
        </section>
      )}
      {mode !== "discovery" && (
        <section className="rounded-xl border border-border bg-card overflow-hidden">
          <div className="flex items-center justify-between border-b border-border bg-muted/20 px-5 py-3">
            <div className="flex items-center gap-2.5">
              <Shield className="h-4 w-4 text-blue-400" />
              <span className="text-[13px] font-semibold text-foreground">Security Findings</span>
            </div>
            <div className="flex items-center gap-4">
              <StatusBadge status={job.status} />
              {job.result.summary && (
                <div className="flex items-center gap-2 text-[11px]">
                  {["critical","high","medium","low","info"].map(sev =>
                    (job.result!.summary[sev] ?? 0) > 0 ? (
                      <span key={sev} className={`rounded border px-1.5 py-0.5 font-semibold uppercase ${SEVERITY_COLORS[sev]}`}>
                        {job.result!.summary[sev]} {sev}
                      </span>
                    ) : null
                  )}
                </div>
              )}
            </div>
          </div>
          <div className="p-5"><FindingsTable findings={job.result.findings ?? []} /></div>
        </section>
      )}
    </>
  );
}

export default function AzurePage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [tab, setTab] = useState<ScanMode>("both");
  const [creds, setCreds] = useState<Record<string, string>>({});
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
      if (all.azure) setCreds(all.azure);
    }).catch(() => {});
    api.cloud.listScans("azure", 5).then(setRecentScans).catch(() => {});
  }, [user]);

  const pollJob = useCallback((id: string) => {
    const interval = setInterval(async () => {
      try {
        const job = await api.cloud.getScan(id);
        setCurrentJob(job);
        if (job.status === "done" || job.status === "failed") {
          clearInterval(interval);
          setScanning(false);
          api.cloud.listScans("azure", 5).then(setRecentScans).catch(() => {});
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
    setSavingCreds(true); setCredsError(""); setCredsSaved(false);
    try {
      await api.cloud.saveCredentials("azure", creds);
      setCredsSaved(true);
      setTimeout(() => setCredsSaved(false), 3000);
    } catch (e: unknown) {
      setCredsError(e instanceof Error ? e.message : "Failed to save");
    } finally { setSavingCreds(false); }
  };

  const handleClearCreds = async () => {
    await api.cloud.deleteCredentials("azure").catch(() => {});
    setCreds({});
  };

  const handleScan = async () => {
    setScanError(""); setScanning(true); setCurrentJob(null);
    try {
      const opts = { ...creds, mode: tab };
      const { id } = await api.cloud.createScan("azure", opts);
      const job = await api.cloud.getScan(id);
      setCurrentJob(job);
      pollJob(id);
    } catch (e: unknown) {
      setScanError(e instanceof Error ? e.message : "Failed to start scan");
      setScanning(false);
    }
  };

  const TABS: { id: ScanMode; label: string; icon: React.ReactNode; desc: string }[] = [
    { id: "discovery", label: "Asset Discovery", icon: <Globe className="h-3.5 w-3.5" />,      desc: "Enumerate IPs, hostnames, and cloud resources via cloudlist" },
    { id: "audit",     label: "Security Audit",  icon: <Shield className="h-3.5 w-3.5" />,     desc: "500+ misconfiguration checks via prowler" },
    { id: "both",      label: "Full Scan",        icon: <ScanSearch className="h-3.5 w-3.5" />, desc: "Run both asset discovery and security audit" },
  ];

  const runLabel =
    tab === "discovery" ? "Run Asset Discovery" :
    tab === "audit"     ? "Run Security Audit" :
                          "Run Full Scan";

  return (
    <AppShell>
      <main className="min-h-screen bg-background bg-dots">
        <div className="mx-auto max-w-4xl px-6 py-8 space-y-6">

          <div className="flex items-center gap-2 text-xs text-muted-foreground/60">
            <Link href="/cloud" className="hover:text-muted-foreground transition-colors">Cloud</Link>
            <ChevronRight className="h-3 w-3" />
            <span className="text-muted-foreground">Azure</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-blue-500/20 bg-blue-500/8">
              <Cloud className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground tracking-tight">Azure</h1>
              <p className="text-[12px] text-muted-foreground/60">Asset discovery and security posture audit for your Azure environment.</p>
            </div>
          </div>

          {/* Credentials */}
          <section className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="flex items-center gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
              <Key className="h-4 w-4 text-blue-400" />
              <span className="text-[13px] font-semibold text-foreground">Service Principal Credentials</span>
              <span className="ml-auto text-[11px] text-muted-foreground/50">Stored in Survex — never leaves your server</span>
            </div>
            <div className="p-5 grid gap-4 sm:grid-cols-2">
              {AZURE_FIELDS.map(f => (
                <div key={f.key} className="space-y-1.5">
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                    {f.label}{f.required && <span className="text-red-500 ml-1">*</span>}
                  </label>
                  <input
                    type={f.type}
                    placeholder={f.placeholder}
                    value={creds[f.key] ?? ""}
                    onChange={e => setCreds(prev => ({ ...prev, [f.key]: e.target.value }))}
                    className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[12px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all"
                  />
                </div>
              ))}
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

          {/* Scan mode tabs */}
          <div className="flex gap-1 rounded-lg border border-border bg-muted/20 p-1">
            {TABS.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)}
                className={`flex-1 rounded-md px-4 py-2 text-[13px] font-semibold transition-all ${
                  tab === t.id
                    ? "bg-card text-foreground shadow-sm border border-border"
                    : "text-muted-foreground hover:text-foreground"
                }`}>
                <span className="flex items-center justify-center gap-2">{t.icon}{t.label}</span>
              </button>
            ))}
          </div>
          <p className="text-[11px] text-muted-foreground/50 -mt-4">
            {TABS.find(t => t.id === tab)?.desc}
          </p>

          {/* Run button */}
          <div className="flex items-center gap-4">
            <button onClick={handleScan} disabled={scanning}
              className="flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 px-6 py-2.5 text-sm font-semibold text-primary-foreground transition-all">
              {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {scanning ? "Scanning…" : runLabel}
            </button>
            {scanError && <div className="flex items-center gap-2 text-sm text-red-400"><AlertCircle className="h-4 w-4 shrink-0" />{scanError}</div>}
          </div>

          {currentJob && <JobResults job={currentJob} mode={tab} />}

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
