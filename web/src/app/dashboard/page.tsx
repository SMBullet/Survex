"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, ScanJob } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import { SeverityBadge } from "@/components/severity-badge";
import {
  Plus, RefreshCw, ExternalLink, Activity, CheckCircle2,
  Clock, AlertTriangle, XCircle, Loader2, ChevronRight,
  Target, Shield,
} from "lucide-react";

// ── Helpers ───────────────────────────────────────────────────────────────────

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const STATUS_CFG: Record<string, {
  dot: string; badge: string; label: string; rowAccent: string;
}> = {
  queued:    { dot: "bg-muted-foreground/40",    badge: "bg-muted text-muted-foreground border-border",                          label: "Queued",    rowAccent: "" },
  running:   { dot: "bg-blue-500 animate-pulse", badge: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20",    label: "Running",   rowAccent: "border-l-2 border-l-blue-500/50" },
  done:      { dot: "bg-primary",                badge: "bg-primary/10 text-primary border-primary/20",                         label: "Done",      rowAccent: "" },
  failed:    { dot: "bg-red-500",                badge: "bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20",        label: "Failed",    rowAccent: "border-l-2 border-l-red-500/50" },
  cancelled: { dot: "bg-muted-foreground/30",    badge: "bg-muted/80 text-muted-foreground/60 border-border",                   label: "Cancelled", rowAccent: "" },
};

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({
  icon, label, value, sub, variant,
}: {
  icon: React.ReactNode; label: string; value: number | string;
  sub?: string; variant?: "primary" | "danger" | "active" | "neutral";
}) {
  const styles = {
    primary: { wrap: "border-primary/20",  icon: "bg-primary/10 border-primary/20 text-primary",                        val: "text-primary" },
    danger:  { wrap: "border-red-500/20",  icon: "bg-red-500/10 border-red-500/20 text-red-500 dark:text-red-400",     val: "text-red-600 dark:text-red-400" },
    active:  { wrap: "border-blue-500/20", icon: "bg-blue-500/10 border-blue-500/20 text-blue-500 dark:text-blue-400", val: "text-blue-600 dark:text-blue-400" },
    neutral: { wrap: "border-border",      icon: "bg-muted border-border text-muted-foreground",                        val: "text-foreground" },
  };
  const s = styles[variant ?? "neutral"];

  return (
    <div className={`rounded-xl border bg-card card-shadow p-5 transition-colors ${s.wrap}`}>
      <div className={`inline-flex h-9 w-9 items-center justify-center rounded-lg border ${s.icon} mb-4`}>
        {icon}
      </div>
      <p className={`text-3xl font-bold tabular-nums tracking-tight ${s.val}`}>{value}</p>
      <p className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground/70 mt-1">{label}</p>
      {sub && <p className="text-[11px] text-muted-foreground/50 mt-0.5">{sub}</p>}
    </div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="rounded-xl border border-border bg-card card-shadow flex flex-col items-center justify-center gap-6 py-24">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10 border border-primary/20">
        <Target className="h-6 w-6 text-primary/50" />
      </div>
      <div className="text-center space-y-1.5">
        <p className="font-semibold text-foreground">No operations yet</p>
        <p className="text-sm text-muted-foreground">Run your first scan to start mapping your attack surface.</p>
      </div>
      <Link
        href="/scans/new"
        className="inline-flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 px-5 py-2.5 text-sm font-semibold text-primary-foreground transition-colors"
      >
        <Plus className="h-4 w-4" />
        Start a Scan
      </Link>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [scans,    setScans]    = useState<ScanJob[]>([]);
  const [fetching, setFetching] = useState(true);

  const fetchScans = useCallback(async () => {
    try { setScans((await api.scans.list()) ?? []); }
    catch { /* ignore */ }
    finally { setFetching(false); }
  }, []);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  useEffect(() => { if (user) fetchScans(); }, [user, fetchScans]);
  useEffect(() => {
    if (!scans.some(s => s.status === "queued" || s.status === "running")) return;
    const t = setInterval(fetchScans, 4000);
    return () => clearInterval(t);
  }, [scans, fetchScans]);

  if (loading || !user) return null;

  const total          = scans.length;
  const active         = scans.filter(s => s.status === "running" || s.status === "queued").length;
  const done           = scans.filter(s => s.status === "done").length;
  const criticalOrHigh = scans.filter(s => s.max_severity === "critical" || s.max_severity === "high").length;

  return (
    <AppShell>
      <main className="min-h-screen bg-background">
        <div className="mx-auto max-w-7xl px-6 py-8 space-y-7">

          {/* Header */}
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1">
              <h1 className="text-2xl font-bold text-foreground tracking-tight">Operations Center</h1>
              <p className="text-sm text-muted-foreground">
                {total} operation{total !== 1 ? "s" : ""} · {done} completed
                {active > 0 && (
                  <span className="ml-2 inline-flex items-center gap-1 rounded-full border border-blue-500/20 bg-blue-500/8 px-2 py-0.5 text-[10px] font-semibold text-blue-600 dark:text-blue-400">
                    <span className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />
                    {active} active
                  </span>
                )}
              </p>
            </div>
            <div className="flex gap-2 shrink-0">
              <button
                onClick={fetchScans}
                disabled={fetching}
                className="flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-all text-sm"
                title="Refresh"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${fetching ? "animate-spin" : ""}`} />
              </button>
              <Link
                href="/scans/new"
                className="flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 px-4 py-2 text-sm font-semibold text-primary-foreground transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
                New Scan
              </Link>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <StatCard
              icon={<Shield className="h-4 w-4" />}
              label="Total Scans" value={total}
              variant="neutral"
            />
            <StatCard
              icon={<Activity className="h-4 w-4" />}
              label="Active" value={active}
              sub={active > 0 ? "running or queued" : "all idle"}
              variant={active > 0 ? "active" : "neutral"}
            />
            <StatCard
              icon={<CheckCircle2 className="h-4 w-4" />}
              label="Completed" value={done}
              variant={done > 0 ? "primary" : "neutral"}
            />
            <StatCard
              icon={<AlertTriangle className="h-4 w-4" />}
              label="High Risk" value={criticalOrHigh}
              sub={criticalOrHigh > 0 ? "critical or high" : "none found"}
              variant={criticalOrHigh > 0 ? "danger" : "neutral"}
            />
          </div>

          {/* Scan table */}
          {fetching && scans.length === 0 ? (
            <div className="rounded-xl border border-border bg-card card-shadow flex items-center justify-center h-48">
              <div className="flex items-center gap-3 text-muted-foreground text-sm">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading operations…
              </div>
            </div>
          ) : scans.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="rounded-xl border border-border bg-card card-shadow overflow-hidden">

              {/* Column headers */}
              <div className="hidden sm:grid sm:grid-cols-[1.2fr_1fr_1fr_110px_70px_90px_80px_40px] px-5 py-3 border-b border-border bg-muted/30">
                {["Client", "Target", "Modules", "Status", "Hits", "Severity", "When", ""].map(h => (
                  <p key={h} className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">{h}</p>
                ))}
              </div>

              <div className="divide-y divide-border">
                {scans.map(scan => {
                  const cfg = STATUS_CFG[scan.status] ?? STATUS_CFG.done;
                  return (
                    <div
                      key={scan.id}
                      onClick={() => router.push(`/scans/detail?id=${scan.id}`)}
                      className={`hidden sm:grid sm:grid-cols-[1.2fr_1fr_1fr_110px_70px_90px_80px_40px] px-5 py-4 cursor-pointer transition-colors hover:bg-muted/30 group ${cfg.rowAccent}`}
                    >
                      <div className="flex items-center gap-2.5 min-w-0 pr-2">
                        <span className={`shrink-0 h-2 w-2 rounded-full ${cfg.dot}`} />
                        <span className="text-sm font-medium text-foreground truncate">{scan.client}</span>
                      </div>
                      <div className="flex items-center min-w-0 pr-2">
                        <span className="text-[12px] font-mono text-muted-foreground truncate">{scan.targets}</span>
                      </div>
                      <div className="flex items-center min-w-0 pr-2">
                        <span className="text-[11px] text-muted-foreground/70 truncate">{scan.modules || "(profile)"}</span>
                      </div>
                      <div className="flex items-center">
                        <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium ${cfg.badge}`}>
                          {scan.status === "running" && <Loader2 className="h-2.5 w-2.5 animate-spin" />}
                          {cfg.label}
                        </span>
                      </div>
                      <div className="flex items-center">
                        <span className={`text-sm font-bold tabular-nums ${(scan.finding_count ?? 0) > 0 ? "text-foreground" : "text-muted-foreground/40"}`}>
                          {scan.finding_count ?? 0}
                        </span>
                      </div>
                      <div className="flex items-center">
                        <SeverityBadge severity={scan.max_severity ?? ""} />
                      </div>
                      <div className="flex items-center">
                        <span className="text-[11px] text-muted-foreground/60 whitespace-nowrap">{timeAgo(scan.created_at)}</span>
                      </div>
                      <div className="flex items-center justify-end">
                        {scan.status === "done" && scan.report_path ? (
                          <a
                            href={api.scans.reportUrl(scan.id)}
                            target="_blank" rel="noreferrer"
                            onClick={e => e.stopPropagation()}
                            className="flex h-7 w-7 items-center justify-center rounded-md border border-border text-muted-foreground/60 hover:text-foreground hover:bg-muted/60 transition-all"
                          >
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : (
                          <ChevronRight className="h-4 w-4 text-muted-foreground/30 group-hover:text-muted-foreground/60 transition-colors" />
                        )}
                      </div>
                    </div>
                  );
                })}

                {/* Mobile cards */}
                {scans.map(scan => {
                  const cfg = STATUS_CFG[scan.status] ?? STATUS_CFG.done;
                  return (
                    <div
                      key={`m-${scan.id}`}
                      onClick={() => router.push(`/scans/detail?id=${scan.id}`)}
                      className={`sm:hidden flex items-center justify-between px-4 py-3.5 cursor-pointer hover:bg-muted/30 transition-colors ${cfg.rowAccent}`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span className={`shrink-0 h-2 w-2 rounded-full ${cfg.dot}`} />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-foreground truncate">{scan.client}</p>
                          <p className="text-[11px] text-muted-foreground font-mono truncate">{scan.targets}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <SeverityBadge severity={scan.max_severity ?? ""} />
                        <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/40" />
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="px-5 py-2.5 border-t border-border bg-muted/20">
                <p className="text-[11px] text-muted-foreground/50">{total} operation{total !== 1 ? "s" : ""} total</p>
              </div>
            </div>
          )}

        </div>
      </main>
    </AppShell>
  );
}
