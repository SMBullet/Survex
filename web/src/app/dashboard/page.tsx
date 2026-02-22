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

const STATUS_CFG: Record<string, { dot: string; badge: string; rowExtra: string; label: string }> = {
  queued:    { dot: "bg-zinc-500",                badge: "bg-zinc-500/15 text-zinc-400 border-zinc-500/25",        rowExtra: "",                              label: "QUEUED"    },
  running:   { dot: "bg-blue-400 animate-pulse",  badge: "bg-blue-500/15 text-blue-400 border-blue-500/25",        rowExtra: "border-l-[2px] border-l-blue-500/60",  label: "RUNNING"   },
  done:      { dot: "bg-emerald-400",             badge: "bg-emerald-500/15 text-emerald-400 border-emerald-500/25", rowExtra: "",                              label: "DONE"      },
  failed:    { dot: "bg-red-400",                 badge: "bg-red-500/15 text-red-400 border-red-500/25",           rowExtra: "border-l-[2px] border-l-red-500/60",   label: "FAILED"    },
  cancelled: { dot: "bg-zinc-600",               badge: "bg-zinc-700/20 text-zinc-500 border-zinc-700/25",        rowExtra: "",                              label: "CANCELLED" },
};

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({
  icon, label, value, sub, color,
}: {
  icon: React.ReactNode; label: string; value: number | string;
  sub?: string; color?: "emerald" | "blue" | "red" | "amber";
}) {
  const map = {
    emerald: { border: "border-emerald-500/20", icon: "bg-emerald-500/10 border-emerald-500/25 text-emerald-400", val: "text-emerald-400" },
    blue:    { border: "border-blue-500/20",    icon: "bg-blue-500/10 border-blue-500/25 text-blue-400",          val: "text-blue-400"    },
    red:     { border: "border-red-500/20",     icon: "bg-red-500/10 border-red-500/25 text-red-400",             val: "text-red-400"     },
    amber:   { border: "border-amber-500/20",   icon: "bg-amber-500/10 border-amber-500/25 text-amber-400",       val: "text-amber-400"   },
  };
  const theme = color ? map[color] : { border: "border-white/[0.07]", icon: "bg-white/5 border-white/[0.08] text-zinc-500", val: "text-white" };

  return (
    <div className={`rounded-xl border bg-[#0a1628]/70 p-5 transition-all ${theme.border}`}>
      <div className="flex items-center justify-between mb-4">
        <div className={`flex h-9 w-9 items-center justify-center rounded-lg border ${theme.icon}`}>
          {icon}
        </div>
      </div>
      <p className={`text-3xl font-bold tabular-nums ${theme.val}`}>{value}</p>
      <p className="text-[11px] font-bold text-zinc-600 uppercase tracking-widest mt-1">{label}</p>
      {sub && <p className="text-[11px] text-zinc-700 mt-0.5">{sub}</p>}
    </div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="rounded-xl border border-white/[0.07] bg-[#0a1628]/70 flex flex-col items-center justify-center gap-6 py-24">
      <div className="relative">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-emerald-500/20 bg-emerald-500/8">
          <Target className="h-7 w-7 text-emerald-400/50" />
        </div>
      </div>
      <div className="text-center space-y-1.5">
        <p className="font-semibold text-white">No operations yet</p>
        <p className="text-sm text-zinc-500">Run your first scan to start mapping your attack surface.</p>
      </div>
      <Link
        href="/scans/new"
        className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-white transition-colors"
      >
        <Plus className="h-4 w-4" />
        Start a Scan
      </Link>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [scans, setScans]       = useState<ScanJob[]>([]);
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
      <main className="min-h-screen bg-[#030812] bg-dots">
        <div className="mx-auto max-w-7xl px-6 py-8 space-y-8">

          {/* Header */}
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-2xl font-bold text-white tracking-tight">Operations Center</h1>
                {active > 0 && (
                  <div className="flex items-center gap-1.5 rounded-full border border-blue-500/25 bg-blue-500/10 px-2.5 py-0.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                    <span className="text-[11px] font-bold text-blue-400 tracking-wider">{active} ACTIVE</span>
                  </div>
                )}
              </div>
              <p className="text-sm text-zinc-500">
                {total} operation{total !== 1 ? "s" : ""} total · {done} completed
              </p>
            </div>
            <div className="flex gap-2 shrink-0">
              <button
                onClick={fetchScans}
                disabled={fetching}
                className="flex items-center gap-2 rounded-lg border border-white/[0.07] bg-white/[0.03] px-3 py-2 text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.06] transition-all"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${fetching ? "animate-spin" : ""}`} />
              </button>
              <Link
                href="/scans/new"
                className="flex items-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-4 py-2 text-sm font-semibold text-white transition-colors"
              >
                <Plus className="h-3.5 w-3.5" />
                New Scan
              </Link>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <StatCard icon={<Shield className="h-4 w-4" />}        label="Total Scans" value={total} />
            <StatCard icon={<Activity className="h-4 w-4" />}      label="Active"      value={active}         sub={active > 0 ? "running or queued" : "all idle"}        color={active > 0 ? "blue" : undefined} />
            <StatCard icon={<CheckCircle2 className="h-4 w-4" />}  label="Completed"   value={done}                                                                      color={done > 0 ? "emerald" : undefined} />
            <StatCard icon={<AlertTriangle className="h-4 w-4" />} label="High Risk"   value={criticalOrHigh} sub={criticalOrHigh > 0 ? "critical or high findings" : "no threats"} color={criticalOrHigh > 0 ? "red" : undefined} />
          </div>

          {/* Scan table */}
          {fetching && scans.length === 0 ? (
            <div className="rounded-xl border border-white/[0.07] bg-[#0a1628]/70 flex items-center justify-center h-48">
              <div className="flex items-center gap-3 text-zinc-500 text-sm">
                <Loader2 className="h-4 w-4 animate-spin" />Loading operations…
              </div>
            </div>
          ) : scans.length === 0 ? (
            <EmptyState />
          ) : (
            <div className="rounded-xl border border-white/[0.07] bg-[#0a1628]/70 overflow-hidden">

              {/* Column headers */}
              <div className="hidden sm:grid sm:grid-cols-[1.2fr_1fr_1fr_110px_70px_90px_80px_40px] gap-0 px-5 py-2.5 border-b border-white/[0.05] bg-white/[0.015]">
                {["Client", "Target", "Modules", "Status", "Hits", "Severity", "When", ""].map(h => (
                  <p key={h} className="text-[10px] font-bold uppercase tracking-widest text-zinc-700">{h}</p>
                ))}
              </div>

              <div className="divide-y divide-white/[0.04]">
                {scans.map(scan => {
                  const cfg = STATUS_CFG[scan.status] ?? STATUS_CFG.done;
                  return (
                    <div
                      key={scan.id}
                      onClick={() => router.push(`/scans/detail?id=${scan.id}`)}
                      className={`hidden sm:grid sm:grid-cols-[1.2fr_1fr_1fr_110px_70px_90px_80px_40px] gap-0 px-5 py-4 cursor-pointer transition-colors hover:bg-white/[0.025] group ${cfg.rowExtra}`}
                    >
                      <div className="flex items-center gap-2.5 min-w-0 pr-2">
                        <span className={`shrink-0 h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
                        <span className="text-sm font-medium text-zinc-200 truncate group-hover:text-white transition-colors">{scan.client}</span>
                      </div>
                      <div className="flex items-center min-w-0 pr-2">
                        <span className="text-[11px] font-mono text-zinc-500 truncate">{scan.targets}</span>
                      </div>
                      <div className="flex items-center min-w-0 pr-2">
                        <span className="text-[11px] text-zinc-600 truncate">{scan.modules || "(profile)"}</span>
                      </div>
                      <div className="flex items-center">
                        <span className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-bold tracking-wider ${cfg.badge}`}>
                          {scan.status === "running" && <Loader2 className="h-2.5 w-2.5 animate-spin" />}
                          {cfg.label}
                        </span>
                      </div>
                      <div className="flex items-center">
                        <span className={`text-sm font-bold tabular-nums ${(scan.finding_count ?? 0) > 0 ? "text-white" : "text-zinc-700"}`}>
                          {scan.finding_count ?? 0}
                        </span>
                      </div>
                      <div className="flex items-center"><SeverityBadge severity={scan.max_severity ?? ""} /></div>
                      <div className="flex items-center">
                        <span className="text-[11px] text-zinc-600 whitespace-nowrap">{timeAgo(scan.created_at)}</span>
                      </div>
                      <div className="flex items-center justify-end">
                        {scan.status === "done" && scan.report_path ? (
                          <a
                            href={api.scans.reportUrl(scan.id)}
                            target="_blank" rel="noreferrer"
                            onClick={e => e.stopPropagation()}
                            className="flex h-7 w-7 items-center justify-center rounded border border-white/[0.07] text-zinc-600 hover:text-zinc-200 hover:border-white/20 hover:bg-white/5 transition-all"
                          >
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5 text-zinc-700 group-hover:text-zinc-500 transition-colors" />
                        )}
                      </div>
                    </div>
                  );
                })}

                {/* Mobile card fallback */}
                {scans.map(scan => {
                  const cfg = STATUS_CFG[scan.status] ?? STATUS_CFG.done;
                  return (
                    <div
                      key={`m-${scan.id}`}
                      onClick={() => router.push(`/scans/detail?id=${scan.id}`)}
                      className={`sm:hidden flex items-center justify-between px-4 py-3.5 cursor-pointer hover:bg-white/[0.03] ${cfg.rowExtra}`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span className={`shrink-0 h-2 w-2 rounded-full ${cfg.dot}`} />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-zinc-200 truncate">{scan.client}</p>
                          <p className="text-[11px] text-zinc-600 font-mono truncate">{scan.targets}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <SeverityBadge severity={scan.max_severity ?? ""} />
                        <ChevronRight className="h-3.5 w-3.5 text-zinc-700" />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </main>
    </AppShell>
  );
}
