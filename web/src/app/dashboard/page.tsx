"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, ScanJob } from "@/lib/api";
import { Nav } from "@/components/nav";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Plus, RefreshCw, ExternalLink, Activity, CheckCircle2, Clock, AlertTriangle, XCircle } from "lucide-react";

const statusColor: Record<string, string> = {
  queued:    "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30",
  running:   "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  done:      "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
  failed:    "bg-red-500/20 text-red-400 border border-red-500/30",
  cancelled: "bg-zinc-500/20 text-zinc-500 border border-zinc-500/20",
};

const statusIcon: Record<string, React.ReactNode> = {
  queued:    <Clock className="h-3 w-3" />,
  running:   <Activity className="h-3 w-3 animate-pulse" />,
  done:      <CheckCircle2 className="h-3 w-3" />,
  failed:    <XCircle className="h-3 w-3" />,
  cancelled: <XCircle className="h-3 w-3" />,
};

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function StatCard({ label, value, sub, color = "text-foreground" }: {
  label: string; value: string | number; sub?: string; color?: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-card p-5 space-y-1">
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{label}</p>
      <p className={`text-3xl font-bold ${color}`}>{value}</p>
      {sub && <p className="text-xs text-muted-foreground">{sub}</p>}
    </div>
  );
}

export default function Dashboard() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [fetching, setFetching] = useState(true);

  const fetchScans = useCallback(async () => {
    try {
      const data = await api.scans.list();
      setScans(data ?? []);
    } catch { /* ignore */ }
    finally { setFetching(false); }
  }, []);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  useEffect(() => { if (user) fetchScans(); }, [user, fetchScans]);

  useEffect(() => {
    const hasActive = scans.some(s => s.status === "queued" || s.status === "running");
    if (!hasActive) return;
    const t = setInterval(fetchScans, 4000);
    return () => clearInterval(t);
  }, [scans, fetchScans]);

  if (loading || !user) return null;

  const total   = scans.length;
  const active  = scans.filter(s => s.status === "running" || s.status === "queued").length;
  const done    = scans.filter(s => s.status === "done").length;
  const criticalOrHigh = scans.filter(s => s.max_severity === "critical" || s.max_severity === "high").length;

  return (
    <div className="min-h-screen bg-background">
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Dashboard</h1>
            <p className="text-sm text-muted-foreground mt-0.5">Overview of your scan history</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={fetchScans} disabled={fetching}>
              <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${fetching ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white" asChild>
              <Link href="/scans/new">
                <Plus className="h-3.5 w-3.5 mr-1.5" />
                New Scan
              </Link>
            </Button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total Scans" value={total} />
          <StatCard label="Active" value={active} color={active > 0 ? "text-blue-400" : "text-foreground"} sub={active > 0 ? "running or queued" : undefined} />
          <StatCard label="Completed" value={done} color="text-emerald-400" />
          <StatCard label="High Risk" value={criticalOrHigh} color={criticalOrHigh > 0 ? "text-red-400" : "text-foreground"} sub={criticalOrHigh > 0 ? "critical or high findings" : undefined} />
        </div>

        {/* Scan table */}
        {fetching && scans.length === 0 ? (
          <div className="rounded-xl border border-border bg-card flex items-center justify-center h-40 text-muted-foreground text-sm">
            Loading…
          </div>
        ) : scans.length === 0 ? (
          <div className="rounded-xl border border-border bg-card flex flex-col items-center justify-center gap-4 py-20">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-muted">
              <Activity className="h-6 w-6 text-muted-foreground" />
            </div>
            <div className="text-center">
              <p className="font-semibold">No scans yet</p>
              <p className="text-sm text-muted-foreground mt-1">Run your first scan to start discovering your attack surface.</p>
            </div>
            <Button className="bg-emerald-600 hover:bg-emerald-500 text-white" asChild>
              <Link href="/scans/new"><Plus className="h-4 w-4 mr-1.5" />Start a Scan</Link>
            </Button>
          </div>
        ) : (
          <div className="rounded-xl border border-border bg-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/40">
                    {["Client", "Targets", "Modules", "Status", "Findings", "Severity", "Started", ""].map(h => (
                      <th key={h} className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scans.map((scan, i) => (
                    <tr
                      key={scan.id}
                      className={`border-b border-border/50 cursor-pointer hover:bg-accent/30 transition-colors ${i === scans.length - 1 ? "border-b-0" : ""}`}
                      onClick={() => router.push(`/scans/${scan.id}`)}
                    >
                      <td className="px-4 py-3 font-medium">{scan.client}</td>
                      <td className="px-4 py-3 text-muted-foreground max-w-[140px] truncate font-mono text-xs">{scan.targets}</td>
                      <td className="px-4 py-3 text-muted-foreground max-w-[180px] truncate text-xs">{scan.modules}</td>
                      <td className="px-4 py-3">
                        <Badge className={`${statusColor[scan.status]} flex items-center gap-1 w-fit text-xs`}>
                          {statusIcon[scan.status]}
                          {scan.status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 font-medium tabular-nums">{scan.finding_count ?? 0}</td>
                      <td className="px-4 py-3"><SeverityBadge severity={scan.max_severity ?? ""} /></td>
                      <td className="px-4 py-3 text-muted-foreground text-xs whitespace-nowrap">{timeAgo(scan.created_at)}</td>
                      <td className="px-4 py-3">
                        {scan.status === "done" && scan.report_path && (
                          <Button variant="ghost" size="icon" className="h-7 w-7" asChild onClick={e => e.stopPropagation()}>
                            <a href={api.scans.reportUrl(scan.id)} target="_blank" rel="noreferrer" title="Open Report">
                              <ExternalLink className="h-3.5 w-3.5" />
                            </a>
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
