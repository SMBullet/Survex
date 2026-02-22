"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, ScanJob } from "@/lib/api";
import { Nav } from "@/components/nav";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ExternalLink, Square, RefreshCw, Clock, Target,
  Layers, CheckCircle2, Circle, Loader2, XCircle,
  AlertTriangle, Activity, Shield, Globe, Server,
} from "lucide-react";

// ── Step detection ────────────────────────────────────────────────────────────

interface Step {
  id: string;
  label: string;
  pattern: RegExp;
  status: "pending" | "active" | "done";
}

const STEP_DEFS: Omit<Step, "status">[] = [
  { id: "start",  label: "Initialising",    pattern: /scan started/ },
  { id: "subs",   label: "Subdomain Enum",  pattern: /subfinder|amass|crts|dnsbrute|certificate trans/i },
  { id: "dns",    label: "DNS Resolution",  pattern: /\bdns\b.*resolv|resolv.*\bdns\b|\[survex\].*dns/i },
  { id: "ports",  label: "Port Scanning",   pattern: /nmap|port.scan/i },
  { id: "http",   label: "HTTP Probing",    pattern: /probing http|httpx/i },
  { id: "tls",    label: "TLS Analysis",    pattern: /\btls\b|analyzing tls/i },
  { id: "web",    label: "Web Security",    pattern: /waf|cors|cookie|security header/i },
  { id: "vuln",   label: "Vuln Scanning",   pattern: /nuclei|graphql|api.endpoint|swagger|ffuf|dalfox|sqlmap|open redirect/i },
  { id: "done",   label: "Complete",        pattern: /scan complete|scan.*done|\[queue\].*complete/ },
];

function buildSteps(logs: string[]): Step[] {
  const reached = new Set<string>();
  for (const line of logs) {
    const l = line.toLowerCase();
    for (const def of STEP_DEFS) {
      if (def.pattern.test(l)) reached.add(def.id);
    }
  }
  const ids = STEP_DEFS.map(d => d.id);
  let lastIdx = -1;
  for (let i = ids.length - 1; i >= 0; i--) {
    if (reached.has(ids[i])) { lastIdx = i; break; }
  }
  return STEP_DEFS.map((def, i) => ({
    ...def,
    status: reached.has(def.id)
      ? (i === lastIdx ? "active" : "done")
      : "pending",
  }));
}

// ── Log coloriser ─────────────────────────────────────────────────────────────

function logClass(line: string): string {
  const l = line.toLowerCase();
  if (/error|failed|fail|panic/.test(l))           return "text-red-400";
  if (/warn|warning/.test(l))                       return "text-yellow-400";
  if (/\[queue\] scan complete/.test(l))            return "text-emerald-300 font-semibold";
  if (/\[queue\]/.test(l))                          return "text-blue-400";
  if (/found \d|discover|\benabled\b|detect/.test(l)) return "text-emerald-400";
  if (/skipped|skip|no /.test(l))                  return "text-zinc-500";
  if (/\[survex\]/.test(l))                         return "text-zinc-300";
  return "text-zinc-400";
}

// ── Status helpers ────────────────────────────────────────────────────────────

const statusStyle: Record<string, string> = {
  queued:    "bg-zinc-500/20 text-zinc-400 border border-zinc-500/30",
  running:   "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  done:      "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
  failed:    "bg-red-500/20 text-red-400 border border-red-500/30",
  cancelled: "bg-zinc-500/20 text-zinc-500 border border-zinc-500/20",
};

function formatDuration(start: string, end?: string) {
  const sec = Math.floor((((end ? new Date(end) : new Date()).getTime()) - new Date(start).getTime()) / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { user, loading } = useAuth();
  const router = useRouter();

  const [scan, setScan]             = useState<ScanJob | null>(null);
  const [logs, setLogs]             = useState<string[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const wsRef  = useRef<WebSocket | null>(null);

  const fetchScan = useCallback(async () => {
    try { const d = await api.scans.get(id); setScan(d); return d; }
    catch { return null; }
  }, [id]);

  const connectWs = useCallback(() => {
    if (wsRef.current) return;
    const ws = new WebSocket(api.scans.logsWsUrl(id));
    wsRef.current = ws;
    ws.onopen    = () => setWsConnected(true);
    ws.onmessage = (e) => setLogs(prev => [...prev, e.data as string]);
    ws.onclose   = () => { setWsConnected(false); wsRef.current = null; };
    ws.onerror   = () => ws.close();
  }, [id]);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);

  useEffect(() => {
    if (!user) return;
    fetchScan().then(() => connectWs());
  }, [user, fetchScan, connectWs]);

  useEffect(() => {
    if (!scan) return;
    if (scan.status !== "queued" && scan.status !== "running") return;
    const t = setInterval(fetchScan, 4000);
    return () => clearInterval(t);
  }, [scan, fetchScan]);

  useEffect(() => {
    const terminal = ["done", "failed", "cancelled"];
    if (scan && terminal.includes(scan.status)) {
      wsRef.current?.close();
      fetchScan();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.status]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const handleCancel = async () => {
    setCancelling(true);
    try { await api.scans.cancel(id); await fetchScan(); }
    catch { /* ignore */ }
    finally { setCancelling(false); }
  };

  if (loading || !user) return null;

  const steps  = buildSteps(logs);
  const isActive = scan?.status === "queued" || scan?.status === "running";

  return (
    <div className="min-h-screen bg-background">
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 space-y-6">

        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="space-y-1">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold">{scan?.client ?? id}</h1>
              {scan && (
                <Badge className={`${statusStyle[scan.status]} flex items-center gap-1.5 text-xs font-medium px-2.5 py-1`}>
                  {scan.status === "running"   && <Loader2 className="h-3 w-3 animate-spin" />}
                  {scan.status === "done"      && <CheckCircle2 className="h-3 w-3" />}
                  {scan.status === "failed"    && <XCircle className="h-3 w-3" />}
                  {scan.status === "cancelled" && <XCircle className="h-3 w-3" />}
                  {scan.status}
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground font-mono">{id}</p>
          </div>
          <div className="flex gap-2">
            {scan?.status === "done" && scan.report_path && (
              <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white" asChild>
                <a href={api.scans.reportUrl(id)} target="_blank" rel="noreferrer">
                  <ExternalLink className="h-3.5 w-3.5 mr-1.5" />Open Report
                </a>
              </Button>
            )}
            {isActive && (
              <Button variant="destructive" size="sm" onClick={handleCancel} disabled={cancelling}>
                {cancelling
                  ? <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                  : <Square className="h-3.5 w-3.5 mr-1.5" />}
                {cancelling ? "Cancelling…" : "Cancel Scan"}
              </Button>
            )}
            <Button variant="outline" size="icon" className="h-8 w-8" onClick={() => fetchScan()}>
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>

        {/* Stats */}
        {scan && (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { icon: <Target className="h-3.5 w-3.5" />,       label: "Target",   value: <span className="font-mono text-xs truncate block">{scan.targets}</span> },
              { icon: <Layers className="h-3.5 w-3.5" />,       label: "Modules",  value: <span className="font-mono text-xs truncate block">{scan.modules || "(profile)"}</span> },
              { icon: <AlertTriangle className="h-3.5 w-3.5" />, label: "Findings", value: <span className="flex items-center gap-2 text-2xl font-bold">{scan.finding_count} <SeverityBadge severity={scan.max_severity ?? ""} /></span> },
              { icon: <Clock className="h-3.5 w-3.5" />,         label: "Duration", value: <span className="text-2xl font-bold">{scan.started_at ? formatDuration(scan.started_at, scan.finished_at) : "—"}</span> },
            ].map(({ icon, label, value }) => (
              <div key={label} className="rounded-xl border border-border bg-card p-4 overflow-hidden">
                <div className="flex items-center gap-1.5 text-xs text-muted-foreground uppercase tracking-wider font-medium mb-2">
                  {icon}{label}
                </div>
                {value}
              </div>
            ))}
          </div>
        )}

        {/* Body */}
        <div className="grid gap-4 lg:grid-cols-[240px_1fr]">

          {/* Step tracker */}
          <div className="rounded-xl border border-border bg-card p-4 h-fit">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-4">Pipeline</p>
            <div className="space-y-0">
              {steps.map((step, i) => (
                <div key={step.id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full transition-all ${
                      step.status === "done"   ? "bg-emerald-500/20 text-emerald-400" :
                      step.status === "active" ? "bg-blue-500/20 text-blue-400 ring-2 ring-blue-500/30" :
                                                 "bg-muted text-muted-foreground/30"
                    }`}>
                      {step.status === "active"
                        ? <Loader2 className="h-3 w-3 animate-spin" />
                        : step.status === "done"
                        ? <CheckCircle2 className="h-3 w-3" />
                        : <Circle className="h-3 w-3" />}
                    </div>
                    {i < steps.length - 1 && (
                      <div className={`w-px flex-1 my-1 min-h-[16px] ${step.status === "done" ? "bg-emerald-500/30" : "bg-border"}`} />
                    )}
                  </div>
                  <div className="pb-3 pt-0.5">
                    <p className={`text-sm leading-tight ${
                      step.status === "done"   ? "text-foreground font-medium" :
                      step.status === "active" ? "text-blue-400 font-semibold" :
                                                 "text-muted-foreground/40"
                    }`}>
                      {step.label}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Terminal */}
          <div className="rounded-xl border border-border bg-card overflow-hidden flex flex-col">
            {/* Terminal title bar */}
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-border bg-zinc-900/50">
              <div className="flex items-center gap-3">
                <div className="flex gap-1.5">
                  <div className="h-3 w-3 rounded-full bg-red-500/60" />
                  <div className="h-3 w-3 rounded-full bg-yellow-500/60" />
                  <div className="h-3 w-3 rounded-full bg-emerald-500/60" />
                </div>
                <span className="text-xs text-zinc-500 font-mono">survex — scan output</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-zinc-500">{logs.length} lines</span>
                {wsConnected && (
                  <span className="flex items-center gap-1 text-xs text-blue-400">
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                    Live
                  </span>
                )}
              </div>
            </div>

            {/* Log output */}
            <div
              ref={logRef}
              className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-[1.6] bg-zinc-950"
              style={{ minHeight: "480px", maxHeight: "620px" }}
            >
              {logs.length === 0 ? (
                <span className="text-zinc-600">
                  {scan?.status === "queued"
                    ? "⏳  Scan is queued — waiting for the worker to pick it up…"
                    : "No output captured yet."}
                </span>
              ) : (
                logs.map((line, i) => (
                  <div key={i} className={`whitespace-pre-wrap break-all ${logClass(line)}`}>
                    {line}
                  </div>
                ))
              )}
              {wsConnected && <span className="text-emerald-400 animate-pulse">█</span>}
            </div>
          </div>
        </div>

        {/* Error */}
        {scan?.error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 space-y-1">
            <p className="text-sm font-semibold text-red-400 flex items-center gap-2">
              <XCircle className="h-4 w-4" />Scan Error
            </p>
            <pre className="text-xs text-red-400/70 whitespace-pre-wrap mt-1">{scan.error}</pre>
          </div>
        )}
      </main>
    </div>
  );
}
