"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, ScanJob, Technology } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ExternalLink, Square, RefreshCw, Clock, Target,
  Layers, CheckCircle2, Circle, Loader2, XCircle,
  AlertTriangle, Cpu, Zap,
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
  { id: "tech",   label: "Tech Detection",  pattern: /fingerprinting tech|techdetect:|cms-scan:/i },
  { id: "tls",    label: "TLS Analysis",    pattern: /\btls\b|analyzing tls/i },
  { id: "web",    label: "Web Security",    pattern: /waf|cors|cookie|security header/i },
  { id: "vuln",   label: "Vuln Scanning",   pattern: /nuclei|graphql|api.endpoint|swagger|ffuf|dalfox|sqlmap|open redirect|wpscan|droopescan/i },
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
  if (/error|failed|fail|panic/.test(l))                    return "text-red-400";
  if (/warn|warning/.test(l))                               return "text-yellow-400";
  if (/\[queue\] scan complete/.test(l))                    return "text-emerald-300 font-semibold";
  if (/\[queue\]/.test(l))                                  return "text-blue-400";
  if (/cms-scan:|wpscan|droopescan|joomscan/.test(l))       return "text-purple-400";
  if (/techdetect:|fingerprinting tech|→ /.test(l))         return "text-violet-400";
  if (/found \d|discover|\benabled\b|detect/.test(l))       return "text-emerald-400";
  if (/skipped|skip|no /.test(l))                           return "text-zinc-500";
  if (/\[survex\]/.test(l))                                 return "text-zinc-300";
  return "text-zinc-400";
}

// ── Technology display helpers ─────────────────────────────────────────────────

const CATEGORY_STYLE: Record<string, { bg: string; text: string; border: string }> = {
  "CMS":         { bg: "bg-purple-500/15",  text: "text-purple-300",  border: "border-purple-500/30" },
  "E-Commerce":  { bg: "bg-blue-500/15",    text: "text-blue-300",    border: "border-blue-500/30" },
  "Framework":   { bg: "bg-orange-500/15",  text: "text-orange-300",  border: "border-orange-500/30" },
  "JavaScript":  { bg: "bg-yellow-500/15",  text: "text-yellow-300",  border: "border-yellow-500/30" },
  "Language":    { bg: "bg-cyan-500/15",    text: "text-cyan-300",    border: "border-cyan-500/30" },
  "Web Server":  { bg: "bg-zinc-500/15",    text: "text-zinc-300",    border: "border-zinc-500/30" },
  "CDN":         { bg: "bg-teal-500/15",    text: "text-teal-300",    border: "border-teal-500/30" },
  "WAF":         { bg: "bg-red-500/15",     text: "text-red-300",     border: "border-red-500/30" },
  "Analytics":   { bg: "bg-green-500/15",   text: "text-green-300",   border: "border-green-500/30" },
};

const DEFAULT_STYLE = { bg: "bg-muted", text: "text-muted-foreground", border: "border-border" };

// CMS names that trigger dedicated scanners
const CMS_SCANNER: Record<string, string> = {
  wordpress: "wpscan",
  drupal:    "droopescan",
  joomla:    "joomscan / droopescan",
};

function groupByCategory(techs: Technology[]) {
  const map: Record<string, Technology[]> = {};
  for (const t of techs) {
    const cat = t.category || "Other";
    (map[cat] ??= []).push(t);
  }
  return map;
}

// Parse CMS scan activity from logs
function parseCMSScanActivity(logs: string[]): { cms: string; tool: string; findings: number }[] {
  const activity: { cms: string; tool: string; findings: number }[] = [];
  const findingsMap: Record<string, number> = {};

  for (const line of logs) {
    const l = line.toLowerCase();
    // "[survex]   cms-scan: WordPress detected on N URL(s) — running wpscan"
    const m = l.match(/cms-scan:.*?(\w+) detected.*running (\w+)/);
    if (m) {
      activity.push({ cms: m[1], tool: m[2], findings: 0 });
    }
    // "[survex]   wpscan: N findings"
    const fmatch = l.match(/(\w+scan):\s+(\d+) findings/);
    if (fmatch) {
      findingsMap[fmatch[1]] = parseInt(fmatch[2], 10);
    }
  }

  return activity.map(a => ({ ...a, findings: findingsMap[a.tool] ?? 0 }));
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
  const sec = Math.floor(
    (((end ? new Date(end) : new Date()).getTime()) - new Date(start).getTime()) / 1000
  );
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ScanDetailClient() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const { user, loading } = useAuth();
  const router = useRouter();

  const [scan, setScan]                     = useState<ScanJob | null>(null);
  const [logs, setLogs]                     = useState<string[]>([]);
  const [wsConnected, setWsConnected]       = useState(false);
  const [cancelling, setCancelling]         = useState(false);
  const [technologies, setTechnologies]     = useState<Technology[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const wsRef  = useRef<WebSocket | null>(null);

  const fetchScan = useCallback(async () => {
    if (!id) return null;
    try { const d = await api.scans.get(id); setScan(d); return d; }
    catch { return null; }
  }, [id]);

  const fetchTechnologies = useCallback(async () => {
    if (!id) return;
    try { const data = await api.scans.technologies(id); setTechnologies(data ?? []); }
    catch { /* no-op if endpoint not ready */ }
  }, [id]);

  const connectWs = useCallback(() => {
    if (!id || wsRef.current) return;
    const ws = new WebSocket(api.scans.logsWsUrl(id));
    wsRef.current = ws;
    ws.onopen    = () => setWsConnected(true);
    ws.onmessage = (e) => setLogs(prev => [...prev, e.data as string]);
    ws.onclose   = () => { setWsConnected(false); wsRef.current = null; };
    ws.onerror   = () => ws.close();
  }, [id]);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);

  useEffect(() => {
    if (!user || !id) return;
    fetchScan().then(() => connectWs());
  }, [user, id, fetchScan, connectWs]);

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
      fetchTechnologies();
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

  const steps   = buildSteps(logs);
  const isActive = scan?.status === "queued" || scan?.status === "running";
  const grouped  = groupByCategory(technologies);
  const cmsActivity = parseCMSScanActivity(logs);

  // Unique CMS names found in technologies
  const detectedCMSNames = technologies
    .filter(t => t.category === "CMS" || t.category === "E-Commerce")
    .map(t => t.name.toLowerCase());

  return (
    <AppShell>
      <main className="mx-auto max-w-7xl px-6 py-8 space-y-6">

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
              {technologies.length > 0 && (
                <Badge className="bg-violet-500/20 text-violet-300 border border-violet-500/30 text-xs">
                  <Cpu className="h-3 w-3 mr-1" />
                  {technologies.length} tech{technologies.length !== 1 ? "s" : ""} detected
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
              { icon: <Target className="h-3.5 w-3.5" />,        label: "Target",   value: <span className="font-mono text-xs truncate block">{scan.targets}</span> },
              { icon: <Layers className="h-3.5 w-3.5" />,        label: "Modules",  value: <span className="font-mono text-xs truncate block">{scan.modules || "(profile)"}</span> },
              { icon: <AlertTriangle className="h-3.5 w-3.5" />,  label: "Findings", value: <span className="flex items-center gap-2 text-2xl font-bold">{scan.finding_count} <SeverityBadge severity={scan.max_severity ?? ""} /></span> },
              { icon: <Clock className="h-3.5 w-3.5" />,          label: "Duration", value: <span className="text-2xl font-bold">{scan.started_at ? formatDuration(scan.started_at, scan.finished_at) : "—"}</span> },
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

        {/* Body: pipeline + terminal */}
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
                    {/* Show CMS tool routing under Tech Detection step */}
                    {step.id === "tech" && step.status === "done" && detectedCMSNames.length > 0 && (
                      <div className="mt-1 space-y-0.5">
                        {detectedCMSNames.map(cms => (
                          <p key={cms} className="text-[10px] text-violet-400 font-mono">
                            → {CMS_SCANNER[cms] ?? cms + " scanner"}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Terminal */}
          <div className="rounded-xl border border-border bg-card overflow-hidden flex flex-col">
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

        {/* ── Technologies Detected ─────────────────────────────────────────── */}
        {technologies.length > 0 && (
          <div className="rounded-xl border border-violet-500/20 bg-card overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-3 border-b border-border bg-violet-500/5">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-violet-400" />
                <span className="text-sm font-semibold">Technologies Detected</span>
                <Badge className="bg-violet-500/20 text-violet-300 border-violet-500/30 text-xs">
                  {technologies.length}
                </Badge>
              </div>
              {cmsActivity.length > 0 && (
                <div className="flex items-center gap-1.5 text-xs text-violet-400">
                  <Zap className="h-3 w-3" />
                  CMS scanners triggered
                </div>
              )}
            </div>

            <div className="p-5 space-y-5">
              {/* Grouped tech badges */}
              {Object.entries(grouped).map(([category, techs]) => {
                const style = CATEGORY_STYLE[category] ?? DEFAULT_STYLE;
                return (
                  <div key={category}>
                    <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 mb-2">
                      {category}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {techs.map((t, i) => (
                        <div
                          key={i}
                          className={`flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium ${style.bg} ${style.text} ${style.border}`}
                        >
                          {t.name}
                          {t.version && (
                            <span className="opacity-60 font-normal">{t.version}</span>
                          )}
                          <span className="opacity-40 text-[10px] font-mono">{t.host}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}

              {/* CMS scanner results */}
              {cmsActivity.length > 0 && (
                <div className="border-t border-border pt-4">
                  <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60 mb-3">
                    CMS Scan Results
                  </p>
                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    {cmsActivity.map((a, i) => (
                      <div key={i} className="flex items-center gap-3 rounded-lg border border-border bg-muted/30 px-3 py-2">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-purple-500/10 text-purple-400">
                          <Zap className="h-4 w-4" />
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs font-medium capitalize">{a.cms}</p>
                          <p className="text-xs text-muted-foreground">
                            <span className="font-mono">{a.tool}</span>
                            {" → "}
                            <span className={a.findings > 0 ? "text-red-400 font-semibold" : "text-emerald-400"}>
                              {a.findings} finding{a.findings !== 1 ? "s" : ""}
                            </span>
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Hint about CMS scanners if CMS found but no activity logged */}
              {detectedCMSNames.length > 0 && cmsActivity.length === 0 && (
                <div className="border-t border-border pt-3 flex items-start gap-2 text-xs text-muted-foreground">
                  <Zap className="h-3.5 w-3.5 shrink-0 mt-0.5 text-violet-400" />
                  <span>
                    <span className="font-medium text-violet-300">CMS detected:</span>{" "}
                    {detectedCMSNames.map(n =>
                      `${n.charAt(0).toUpperCase() + n.slice(1)} → ${CMS_SCANNER[n] ?? "scanner"}`
                    ).join(", ")}.
                    {" "}Install the tool to get vulnerability findings automatically.
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

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
    </AppShell>
  );
}
