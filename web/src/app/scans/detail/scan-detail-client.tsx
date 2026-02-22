"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, ScanJob, Technology } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import { SeverityBadge } from "@/components/severity-badge";
import {
  ExternalLink, Square, RefreshCw, Clock, Target,
  Layers, CheckCircle2, Circle, Loader2, XCircle,
  AlertTriangle, Cpu, Zap, ChevronRight, Activity,
  Shield, Globe, Terminal,
} from "lucide-react";

// ── Step definitions ──────────────────────────────────────────────────────────

interface Step { id: string; label: string; pattern: RegExp; status: "pending" | "active" | "done"; }

const STEP_DEFS: Omit<Step, "status">[] = [
  { id: "start",  label: "Initializing",   pattern: /scan started/ },
  { id: "subs",   label: "Subdomain Enum", pattern: /subfinder|amass|crts|dnsbrute|certificate trans/i },
  { id: "dns",    label: "DNS Resolution", pattern: /\bdns\b.*resolv|resolv.*\bdns\b|\[survex\].*dns/i },
  { id: "ports",  label: "Port Scanning",  pattern: /nmap|port.scan/i },
  { id: "http",   label: "HTTP Probing",   pattern: /probing http|httpx/i },
  { id: "tech",   label: "Tech Detection", pattern: /fingerprinting tech|techdetect:|cms-scan:/i },
  { id: "tls",    label: "TLS Analysis",   pattern: /\btls\b|analyzing tls/i },
  { id: "web",    label: "Web Security",   pattern: /waf|cors|cookie|security header/i },
  { id: "vuln",   label: "Vuln Scanning",  pattern: /nuclei|graphql|api.endpoint|swagger|ffuf|dalfox|sqlmap|open redirect|wpscan|droopescan/i },
  { id: "done",   label: "Complete",       pattern: /scan complete|scan.*done|\[queue\].*complete/ },
];

function buildSteps(logs: string[]): Step[] {
  const reached = new Set<string>();
  for (const line of logs) {
    for (const def of STEP_DEFS) {
      if (def.pattern.test(line)) reached.add(def.id);
    }
  }
  const ids = STEP_DEFS.map(d => d.id);
  let lastIdx = -1;
  for (let i = ids.length - 1; i >= 0; i--) {
    if (reached.has(ids[i])) { lastIdx = i; break; }
  }
  return STEP_DEFS.map((def, i) => ({
    ...def,
    status: reached.has(def.id) ? (i === lastIdx ? "active" : "done") : "pending",
  }));
}

// ── Log colorizer ─────────────────────────────────────────────────────────────

function logClass(line: string): string {
  const l = line.toLowerCase();
  if (/error|failed|fail|panic/.test(l))              return "text-red-400";
  if (/warn|warning/.test(l))                         return "text-yellow-400/80";
  if (/\[queue\] scan complete/.test(l))              return "text-emerald-300 font-semibold";
  if (/\[queue\]/.test(l))                            return "text-blue-400";
  if (/cms-scan:|wpscan|droopescan|joomscan/.test(l)) return "text-purple-400";
  if (/techdetect:|fingerprinting tech|→ /.test(l))  return "text-violet-400";
  if (/found \d|discover|\benabled\b|detect/.test(l)) return "text-emerald-400";
  if (/skipped|skip|no /.test(l))                    return "text-zinc-600";
  if (/\[survex\]/.test(l))                          return "text-zinc-400";
  return "text-zinc-500";
}

// ── Technology display ────────────────────────────────────────────────────────

const CATEGORY_STYLE: Record<string, { bg: string; text: string; border: string }> = {
  "CMS":         { bg: "bg-purple-500/12",  text: "text-purple-300",  border: "border-purple-500/25" },
  "E-Commerce":  { bg: "bg-blue-500/12",    text: "text-blue-300",    border: "border-blue-500/25"   },
  "Framework":   { bg: "bg-orange-500/12",  text: "text-orange-300",  border: "border-orange-500/25" },
  "JavaScript":  { bg: "bg-yellow-500/12",  text: "text-yellow-300",  border: "border-yellow-500/25" },
  "Language":    { bg: "bg-cyan-500/12",    text: "text-cyan-300",    border: "border-cyan-500/25"   },
  "Web Server":  { bg: "bg-zinc-500/15",    text: "text-zinc-300",    border: "border-zinc-500/25"   },
  "CDN":         { bg: "bg-teal-500/12",    text: "text-teal-300",    border: "border-teal-500/25"   },
  "WAF":         { bg: "bg-red-500/12",     text: "text-red-300",     border: "border-red-500/25"    },
  "Analytics":   { bg: "bg-green-500/12",   text: "text-green-300",   border: "border-green-500/25"  },
};
const DEFAULT_STYLE = { bg: "bg-zinc-800/40", text: "text-zinc-400", border: "border-zinc-700/30" };

const CMS_SCANNER: Record<string, string> = {
  wordpress: "wpscan",
  drupal:    "droopescan",
  joomla:    "joomscan / droopescan",
};

function groupByCategory(techs: Technology[]) {
  const map: Record<string, Technology[]> = {};
  for (const t of techs) { (map[t.category || "Other"] ??= []).push(t); }
  return map;
}

function parseCMSScanActivity(logs: string[]): { cms: string; tool: string; findings: number }[] {
  const activity: { cms: string; tool: string; findings: number }[] = [];
  const findingsMap: Record<string, number> = {};
  for (const line of logs) {
    const l = line.toLowerCase();
    const m = l.match(/cms-scan:.*?(\w+) detected.*running (\w+)/);
    if (m) activity.push({ cms: m[1], tool: m[2], findings: 0 });
    const fm = l.match(/(\w+scan):\s+(\d+) findings/);
    if (fm) findingsMap[fm[1]] = parseInt(fm[2], 10);
  }
  return activity.map(a => ({ ...a, findings: findingsMap[a.tool] ?? 0 }));
}

// ── Severity theming ──────────────────────────────────────────────────────────

const SEV_THEME: Record<string, { border: string; glow: string; badge: string }> = {
  critical: { border: "border-red-500/30",    glow: "shadow-red-500/10",    badge: "text-red-400" },
  high:     { border: "border-orange-500/30", glow: "shadow-orange-500/10", badge: "text-orange-400" },
  medium:   { border: "border-yellow-500/20", glow: "shadow-yellow-500/10", badge: "text-yellow-400" },
  low:      { border: "border-blue-500/20",   glow: "shadow-blue-500/10",   badge: "text-blue-400" },
  info:     { border: "border-zinc-700/40",   glow: "",                     badge: "text-zinc-400" },
  "":       { border: "border-white/[0.07]",  glow: "",                     badge: "text-zinc-500" },
};

function formatDuration(start: string, end?: string | null) {
  const sec = Math.floor((((end ? new Date(end) : new Date()).getTime()) - new Date(start).getTime()) / 1000);
  if (sec < 0)  return "—";
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

const STATUS_BADGE: Record<string, string> = {
  queued:    "bg-zinc-500/15 text-zinc-400 border-zinc-500/25",
  running:   "bg-blue-500/15 text-blue-400 border-blue-500/25",
  done:      "bg-emerald-500/15 text-emerald-400 border-emerald-500/25",
  failed:    "bg-red-500/15 text-red-400 border-red-500/25",
  cancelled: "bg-zinc-700/20 text-zinc-500 border-zinc-700/25",
};

// ── Component ─────────────────────────────────────────────────────────────────

export default function ScanDetailClient() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const { user, loading } = useAuth();
  const router = useRouter();

  const [scan, setScan]                 = useState<ScanJob | null>(null);
  const [logs, setLogs]                 = useState<string[]>([]);
  const [wsConnected, setWsConnected]   = useState(false);
  const [cancelling, setCancelling]     = useState(false);
  const [technologies, setTechnologies] = useState<Technology[]>([]);
  const logRef = useRef<HTMLDivElement>(null);
  const wsRef  = useRef<WebSocket | null>(null);

  const fetchScan = useCallback(async () => {
    if (!id) return null;
    try { const d = await api.scans.get(id); setScan(d); return d; }
    catch { return null; }
  }, [id]);

  const fetchTechnologies = useCallback(async () => {
    if (!id) return;
    try { setTechnologies((await api.scans.technologies(id)) ?? []); }
    catch { /* no-op */ }
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
  useEffect(() => { if (user && id) fetchScan().then(() => connectWs()); }, [user, id, fetchScan, connectWs]);
  useEffect(() => {
    if (!scan || (scan.status !== "queued" && scan.status !== "running")) return;
    const t = setInterval(fetchScan, 4000);
    return () => clearInterval(t);
  }, [scan, fetchScan]);
  useEffect(() => {
    if (scan && ["done", "failed", "cancelled"].includes(scan.status)) {
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

  const steps       = buildSteps(logs);
  const isActive    = scan?.status === "queued" || scan?.status === "running";
  const grouped     = groupByCategory(technologies);
  const cmsActivity = parseCMSScanActivity(logs);
  const detectedCMSNames = technologies
    .filter(t => t.category === "CMS" || t.category === "E-Commerce")
    .map(t => t.name.toLowerCase());

  const sev = (scan?.max_severity ?? "").toLowerCase();
  const sevTheme = SEV_THEME[sev] ?? SEV_THEME[""];

  const completedSteps = steps.filter(s => s.status === "done").length;
  const totalSteps     = steps.length;
  const progress       = totalSteps > 0 ? Math.round((completedSteps / totalSteps) * 100) : 0;

  return (
    <AppShell>
      <main className="min-h-screen bg-[#030812] bg-dots">
        <div className="mx-auto max-w-7xl px-6 py-8 space-y-6">

          {/* ── Breadcrumb ─────────────────────────────────────────── */}
          <div className="flex items-center gap-2 text-xs text-zinc-600">
            <span className="hover:text-zinc-400 cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
            <ChevronRight className="h-3 w-3" />
            <span className="text-zinc-400 font-mono">{scan?.client ?? id}</span>
          </div>

          {/* ── Header ────────────────────────────────────────────── */}
          <div className={`rounded-xl border bg-[#0a1628]/80 p-5 shadow-lg ${sevTheme.border} ${sevTheme.glow}`}>
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div className="space-y-2">
                <div className="flex items-center gap-3 flex-wrap">
                  <h1 className="text-xl font-bold text-white tracking-tight">{scan?.client ?? id}</h1>
                  {scan && (
                    <span className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1 text-[11px] font-bold tracking-wider ${STATUS_BADGE[scan.status]}`}>
                      {scan.status === "running"   && <Loader2 className="h-3 w-3 animate-spin" />}
                      {scan.status === "done"      && <CheckCircle2 className="h-3 w-3" />}
                      {scan.status === "failed"    && <XCircle className="h-3 w-3" />}
                      {scan.status === "cancelled" && <XCircle className="h-3 w-3" />}
                      {scan.status.toUpperCase()}
                    </span>
                  )}
                  {technologies.length > 0 && (
                    <span className="inline-flex items-center gap-1.5 rounded border border-violet-500/25 bg-violet-500/10 px-2.5 py-1 text-[11px] font-bold text-violet-400">
                      <Cpu className="h-3 w-3" />
                      {technologies.length} tech{technologies.length !== 1 ? "s" : ""}
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-zinc-600 font-mono">{id}</p>

                {/* Progress bar (only when running) */}
                {isActive && (
                  <div className="flex items-center gap-3 pt-1">
                    <div className="flex-1 h-1 rounded-full bg-white/5 overflow-hidden max-w-[200px]">
                      <div
                        className="h-full bg-emerald-500/60 rounded-full transition-all duration-500"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-zinc-600 font-mono">{progress}%</span>
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {scan?.status === "done" && scan.report_path && (
                  <a
                    href={api.scans.reportUrl(id)}
                    target="_blank" rel="noreferrer"
                    className="flex items-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 px-3.5 py-2 text-[13px] font-semibold text-white transition-colors"
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                    HTML Report
                  </a>
                )}
                {isActive && (
                  <button
                    onClick={handleCancel}
                    disabled={cancelling}
                    className="flex items-center gap-2 rounded-lg border border-red-500/25 bg-red-500/8 hover:bg-red-500/15 px-3.5 py-2 text-[13px] font-medium text-red-400 transition-colors disabled:opacity-50"
                  >
                    {cancelling ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Square className="h-3.5 w-3.5" />}
                    {cancelling ? "Stopping…" : "Stop Scan"}
                  </button>
                )}
                <button
                  onClick={() => fetchScan()}
                  className="flex h-9 w-9 items-center justify-center rounded-lg border border-white/[0.07] text-zinc-500 hover:text-zinc-200 hover:bg-white/5 transition-all"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* ── Stat strip ────────────────────────────────────────── */}
          {scan && (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { icon: <Target className="h-3.5 w-3.5" />,         label: "Target",   val: <span className="font-mono text-[11px] text-zinc-300 truncate block">{scan.targets}</span> },
                { icon: <Layers className="h-3.5 w-3.5" />,         label: "Modules",  val: <span className="font-mono text-[11px] text-zinc-300 truncate block">{scan.modules || "(profile)"}</span> },
                { icon: <AlertTriangle className="h-3.5 w-3.5" />,  label: "Findings", val: <div className="flex items-center gap-2"><span className="text-2xl font-bold text-white tabular-nums">{scan.finding_count}</span><SeverityBadge severity={scan.max_severity ?? ""} /></div> },
                { icon: <Clock className="h-3.5 w-3.5" />,          label: "Duration", val: <span className="text-2xl font-bold text-white tabular-nums">{scan.started_at ? formatDuration(scan.started_at, scan.finished_at) : "—"}</span> },
              ].map(({ icon, label, val }) => (
                <div key={label} className="rounded-xl border border-white/[0.07] bg-[#0a1628]/60 p-4">
                  <div className="flex items-center gap-1.5 text-[10px] text-zinc-600 uppercase tracking-widest font-bold mb-2">
                    {icon}{label}
                  </div>
                  {val}
                </div>
              ))}
            </div>
          )}

          {/* ── Pipeline + Terminal ────────────────────────────────── */}
          <div className="grid gap-4 lg:grid-cols-[220px_1fr]">

            {/* Step tracker */}
            <div className="rounded-xl border border-white/[0.07] bg-[#0a1628]/60 p-4 h-fit">
              <p className="text-[10px] font-bold uppercase tracking-widest text-zinc-700 mb-4 px-1">
                Pipeline
              </p>
              <div className="space-y-0">
                {steps.map((step, i) => (
                  <div key={step.id} className="flex gap-3">
                    {/* Icon + connector */}
                    <div className="flex flex-col items-center">
                      <div className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full transition-all ${
                        step.status === "done"   ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30" :
                        step.status === "active" ? "bg-blue-500/15 text-blue-400 border border-blue-500/40 ring-2 ring-blue-500/15" :
                                                   "bg-white/[0.03] text-zinc-700 border border-white/[0.06]"
                      }`}>
                        {step.status === "active"
                          ? <Loader2 className="h-3 w-3 animate-spin" />
                          : step.status === "done"
                          ? <CheckCircle2 className="h-3 w-3" />
                          : <Circle className="h-2.5 w-2.5" />}
                      </div>
                      {i < steps.length - 1 && (
                        <div className={`w-px my-1 flex-1 min-h-[14px] ${step.status === "done" ? "bg-emerald-500/25" : "bg-white/[0.05]"}`} />
                      )}
                    </div>
                    {/* Label */}
                    <div className="pb-2.5 pt-0.5 min-w-0">
                      <p className={`text-[13px] leading-tight ${
                        step.status === "done"   ? "text-zinc-300 font-medium" :
                        step.status === "active" ? "text-blue-400 font-semibold" :
                                                   "text-zinc-700"
                      }`}>
                        {step.label}
                      </p>
                      {/* CMS tool routing under Tech Detection */}
                      {step.id === "tech" && step.status === "done" && detectedCMSNames.length > 0 && (
                        <div className="mt-1 space-y-0.5">
                          {detectedCMSNames.map(cms => (
                            <p key={cms} className="text-[10px] text-violet-500 font-mono">
                              → {CMS_SCANNER[cms] ?? cms}
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
            <div className="rounded-xl border border-white/[0.07] bg-[#030812] overflow-hidden flex flex-col">
              {/* Terminal chrome */}
              <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/[0.06] bg-[#060c18]">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-full bg-red-500/60" />
                    <div className="h-2.5 w-2.5 rounded-full bg-yellow-500/60" />
                    <div className="h-2.5 w-2.5 rounded-full bg-emerald-500/60" />
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] text-zinc-600 font-mono">
                    <Terminal className="h-3 w-3" />
                    survex — scan output
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-[10px] text-zinc-700 font-mono">{logs.length} lines</span>
                  {wsConnected && (
                    <span className="flex items-center gap-1.5 text-[10px] text-blue-400 font-mono">
                      <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                      LIVE
                    </span>
                  )}
                </div>
              </div>

              {/* Log body */}
              <div
                ref={logRef}
                className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-[1.7] bg-[#020609]"
                style={{ minHeight: "480px", maxHeight: "600px" }}
              >
                {logs.length === 0 ? (
                  <span className="text-zinc-700">
                    {scan?.status === "queued"
                      ? "⏳  Scan queued — waiting for worker…"
                      : "No output yet."}
                  </span>
                ) : (
                  logs.map((line, i) => (
                    <div key={i} className={`whitespace-pre-wrap break-all leading-relaxed ${logClass(line)}`}>
                      {line}
                    </div>
                  ))
                )}
                {wsConnected && <span className="text-emerald-400 animate-blink">█</span>}
              </div>
            </div>
          </div>

          {/* ── Technologies panel ─────────────────────────────────── */}
          {technologies.length > 0 && (
            <div className="rounded-xl border border-violet-500/20 bg-[#0a1628]/60 overflow-hidden">
              <div className="flex items-center justify-between px-5 py-3 border-b border-white/[0.05] bg-violet-500/[0.03]">
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-violet-400" />
                  <span className="text-[13px] font-semibold text-white">Technologies Detected</span>
                  <span className="rounded-full border border-violet-500/25 bg-violet-500/10 px-2 py-0.5 text-[10px] font-bold text-violet-400">
                    {technologies.length}
                  </span>
                </div>
                {cmsActivity.length > 0 && (
                  <div className="flex items-center gap-1.5 text-[11px] text-violet-500">
                    <Zap className="h-3 w-3" />
                    CMS scanners triggered
                  </div>
                )}
              </div>

              <div className="p-5 space-y-5">
                {Object.entries(grouped).map(([category, techs]) => {
                  const style = CATEGORY_STYLE[category] ?? DEFAULT_STYLE;
                  return (
                    <div key={category}>
                      <p className="text-[9px] font-bold uppercase tracking-[0.2em] text-zinc-700 mb-2.5">{category}</p>
                      <div className="flex flex-wrap gap-2">
                        {techs.map((t, i) => (
                          <div key={i} className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[12px] font-medium ${style.bg} ${style.text} ${style.border}`}>
                            {t.name}
                            {t.version && <span className="opacity-50 font-normal text-[11px]">{t.version}</span>}
                            <span className="opacity-30 text-[9px] font-mono">{t.host}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}

                {/* CMS scan results */}
                {cmsActivity.length > 0 && (
                  <div className="border-t border-white/[0.05] pt-4">
                    <p className="text-[9px] font-bold uppercase tracking-[0.2em] text-zinc-700 mb-3">CMS Scan Results</p>
                    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                      {cmsActivity.map((a, i) => (
                        <div key={i} className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3.5 py-2.5">
                          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-purple-500/20 bg-purple-500/8 text-purple-400">
                            <Zap className="h-3.5 w-3.5" />
                          </div>
                          <div className="min-w-0">
                            <p className="text-[12px] font-semibold text-zinc-300 capitalize">{a.cms}</p>
                            <p className="text-[11px] text-zinc-600">
                              <span className="font-mono text-zinc-500">{a.tool}</span>
                              {" → "}
                              <span className={a.findings > 0 ? "text-red-400 font-bold" : "text-emerald-400"}>
                                {a.findings} finding{a.findings !== 1 ? "s" : ""}
                              </span>
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Install hint */}
                {detectedCMSNames.length > 0 && cmsActivity.length === 0 && (
                  <div className="border-t border-white/[0.05] pt-3 flex items-start gap-2 text-[11px] text-zinc-600">
                    <Zap className="h-3.5 w-3.5 shrink-0 mt-0.5 text-violet-500/60" />
                    <span>
                      <span className="text-violet-400 font-medium">CMS detected:</span>{" "}
                      {detectedCMSNames.map(n =>
                        `${n.charAt(0).toUpperCase() + n.slice(1)} → ${CMS_SCANNER[n] ?? "scanner"}`
                      ).join(", ")}.
                      {" "}Install the tool to get automatic vulnerability findings.
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Error ─────────────────────────────────────────────── */}
          {scan?.error && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4">
              <div className="flex items-center gap-2 mb-2">
                <XCircle className="h-4 w-4 text-red-400" />
                <p className="text-[13px] font-semibold text-red-400">Scan Error</p>
              </div>
              <pre className="text-[11px] text-red-400/60 whitespace-pre-wrap font-mono">{scan.error}</pre>
            </div>
          )}
        </div>
      </main>
    </AppShell>
  );
}
