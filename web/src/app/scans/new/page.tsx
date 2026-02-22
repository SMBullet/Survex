"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  AlertCircle, Globe, Shield, Server, Zap, Eye, Cloud, Activity, ChevronRight, Check, Target,
} from "lucide-react";

// ── Data ──────────────────────────────────────────────────────────────────────

// Nuclei template categories — maps UI label to nuclei template path.
// Order follows severity/impact: CVEs first, then discovery, then detection.
const NUCLEI_CATEGORIES = [
  { path: "http/cves/",             label: "CVEs",               desc: "Log4j, Spring4Shell, MOVEit, Confluence…", on: true  },
  { path: "http/vulnerabilities/",  label: "Generic Vulns",      desc: "XSS, SQLi, SSRF, path traversal, RCE",    on: true  },
  { path: "http/takeovers/",        label: "Takeovers",          desc: "Dangling CNAME → service takeover",        on: true  },
  { path: "http/exposures/",        label: "File Exposures",     desc: ".env, SSH keys, .git/config, Dockerfiles", on: true  },
  { path: "http/exposures/tokens/", label: "Token Exposure",     desc: "API keys and secrets in HTTP responses",   on: true  },
  { path: "http/file-inclusion/",   label: "File Inclusion",     desc: "LFI / path traversal checks",              on: true  },
  { path: "http/exposed-panels/",   label: "Admin Panels",       desc: "Exposed management interfaces",            on: true  },
  { path: "http/default-logins/",   label: "Default Creds",      desc: "190+ vendors: Jira, Jenkins, Grafana…",   on: true  },
  { path: "http/misconfiguration/", label: "Misconfigs",         desc: "CORS, debug endpoints, open redirects",    on: true  },
  { path: "ssl/",                   label: "TLS/SSL",            desc: "Deprecated versions, weak ciphers, expired certs", on: true },
  { path: "dns/",                   label: "DNS",                desc: "Azure/ElasticBeanstalk takeovers, DNS misconfigs", on: true },
  { path: "cloud/",                 label: "Cloud",              desc: "S3, GCS, Azure bucket misconfigurations",  on: true  },
  { path: "network/default-login/", label: "Network Creds",      desc: "Redis, FTP, MSSQL, PostgreSQL, SMTP",     on: true  },
  { path: "network/misconfig/",     label: "Network Misconfigs", desc: "Exposed memcached, open proxies",          on: true  },
  { path: "network/exposures/",     label: "Network Exposures",  desc: "Sensitive data over network protocols",    on: true  },
  { path: "http/technologies/",     label: "Tech Detection",     desc: "Technology fingerprinting (noisy, info)",  on: false },
  { path: "network/detection/",     label: "Network Detection",  desc: "Service fingerprinting over network",      on: false },
];

const DEFAULT_NUCLEI_CATEGORIES = new Set(
  NUCLEI_CATEGORIES.filter(c => c.on).map(c => c.path)
);

const NUCLEI_SEVERITIES = [
  { value: "critical", color: "text-red-400    border-red-500/30    bg-red-500/8"    },
  { value: "high",     color: "text-orange-400 border-orange-500/30 bg-orange-500/8" },
  { value: "medium",   color: "text-yellow-400 border-yellow-500/30 bg-yellow-500/8" },
  { value: "low",      color: "text-blue-400   border-blue-500/30   bg-blue-500/8"   },
  { value: "info",     color: "text-zinc-400   border-zinc-500/30   bg-zinc-700/20"  },
];
const DEFAULT_NUCLEI_SEVERITIES = new Set(["critical", "high", "medium", "info"]);

const MODULE_GROUPS = [
  {
    label: "Recon",
    color: "text-cyan-400",
    border: "border-cyan-500/20",
    bg: "bg-cyan-500/5",
    icon: <Globe className="h-3.5 w-3.5" />,
    modules: [
      { id: "crts",       label: "Certificate Transparency", desc: "Mine crt.sh for subdomains",          builtin: true },
      { id: "dns",        label: "DNS Resolution",           desc: "Resolve all discovered hosts",         builtin: true },
      { id: "dnsbrute",   label: "DNS Bruteforce",           desc: "Wordlist-based subdomain discovery",   builtin: true },
      { id: "subfinder",  label: "Subfinder",                desc: "Passive subdomain enumeration" },
      { id: "amass",      label: "Amass",                    desc: "OSINT subdomain enumeration" },
      { id: "gau",        label: "Historical URLs",          desc: "Fetch URLs from gau / Wayback" },
      { id: "katana",     label: "JS Crawler",               desc: "Crawl JS-heavy sites with katana" },
      { id: "screenshot", label: "Screenshots",              desc: "Capture screenshots via gowitness" },
      { id: "shodan",     label: "Shodan Enrichment",        desc: "Enrich IPs with Shodan data",          builtin: true },
    ],
  },
  {
    label: "Web Security",
    color: "text-violet-400",
    border: "border-violet-500/20",
    bg: "bg-violet-500/5",
    icon: <Shield className="h-3.5 w-3.5" />,
    modules: [
      { id: "httpx",     label: "HTTP Probing",       desc: "Probe live HTTP/S services",            builtin: true },
      { id: "tls",       label: "TLS Analysis",       desc: "Analyse certs and cipher suites",       builtin: true },
      { id: "waf",       label: "WAF Detection",      desc: "Fingerprint web application firewalls", builtin: true },
      { id: "headers",   label: "Security Headers",   desc: "Audit HTTP response headers",           builtin: true },
      { id: "cors",      label: "CORS",               desc: "Detect CORS misconfigurations",         builtin: true },
      { id: "cookies",   label: "Cookie Security",    desc: "Check Secure / HttpOnly / SameSite",    builtin: true },
      { id: "takeover",  label: "Subdomain Takeover", desc: "Detect dangling DNS / takeover risk",   builtin: true },
      { id: "email",     label: "Email Security",     desc: "SPF, DMARC and DKIM checks",            builtin: true },
      { id: "jsscan",    label: "JS Secret Scan",     desc: "Extract secrets from JS bundles",       builtin: true },
      { id: "github",    label: "GitHub Exposure",    desc: "Search GitHub for leaked code",         builtin: true },
      { id: "s3",        label: "Cloud Storage",      desc: "S3 / GCS / Azure bucket exposure",      builtin: true },
    ],
  },
  {
    label: "Active Scanning",
    color: "text-red-400",
    border: "border-red-500/20",
    bg: "bg-red-500/5",
    icon: <Zap className="h-3.5 w-3.5" />,
    modules: [
      { id: "nmap",         label: "Port Scanning",     desc: "Full port scan with nmap" },
      { id: "nuclei",       label: "Nuclei",            desc: "CVE / vuln template scanning" },
      { id: "apidiscovery", label: "API Discovery",     desc: "Discover Swagger / OpenAPI / actuator", builtin: true },
      { id: "graphql",      label: "GraphQL",           desc: "GraphQL introspection probing",          builtin: true },
      { id: "ffuf",         label: "Content Discovery", desc: "Bruteforce hidden paths",                builtin: true },
      { id: "openredirect", label: "Open Redirect",     desc: "Test for open redirect vulns",           builtin: true },
      { id: "dalfox",       label: "XSS Scan",          desc: "Automated XSS scanning with dalfox" },
      { id: "sqlmap",       label: "SQLi Scan",         desc: "SQL injection testing with sqlmap" },
    ],
  },
];

const ALL_IDS = MODULE_GROUPS.flatMap(g => g.modules.map(m => m.id));

const PROFILES = [
  {
    value: "quick",   label: "Quick",   icon: <Zap className="h-4 w-4" />,
    desc: "Fast recon + HTTP probing",
    modules: ["crts","dns","httpx","tls","headers"],
    color: "border-cyan-500/30 bg-cyan-500/8",
    active: "border-cyan-500 bg-cyan-500/15 text-cyan-300",
    iconColor: "text-cyan-400",
  },
  {
    value: "web",     label: "Web",     icon: <Globe className="h-4 w-4" />,
    desc: "Full web + vuln scanning",
    modules: ["subfinder","crts","amass","dns","httpx","tls","waf","headers","cors","cookies","nuclei"],
    color: "border-violet-500/30 bg-violet-500/8",
    active: "border-violet-500 bg-violet-500/15 text-violet-300",
    iconColor: "text-violet-400",
  },
  {
    value: "full",    label: "Full",    icon: <Shield className="h-4 w-4" />,
    desc: "Every module — most thorough",
    modules: ALL_IDS,
    color: "border-rose-500/30 bg-rose-500/8",
    active: "border-rose-500 bg-rose-500/15 text-rose-300",
    iconColor: "text-rose-400",
  },
  {
    value: "passive", label: "Passive", icon: <Eye className="h-4 w-4" />,
    desc: "No active probing",
    modules: ["crts","dns","shodan"],
    color: "border-zinc-600/30 bg-zinc-700/10",
    active: "border-zinc-500 bg-zinc-500/15 text-zinc-300",
    iconColor: "text-zinc-400",
  },
  {
    value: "cloud",   label: "Cloud",   icon: <Cloud className="h-4 w-4" />,
    desc: "Cloud storage + nuclei cloud",
    modules: ["subfinder","crts","dns","httpx","s3","nuclei"],
    color: "border-blue-500/30 bg-blue-500/8",
    active: "border-blue-500 bg-blue-500/15 text-blue-300",
    iconColor: "text-blue-400",
  },
  {
    value: "custom",  label: "Custom",  icon: <Activity className="h-4 w-4" />,
    desc: "Choose modules manually",
    modules: [],
    color: "border-amber-500/30 bg-amber-500/8",
    active: "border-amber-500 bg-amber-500/15 text-amber-300",
    iconColor: "text-amber-400",
  },
];

const PORT_OPTIONS = [
  { value: "top-1000", label: "Top 1,000",       sub: "default" },
  { value: "top-100",  label: "Top 100",          sub: "fast" },
  { value: "full",     label: "All 65,535",       sub: "thorough" },
  { value: "web",      label: "Web ports only",   sub: "80,443,8080…" },
  { value: "db",       label: "Database ports",   sub: "MySQL,PG,Mongo…" },
];

// ── Component ─────────────────────────────────────────────────────────────────

export default function NewScanPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [client, setClient]         = useState("");
  const [targetsText, setTargets]   = useState("");
  const [profile, setProfile]       = useState("quick");
  const [selected, setSelected]     = useState<Set<string>>(new Set(["httpx","tls","headers","cors"]));
  const [ports, setPorts]           = useState("top-1000");
  const [noSubs, setNoSubs]         = useState(false);
  const [passive, setPassive]       = useState(false);
  const [rate, setRate]                         = useState(150);
  const [threads, setThreads]                   = useState(50);
  const [nucleiSeverities, setNucleiSeverities] = useState<Set<string>>(DEFAULT_NUCLEI_SEVERITIES);
  const [nucleiCategories, setNucleiCategories] = useState<Set<string>>(DEFAULT_NUCLEI_CATEGORIES);
  const [submitting, setSubmitting]             = useState(false);
  const [error, setError]                       = useState("");

  if (!loading && !user) { router.replace("/login"); return null; }

  const toggle = (id: string) =>
    setSelected(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const currentProfile = PROFILES.find(p => p.value === profile)!;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const targets = targetsText.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (!targets.length) { setError("Enter at least one target."); return; }

    const isCustom = profile === "custom";
    const modules  = isCustom ? (selected.size > 0 ? [...selected] : ["httpx","tls","headers"]) : [];

    // Determine if nuclei is in the active module set
    const activeModules = isCustom ? modules : currentProfile.modules;
    const nucleiActive  = activeModules.includes("nuclei");

    // Build nuclei options — only send when nuclei is active
    const nucleiOpts: Record<string, unknown> = {};
    if (nucleiActive) {
      // Severity — only pass when different from default (critical,high,medium,info)
      const sevList = NUCLEI_SEVERITIES.map(s => s.value).filter(s => nucleiSeverities.has(s));
      if (sevList.join(",") !== "critical,high,medium,info") {
        nucleiOpts.nuclei_severity = sevList.join(",");
      }
      // Template categories — pass selected list (backend uses custom list when non-empty)
      nucleiOpts.nuclei_templates = [...nucleiCategories];
    }

    setSubmitting(true);
    try {
      const job = await api.scans.create({
        client: client || targets[0],
        targets,
        modules,
        options: { no_subs: noSubs, passive, ports, profile: isCustom ? "" : profile, rate, threads, ...nucleiOpts },
      });
      router.push(`/scans/detail?id=${job.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create scan");
      setSubmitting(false);
    }
  };

  // Active module count for display
  const activeModuleCount = profile === "custom" ? selected.size : currentProfile.modules.length;

  // Is nuclei part of the current scan?
  const nucleiActive = profile === "custom"
    ? selected.has("nuclei")
    : currentProfile.modules.includes("nuclei");

  const toggleSeverity = (v: string) =>
    setNucleiSeverities(prev => { const n = new Set(prev); n.has(v) ? n.delete(v) : n.add(v); return n; });

  const toggleCategory = (path: string) =>
    setNucleiCategories(prev => { const n = new Set(prev); n.has(path) ? n.delete(path) : n.add(path); return n; });

  return (
    <AppShell>
      <main className="min-h-screen bg-[#0d0018] bg-dots">
        <div className="mx-auto max-w-5xl px-6 py-8">

          {/* Header */}
          <div className="mb-8 space-y-1">
            <div className="flex items-center gap-2 text-xs text-zinc-600 mb-3">
              <span className="hover:text-zinc-400 cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
              <ChevronRight className="h-3 w-3" />
              <span className="text-zinc-400">New Scan</span>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Target Acquisition</h1>
            <p className="text-sm text-zinc-500">Configure scan scope, profile, and modules.</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">

            {/* ── Target ────────────────────────────────────────────────── */}
            <section className="rounded-xl border border-white/[0.07] bg-[#160025]/70 overflow-hidden">
              <div className="flex items-center gap-2.5 border-b border-white/[0.05] bg-white/[0.02] px-5 py-3">
                <Globe className="h-4 w-4 text-red-400" />
                <span className="text-[13px] font-semibold text-white">Target Scope</span>
              </div>
              <div className="p-5 grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label className="text-[11px] font-bold uppercase tracking-widest text-zinc-600">
                    Client Name <span className="text-zinc-700 font-normal normal-case tracking-normal">(optional)</span>
                  </Label>
                  <Input
                    placeholder="acme-corp"
                    value={client}
                    onChange={e => setClient(e.target.value)}
                    className="bg-white/[0.04] border-white/[0.08] text-white placeholder:text-zinc-700 focus:border-red-500/50 h-9"
                  />
                </div>
                <div className="space-y-2 sm:col-span-2">
                  <Label className="text-[11px] font-bold uppercase tracking-widest text-zinc-600">
                    Targets <span className="text-red-500">*</span>
                  </Label>
                  <Textarea
                    placeholder={"example.com\napp.example.com\n192.168.1.0/24"}
                    rows={4}
                    value={targetsText}
                    onChange={e => setTargets(e.target.value)}
                    className="font-mono text-sm resize-none bg-white/[0.04] border-white/[0.08] text-amber-300 placeholder:text-zinc-700 focus:border-red-500/50"
                    required
                  />
                  <p className="text-[11px] text-zinc-600">Domains, IPs, or CIDR ranges — one per line or comma-separated.</p>
                </div>
              </div>
            </section>

            {/* ── Profile selector ──────────────────────────────────────── */}
            <section className="rounded-xl border border-white/[0.07] bg-[#160025]/70 overflow-hidden">
              <div className="flex items-center gap-2.5 border-b border-white/[0.05] bg-white/[0.02] px-5 py-3">
                <Activity className="h-4 w-4 text-red-400" />
                <span className="text-[13px] font-semibold text-white">Scan Profile</span>
                <span className="ml-auto text-[11px] text-zinc-600">{activeModuleCount} module{activeModuleCount !== 1 ? "s" : ""}</span>
              </div>
              <div className="p-5">
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                  {PROFILES.map(p => {
                    const isActive = profile === p.value;
                    return (
                      <button
                        key={p.value}
                        type="button"
                        onClick={() => setProfile(p.value)}
                        className={`relative flex flex-col items-start gap-2 rounded-xl border p-3.5 text-left transition-all ${
                          isActive ? p.active : "border-white/[0.07] bg-white/[0.02] hover:bg-white/[0.04] hover:border-white/15"
                        }`}
                      >
                        <div className={`flex h-7 w-7 items-center justify-center rounded-lg border ${
                          isActive ? "border-current/30 bg-current/10" : "border-white/[0.07] bg-white/5"
                        }`}>
                          <span className={isActive ? "text-inherit" : "text-zinc-600"}>{p.icon}</span>
                        </div>
                        <div>
                          <p className={`text-[13px] font-semibold ${isActive ? "" : "text-zinc-300"}`}>{p.label}</p>
                          <p className="text-[10px] text-zinc-600 mt-0.5 leading-snug">{p.desc}</p>
                        </div>
                        {p.modules.length > 0 && (
                          <span className="absolute top-2 right-2 text-[9px] text-zinc-600 font-mono">{p.modules.length}</span>
                        )}
                        {isActive && (
                          <span className="absolute bottom-2 right-2">
                            <Check className="h-3 w-3" />
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>

                {/* Profile preview chips */}
                {profile !== "custom" && currentProfile.modules.length > 0 && (
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {currentProfile.modules.map(m => (
                      <span key={m} className="rounded border border-white/[0.07] bg-white/[0.03] px-2 py-0.5 text-[11px] font-mono text-zinc-500">
                        {m}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </section>

            {/* ── Custom module picker ───────────────────────────────────── */}
            {profile === "custom" && (
              <section className="rounded-xl border border-amber-500/15 bg-[#160025]/70 overflow-hidden">
                <div className="flex items-center gap-2.5 border-b border-white/[0.05] bg-white/[0.02] px-5 py-3">
                  <Shield className="h-4 w-4 text-amber-400" />
                  <span className="text-[13px] font-semibold text-white">Module Selection</span>
                  <span className="ml-2 rounded-full border border-amber-500/25 bg-amber-500/10 px-2 py-0.5 text-[10px] font-bold text-amber-400">
                    {selected.size} selected
                  </span>
                  <div className="ml-auto flex gap-1.5">
                    <button type="button" onClick={() => setSelected(new Set(ALL_IDS))}
                      className="rounded px-2 py-1 text-[11px] text-zinc-400 hover:text-white hover:bg-white/5 transition-colors">
                      All
                    </button>
                    <button type="button" onClick={() => setSelected(new Set())}
                      className="rounded px-2 py-1 text-[11px] text-zinc-600 hover:text-zinc-300 hover:bg-white/5 transition-colors">
                      Clear
                    </button>
                  </div>
                </div>
                <div className="p-5 space-y-5">
                  {MODULE_GROUPS.map(group => (
                    <div key={group.label}>
                      <div className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 mb-3 ${group.border} ${group.bg}`}>
                        <span className={group.color}>{group.icon}</span>
                        <span className={`text-[10px] font-bold uppercase tracking-widest ${group.color}`}>{group.label}</span>
                      </div>
                      <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                        {group.modules.map(m => {
                          const on = selected.has(m.id);
                          return (
                            <label
                              key={m.id}
                              onClick={() => toggle(m.id)}
                              className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-all ${
                                on
                                  ? "border-red-500/40 bg-red-500/6 text-white"
                                  : "border-white/[0.06] hover:border-white/15 text-zinc-500 hover:text-zinc-300"
                              }`}
                            >
                              <div className={`mt-0.5 h-4 w-4 shrink-0 rounded border flex items-center justify-center transition-all ${
                                on ? "bg-red-500 border-red-500" : "border-white/20 bg-white/5"
                              }`}>
                                {on && <Check className="h-2.5 w-2.5 text-white" />}
                              </div>
                              <div className="min-w-0">
                                <div className="flex items-center gap-1.5 flex-wrap">
                                  <span className="text-[13px] font-medium">{m.label}</span>
                                  {m.builtin && (
                                    <span className="text-[9px] bg-zinc-700/50 text-zinc-500 rounded px-1.5 py-0.5 font-bold uppercase tracking-wider">
                                      built-in
                                    </span>
                                  )}
                                </div>
                                <p className="text-[11px] text-zinc-600 mt-0.5">{m.desc}</p>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* ── Options ───────────────────────────────────────────────── */}
            <section className="rounded-xl border border-white/[0.07] bg-[#160025]/70 overflow-hidden">
              <div className="flex items-center gap-2.5 border-b border-white/[0.05] bg-white/[0.02] px-5 py-3">
                <Server className="h-4 w-4 text-red-400" />
                <span className="text-[13px] font-semibold text-white">Scan Options</span>
              </div>
              <div className="p-5 space-y-5">

                {/* Port profile */}
                <div className="space-y-2">
                  <Label className="text-[11px] font-bold uppercase tracking-widest text-zinc-600">Port Profile</Label>
                  <div className="flex flex-wrap gap-2">
                    {PORT_OPTIONS.map(p => (
                      <button
                        key={p.value}
                        type="button"
                        onClick={() => setPorts(p.value)}
                        className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-[12px] transition-all ${
                          ports === p.value
                            ? "border-red-500/40 bg-red-500/10 text-red-300"
                            : "border-white/[0.07] bg-white/[0.02] text-zinc-400 hover:text-zinc-200 hover:bg-white/5"
                        }`}
                      >
                        <span className="font-medium">{p.label}</span>
                        <span className="text-[10px] opacity-60">{p.sub}</span>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Rate + threads */}
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <div className="space-y-2">
                    <Label className="text-[11px] font-bold uppercase tracking-widest text-zinc-600">Rate (req/s)</Label>
                    <Input
                      type="number" min={1} max={500}
                      value={rate} onChange={e => setRate(Number(e.target.value))}
                      className="bg-white/[0.04] border-white/[0.08] text-white h-9 font-mono focus:border-red-500/50"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-[11px] font-bold uppercase tracking-widest text-zinc-600">Threads</Label>
                    <Input
                      type="number" min={1} max={200}
                      value={threads} onChange={e => setThreads(Number(e.target.value))}
                      className="bg-white/[0.04] border-white/[0.08] text-white h-9 font-mono focus:border-red-500/50"
                    />
                  </div>
                </div>

                {/* Toggles */}
                <div className="flex flex-wrap gap-4">
                  {[
                    { id: "nosubs",  label: "Skip subdomain enumeration", sub: "Scan provided targets as-is", val: noSubs,  set: setNoSubs },
                    { id: "passive", label: "Passive recon only",          sub: "No active probing or ports",  val: passive, set: setPassive },
                  ].map(opt => (
                    <label
                      key={opt.id}
                      className="flex items-start gap-3 cursor-pointer group"
                    >
                      <div
                        onClick={() => opt.set(!opt.val)}
                        className={`mt-0.5 h-4 w-4 shrink-0 rounded border flex items-center justify-center transition-all cursor-pointer ${
                          opt.val ? "bg-red-500 border-red-500" : "border-white/20 bg-white/5 group-hover:border-white/40"
                        }`}
                      >
                        {opt.val && <Check className="h-2.5 w-2.5 text-white" />}
                      </div>
                      <div>
                        <p className="text-[13px] font-medium text-zinc-300">{opt.label}</p>
                        <p className="text-[11px] text-zinc-600">{opt.sub}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </section>

            {/* ── Nuclei Configuration ──────────────────────────────────── */}
            {nucleiActive && (
              <section className="rounded-xl border border-red-500/15 bg-[#160025]/70 overflow-hidden">
                <div className="flex items-center gap-2.5 border-b border-white/[0.05] bg-white/[0.02] px-5 py-3">
                  <Target className="h-4 w-4 text-red-400" />
                  <span className="text-[13px] font-semibold text-white">Nuclei Configuration</span>
                  <span className="ml-2 text-[11px] text-zinc-600">
                    {nucleiCategories.size} template categor{nucleiCategories.size === 1 ? "y" : "ies"} · {nucleiSeverities.size} severit{nucleiSeverities.size === 1 ? "y" : "ies"}
                  </span>
                </div>
                <div className="p-5 space-y-5">

                  {/* Severity */}
                  <div className="space-y-2">
                    <Label className="text-[11px] font-bold uppercase tracking-widest text-zinc-600">Severity Levels</Label>
                    <div className="flex flex-wrap gap-2">
                      {NUCLEI_SEVERITIES.map(s => {
                        const on = nucleiSeverities.has(s.value);
                        return (
                          <button
                            key={s.value}
                            type="button"
                            onClick={() => toggleSeverity(s.value)}
                            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[12px] font-medium capitalize transition-all ${
                              on
                                ? s.color
                                : "border-white/[0.07] bg-white/[0.02] text-zinc-600 hover:text-zinc-400 hover:bg-white/5"
                            }`}
                          >
                            <div className={`h-1.5 w-1.5 rounded-full ${on ? "bg-current" : "bg-zinc-700"}`} />
                            {s.value}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Template categories */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <Label className="text-[11px] font-bold uppercase tracking-widest text-zinc-600">Template Categories</Label>
                      <div className="flex gap-1.5">
                        <button type="button" onClick={() => setNucleiCategories(new Set(NUCLEI_CATEGORIES.map(c => c.path)))}
                          className="rounded px-2 py-1 text-[11px] text-zinc-400 hover:text-white hover:bg-white/5 transition-colors">
                          All
                        </button>
                        <button type="button" onClick={() => setNucleiCategories(DEFAULT_NUCLEI_CATEGORIES)}
                          className="rounded px-2 py-1 text-[11px] text-zinc-400 hover:text-white hover:bg-white/5 transition-colors">
                          Default
                        </button>
                        <button type="button" onClick={() => setNucleiCategories(new Set())}
                          className="rounded px-2 py-1 text-[11px] text-zinc-600 hover:text-zinc-300 hover:bg-white/5 transition-colors">
                          None
                        </button>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                      {NUCLEI_CATEGORIES.map(cat => {
                        const on = nucleiCategories.has(cat.path);
                        return (
                          <label
                            key={cat.path}
                            onClick={() => toggleCategory(cat.path)}
                            className={`flex items-start gap-3 rounded-lg border p-2.5 cursor-pointer transition-all ${
                              on
                                ? "border-red-500/30 bg-red-500/5 text-white"
                                : "border-white/[0.06] hover:border-white/15 text-zinc-500 hover:text-zinc-300"
                            }`}
                          >
                            <div className={`mt-0.5 h-3.5 w-3.5 shrink-0 rounded border flex items-center justify-center transition-all ${
                              on ? "bg-red-500 border-red-500" : "border-white/20 bg-white/5"
                            }`}>
                              {on && <Check className="h-2 w-2 text-white" />}
                            </div>
                            <div className="min-w-0">
                              <p className="text-[12px] font-medium">{cat.label}</p>
                              <p className="text-[10px] text-zinc-600 mt-0.5 leading-snug">{cat.desc}</p>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </div>

                </div>
              </section>
            )}

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2.5 rounded-lg border border-red-500/20 bg-red-500/8 px-4 py-3 text-sm text-red-400">
                <AlertCircle className="h-4 w-4 shrink-0" />
                {error}
              </div>
            )}

            {/* Submit */}
            <div className="flex items-center gap-3 pt-1">
              <button
                type="submit"
                disabled={submitting}
                className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 px-6 py-2.5 text-sm font-semibold text-white transition-all"
              >
                {submitting ? (
                  <>
                    <span className="h-3.5 w-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                    Launching…
                  </>
                ) : (
                  <>
                    Launch Scan
                    <ChevronRight className="h-4 w-4" />
                  </>
                )}
              </button>
              <button
                type="button"
                onClick={() => router.push("/dashboard")}
                className="rounded-lg border border-white/[0.07] px-5 py-2.5 text-sm text-zinc-400 hover:text-zinc-200 hover:bg-white/5 transition-all"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </main>
    </AppShell>
  );
}
