"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import { Nav } from "@/components/nav";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  AlertCircle, Globe, Shield, Server, Zap, Eye, Cloud, Activity, ChevronRight,
} from "lucide-react";

// ── Module catalogue ──────────────────────────────────────────────────────────

const MODULE_GROUPS = [
  {
    label: "Recon",
    icon: <Globe className="h-4 w-4" />,
    modules: [
      { id: "crts",       label: "Certificate Transparency", desc: "Mine crt.sh for subdomains",          builtin: true },
      { id: "dns",        label: "DNS Resolution",           desc: "Resolve all discovered hosts",         builtin: true },
      { id: "dnsbrute",   label: "DNS Bruteforce",           desc: "Wordlist-based subdomain bruteforce",  builtin: true },
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
    icon: <Shield className="h-4 w-4" />,
    modules: [
      { id: "httpx",     label: "HTTP Probing",       desc: "Probe live HTTP services",              builtin: true },
      { id: "tls",       label: "TLS Analysis",       desc: "Analyse certificates and ciphers",      builtin: true },
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
    icon: <Zap className="h-4 w-4" />,
    modules: [
      { id: "nmap",         label: "Port Scanning",    desc: "Full port scan with nmap" },
      { id: "nuclei",       label: "Nuclei",           desc: "CVE / vuln template scanning" },
      { id: "apidiscovery", label: "API Discovery",    desc: "Discover Swagger / OpenAPI / actuator",  builtin: true },
      { id: "graphql",      label: "GraphQL",          desc: "GraphQL introspection probing",           builtin: true },
      { id: "ffuf",         label: "Content Discovery", desc: "Bruteforce hidden paths",               builtin: true },
      { id: "openredirect", label: "Open Redirect",    desc: "Test for open redirect vulnerabilities",  builtin: true },
      { id: "dalfox",       label: "XSS Scan",         desc: "Automated XSS scanning with dalfox" },
      { id: "sqlmap",       label: "SQLi Scan",        desc: "SQL injection testing with sqlmap" },
    ],
  },
];

const ALL_IDS = MODULE_GROUPS.flatMap(g => g.modules.map(m => m.id));

// ── Profiles ──────────────────────────────────────────────────────────────────

const PROFILES = [
  { value: "custom",  label: "Custom",  desc: "Choose modules manually",             icon: <Activity className="h-4 w-4" />,  modules: [] as string[] },
  { value: "quick",   label: "Quick",   desc: "crts · dns · httpx · tls · headers",  icon: <Zap className="h-4 w-4" />,       modules: ["crts","dns","httpx","tls","headers"] },
  { value: "web",     label: "Web",     desc: "Full web scan + vuln scanning",        icon: <Globe className="h-4 w-4" />,     modules: ["subfinder","crts","amass","dns","httpx","tls","waf","headers","cors","cookies","nuclei"] },
  { value: "full",    label: "Full",    desc: "Every module — most thorough",         icon: <Shield className="h-4 w-4" />,    modules: ALL_IDS },
  { value: "passive", label: "Passive", desc: "No active probing (crts, dns, shodan)",icon: <Eye className="h-4 w-4" />,      modules: ["crts","dns","shodan"] },
  { value: "cloud",   label: "Cloud",   desc: "Cloud storage + nuclei cloud templates",icon: <Cloud className="h-4 w-4" />,   modules: ["subfinder","crts","dns","httpx","s3","nuclei"] },
];

const PORT_OPTIONS = [
  { value: "top-1000", label: "Top 1,000 (default)" },
  { value: "top-100",  label: "Top 100 (fast)" },
  { value: "full",     label: "All 65,535 ports" },
  { value: "web",      label: "Web ports only" },
  { value: "db",       label: "Database ports only" },
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
  const [rate, setRate]             = useState(150);
  const [threads, setThreads]       = useState(50);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState("");

  if (!loading && !user) { router.replace("/login"); return null; }

  const currentProfile = PROFILES.find(p => p.value === profile)!;

  const toggle = (id: string) =>
    setSelected(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const targets = targetsText.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (!targets.length) { setError("Enter at least one target."); return; }

    const isCustom = profile === "custom";
    const modules  = isCustom ? (selected.size > 0 ? [...selected] : ["httpx","tls","headers"]) : [];

    setSubmitting(true);
    try {
      const job = await api.scans.create({
        client: client || targets[0],
        targets,
        modules,
        options: { no_subs: noSubs, passive, ports, profile: isCustom ? "" : profile, rate, threads },
      });
      router.push(`/scans/${job.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create scan");
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <Nav />
      <main className="mx-auto max-w-4xl px-4 py-8">
        <div className="mb-8">
          <h1 className="text-2xl font-bold">New Scan</h1>
          <p className="text-muted-foreground mt-1 text-sm">Configure your scan target, profile, and modules.</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">

          {/* Target */}
          <section className="rounded-xl border border-border bg-card p-5 space-y-4">
            <h2 className="font-semibold flex items-center gap-2 text-sm">
              <Globe className="h-4 w-4 text-emerald-500" />Target
            </h2>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>Client name <span className="text-muted-foreground font-normal text-xs">(optional)</span></Label>
                <Input placeholder="acme-corp" value={client} onChange={e => setClient(e.target.value)} />
              </div>
              <div className="space-y-1.5 sm:col-span-2">
                <Label>Targets <span className="text-destructive">*</span></Label>
                <Textarea
                  placeholder={"example.com\napp.example.com\n192.168.1.0/24"}
                  rows={3}
                  value={targetsText}
                  onChange={e => setTargets(e.target.value)}
                  className="font-mono text-sm resize-none"
                  required
                />
                <p className="text-xs text-muted-foreground">Domains, IPs, CIDR ranges — one per line.</p>
              </div>
            </div>
          </section>

          {/* Profile */}
          <section className="rounded-xl border border-border bg-card p-5 space-y-4">
            <h2 className="font-semibold flex items-center gap-2 text-sm">
              <Activity className="h-4 w-4 text-emerald-500" />Scan Profile
            </h2>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
              {PROFILES.map(p => (
                <button
                  key={p.value}
                  type="button"
                  onClick={() => setProfile(p.value)}
                  className={`relative rounded-lg border p-3 text-left transition-all ${
                    profile === p.value
                      ? "border-emerald-500 bg-emerald-500/10"
                      : "border-border hover:border-muted-foreground/50 text-muted-foreground"
                  }`}
                >
                  <div className={`mb-1.5 ${profile === p.value ? "text-emerald-500" : "text-muted-foreground"}`}>{p.icon}</div>
                  <p className="text-sm font-semibold">{p.label}</p>
                  <p className="text-xs mt-0.5 leading-snug text-muted-foreground">{p.desc}</p>
                  {p.modules.length > 0 && (
                    <span className="absolute top-2 right-2 text-[10px] bg-muted rounded px-1 text-muted-foreground">
                      {p.modules.length}
                    </span>
                  )}
                </button>
              ))}
            </div>
            {profile !== "custom" && currentProfile.modules.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {currentProfile.modules.map(m => (
                  <Badge key={m} variant="secondary" className="text-xs font-mono">{m}</Badge>
                ))}
              </div>
            )}
          </section>

          {/* Custom module picker */}
          {profile === "custom" && (
            <section className="rounded-xl border border-border bg-card p-5 space-y-5">
              <div className="flex items-center justify-between">
                <h2 className="font-semibold flex items-center gap-2 text-sm">
                  <Shield className="h-4 w-4 text-emerald-500" />Modules
                  <Badge className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">{selected.size} selected</Badge>
                </h2>
                <div className="flex gap-2">
                  <Button type="button" variant="outline" size="sm" onClick={() => setSelected(new Set(ALL_IDS))}>All</Button>
                  <Button type="button" variant="ghost" size="sm" onClick={() => setSelected(new Set())}>Clear</Button>
                </div>
              </div>

              {MODULE_GROUPS.map(group => (
                <div key={group.label} className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground">{group.icon}</span>
                    <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{group.label}</span>
                  </div>
                  <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                    {group.modules.map(m => {
                      const on = selected.has(m.id);
                      return (
                        <label
                          key={m.id}
                          className={`flex items-start gap-2.5 rounded-lg border p-3 cursor-pointer transition-all ${
                            on
                              ? "border-emerald-500/50 bg-emerald-500/5 text-foreground"
                              : "border-border hover:border-muted-foreground/40 text-muted-foreground"
                          }`}
                        >
                          <input
                            type="checkbox"
                            className="mt-0.5 h-3.5 w-3.5 accent-emerald-500 shrink-0"
                            checked={on}
                            onChange={() => toggle(m.id)}
                          />
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className="text-sm font-medium">{m.label}</span>
                              {m.builtin && <span className="text-[10px] bg-muted text-muted-foreground rounded px-1 shrink-0">built-in</span>}
                            </div>
                            <p className="text-xs text-muted-foreground mt-0.5">{m.desc}</p>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>
              ))}
            </section>
          )}

          {/* Options */}
          <section className="rounded-xl border border-border bg-card p-5 space-y-4">
            <h2 className="font-semibold flex items-center gap-2 text-sm">
              <Server className="h-4 w-4 text-emerald-500" />Options
            </h2>
            <div className="grid gap-4 sm:grid-cols-3">
              <div className="space-y-1.5">
                <Label>Port Profile</Label>
                <Select value={ports} onValueChange={setPorts}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {PORT_OPTIONS.map(p => <SelectItem key={p.value} value={p.value}>{p.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Rate <span className="text-xs text-muted-foreground">(req/s)</span></Label>
                <Input type="number" min={1} max={500} value={rate} onChange={e => setRate(Number(e.target.value))} />
              </div>
              <div className="space-y-1.5">
                <Label>Threads</Label>
                <Input type="number" min={1} max={200} value={threads} onChange={e => setThreads(Number(e.target.value))} />
              </div>
            </div>
            <div className="flex flex-wrap gap-6">
              {[
                { id: "nosubs",  label: "Skip subdomain enumeration", sub: "Scan provided targets directly",     checked: noSubs,  set: setNoSubs },
                { id: "passive", label: "Passive recon only",          sub: "No active probing or port scanning", checked: passive, set: setPassive },
              ].map(opt => (
                <label key={opt.id} className="flex items-start gap-3 cursor-pointer group">
                  <input type="checkbox" className="mt-1 h-4 w-4 accent-emerald-500" checked={opt.checked} onChange={e => opt.set(e.target.checked)} />
                  <div>
                    <p className="text-sm font-medium">{opt.label}</p>
                    <p className="text-xs text-muted-foreground">{opt.sub}</p>
                  </div>
                </label>
              ))}
            </div>
          </section>

          {error && (
            <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
              <AlertCircle className="h-4 w-4 shrink-0" />{error}
            </div>
          )}

          <div className="flex gap-3 pt-1">
            <Button type="submit" disabled={submitting} className="bg-emerald-600 hover:bg-emerald-500 text-white px-6 gap-1.5">
              {submitting ? "Starting…" : <>Start Scan <ChevronRight className="h-4 w-4" /></>}
            </Button>
            <Button type="button" variant="outline" onClick={() => router.push("/dashboard")}>Cancel</Button>
          </div>
        </form>
      </main>
    </div>
  );
}
