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
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const MODULE_GROUPS = {
  Recon: [
    { id: "crts", label: "Certificate Transparency (crts)" },
    { id: "dns", label: "DNS Resolution (dns)" },
    { id: "dnsbrute", label: "DNS Bruteforce (dnsbrute)" },
    { id: "subfinder", label: "Subfinder (external)" },
    { id: "amass", label: "Amass (external)" },
    { id: "gau", label: "Historical URLs (gau)" },
    { id: "katana", label: "JS Crawler (katana)" },
    { id: "screenshot", label: "Screenshots (gowitness)" },
    { id: "shodan", label: "Shodan Enrichment" },
  ],
  "Web Security": [
    { id: "httpx", label: "HTTP Probing (httpx)" },
    { id: "tls", label: "TLS Analysis" },
    { id: "waf", label: "WAF Detection" },
    { id: "headers", label: "Security Headers" },
    { id: "cors", label: "CORS Misconfigurations" },
    { id: "cookies", label: "Cookie Security" },
    { id: "takeover", label: "Subdomain Takeover" },
    { id: "email", label: "Email Security (SPF/DMARC)" },
    { id: "jsscan", label: "JS Secret Scanning" },
    { id: "github", label: "GitHub Exposure" },
    { id: "s3", label: "Cloud Storage (S3/GCS/Azure)" },
  ],
  "Active Scanning": [
    { id: "nmap", label: "Port Scanning (nmap)" },
    { id: "nuclei", label: "Vulnerability Scan (nuclei)" },
    { id: "apidiscovery", label: "API Discovery (Swagger/OpenAPI)" },
    { id: "graphql", label: "GraphQL Introspection" },
    { id: "ffuf", label: "Content Discovery (ffuf)" },
    { id: "openredirect", label: "Open Redirect Testing" },
    { id: "dalfox", label: "XSS Scanning (dalfox)" },
    { id: "sqlmap", label: "SQLi Scanning (sqlmap)" },
  ],
};

const PROFILES = [
  { value: "custom", label: "Custom (use selected modules)" },
  { value: "quick", label: "Quick — crts, dns, httpx, tls, headers" },
  { value: "web", label: "Web — full web security scan" },
  { value: "full", label: "Full — all modules" },
  { value: "passive", label: "Passive — crts, dns, shodan only" },
  { value: "stealth", label: "Stealth — slow, low-noise" },
  { value: "cloud", label: "Cloud — S3, nuclei cloud templates" },
];

const PORT_PROFILES = [
  { value: "top-1000", label: "Top 1000 ports (default)" },
  { value: "top-100", label: "Top 100 ports (faster)" },
  { value: "full", label: "Full port scan (0-65535)" },
  { value: "web", label: "Web ports (80, 443, 8080, 8443…)" },
  { value: "db", label: "Database ports (3306, 5432, 27017…)" },
];

export default function NewScanPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [client, setClient] = useState("");
  const [targetsText, setTargetsText] = useState("");
  const [selectedModules, setSelectedModules] = useState<Set<string>>(
    new Set(["httpx", "tls", "headers", "cors"])
  );
  const [profile, setProfile] = useState("custom");
  const [ports, setPorts] = useState("top-1000");
  const [noSubs, setNoSubs] = useState(false);
  const [passive, setPassive] = useState(false);
  const [rate, setRate] = useState(150);
  const [threads, setThreads] = useState(50);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  if (!loading && !user) {
    router.replace("/login");
    return null;
  }

  const toggleModule = (id: string) => {
    setSelectedModules((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    const all = Object.values(MODULE_GROUPS)
      .flat()
      .map((m) => m.id);
    setSelectedModules(new Set(all));
  };

  const clearAll = () => setSelectedModules(new Set());

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    const targets = targetsText
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (targets.length === 0) {
      setError("Enter at least one target");
      return;
    }

    const isCustom = profile === "custom";
    const modules = isCustom
      ? selectedModules.size > 0
        ? Array.from(selectedModules)
        : ["httpx", "tls", "headers"]
      : [];

    setSubmitting(true);
    try {
      const job = await api.scans.create({
        client: client || targets[0],
        targets,
        modules,
        options: {
          no_subs: noSubs,
          passive,
          ports,
          profile: isCustom ? "" : profile,
          rate,
          threads,
        },
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
        <h1 className="text-2xl font-bold mb-6">New Scan</h1>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Basic Info */}
          <Card>
            <CardHeader>
              <CardTitle>Target</CardTitle>
              <CardDescription>
                One target per line: domains, IPs, or CIDR ranges.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="client">Client Name (optional)</Label>
                <Input
                  id="client"
                  placeholder="acme-corp"
                  value={client}
                  onChange={(e) => setClient(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="targets">Targets *</Label>
                <Textarea
                  id="targets"
                  placeholder="example.com&#10;app.example.com&#10;192.168.1.0/24"
                  rows={4}
                  value={targetsText}
                  onChange={(e) => setTargetsText(e.target.value)}
                  required
                />
              </div>
            </CardContent>
          </Card>

          {/* Scan Profile */}
          <Card>
            <CardHeader>
              <CardTitle>Scan Profile</CardTitle>
              <CardDescription>
                Use a preset profile or select individual modules below.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>Profile</Label>
                <Select value={profile} onValueChange={setProfile}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select profile" />
                  </SelectTrigger>
                  <SelectContent>
                    {PROFILES.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Port Profile</Label>
                <Select value={ports} onValueChange={setPorts}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PORT_PROFILES.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="no-subs"
                  checked={noSubs}
                  onChange={(e) => setNoSubs(e.target.checked)}
                  className="h-4 w-4"
                />
                <Label htmlFor="no-subs" className="cursor-pointer">
                  Skip subdomain enumeration
                </Label>
              </div>

              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="passive"
                  checked={passive}
                  onChange={(e) => setPassive(e.target.checked)}
                  className="h-4 w-4"
                />
                <Label htmlFor="passive" className="cursor-pointer">
                  Passive mode only
                </Label>
              </div>
            </CardContent>
          </Card>

          {/* Module Selector */}
          {profile === "custom" && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Modules</CardTitle>
                    <CardDescription>
                      {selectedModules.size} selected
                    </CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={selectAll}
                    >
                      All
                    </Button>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={clearAll}
                    >
                      Clear
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  {Object.entries(MODULE_GROUPS).map(([group, modules]) => (
                    <div key={group}>
                      <h4 className="text-sm font-semibold text-muted-foreground mb-3">
                        {group}
                      </h4>
                      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                        {modules.map((m) => (
                          <label
                            key={m.id}
                            className={`flex items-center gap-2 rounded-md border px-3 py-2 text-sm cursor-pointer transition-colors ${
                              selectedModules.has(m.id)
                                ? "border-primary bg-primary/10 text-foreground"
                                : "border-border text-muted-foreground hover:border-muted-foreground"
                            }`}
                          >
                            <input
                              type="checkbox"
                              className="h-3.5 w-3.5"
                              checked={selectedModules.has(m.id)}
                              onChange={() => toggleModule(m.id)}
                            />
                            {m.label}
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Advanced */}
          <Card>
            <CardHeader>
              <CardTitle>Performance</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label>Rate (req/s)</Label>
                <Input
                  type="number"
                  min={1}
                  max={500}
                  value={rate}
                  onChange={(e) => setRate(Number(e.target.value))}
                />
              </div>
              <div className="space-y-2">
                <Label>Threads</Label>
                <Input
                  type="number"
                  min={1}
                  max={200}
                  value={threads}
                  onChange={(e) => setThreads(Number(e.target.value))}
                />
              </div>
            </CardContent>
          </Card>

          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}

          <div className="flex gap-3">
            <Button type="submit" disabled={submitting}>
              {submitting ? "Starting…" : "Start Scan"}
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => router.back()}
            >
              Cancel
            </Button>
          </div>
        </form>
      </main>
    </div>
  );
}
