"use client";

import { useState } from "react";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
  Github, Search, Key, AlertCircle, ChevronRight,
  Eye, Lock, Code, Globe,
} from "lucide-react";

const WHAT_IT_FINDS = [
  { icon: <Key className="h-4 w-4" />,    label: "API Keys & Tokens",     desc: "Hardcoded credentials, API keys, access tokens in public repos" },
  { icon: <Lock className="h-4 w-4" />,   label: "Secrets & Passwords",   desc: "Passwords, private keys, connection strings accidentally committed" },
  { icon: <Code className="h-4 w-4" />,   label: "Source Code Leaks",     desc: "Internal configs, .env files, infrastructure-as-code with secrets" },
  { icon: <Globe className="h-4 w-4" />,  label: "Internal Endpoints",    desc: "Internal hostnames, IP ranges, staging/dev URLs exposed in code" },
  { icon: <Eye className="h-4 w-4" />,    label: "Employee Accounts",     desc: "Developer repositories that reference your domains or brand" },
];

export default function GitHubPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [targets, setTargets]   = useState("");
  const [client, setClient]     = useState("");
  const [token, setToken]       = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]       = useState("");

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  if (loading || !user) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    const targetList = targets.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (!targetList.length) {
      setError("Enter at least one domain to search.");
      return;
    }

    setSubmitting(true);
    try {
      const job = await api.scans.create({
        client: client || targetList[0],
        targets: targetList,
        modules: ["github"],
        options: {
          no_subs: true,
          github_token: token,
        } as Record<string, unknown>,
      });
      router.push(`/scans/detail?id=${job.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setSubmitting(false);
    }
  };

  return (
    <AppShell>
      <main className="mx-auto max-w-3xl px-6 py-8 space-y-6">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted border border-border">
            <Github className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">GitHub Exposure Scan</h1>
            <p className="text-sm text-muted-foreground">
              Search GitHub for leaked secrets, credentials, and code exposures related to your domains.
            </p>
          </div>
        </div>

        {/* What it finds */}
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {WHAT_IT_FINDS.map(item => (
            <div key={item.label} className="flex gap-3 rounded-lg border border-border bg-card p-3">
              <span className="shrink-0 text-muted-foreground mt-0.5">{item.icon}</span>
              <div>
                <p className="text-sm font-medium">{item.label}</p>
                <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{item.desc}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <section className="rounded-xl border border-border bg-card p-5 space-y-4">
            <h2 className="font-semibold flex items-center gap-2 text-sm">
              <Search className="h-4 w-4 text-emerald-500" />
              Search Parameters
            </h2>

            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label>
                  Target Domains <span className="text-destructive">*</span>
                </Label>
                <Textarea
                  placeholder={"example.com\nacme-corp.com\nmycompany.io"}
                  rows={4}
                  value={targets}
                  onChange={e => setTargets(e.target.value)}
                  className="font-mono text-sm resize-none"
                  required
                />
                <p className="text-xs text-muted-foreground">
                  One domain per line. Survex searches GitHub for code referencing these domains.
                </p>
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label>
                    Client Name <span className="text-muted-foreground font-normal text-xs">(optional)</span>
                  </Label>
                  <Input
                    placeholder="acme-corp"
                    value={client}
                    onChange={e => setClient(e.target.value)}
                  />
                </div>

                <div className="space-y-1.5">
                  <Label className="flex items-center gap-1.5">
                    GitHub Token
                    <span className="text-muted-foreground font-normal text-xs">(recommended)</span>
                  </Label>
                  <Input
                    type="password"
                    placeholder="ghp_…"
                    value={token}
                    onChange={e => setToken(e.target.value)}
                    className="font-mono"
                  />
                </div>
              </div>
            </div>
          </section>

          {/* Token info */}
          <div className="rounded-lg border border-border bg-muted/30 px-4 py-3 space-y-1">
            <div className="flex items-center gap-2 text-sm font-medium">
              <Key className="h-3.5 w-3.5 text-muted-foreground" />
              GitHub Token (optional but recommended)
            </div>
            <p className="text-xs text-muted-foreground">
              Without a token, GitHub limits to 10 requests/minute. A personal access token (no scopes needed)
              gives 30 requests/minute and access to more results.
              <a
                href="https://github.com/settings/tokens/new"
                target="_blank"
                rel="noreferrer"
                className="ml-1 text-blue-400 hover:underline"
              >
                Create one here ↗
              </a>
            </p>
          </div>

          {error && (
            <div className="flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
              <AlertCircle className="h-4 w-4 shrink-0" />{error}
            </div>
          )}

          <div className="flex gap-3">
            <Button
              type="submit"
              disabled={submitting}
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-6 gap-1.5"
            >
              {submitting ? "Starting…" : (
                <>
                  <Search className="h-4 w-4" />
                  Search GitHub
                  <ChevronRight className="h-4 w-4" />
                </>
              )}
            </Button>
            <Button type="button" variant="outline" onClick={() => router.push("/dashboard")}>
              Cancel
            </Button>
          </div>
        </form>

        {/* Rate limit note */}
        <div className="flex items-start gap-2 text-xs text-muted-foreground">
          <Badge variant="outline" className="shrink-0 text-xs">Note</Badge>
          Results depend on GitHub&apos;s code search API. Private repositories are not accessible
          without appropriate repository-scoped tokens.
        </div>
      </main>
    </AppShell>
  );
}
