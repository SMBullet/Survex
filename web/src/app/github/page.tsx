"use client";

import { useState } from "react";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import {
  Github, Search, Key, AlertCircle, ChevronRight,
  Eye, Lock, Code, Globe, Loader2,
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

  const [targets, setTargets]       = useState("");
  const [client, setClient]         = useState("");
  const [token, setToken]           = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError]           = useState("");

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
      <main className="min-h-screen bg-background bg-dots">
        <div className="mx-auto max-w-3xl px-6 py-8 space-y-6">

          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground/60">
            <span className="hover:text-muted-foreground cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
            <ChevronRight className="h-3 w-3" />
            <span className="text-muted-foreground">GitHub Scanning</span>
          </div>

          {/* Header */}
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-card">
              <Github className="h-5 w-5 text-foreground/80" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-foreground tracking-tight">GitHub Exposure Scan</h1>
              <p className="text-[12px] text-muted-foreground/60">Search GitHub for leaked secrets, credentials, and code exposures related to your domains.</p>
            </div>
          </div>

          {/* What it finds */}
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {WHAT_IT_FINDS.map(item => (
              <div key={item.label} className="flex gap-3 rounded-lg border border-border bg-card/90 p-3 hover:border-red-500/15 hover:bg-red-500/4 transition-all">
                <span className="shrink-0 text-muted-foreground/60 mt-0.5">{item.icon}</span>
                <div>
                  <p className="text-[13px] font-medium text-foreground/80">{item.label}</p>
                  <p className="text-[11px] text-muted-foreground/60 mt-0.5 leading-relaxed">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <section className="rounded-xl border border-border bg-card overflow-hidden">
              <div className="flex items-center gap-2.5 border-b border-border bg-muted/20 px-5 py-3">
                <Search className="h-4 w-4 text-red-400" />
                <span className="text-[13px] font-semibold text-foreground">Search Parameters</span>
              </div>
              <div className="p-5 space-y-4">

                <div className="space-y-1.5">
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                    Target Domains <span className="text-red-500">*</span>
                  </label>
                  <textarea
                    placeholder={"example.com\nacme-corp.com\nmycompany.io"}
                    rows={4}
                    value={targets}
                    onChange={e => setTargets(e.target.value)}
                    className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[13px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all resize-none"
                    required
                  />
                  <p className="text-[11px] text-muted-foreground/40">
                    One domain per line. Survex searches GitHub for code referencing these domains.
                  </p>
                </div>

                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                      Client Name <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(optional)</span>
                    </label>
                    <input
                      type="text"
                      placeholder="acme-corp"
                      value={client}
                      onChange={e => setClient(e.target.value)}
                      className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 text-[13px] text-foreground/80 placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all"
                    />
                  </div>

                  <div className="space-y-1.5">
                    <label className="block text-[11px] font-bold uppercase tracking-widest text-muted-foreground/60">
                      GitHub Token <span className="text-muted-foreground/40 font-normal normal-case tracking-normal">(recommended)</span>
                    </label>
                    <input
                      type="password"
                      placeholder="ghp_…"
                      value={token}
                      onChange={e => setToken(e.target.value)}
                      className="w-full rounded-lg border border-border bg-secondary px-3.5 py-2.5 font-mono text-[13px] text-foreground/80 placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/50 transition-all"
                    />
                  </div>
                </div>

              </div>
            </section>

            {/* Token info */}
            <div className="rounded-lg border border-amber-500/15 bg-amber-500/5 px-4 py-3 space-y-1">
              <div className="flex items-center gap-2 text-sm font-medium text-amber-400">
                <Key className="h-3.5 w-3.5" />
                GitHub Token (optional but recommended)
              </div>
              <p className="text-[12px] text-muted-foreground">
                Without a token, GitHub limits to 10 requests/minute. A personal access token (no scopes needed)
                gives 30 requests/minute and access to more results. You can also set a global token in{" "}
                <span
                  className="text-red-400 cursor-pointer hover:underline"
                  onClick={() => router.push("/settings")}
                >
                  Settings
                </span>{" "}
                and it will auto-inject into every scan.
              </p>
            </div>

            {error && (
              <div className="flex items-center gap-2.5 rounded-lg border border-red-500/20 bg-red-500/8 px-4 py-3 text-sm text-red-400">
                <AlertCircle className="h-4 w-4 shrink-0" />{error}
              </div>
            )}

            <div className="flex gap-3">
              <button
                type="submit"
                disabled={submitting}
                className="flex items-center gap-2 rounded-lg bg-primary hover:bg-primary/90 disabled:opacity-50 px-6 py-2.5 text-sm font-semibold text-primary-foreground transition-all"
              >
                {submitting ? (
                  <><Loader2 className="h-3.5 w-3.5 animate-spin" />Starting…</>
                ) : (
                  <><Search className="h-4 w-4" />Search GitHub<ChevronRight className="h-4 w-4" /></>
                )}
              </button>
              <button
                type="button"
                onClick={() => router.push("/dashboard")}
                className="rounded-lg border border-border px-5 py-2.5 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/40 transition-all"
              >
                Cancel
              </button>
            </div>
          </form>

          {/* Note */}
          <p className="text-[11px] text-muted-foreground/40 border-t border-border pt-4">
            <span className="font-bold text-muted-foreground/60">Note:</span> Results depend on GitHub&apos;s code search API.
            Private repositories are not accessible without appropriate repository-scoped tokens.
          </p>
        </div>
      </main>
    </AppShell>
  );
}
