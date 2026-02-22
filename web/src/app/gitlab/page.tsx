"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { AppShell } from "@/components/app-shell";
import { GitBranch, Key, Lock, Code, Globe, ChevronRight, Eye } from "lucide-react";
import Link from "next/link";

const PLANNED = [
  { icon: <Key className="h-4 w-4" />,    label: "Secret Scanning",       desc: "Search GitLab repositories for hardcoded credentials and API keys" },
  { icon: <Lock className="h-4 w-4" />,   label: "Pipeline Exposure",     desc: "Detect CI/CD pipelines that leak environment variables or secrets" },
  { icon: <Code className="h-4 w-4" />,   label: "Internal Code Leaks",   desc: "Find internal infrastructure details in public or misconfigured repos" },
  { icon: <Globe className="h-4 w-4" />,  label: "Domain References",     desc: "Search for your domains across GitLab instance code and issues" },
  { icon: <Eye className="h-4 w-4" />,    label: "Public Project Audit",  desc: "Enumerate public projects on your GitLab instance for misconfigurations" },
];

export default function GitLabPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  if (loading || !user) return null;

  return (
    <AppShell>
      <main className="min-h-screen bg-[#0d0018] bg-dots">
        <div className="mx-auto max-w-3xl px-6 py-8 space-y-6">

          {/* Header */}
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-orange-500/10 text-orange-400 border border-orange-500/20">
              <GitBranch className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">GitLab Exposure Scan</h1>
              <p className="text-sm text-zinc-500">
                Search GitLab repositories for leaked secrets, credentials, and internal code exposures.
              </p>
            </div>
          </div>

          {/* Coming soon banner */}
          <div className="rounded-xl border border-orange-500/20 bg-[#160025]/70 p-6 flex flex-col items-center text-center space-y-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-orange-500/20 bg-orange-500/10">
              <GitBranch className="h-6 w-6 text-orange-400" />
            </div>
            <div>
              <div className="flex items-center justify-center gap-2 mb-2">
                <p className="font-semibold text-lg text-white">Coming Soon</p>
                <span className="text-[11px] font-bold px-2 py-0.5 rounded border bg-orange-500/15 text-orange-400 border-orange-500/25">
                  In Development
                </span>
              </div>
              <p className="text-zinc-500 text-sm max-w-md">
                GitLab scanning is currently in development. It will support both gitlab.com
                and self-hosted GitLab instances via the GitLab REST API.
              </p>
            </div>
          </div>

          {/* Planned features */}
          <div className="rounded-xl border border-white/[0.07] bg-[#160025]/70 p-5 space-y-4">
            <p className="text-xs font-bold text-zinc-600 uppercase tracking-widest">Planned Features</p>
            <div className="space-y-3">
              {PLANNED.map(item => (
                <div key={item.label} className="flex gap-3">
                  <span className="shrink-0 text-zinc-600 mt-0.5">{item.icon}</span>
                  <div>
                    <p className="text-sm font-medium text-zinc-300">{item.label}</p>
                    <p className="text-xs text-zinc-600 mt-0.5">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Use GitHub in the meantime */}
          <div className="rounded-xl border border-white/[0.07] bg-[#160025]/70 p-5 space-y-3">
            <p className="text-sm font-medium text-white">Looking for code exposure scanning now?</p>
            <p className="text-sm text-zinc-500">
              GitHub exposure scanning is available today. Survex can search GitHub for leaked
              secrets, credentials, and internal code references for your domains.
            </p>
            <Link
              href="/github"
              className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-medium px-4 py-2 transition-colors"
            >
              Go to GitHub Scanning
              <ChevronRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </main>
    </AppShell>
  );
}
