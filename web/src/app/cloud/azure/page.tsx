"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { AppShell } from "@/components/app-shell";
import { Database, ChevronRight } from "lucide-react";
import Link from "next/link";

export default function AzurePage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  if (loading || !user) return null;

  return (
    <AppShell>
      <main className="min-h-screen bg-[#0d0018] bg-dots">
        <div className="mx-auto max-w-3xl px-6 py-8 space-y-6">

          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs text-zinc-600">
            <Link href="/cloud" className="hover:text-zinc-400 transition-colors">Cloud</Link>
            <ChevronRight className="h-3 w-3" />
            <span className="text-zinc-400">Azure</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Azure Asset Discovery</h1>
              <p className="text-sm text-zinc-500">Microsoft Azure enumeration and exposure detection</p>
            </div>
          </div>

          <div className="rounded-xl border border-blue-500/20 bg-[#160025]/70 p-8 text-center space-y-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-blue-500/20 bg-blue-500/8 mx-auto">
              <Database className="h-8 w-8 text-blue-400/60" />
            </div>
            <div>
              <p className="font-semibold text-lg text-white">Coming Soon</p>
              <p className="text-zinc-500 text-sm mt-2 max-w-md mx-auto">
                Azure Blob Storage enumeration, App Service exposure detection,
                Azure SQL public endpoints, and AD application discovery.
              </p>
            </div>
            <div className="flex flex-wrap gap-2 justify-center">
              {["Blob Storage", "App Services", "Azure SQL", "AD Apps", "Function URLs"].map(f => (
                <span key={f} className="rounded-md border border-blue-500/15 bg-blue-500/5 px-3 py-1 text-[12px] text-blue-400/70 font-medium">
                  {f}
                </span>
              ))}
            </div>
            <Link
              href="/cloud"
              className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              <ChevronRight className="h-3.5 w-3.5 rotate-180" />
              Back to Cloud Overview
            </Link>
          </div>
        </div>
      </main>
    </AppShell>
  );
}
