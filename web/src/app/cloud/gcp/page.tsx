"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { AppShell } from "@/components/app-shell";
import { Cpu, ChevronRight } from "lucide-react";
import Link from "next/link";

export default function GCPPage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  if (loading || !user) return null;

  return (
    <AppShell>
      <main className="mx-auto max-w-3xl px-6 py-8 space-y-6">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Cpu className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">GCP Asset Discovery</h1>
            <p className="text-sm text-muted-foreground">Google Cloud Platform enumeration and exposure detection</p>
          </div>
        </div>

        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-8 text-center space-y-4">
          <Cpu className="h-12 w-12 text-emerald-400/60 mx-auto" />
          <div>
            <p className="font-semibold text-lg">Coming Soon</p>
            <p className="text-muted-foreground text-sm mt-2 max-w-md mx-auto">
              GCS bucket enumeration, Cloud Run / App Engine exposure, BigQuery public
              dataset detection, and Firebase misconfiguration scanning.
            </p>
          </div>
          <Link
            href="/cloud"
            className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"
          >
            <ChevronRight className="h-3.5 w-3.5 rotate-180" />
            Back to Cloud Overview
          </Link>
        </div>
      </main>
    </AppShell>
  );
}
