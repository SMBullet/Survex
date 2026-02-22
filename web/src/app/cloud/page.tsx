"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { AppShell } from "@/components/app-shell";
import { Server, Database, Cpu, Cloud, Lock, Eye, AlertTriangle, ChevronRight } from "lucide-react";
import Link from "next/link";

const PROVIDERS = [
  {
    id: "aws",
    name: "Amazon Web Services",
    short: "AWS",
    icon: <Server className="h-8 w-8" />,
    color: "text-orange-400",
    border: "border-orange-500/20",
    bg: "bg-orange-500/8",
    badge: "Coming Soon",
    badgeColor: "bg-orange-500/15 text-orange-400 border-orange-500/25",
    href: "/cloud/aws",
    description: "Enumerate exposed S3 buckets, EC2 instances, RDS endpoints, Lambda function URLs, and misconfigured IAM roles across your AWS footprint.",
    features: [
      "S3 bucket public exposure check",
      "EC2 public IP enumeration",
      "RDS / Elasticsearch endpoint detection",
      "CloudFront distribution mapping",
      "IAM misconfiguration detection",
    ],
  },
  {
    id: "azure",
    name: "Microsoft Azure",
    short: "Azure",
    icon: <Database className="h-8 w-8" />,
    color: "text-blue-400",
    border: "border-blue-500/20",
    bg: "bg-blue-500/8",
    badge: "Coming Soon",
    badgeColor: "bg-blue-500/15 text-blue-400 border-blue-500/25",
    href: "/cloud/azure",
    description: "Discover exposed Azure Blob Storage containers, App Services, Azure SQL databases, and Key Vault misconfigurations.",
    features: [
      "Blob Storage container enumeration",
      "App Service / Function App exposure",
      "Azure SQL public endpoint check",
      "Storage Account misconfiguration",
      "Azure AD app registration exposure",
    ],
  },
  {
    id: "gcp",
    name: "Google Cloud Platform",
    short: "GCP",
    icon: <Cpu className="h-8 w-8" />,
    color: "text-violet-400",
    border: "border-violet-500/20",
    bg: "bg-violet-500/8",
    badge: "Coming Soon",
    badgeColor: "bg-violet-500/15 text-violet-400 border-violet-500/25",
    href: "/cloud/gcp",
    description: "Find publicly accessible GCS buckets, Cloud Run services, BigQuery datasets, and misconfigured Firebase endpoints.",
    features: [
      "GCS bucket public access detection",
      "Cloud Run / App Engine exposure",
      "BigQuery public dataset check",
      "Firebase / Firestore misconfiguration",
      "Cloud Functions URL enumeration",
    ],
  },
];

const TIPS = [
  { icon: <Lock className="h-4 w-4" />, text: "Always rotate credentials if secrets are found in public storage" },
  { icon: <Eye className="h-4 w-4" />, text: "Enable versioning on S3/GCS buckets to track accidental exposure" },
  { icon: <AlertTriangle className="h-4 w-4" />, text: "Restrict CORS on cloud storage to your known origins only" },
];

export default function CloudPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  if (loading || !user) return null;

  return (
    <AppShell>
      <main className="min-h-screen bg-[#0d0018] bg-dots">
        <div className="mx-auto max-w-5xl px-6 py-8 space-y-8">

          {/* Header */}
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <Cloud className="h-5 w-5" />
              </div>
              <h1 className="text-2xl font-bold text-white">Cloud Asset Discovery</h1>
            </div>
            <p className="text-zinc-500 text-sm">
              Enumerate and assess your cloud infrastructure exposure across AWS, Azure, and GCP.
            </p>
          </div>

          {/* Provider cards */}
          <div className="grid gap-4 lg:grid-cols-3">
            {PROVIDERS.map(p => (
              <div key={p.id} className={`rounded-xl border ${p.border} ${p.bg} bg-[#160025]/60 p-5 space-y-4 relative flex flex-col`}>
                <span className={`absolute top-4 right-4 text-[10px] font-bold px-2 py-0.5 rounded border ${p.badgeColor}`}>
                  {p.badge}
                </span>

                <div className={p.color}>{p.icon}</div>

                <div>
                  <p className="font-semibold text-white">{p.name}</p>
                  <p className="text-xs text-zinc-500 mt-1 leading-relaxed">{p.description}</p>
                </div>

                <ul className="space-y-1.5 flex-1">
                  {p.features.map(f => (
                    <li key={f} className="flex items-start gap-2 text-xs text-zinc-600">
                      <ChevronRight className="h-3 w-3 mt-0.5 shrink-0 text-zinc-700" />
                      {f}
                    </li>
                  ))}
                </ul>

                <Link
                  href={p.href}
                  className="flex items-center justify-center gap-1.5 rounded-lg border border-white/[0.07] bg-white/[0.03] px-3 py-2 text-sm font-medium text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.06] transition-colors"
                >
                  Configure {p.short}
                  <ChevronRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            ))}
          </div>

          {/* Cloud storage scan — already available */}
          <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-5 space-y-3">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-red-400 animate-pulse" />
              <p className="font-semibold text-sm text-red-400">Available Now — Cloud Storage Scan</p>
            </div>
            <p className="text-sm text-zinc-500">
              S3, GCS, and Azure Blob exposure detection is already available in the standard scan pipeline.
              Use the <span className="font-mono text-xs bg-white/5 border border-white/[0.07] px-1.5 py-0.5 rounded text-zinc-300">s3</span> module when creating a new scan.
            </p>
            <Link
              href="/scans/new"
              className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-medium px-4 py-2 transition-colors"
            >
              Start Cloud Storage Scan
              <ChevronRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          {/* Tips */}
          <div className="rounded-xl border border-white/[0.07] bg-[#160025]/70 p-5 space-y-3">
            <p className="text-xs font-bold text-zinc-600 uppercase tracking-widest">Security Tips</p>
            <div className="space-y-2">
              {TIPS.map((t, i) => (
                <div key={i} className="flex items-start gap-2.5 text-sm text-zinc-500">
                  <span className="shrink-0 mt-0.5 text-zinc-700">{t.icon}</span>
                  {t.text}
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </AppShell>
  );
}
