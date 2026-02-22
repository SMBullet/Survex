"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Server, Database, Cpu, Cloud, Lock, Eye, AlertTriangle, ChevronRight } from "lucide-react";
import Link from "next/link";

const PROVIDERS = [
  {
    id: "aws",
    name: "Amazon Web Services",
    short: "AWS",
    icon: <Server className="h-8 w-8" />,
    color: "text-orange-400",
    bg: "bg-orange-500/10 border-orange-500/20",
    badge: "Coming Soon",
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
    bg: "bg-blue-500/10 border-blue-500/20",
    badge: "Coming Soon",
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
    color: "text-emerald-400",
    bg: "bg-emerald-500/10 border-emerald-500/20",
    badge: "Coming Soon",
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
      <main className="mx-auto max-w-5xl px-6 py-8 space-y-8">
        {/* Header */}
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Cloud className="h-5 w-5" />
            </div>
            <h1 className="text-2xl font-bold">Cloud Asset Discovery</h1>
          </div>
          <p className="text-muted-foreground text-sm">
            Enumerate and assess your cloud infrastructure exposure across AWS, Azure, and GCP.
          </p>
        </div>

        {/* Provider cards */}
        <div className="grid gap-4 lg:grid-cols-3">
          {PROVIDERS.map(p => (
            <div key={p.id} className={`rounded-xl border ${p.bg} p-5 space-y-4 relative flex flex-col`}>
              <Badge className="absolute top-4 right-4 bg-muted text-muted-foreground border-0 text-xs">
                {p.badge}
              </Badge>

              <div className={`${p.color}`}>{p.icon}</div>

              <div>
                <p className="font-semibold text-foreground">{p.name}</p>
                <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{p.description}</p>
              </div>

              <ul className="space-y-1.5 flex-1">
                {p.features.map(f => (
                  <li key={f} className="flex items-start gap-2 text-xs text-muted-foreground">
                    <ChevronRight className="h-3 w-3 mt-0.5 shrink-0 text-muted-foreground/50" />
                    {f}
                  </li>
                ))}
              </ul>

              <Link
                href={p.href}
                className={`flex items-center justify-center gap-1.5 rounded-lg border border-border px-3 py-2 text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-accent/50 transition-colors`}
              >
                Configure {p.short}
                <ChevronRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          ))}
        </div>

        {/* S3 quick scan (already supported) */}
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-5 space-y-3">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-emerald-400" />
            <p className="font-semibold text-sm text-emerald-400">Available Now — Cloud Storage Scan</p>
          </div>
          <p className="text-sm text-muted-foreground">
            S3, GCS, and Azure Blob exposure detection is already available in the standard scan pipeline.
            Use the <span className="font-mono text-xs bg-muted px-1 rounded">s3</span> module when creating a new scan.
          </p>
          <Link
            href="/scans/new"
            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium px-4 py-2 transition-colors"
          >
            Start Cloud Storage Scan
            <ChevronRight className="h-3.5 w-3.5" />
          </Link>
        </div>

        {/* Tips */}
        <div className="rounded-xl border border-border bg-card p-5 space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Security Tips</p>
          <div className="space-y-2">
            {TIPS.map((t, i) => (
              <div key={i} className="flex items-start gap-2.5 text-sm text-muted-foreground">
                <span className="shrink-0 mt-0.5 text-muted-foreground/60">{t.icon}</span>
                {t.text}
              </div>
            ))}
          </div>
        </div>
      </main>
    </AppShell>
  );
}
