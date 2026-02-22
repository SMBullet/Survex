"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, AssetEntry } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import {
  Database, Search, ChevronRight, Loader2,
  Globe, Server, Filter, Download,
} from "lucide-react";

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const TYPE_STYLE: Record<string, { bg: string; text: string; border: string; icon: React.ReactNode }> = {
  subdomain: {
    bg: "bg-primary/10", text: "text-red-400", border: "border-primary/25",
    icon: <Server className="h-3 w-3" />,
  },
  url: {
    bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/25",
    icon: <Globe className="h-3 w-3" />,
  },
};
const DEFAULT_STYLE = {
  bg: "bg-zinc-700/20", text: "text-muted-foreground", border: "border-zinc-700/30",
  icon: <Server className="h-3 w-3" />,
};

export default function AssetsPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [assets, setAssets]       = useState<AssetEntry[]>([]);
  const [fetching, setFetching]   = useState(true);
  const [search, setSearch]       = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | "subdomain" | "url">("all");

  const loadAssets = useCallback(async () => {
    try { setAssets((await api.assets.list()) ?? []); }
    catch { /* ignore */ }
    finally { setFetching(false); }
  }, []);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  useEffect(() => { if (user) loadAssets(); }, [user, loadAssets]);

  const filtered = useMemo(() => {
    let list = assets;
    if (typeFilter !== "all") list = list.filter(a => a.type === typeFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(a =>
        a.asset.toLowerCase().includes(q) || a.client.toLowerCase().includes(q)
      );
    }
    return list;
  }, [assets, typeFilter, search]);

  const exportCSV = () => {
    const rows = [
      ["Asset", "Type", "Client", "First Seen", "Last Seen", "Scan ID"],
      ...filtered.map(a => [a.asset, a.type, a.client, a.first_seen, a.last_seen, a.scan_id]),
    ];
    const csv = rows.map(r => r.map(v => `"${v}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "assets.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const subCount  = assets.filter(a => a.type === "subdomain").length;
  const urlCount  = assets.filter(a => a.type === "url").length;
  const clients   = [...new Set(assets.map(a => a.client))].length;

  if (loading || !user) return null;

  return (
    <AppShell>
      <main className="min-h-screen bg-background bg-dots">
        <div className="mx-auto max-w-6xl px-6 py-8 space-y-6">

          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground/70">
            <span className="hover:text-muted-foreground cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
            <ChevronRight className="h-3 w-3" />
            <span className="text-muted-foreground">Asset Inventory</span>
          </div>

          {/* Header */}
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-card">
                <Database className="h-5 w-5 text-muted-foreground" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-foreground tracking-tight">Asset Inventory</h1>
                <p className="text-[12px] text-muted-foreground/70">All discovered assets across every scan — with first and last seen timestamps.</p>
              </div>
            </div>
            {filtered.length > 0 && (
              <button
                onClick={exportCSV}
                className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 px-3.5 py-2 text-[13px] font-medium text-muted-foreground hover:text-foreground hover:bg-white/[0.06] transition-all"
              >
                <Download className="h-3.5 w-3.5" />
                Export CSV
              </button>
            )}
          </div>

          {/* Stat pills */}
          {!fetching && assets.length > 0 && (
            <div className="flex flex-wrap gap-3">
              <div className="flex items-center gap-2 rounded-lg border border-primary/20 bg-primary/8 px-3.5 py-2">
                <Server className="h-3.5 w-3.5 text-red-400" />
                <span className="text-[13px] font-bold text-red-400 tabular-nums">{subCount}</span>
                <span className="text-[11px] text-red-600 font-medium">Subdomains</span>
              </div>
              <div className="flex items-center gap-2 rounded-lg border border-blue-500/20 bg-blue-500/8 px-3.5 py-2">
                <Globe className="h-3.5 w-3.5 text-blue-400" />
                <span className="text-[13px] font-bold text-blue-400 tabular-nums">{urlCount}</span>
                <span className="text-[11px] text-blue-600 font-medium">Live URLs</span>
              </div>
              <div className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 px-3.5 py-2">
                <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                <span className="text-[13px] font-bold text-foreground/90 tabular-nums">{clients}</span>
                <span className="text-[11px] text-muted-foreground/70 font-medium">Clients</span>
              </div>
            </div>
          )}

          {/* Search + filter bar */}
          {assets.length > 0 && (
            <div className="flex flex-wrap gap-3 items-center">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/70" />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Search assets or clients…"
                  className="w-full rounded-lg border border-border bg-card/90 pl-9 pr-4 py-2.5 text-[13px] text-foreground/90 placeholder:text-muted-foreground/50 focus:outline-none focus:border-primary/40 transition-all"
                />
              </div>
              <div className="flex gap-1.5">
                {(["all", "subdomain", "url"] as const).map(t => (
                  <button
                    key={t}
                    onClick={() => setTypeFilter(t)}
                    className={`rounded-md border px-3 py-2 text-[11px] font-bold transition-all ${
                      typeFilter === t
                        ? "bg-muted/60 border-border/60 text-foreground"
                        : "border-border text-muted-foreground/70 hover:text-muted-foreground hover:bg-muted/40"
                    }`}
                  >
                    {t === "all" ? "All" : t.charAt(0).toUpperCase() + t.slice(1) + "s"}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Table */}
          {fetching ? (
            <div className="flex items-center gap-3 text-muted-foreground/70 text-sm py-12 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" />Loading assets…
            </div>
          ) : assets.length === 0 ? (
            <div className="rounded-xl border border-border bg-card flex flex-col items-center justify-center gap-4 py-20">
              <Database className="h-10 w-10 text-muted-foreground/50" />
              <div className="text-center space-y-1">
                <p className="font-semibold text-foreground">No assets yet</p>
                <p className="text-sm text-muted-foreground">Run scans to discover and track your attack surface assets.</p>
              </div>
            </div>
          ) : filtered.length === 0 ? (
            <div className="rounded-xl border border-border bg-card flex items-center justify-center py-12 text-muted-foreground/70 text-sm">
              No assets match your filter.
            </div>
          ) : (
            <div className="rounded-xl border border-border bg-card/90 overflow-hidden">
              {/* Column headers */}
              <div className="hidden sm:grid sm:grid-cols-[2fr_90px_130px_100px_100px] gap-0 px-5 py-2.5 border-b border-border bg-muted/30">
                {["Asset", "Type", "Client", "First Seen", "Last Seen"].map(h => (
                  <p key={h} className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/50">{h}</p>
                ))}
              </div>

              <div className="divide-y divide-border">
                {filtered.map((a, i) => {
                  const style = TYPE_STYLE[a.type] ?? DEFAULT_STYLE;
                  return (
                    <div key={i} className="hidden sm:grid sm:grid-cols-[2fr_90px_130px_100px_100px] gap-0 px-5 py-3 items-center hover:bg-muted/30 group transition-colors">
                      {/* Asset */}
                      <div className="flex items-center gap-2 min-w-0 pr-3">
                        <span className={`shrink-0 ${style.text}`}>{style.icon}</span>
                        <span className="text-[12px] font-mono text-foreground/90 truncate group-hover:text-foreground transition-colors">{a.asset}</span>
                      </div>
                      {/* Type badge */}
                      <div>
                        <span className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-bold ${style.bg} ${style.text} ${style.border}`}>
                          {a.type}
                        </span>
                      </div>
                      {/* Client */}
                      <div className="min-w-0 pr-2">
                        <span className="text-[11px] text-muted-foreground/70 truncate block">{a.client}</span>
                      </div>
                      {/* First seen */}
                      <div>
                        <span className="text-[11px] text-muted-foreground/50 font-mono">{timeAgo(a.first_seen)}</span>
                      </div>
                      {/* Last seen */}
                      <div>
                        <span className="text-[11px] text-muted-foreground font-mono">{timeAgo(a.last_seen)}</span>
                      </div>
                    </div>
                  );
                })}

                {/* Mobile cards */}
                {filtered.map((a, i) => {
                  const style = TYPE_STYLE[a.type] ?? DEFAULT_STYLE;
                  return (
                    <div key={`m-${i}`} className="sm:hidden flex items-center justify-between px-4 py-3 gap-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`shrink-0 ${style.text}`}>{style.icon}</span>
                        <div className="min-w-0">
                          <p className="text-[12px] font-mono text-foreground/90 truncate">{a.asset}</p>
                          <p className="text-[10px] text-muted-foreground/70">{a.client} · {timeAgo(a.last_seen)}</p>
                        </div>
                      </div>
                      <span className={`shrink-0 inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[10px] font-bold ${style.bg} ${style.text} ${style.border}`}>
                        {a.type}
                      </span>
                    </div>
                  );
                })}
              </div>

              <div className="px-5 py-2.5 border-t border-border bg-muted/10">
                <span className="text-[10px] text-muted-foreground/50">
                  Showing {filtered.length} of {assets.length} assets
                </span>
              </div>
            </div>
          )}

        </div>
      </main>
    </AppShell>
  );
}
