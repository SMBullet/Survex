"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import type { ScanJob } from "@/lib/api";
import {
  Shield, LayoutDashboard, Plus, LogOut,
  Cloud, ChevronDown, Server, Database, Cpu,
  Github, GitBranch, Radar,
} from "lucide-react";

// ── Nav item ─────────────────────────────────────────────────────────────────

function NavItem({
  href, icon, label, active, accent, small, badge,
}: {
  href: string; icon: React.ReactNode; label: string;
  active: boolean; accent?: boolean; small?: boolean; badge?: number;
}) {
  return (
    <Link
      href={href}
      className={`
        group relative flex items-center gap-2.5 rounded-md px-3 transition-all duration-150
        ${small ? "py-1.5 text-[11px]" : "py-2 text-[13px]"}
        ${active
          ? "bg-emerald-500/10 text-emerald-400 font-medium"
          : accent
            ? "text-emerald-500/70 hover:text-emerald-400 hover:bg-emerald-500/8"
            : "text-zinc-500 hover:text-zinc-200 hover:bg-white/5"
        }
      `}
    >
      {/* Active left-border glow */}
      {active && (
        <span className="absolute left-0 top-1/2 -translate-y-1/2 h-[55%] w-[2px] rounded-r-full bg-emerald-400 glow-sm-emerald" />
      )}
      <span className={`shrink-0 ${active ? "text-emerald-400" : accent ? "text-emerald-600" : "text-zinc-600 group-hover:text-zinc-400"}`}>
        {icon}
      </span>
      <span className="truncate flex-1">{label}</span>
      {badge !== undefined && badge > 0 && (
        <span className="ml-auto shrink-0 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-blue-500/20 border border-blue-500/30 px-1 text-[10px] font-bold text-blue-400">
          {badge}
        </span>
      )}
    </Link>
  );
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

export function Sidebar() {
  const { user, logout } = useAuth();
  const pathname  = usePathname();
  const router    = useRouter();
  const [cloudOpen, setCloudOpen]     = useState(false);
  const [activeScans, setActiveScans] = useState(0);

  const fetchActiveScans = useCallback(async () => {
    try {
      const scans: ScanJob[] = await api.scans.list();
      setActiveScans(scans?.filter(s => s.status === "running" || s.status === "queued").length ?? 0);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    if (!user) return;
    fetchActiveScans();
    const t = setInterval(fetchActiveScans, 8000);
    return () => clearInterval(t);
  }, [user, fetchActiveScans]);

  const handleLogout = () => { logout(); router.push("/login"); };

  if (!user) return null;

  const is = (p: string) => pathname === p;
  const sw = (p: string) => pathname.startsWith(p);
  const initials = user.email.slice(0, 2).toUpperCase();

  return (
    <aside className="flex h-screen w-52 shrink-0 flex-col border-r border-white/[0.06] bg-[#060c18]">

      {/* Logo */}
      <div className="flex h-14 items-center gap-3 border-b border-white/[0.06] px-4">
        <div className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
          <Shield className="h-4 w-4 text-emerald-400" />
          {activeScans > 0 && (
            <span className="absolute -right-1 -top-1 flex h-3 w-3 items-center justify-center rounded-full border-2 border-[#060c18] bg-blue-400">
              <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-ping" />
            </span>
          )}
        </div>
        <div className="flex flex-col leading-none gap-0.5">
          <span className="text-[13px] font-bold tracking-widest text-white">SURVEX</span>
          <span className="text-[9px] tracking-widest text-emerald-500/50 font-semibold">ASM PLATFORM</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-4">

        <div>
          <p className="px-3 pb-2 text-[9px] font-bold uppercase tracking-[0.18em] text-zinc-700">Overview</p>
          <div className="space-y-0.5">
            <NavItem href="/dashboard" icon={<LayoutDashboard className="h-3.5 w-3.5" />} label="Dashboard"    active={is("/dashboard")} />
            <NavItem href="/scans/new" icon={<Plus className="h-3.5 w-3.5" />}            label="New Scan"     active={is("/scans/new")} accent />
            <NavItem href="/dashboard" icon={<Radar className="h-3.5 w-3.5" />}           label="Active Scans" active={false} badge={activeScans} />
          </div>
        </div>

        <div className="h-px mx-1 bg-white/[0.05]" />

        <div>
          <p className="px-3 pb-2 text-[9px] font-bold uppercase tracking-[0.18em] text-zinc-700">Discovery</p>
          <div className="space-y-0.5">

            {/* Cloud collapsible */}
            <button
              type="button"
              onClick={() => setCloudOpen(o => !o)}
              className={`w-full flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] transition-all duration-150 ${
                sw("/cloud") ? "bg-emerald-500/10 text-emerald-400 font-medium" : "text-zinc-500 hover:text-zinc-200 hover:bg-white/5"
              }`}
            >
              <Cloud className={`h-3.5 w-3.5 shrink-0 ${sw("/cloud") ? "text-emerald-400" : "text-zinc-600"}`} />
              <span className="flex-1 text-left">Cloud Assets</span>
              <ChevronDown className={`h-3 w-3 shrink-0 text-zinc-600 transition-transform duration-200 ${cloudOpen ? "" : "-rotate-90"}`} />
            </button>

            {cloudOpen && (
              <div className="ml-4 pl-3 space-y-0.5 border-l border-white/[0.05]">
                <NavItem href="/cloud/aws"   icon={<Server className="h-3 w-3" />}   label="AWS"   active={is("/cloud/aws")}   small />
                <NavItem href="/cloud/azure" icon={<Database className="h-3 w-3" />} label="Azure" active={is("/cloud/azure")} small />
                <NavItem href="/cloud/gcp"   icon={<Cpu className="h-3 w-3" />}      label="GCP"   active={is("/cloud/gcp")}   small />
              </div>
            )}

            <NavItem href="/github" icon={<Github className="h-3.5 w-3.5" />}    label="GitHub" active={is("/github")} />
            <NavItem href="/gitlab" icon={<GitBranch className="h-3.5 w-3.5" />} label="GitLab" active={is("/gitlab")} />
          </div>
        </div>
      </nav>

      {/* Footer */}
      <div className="border-t border-white/[0.06] p-3 space-y-2.5">
        {/* Status */}
        <div className="flex items-center gap-2 px-1">
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
          </span>
          <span className="text-[10px] font-bold tracking-widest text-emerald-500/60">SYSTEM ONLINE</span>
        </div>
        {/* User row */}
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-white/10 bg-white/5 text-[11px] font-bold text-zinc-300">
            {initials}
          </div>
          <span className="text-[11px] text-zinc-500 truncate flex-1 font-mono min-w-0" title={user.email}>
            {user.email}
          </span>
          <button
            onClick={handleLogout}
            className="shrink-0 flex h-6 w-6 items-center justify-center rounded-md text-zinc-600 hover:text-red-400 hover:bg-red-500/10 transition-colors"
            title="Sign out"
          >
            <LogOut className="h-3 w-3" />
          </button>
        </div>
      </div>
    </aside>
  );
}
