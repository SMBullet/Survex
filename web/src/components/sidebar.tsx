"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import type { ScanJob } from "@/lib/api";
import {
  Shield, LayoutDashboard, Plus, LogOut,
  Cloud, ChevronDown, Server, Database, Cpu,
  Github, GitBranch, Radar, CalendarClock,
  Settings, Sun, Moon,
} from "lucide-react";

// ── Nav item ──────────────────────────────────────────────────────────────────

function NavItem({
  href, icon, label, active, highlight, small, badge,
}: {
  href: string; icon: React.ReactNode; label: string;
  active: boolean; highlight?: boolean; small?: boolean; badge?: number;
}) {
  return (
    <Link
      href={href}
      className={`
        group relative flex items-center gap-2.5 rounded-lg px-3 transition-all duration-150
        ${small ? "py-1.5 text-[11px]" : "py-2 text-[13px]"}
        ${active
          ? "bg-primary/10 text-primary font-medium"
          : highlight
            ? "text-primary/70 hover:text-primary hover:bg-primary/8"
            : "text-muted-foreground hover:text-foreground hover:bg-muted/60"
        }
      `}
    >
      {active && (
        <span className="absolute left-0 top-1/2 -translate-y-1/2 h-[55%] w-[2.5px] rounded-r-full bg-primary" />
      )}
      <span className={`shrink-0 transition-colors ${
        active     ? "text-primary"
        : highlight ? "text-primary/60"
        :             "text-muted-foreground/60 group-hover:text-muted-foreground"
      }`}>
        {icon}
      </span>
      <span className="truncate flex-1">{label}</span>
      {badge !== undefined && badge > 0 && (
        <span className="ml-auto shrink-0 flex h-[18px] min-w-[18px] items-center justify-center rounded-full bg-primary/15 border border-primary/25 px-1.5 text-[10px] font-bold text-primary">
          {badge}
        </span>
      )}
    </Link>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="px-3 pb-1.5 pt-0.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground/50 select-none">
      {children}
    </p>
  );
}

function Divider() {
  return <div className="mx-2 my-1 h-px bg-border" />;
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

export function Sidebar() {
  const { user, logout }    = useAuth();
  const pathname            = usePathname();
  const router              = useRouter();
  const { theme, setTheme } = useTheme();
  const [mounted,     setMounted]     = useState(false);
  const [cloudOpen,   setCloudOpen]   = useState(false);
  const [activeScans, setActiveScans] = useState(0);

  useEffect(() => setMounted(true), []);

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
    <aside className="flex h-screen w-[210px] shrink-0 flex-col border-r border-sidebar-border bg-sidebar">

      {/* Logo */}
      <div className="flex h-[54px] items-center gap-3 border-b border-sidebar-border px-4">
        <div className="relative flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10 border border-primary/20">
          <Shield className="h-4 w-4 text-primary" />
          {activeScans > 0 && (
            <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full border-2 border-sidebar bg-primary" />
          )}
        </div>
        <div className="flex flex-col leading-none gap-0.5">
          <span className="text-[13px] font-bold tracking-widest text-foreground">SURVEX</span>
          <span className="text-[9px] tracking-widest text-muted-foreground/50 font-medium">ASM PLATFORM</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-3">

        <div>
          <SectionLabel>Overview</SectionLabel>
          <div className="space-y-0.5">
            <NavItem href="/dashboard" icon={<LayoutDashboard className="h-3.5 w-3.5" />} label="Dashboard"    active={is("/dashboard")} />
            <NavItem href="/scans/new" icon={<Plus           className="h-3.5 w-3.5" />} label="New Scan"     active={is("/scans/new")} highlight />
            <NavItem href="/dashboard" icon={<Radar          className="h-3.5 w-3.5" />} label="Active Scans" active={false} badge={activeScans} />
          </div>
        </div>

        <Divider />

        <div>
          <SectionLabel>Intelligence</SectionLabel>
          <div className="space-y-0.5">
            <NavItem href="/assets"    icon={<Database      className="h-3.5 w-3.5" />} label="Asset Inventory" active={sw("/assets")} />
            <NavItem href="/schedules" icon={<CalendarClock className="h-3.5 w-3.5" />} label="Schedules"       active={sw("/schedules")} />
          </div>
        </div>

        <Divider />

        <div>
          <SectionLabel>Discovery</SectionLabel>
          <div className="space-y-0.5">

            <button
              type="button"
              onClick={() => setCloudOpen(o => !o)}
              className={`w-full flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition-all duration-150 ${
                sw("/cloud")
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/60"
              }`}
            >
              <Cloud className={`h-3.5 w-3.5 shrink-0 ${sw("/cloud") ? "text-primary" : "text-muted-foreground/60"}`} />
              <span className="flex-1 text-left">Cloud Assets</span>
              <ChevronDown className={`h-3 w-3 shrink-0 text-muted-foreground/40 transition-transform duration-200 ${cloudOpen ? "" : "-rotate-90"}`} />
            </button>

            {cloudOpen && (
              <div className="ml-4 pl-2.5 space-y-0.5 border-l border-border">
                <NavItem href="/cloud/aws"   icon={<Server   className="h-3 w-3" />} label="AWS"   active={is("/cloud/aws")}   small />
                <NavItem href="/cloud/azure" icon={<Database className="h-3 w-3" />} label="Azure" active={is("/cloud/azure")} small />
                <NavItem href="/cloud/gcp"   icon={<Cpu      className="h-3 w-3" />} label="GCP"   active={is("/cloud/gcp")}   small />
              </div>
            )}

            <NavItem href="/github" icon={<Github    className="h-3.5 w-3.5" />} label="GitHub" active={is("/github")} />
            <NavItem href="/gitlab" icon={<GitBranch className="h-3.5 w-3.5" />} label="GitLab" active={is("/gitlab")} />
          </div>
        </div>

        <Divider />

        <div>
          <SectionLabel>Platform</SectionLabel>
          <div className="space-y-0.5">
            <NavItem href="/settings" icon={<Settings className="h-3.5 w-3.5" />} label="Settings" active={sw("/settings")} />
          </div>
        </div>

      </nav>

      {/* Footer */}
      <div className="border-t border-sidebar-border p-3 space-y-2">

        {/* Theme toggle — full row, clearly visible */}
        {mounted && (
          <button
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            className="w-full flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors"
          >
            {theme === "dark"
              ? <Sun  className="h-3.5 w-3.5 shrink-0 text-primary" />
              : <Moon className="h-3.5 w-3.5 shrink-0 text-primary" />
            }
            <span className="flex-1 text-left">
              {theme === "dark" ? "Light mode" : "Dark mode"}
            </span>
            <span className="text-[10px] text-muted-foreground/40 font-mono">
              {theme === "dark" ? "☀" : "🌙"}
            </span>
          </button>
        )}

        {/* User row */}
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/12 border border-primary/20 text-[11px] font-bold text-primary">
            {initials}
          </div>
          <span className="flex-1 min-w-0 text-[11px] text-muted-foreground truncate font-mono" title={user.email}>
            {user.email}
          </span>
          <button
            onClick={handleLogout}
            className="shrink-0 flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground/60 hover:text-destructive hover:bg-destructive/8 transition-colors"
            title="Sign out"
          >
            <LogOut className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </aside>
  );
}
