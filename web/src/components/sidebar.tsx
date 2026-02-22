"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import {
  Shield, LayoutDashboard, Plus, LogOut, Sun, Moon,
  Cloud, ChevronDown, ChevronRight, Server, Database, Cpu,
  Github, GitBranch, Activity,
} from "lucide-react";

function NavItem({
  href, icon, label, active, accent, small,
}: {
  href: string; icon: React.ReactNode; label: string;
  active: boolean; accent?: boolean; small?: boolean;
}) {
  return (
    <Link
      href={href}
      className={`flex items-center gap-2 rounded-md px-2 transition-colors
        ${small ? "py-1 text-xs" : "py-1.5 text-sm"}
        ${active
          ? "bg-accent text-accent-foreground font-medium"
          : accent
            ? "text-emerald-500 hover:text-emerald-400 hover:bg-emerald-500/10"
            : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
        }`}
    >
      {icon}
      {label}
    </Link>
  );
}

export function Sidebar() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const { theme, setTheme } = useTheme();
  const [cloudOpen, setCloudOpen] = useState(false);

  const handleLogout = () => {
    logout();
    router.push("/login");
  };

  if (!user) return null;

  const is = (path: string) => pathname === path;
  const startsWith = (path: string) => pathname.startsWith(path);

  return (
    <aside className="flex h-screen w-56 shrink-0 flex-col border-r border-border bg-card">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 border-b border-border px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-emerald-500 text-white">
          <Shield className="h-4 w-4" />
        </div>
        <span className="font-bold tracking-tight text-foreground">Survex</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-4">

        {/* Main */}
        <div className="space-y-0.5">
          <p className="px-2 mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/50">
            Main
          </p>
          <NavItem
            href="/dashboard"
            icon={<LayoutDashboard className="h-4 w-4" />}
            label="Dashboard"
            active={is("/dashboard")}
          />
          <NavItem
            href="/scans/new"
            icon={<Plus className="h-4 w-4" />}
            label="New Scan"
            active={is("/scans/new")}
            accent
          />
        </div>

        {/* Discovery */}
        <div className="space-y-0.5">
          <p className="px-2 mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/50">
            Discovery
          </p>

          {/* Cloud collapsible */}
          <button
            type="button"
            onClick={() => setCloudOpen(o => !o)}
            className={`w-full flex items-center justify-between rounded-md px-2 py-1.5 text-sm transition-colors
              ${startsWith("/cloud")
                ? "bg-accent text-accent-foreground font-medium"
                : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
              }`}
          >
            <span className="flex items-center gap-2">
              <Cloud className="h-4 w-4" />
              Cloud Assets
            </span>
            {cloudOpen
              ? <ChevronDown className="h-3 w-3 shrink-0" />
              : <ChevronRight className="h-3 w-3 shrink-0" />
            }
          </button>

          {cloudOpen && (
            <div className="ml-5 space-y-0.5 border-l border-border pl-2">
              <NavItem href="/cloud/aws"   icon={<Server className="h-3.5 w-3.5" />}   label="AWS"   active={is("/cloud/aws")}   small />
              <NavItem href="/cloud/azure" icon={<Database className="h-3.5 w-3.5" />} label="Azure" active={is("/cloud/azure")} small />
              <NavItem href="/cloud/gcp"   icon={<Cpu className="h-3.5 w-3.5" />}      label="GCP"   active={is("/cloud/gcp")}   small />
            </div>
          )}

          <NavItem
            href="/github"
            icon={<Github className="h-4 w-4" />}
            label="GitHub"
            active={is("/github")}
          />
          <NavItem
            href="/gitlab"
            icon={<GitBranch className="h-4 w-4" />}
            label="GitLab"
            active={is("/gitlab")}
          />
        </div>

        {/* Active Scans indicator */}
        <div className="space-y-0.5">
          <p className="px-2 mb-2 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/50">
            Scanning
          </p>
          <NavItem
            href="/dashboard"
            icon={<Activity className="h-4 w-4" />}
            label="All Scans"
            active={false}
          />
        </div>
      </nav>

      {/* Bottom bar */}
      <div className="border-t border-border p-3">
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground truncate max-w-[110px]" title={user.email}>
            {user.email}
          </span>
          <div className="flex items-center gap-0.5">
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
              aria-label="Toggle theme"
            >
              <Sun className="h-3.5 w-3.5 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
              <Moon className="absolute h-3.5 w-3.5 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={handleLogout}
              aria-label="Sign out"
            >
              <LogOut className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </div>
    </aside>
  );
}
