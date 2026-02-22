"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Shield, Plus, LogOut, Sun, Moon, ChevronRight } from "lucide-react";

export function Nav() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const { theme, setTheme } = useTheme();

  const handleLogout = () => {
    logout();
    router.push("/login");
  };

  if (!user) return null;

  return (
    <header className="sticky top-0 z-50 border-b border-border/60 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/80">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4">
        {/* Logo + nav */}
        <div className="flex items-center gap-6">
          <Link href="/dashboard" className="flex items-center gap-2 font-bold tracking-tight">
            <div className="flex h-7 w-7 items-center justify-center rounded-md bg-red-600 text-white">
              <Shield className="h-4 w-4" />
            </div>
            <span>Survex</span>
          </Link>

          <nav className="hidden sm:flex items-center gap-1 text-sm">
            <Link
              href="/dashboard"
              className={`rounded-md px-3 py-1.5 transition-colors ${
                pathname === "/dashboard"
                  ? "bg-accent text-accent-foreground font-medium"
                  : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
              }`}
            >
              Scans
            </Link>
          </nav>
        </div>

        {/* Right side */}
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            className="hidden sm:flex items-center gap-1.5 font-medium"
            asChild
          >
            <Link href="/scans/new">
              <Plus className="h-3.5 w-3.5" />
              New Scan
            </Link>
          </Button>

          {/* Theme toggle */}
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label="Toggle theme"
          >
            <Sun className="h-4 w-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
            <Moon className="absolute h-4 w-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
          </Button>

          {/* User + logout */}
          <div className="hidden sm:flex items-center gap-1 text-sm text-muted-foreground">
            <ChevronRight className="h-3 w-3" />
            <span>{user.email}</span>
          </div>
          <Button variant="ghost" size="icon" onClick={handleLogout} aria-label="Sign out">
            <LogOut className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </header>
  );
}
