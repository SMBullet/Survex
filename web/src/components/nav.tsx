"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Shield, Plus, LogOut } from "lucide-react";

export function Nav() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  const handleLogout = () => {
    logout();
    router.push("/login");
  };

  if (!user) return null;

  return (
    <header className="border-b border-border bg-card">
      <div className="mx-auto flex h-14 max-w-7xl items-center justify-between px-4">
        <div className="flex items-center gap-6">
          <Link
            href="/dashboard"
            className="flex items-center gap-2 font-semibold"
          >
            <Shield className="h-5 w-5 text-primary" />
            <span>Survex</span>
          </Link>
          <nav className="flex gap-4 text-sm">
            <Link
              href="/dashboard"
              className={
                pathname === "/dashboard"
                  ? "text-foreground font-medium"
                  : "text-muted-foreground hover:text-foreground"
              }
            >
              Scans
            </Link>
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" asChild>
            <Link href="/scans/new">
              <Plus className="h-4 w-4 mr-1" />
              New Scan
            </Link>
          </Button>
          <span className="text-sm text-muted-foreground hidden sm:block">
            {user.email}
          </span>
          <Button variant="ghost" size="icon" onClick={handleLogout}>
            <LogOut className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </header>
  );
}
