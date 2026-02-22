"use client";

import { Sidebar } from "@/components/sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen overflow-hidden bg-[#0d0018]">
      <Sidebar />
      <div className="flex-1 overflow-y-auto">
        {children}
      </div>
    </div>
  );
}
