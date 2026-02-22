"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, Schedule } from "@/lib/api";
import { AppShell } from "@/components/app-shell";
import {
  CalendarClock, Plus, Trash2, ToggleLeft, ToggleRight,
  Loader2, ChevronRight, Clock, Target, Play, Pause,
  AlertCircle,
} from "lucide-react";

const INTERVALS = [
  { h: 6,   label: "Every 6 hours" },
  { h: 12,  label: "Every 12 hours" },
  { h: 24,  label: "Daily" },
  { h: 48,  label: "Every 2 days" },
  { h: 72,  label: "Every 3 days" },
  { h: 168, label: "Weekly" },
];

function formatNextRun(iso: string) {
  const d = new Date(iso);
  const diff = d.getTime() - Date.now();
  if (diff <= 0) return "due now";
  const h = Math.floor(diff / 3600000);
  if (h < 1) return `in ${Math.floor(diff / 60000)}m`;
  if (h < 24) return `in ${h}h`;
  return `in ${Math.floor(h / 24)}d`;
}

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1)  return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function SchedulesPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [fetching, setFetching]   = useState(true);
  const [showForm, setShowForm]   = useState(false);

  // New schedule form state
  const [formClient,   setFormClient]   = useState("");
  const [formTargets,  setFormTargets]  = useState("");
  const [formModules,  setFormModules]  = useState("httpx,tls,headers,cors,nuclei");
  const [formInterval, setFormInterval] = useState(24);
  const [creating,     setCreating]     = useState(false);
  const [formError,    setFormError]    = useState("");

  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const loadSchedules = useCallback(async () => {
    try { setSchedules((await api.schedules.list()) ?? []); }
    catch { /* ignore */ }
    finally { setFetching(false); }
  }, []);

  useEffect(() => { if (!loading && !user) router.replace("/login"); }, [user, loading, router]);
  useEffect(() => { if (user) loadSchedules(); }, [user, loadSchedules]);

  const handleCreate = async () => {
    if (!formTargets.trim()) { setFormError("At least one target required"); return; }
    setCreating(true);
    setFormError("");
    try {
      const targets = formTargets.split(/[\n,]/).map(t => t.trim()).filter(Boolean);
      const modules = formModules.split(",").map(m => m.trim()).filter(Boolean);
      const s = await api.schedules.create({
        client:     formClient || targets[0],
        targets,
        modules,
        interval_h: formInterval,
      });
      setSchedules(prev => [s, ...prev]);
      setShowForm(false);
      setFormClient("");
      setFormTargets("");
      setFormModules("httpx,tls,headers,cors,nuclei");
      setFormInterval(24);
    } catch (e: unknown) {
      setFormError(e instanceof Error ? e.message : "Create failed");
    } finally {
      setCreating(false);
    }
  };

  const handleToggle = async (s: Schedule) => {
    setTogglingId(s.id);
    try {
      await api.schedules.toggle(s.id, !s.enabled);
      setSchedules(prev => prev.map(x => x.id === s.id ? { ...x, enabled: !s.enabled } : x));
    } catch { /* ignore */ }
    finally { setTogglingId(null); }
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    try {
      await api.schedules.delete(id);
      setSchedules(prev => prev.filter(x => x.id !== id));
    } catch { /* ignore */ }
    finally { setDeletingId(null); }
  };

  if (loading || !user) return null;

  return (
    <AppShell>
      <main className="min-h-screen bg-[#0d0018] bg-dots">
        <div className="mx-auto max-w-4xl px-6 py-8 space-y-6">

          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs text-zinc-600">
            <span className="hover:text-zinc-400 cursor-pointer" onClick={() => router.push("/dashboard")}>Dashboard</span>
            <ChevronRight className="h-3 w-3" />
            <span className="text-zinc-400">Schedules</span>
          </div>

          {/* Header */}
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/[0.08] bg-[#160025]">
                <CalendarClock className="h-5 w-5 text-zinc-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-white tracking-tight">Recurring Scans</h1>
                <p className="text-[12px] text-zinc-600">Automated scans that run on a schedule and alert you to changes.</p>
              </div>
            </div>
            <button
              onClick={() => setShowForm(s => !s)}
              className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 px-4 py-2 text-sm font-semibold text-white transition-colors"
            >
              <Plus className="h-4 w-4" />
              New Schedule
            </button>
          </div>

          {/* Create form */}
          {showForm && (
            <div className="rounded-xl border border-red-500/20 bg-[#160025]/80 overflow-hidden">
              <div className="px-5 py-3.5 border-b border-white/[0.05] bg-red-500/[0.03]">
                <span className="text-[13px] font-semibold text-white">New Recurring Scan</span>
              </div>
              <div className="p-5 space-y-4">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <label className="block text-[11px] font-bold uppercase tracking-widest text-zinc-600">Client Name</label>
                    <input
                      value={formClient}
                      onChange={e => setFormClient(e.target.value)}
                      placeholder="e.g. acme-corp"
                      className="w-full rounded-lg border border-white/[0.08] bg-[#0a0014] px-3.5 py-2.5 text-[13px] text-zinc-200 placeholder:text-zinc-700 focus:outline-none focus:border-red-500/40 transition-all"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="block text-[11px] font-bold uppercase tracking-widest text-zinc-600">Interval</label>
                    <select
                      value={formInterval}
                      onChange={e => setFormInterval(Number(e.target.value))}
                      className="w-full rounded-lg border border-white/[0.08] bg-[#0a0014] px-3.5 py-2.5 text-[13px] text-zinc-200 focus:outline-none focus:border-red-500/40 transition-all"
                    >
                      {INTERVALS.map(iv => (
                        <option key={iv.h} value={iv.h}>{iv.label}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-zinc-600">Targets</label>
                  <textarea
                    value={formTargets}
                    onChange={e => setFormTargets(e.target.value)}
                    placeholder="example.com&#10;app.example.com"
                    rows={3}
                    className="w-full rounded-lg border border-white/[0.08] bg-[#0a0014] px-3.5 py-2.5 text-[13px] font-mono text-zinc-200 placeholder:text-zinc-700 focus:outline-none focus:border-red-500/40 transition-all resize-none"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="block text-[11px] font-bold uppercase tracking-widest text-zinc-600">Modules (comma-separated)</label>
                  <input
                    value={formModules}
                    onChange={e => setFormModules(e.target.value)}
                    placeholder="httpx,tls,headers,cors,nuclei"
                    className="w-full rounded-lg border border-white/[0.08] bg-[#0a0014] px-3.5 py-2.5 text-[13px] font-mono text-zinc-200 placeholder:text-zinc-700 focus:outline-none focus:border-red-500/40 transition-all"
                  />
                </div>
                {formError && (
                  <div className="flex items-center gap-2 text-[12px] text-red-400">
                    <AlertCircle className="h-4 w-4 shrink-0" />{formError}
                  </div>
                )}
                <div className="flex items-center justify-end gap-2 pt-1">
                  <button
                    onClick={() => setShowForm(false)}
                    className="px-4 py-2 text-[13px] text-zinc-500 hover:text-zinc-300 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleCreate}
                    disabled={creating}
                    className="flex items-center gap-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:opacity-50 px-4 py-2 text-[13px] font-semibold text-white transition-colors"
                  >
                    {creating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CalendarClock className="h-3.5 w-3.5" />}
                    {creating ? "Creating…" : "Create Schedule"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Schedule list */}
          {fetching ? (
            <div className="flex items-center gap-3 text-zinc-600 text-sm py-12 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" />Loading…
            </div>
          ) : schedules.length === 0 ? (
            <div className="rounded-xl border border-white/[0.07] bg-[#160025]/70 flex flex-col items-center justify-center gap-4 py-20">
              <CalendarClock className="h-10 w-10 text-zinc-700" />
              <div className="text-center space-y-1">
                <p className="font-semibold text-white">No recurring scans</p>
                <p className="text-sm text-zinc-500">Create a schedule to automatically monitor your attack surface.</p>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-white/[0.07] bg-[#160025]/60 overflow-hidden">
              {/* Headers */}
              <div className="hidden sm:grid sm:grid-cols-[1fr_1fr_120px_100px_80px_40px] gap-0 px-5 py-2.5 border-b border-white/[0.05] bg-white/[0.015]">
                {["Client / Targets", "Modules", "Interval", "Next Run", "Status", ""].map(h => (
                  <p key={h} className="text-[10px] font-bold uppercase tracking-widest text-zinc-700">{h}</p>
                ))}
              </div>

              <div className="divide-y divide-white/[0.04]">
                {schedules.map(s => (
                  <div
                    key={s.id}
                    className={`hidden sm:grid sm:grid-cols-[1fr_1fr_120px_100px_80px_40px] gap-0 px-5 py-4 items-center ${!s.enabled ? "opacity-50" : ""}`}
                  >
                    {/* Client */}
                    <div className="min-w-0 pr-3">
                      <p className="text-[13px] font-medium text-zinc-200 truncate">{s.client}</p>
                      <p className="text-[11px] font-mono text-zinc-600 truncate">{s.targets}</p>
                    </div>
                    {/* Modules */}
                    <div className="min-w-0 pr-3 flex items-center">
                      <span className="text-[11px] text-zinc-600 truncate">{s.modules || "(default)"}</span>
                    </div>
                    {/* Interval */}
                    <div className="flex items-center gap-1.5">
                      <Clock className="h-3 w-3 text-zinc-700 shrink-0" />
                      <span className="text-[12px] text-zinc-400">
                        {INTERVALS.find(iv => iv.h === s.interval_h)?.label ?? `${s.interval_h}h`}
                      </span>
                    </div>
                    {/* Next run */}
                    <div className="flex items-center gap-1.5">
                      <Target className="h-3 w-3 text-zinc-700 shrink-0" />
                      <span className="text-[12px] text-zinc-500 font-mono">{formatNextRun(s.next_run)}</span>
                    </div>
                    {/* Toggle */}
                    <div>
                      <button
                        onClick={() => handleToggle(s)}
                        disabled={togglingId === s.id}
                        className="flex items-center gap-1.5 text-[11px] font-medium transition-colors"
                      >
                        {togglingId === s.id ? (
                          <Loader2 className="h-4 w-4 animate-spin text-zinc-600" />
                        ) : s.enabled ? (
                          <><ToggleRight className="h-5 w-5 text-red-400" /><span className="text-red-500">ON</span></>
                        ) : (
                          <><ToggleLeft className="h-5 w-5 text-zinc-600" /><span className="text-zinc-600">OFF</span></>
                        )}
                      </button>
                    </div>
                    {/* Delete */}
                    <div className="flex justify-end">
                      <button
                        onClick={() => handleDelete(s.id)}
                        disabled={deletingId === s.id}
                        className="flex h-7 w-7 items-center justify-center rounded border border-white/[0.07] text-zinc-600 hover:text-red-400 hover:border-red-500/30 hover:bg-red-500/8 disabled:opacity-40 transition-all"
                      >
                        {deletingId === s.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                      </button>
                    </div>
                  </div>
                ))}

                {/* Mobile cards */}
                {schedules.map(s => (
                  <div
                    key={`m-${s.id}`}
                    className={`sm:hidden flex items-center justify-between px-4 py-3.5 gap-3 ${!s.enabled ? "opacity-50" : ""}`}
                  >
                    <div className="min-w-0">
                      <p className="text-[13px] font-medium text-zinc-200 truncate">{s.client}</p>
                      <p className="text-[11px] text-zinc-600 font-mono truncate">{s.targets}</p>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-[10px] text-zinc-600">
                          {INTERVALS.find(iv => iv.h === s.interval_h)?.label ?? `${s.interval_h}h`}
                        </span>
                        <span className="text-[10px] text-zinc-700">{formatNextRun(s.next_run)}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={() => handleToggle(s)} disabled={togglingId === s.id} className="transition-colors">
                        {s.enabled ? <Play className="h-4 w-4 text-red-400" /> : <Pause className="h-4 w-4 text-zinc-600" />}
                      </button>
                      <button onClick={() => handleDelete(s.id)} disabled={deletingId === s.id} className="text-zinc-600 hover:text-red-400 transition-colors">
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {schedules.length > 0 && (
            <p className="text-[11px] text-zinc-700 text-center">
              Last refresh: {timeAgo(new Date().toISOString())} · Schedules are checked every minute by the server.
            </p>
          )}

        </div>
      </main>
    </AppShell>
  );
}
