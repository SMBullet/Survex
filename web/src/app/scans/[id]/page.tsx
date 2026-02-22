"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, ScanJob } from "@/lib/api";
import { Nav } from "@/components/nav";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ExternalLink,
  Square,
  RefreshCw,
  Clock,
  Target,
  Layers,
} from "lucide-react";

const statusColor: Record<string, string> = {
  queued: "bg-slate-500 text-white",
  running: "bg-blue-500 text-white",
  done: "bg-green-600 text-white",
  failed: "bg-red-600 text-white",
  cancelled: "bg-slate-600 text-white",
};

function formatDuration(start: string, end?: string) {
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const secs = Math.floor((e - s) / 1000);
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { user, loading } = useAuth();
  const router = useRouter();

  const [scan, setScan] = useState<ScanJob | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const fetchScan = useCallback(async () => {
    try {
      const data = await api.scans.get(id);
      setScan(data);
      return data;
    } catch {
      return null;
    }
  }, [id]);

  // Connect WebSocket for live logs
  const connectWs = useCallback(() => {
    if (wsRef.current) return;
    const ws = new WebSocket(api.scans.logsWsUrl(id));
    wsRef.current = ws;

    ws.onopen = () => setWsConnected(true);
    ws.onmessage = (e) =>
      setLogs((prev) => [...prev, e.data as string]);
    ws.onclose = () => {
      setWsConnected(false);
      wsRef.current = null;
    };
    ws.onerror = () => {
      ws.close();
    };
  }, [id]);

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [user, loading, router]);

  useEffect(() => {
    if (!user) return;
    fetchScan().then((s) => {
      if (s && (s.status === "queued" || s.status === "running")) {
        connectWs();
      }
    });
  }, [user, fetchScan, connectWs]);

  // Poll when running for status updates (WebSocket gives logs, not metadata)
  useEffect(() => {
    if (!scan) return;
    if (scan.status !== "queued" && scan.status !== "running") return;
    const t = setInterval(fetchScan, 5000);
    return () => clearInterval(t);
  }, [scan, fetchScan]);

  // Disconnect WS when scan finishes
  useEffect(() => {
    if (scan?.status === "done" || scan?.status === "failed" || scan?.status === "cancelled") {
      wsRef.current?.close();
    }
  }, [scan?.status]);

  // Auto-scroll log pane
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  const handleCancel = async () => {
    try {
      await api.scans.cancel(id);
      fetchScan();
    } catch {
      // ignore
    }
  };

  if (loading || !user) return null;

  return (
    <div className="min-h-screen bg-background">
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold">{scan?.client ?? id}</h1>
              {scan && (
                <Badge className={statusColor[scan.status]}>
                  {scan.status}
                </Badge>
              )}
            </div>
            <p className="text-sm text-muted-foreground mt-1 font-mono">
              ID: {id}
            </p>
          </div>

          <div className="flex gap-2">
            {scan?.status === "done" && scan.report_path && (
              <Button variant="outline" size="sm" asChild>
                <a
                  href={api.scans.reportUrl(id)}
                  target="_blank"
                  rel="noreferrer"
                >
                  <ExternalLink className="h-4 w-4 mr-1" />
                  Open Report
                </a>
              </Button>
            )}
            {(scan?.status === "queued" || scan?.status === "running") && (
              <Button variant="destructive" size="sm" onClick={handleCancel}>
                <Square className="h-4 w-4 mr-1" />
                Cancel
              </Button>
            )}
            <Button variant="ghost" size="icon" onClick={() => fetchScan()}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Stats */}
        {scan && (
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2 text-muted-foreground text-sm mb-1">
                  <Target className="h-4 w-4" />
                  Targets
                </div>
                <p className="text-sm font-mono truncate">{scan.targets}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2 text-muted-foreground text-sm mb-1">
                  <Layers className="h-4 w-4" />
                  Modules
                </div>
                <p className="text-sm font-mono truncate">{scan.modules}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-muted-foreground text-sm mb-1">
                  Findings
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-2xl font-bold">
                    {scan.finding_count}
                  </span>
                  <SeverityBadge severity={scan.max_severity ?? ""} />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2 text-muted-foreground text-sm mb-1">
                  <Clock className="h-4 w-4" />
                  Duration
                </div>
                <p className="text-xl font-bold">
                  {scan.started_at
                    ? formatDuration(scan.started_at, scan.finished_at)
                    : "—"}
                </p>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Live Logs */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Scan Logs</CardTitle>
                <CardDescription>
                  {wsConnected
                    ? "Live — connected"
                    : logs.length > 0
                    ? "Showing captured output"
                    : "Waiting for scan to start…"}
                </CardDescription>
              </div>
              {!wsConnected &&
                scan?.status !== "queued" &&
                scan?.status !== "running" && (
                  <Badge variant="outline">
                    {logs.length} line{logs.length !== 1 ? "s" : ""}
                  </Badge>
                )}
            </div>
          </CardHeader>
          <CardContent>
            <div
              ref={logRef}
              className="h-[480px] overflow-y-auto rounded-md bg-black p-4 font-mono text-xs leading-5 text-green-400"
            >
              {logs.length === 0 ? (
                <span className="text-zinc-500">
                  {scan?.status === "queued"
                    ? "Scan is queued, waiting to start…"
                    : "No output yet."}
                </span>
              ) : (
                logs.map((line, i) => (
                  <div key={i} className="whitespace-pre-wrap break-all">
                    {line}
                  </div>
                ))
              )}
              {wsConnected && (
                <span className="inline-block animate-pulse text-green-300">
                  █
                </span>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Error */}
        {scan?.error && (
          <Card className="border-destructive">
            <CardHeader>
              <CardTitle className="text-destructive">Scan Error</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="text-sm text-destructive whitespace-pre-wrap">
                {scan.error}
              </pre>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  );
}
