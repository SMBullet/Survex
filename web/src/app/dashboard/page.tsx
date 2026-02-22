"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { api, ScanJob } from "@/lib/api";
import { Nav } from "@/components/nav";
import { SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Plus, RefreshCw, ExternalLink } from "lucide-react";

const statusColor: Record<string, string> = {
  queued: "bg-slate-500 text-white",
  running: "bg-blue-500 text-white animate-pulse",
  done: "bg-green-600 text-white",
  failed: "bg-red-600 text-white",
  cancelled: "bg-slate-600 text-white",
};

function formatDate(iso: string) {
  return new Date(iso).toLocaleString();
}

export default function Dashboard() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [fetching, setFetching] = useState(true);

  const fetchScans = useCallback(async () => {
    try {
      const data = await api.scans.list();
      setScans(data ?? []);
    } catch {
      // ignore
    } finally {
      setFetching(false);
    }
  }, []);

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [user, loading, router]);

  useEffect(() => {
    if (user) fetchScans();
  }, [user, fetchScans]);

  // Poll every 5 s if any scan is active.
  useEffect(() => {
    const hasActive = scans.some(
      (s) => s.status === "queued" || s.status === "running"
    );
    if (!hasActive) return;
    const t = setInterval(fetchScans, 5000);
    return () => clearInterval(t);
  }, [scans, fetchScans]);

  if (loading || !user) return null;

  return (
    <div className="min-h-screen bg-background">
      <Nav />
      <main className="mx-auto max-w-7xl px-4 py-8">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Scan History</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {scans.length} scan{scans.length !== 1 ? "s" : ""} total
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={fetchScans}>
              <RefreshCw className="h-4 w-4 mr-1" />
              Refresh
            </Button>
            <Button size="sm" asChild>
              <Link href="/scans/new">
                <Plus className="h-4 w-4 mr-1" />
                New Scan
              </Link>
            </Button>
          </div>
        </div>

        {fetching && scans.length === 0 ? (
          <Card>
            <CardContent className="flex items-center justify-center py-16 text-muted-foreground">
              Loading scans…
            </CardContent>
          </Card>
        ) : scans.length === 0 ? (
          <Card>
            <CardHeader className="text-center">
              <CardTitle>No scans yet</CardTitle>
              <CardDescription>
                Run your first scan to discover attack surface findings.
              </CardDescription>
            </CardHeader>
            <CardContent className="flex justify-center pb-8">
              <Button asChild>
                <Link href="/scans/new">
                  <Plus className="h-4 w-4 mr-1" />
                  Start a Scan
                </Link>
              </Button>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Client</TableHead>
                  <TableHead>Targets</TableHead>
                  <TableHead>Modules</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead>Max Sev.</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => (
                  <TableRow
                    key={scan.id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => router.push(`/scans/${scan.id}`)}
                  >
                    <TableCell className="font-medium">{scan.client}</TableCell>
                    <TableCell className="max-w-[160px] truncate text-sm text-muted-foreground">
                      {scan.targets}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-[180px] truncate">
                      {scan.modules}
                    </TableCell>
                    <TableCell>
                      <Badge className={statusColor[scan.status] ?? ""}>
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell>{scan.finding_count ?? 0}</TableCell>
                    <TableCell>
                      <SeverityBadge severity={scan.max_severity ?? ""} />
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatDate(scan.created_at)}
                    </TableCell>
                    <TableCell>
                      {scan.status === "done" && scan.report_path && (
                        <Button
                          variant="ghost"
                          size="icon"
                          asChild
                          onClick={(e) => e.stopPropagation()}
                        >
                          <a
                            href={api.scans.reportUrl(scan.id)}
                            target="_blank"
                            rel="noreferrer"
                          >
                            <ExternalLink className="h-4 w-4" />
                          </a>
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        )}
      </main>
    </div>
  );
}
