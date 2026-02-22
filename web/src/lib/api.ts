const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

export interface Technology {
  host: string;
  name: string;
  category: string; // CMS | E-Commerce | Framework | JavaScript | Language | Web Server | CDN | WAF | Analytics
  version?: string;
}

export interface ScanJob {
  id: string;
  user_id: number;
  client: string;
  targets: string;
  modules: string;
  options: string;
  status: "queued" | "running" | "done" | "failed" | "cancelled";
  created_at: string;
  started_at?: string;
  finished_at?: string;
  finding_count: number;
  max_severity: string;
  report_path?: string;
  error?: string;
}

function token(): string {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("survex_token") ?? "";
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  const t = token();
  if (t) headers["Authorization"] = `Bearer ${t}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? res.statusText);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

export const api = {
  auth: {
    register: (email: string, password: string) =>
      request<{ token: string; user: { id: number; email: string } }>(
        "/api/v1/auth/register",
        { method: "POST", body: JSON.stringify({ email, password }) }
      ),
    login: (email: string, password: string) =>
      request<{ token: string; user: { id: number; email: string } }>(
        "/api/v1/auth/login",
        { method: "POST", body: JSON.stringify({ email, password }) }
      ),
    me: () =>
      request<{ id: number; email: string }>("/api/v1/auth/me"),
  },

  scans: {
    list: () => request<ScanJob[]>("/api/v1/scans"),
    get: (id: string) => request<ScanJob>(`/api/v1/scans/${id}`),
    create: (payload: {
      client: string;
      targets: string[];
      modules: string[];
      options: Record<string, unknown>;
    }) =>
      request<ScanJob>("/api/v1/scans", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    cancel: (id: string) =>
      request<{ status: string }>(`/api/v1/scans/${id}`, {
        method: "DELETE",
      }),
    technologies: (id: string) => request<Technology[]>(`/api/v1/scans/${id}/technologies`),
    reportUrl: (id: string) => `${BASE}/api/v1/scans/${id}/report?token=${token()}`,
    logsWsUrl: (id: string) => {
      const t = token();
      const base = BASE.replace(/^http/, "ws");
      return `${base}/api/v1/scans/${id}/logs?token=${t}`;
    },
  },
};
