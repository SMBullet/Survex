const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

export interface Finding {
  asset: string;
  port?: number;
  severity: string; // info | low | medium | high | critical
  title: string;
  detail?: string;
  first_seen: string;
  new: boolean;
  cvss_score?: number;   // 0–10 CVSS v3.1 base score
  cvss_vector?: string;  // e.g. CVSS:3.1/AV:N/AC:L/...
}

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

export interface WebhookEntry {
  name: string;
  url: string;
}

export interface UserSettings {
  shodan_key: string;
  github_token: string;
  webhook_urls: WebhookEntry[];
  ai_provider: string;  // "anthropic" | "openai" | "deepseek" | "gemini" | "ollama"
  ai_api_key: string;
  ai_model: string;
  ai_base_url: string;  // for Ollama custom endpoints
}

export interface FalsePositive {
  id: number;
  fingerprint: string;
  asset: string;
  title: string;
  created_at: string;
}

export interface Schedule {
  id: string;
  user_id: number;
  client: string;
  targets: string;
  modules: string;
  options: string;
  interval_h: number;
  enabled: boolean;
  next_run: string;
  last_run?: string;
  created_at: string;
}

export interface AssetEntry {
  asset: string;
  type: string;   // subdomain | url
  client: string;
  scan_id: string;
  first_seen: string;
  last_seen: string;
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
    findings: (id: string) => request<Finding[]>(`/api/v1/scans/${id}/findings?filter_fp=true`),
    reportUrl: (id: string) => `${BASE}/api/v1/scans/${id}/report?token=${token()}`,
    logsWsUrl: (id: string) => {
      const t = token();
      const base = BASE.replace(/^http/, "ws");
      return `${base}/api/v1/scans/${id}/logs?token=${t}`;
    },
  },

  settings: {
    get: () => request<UserSettings>("/api/v1/settings"),
    put: (payload: UserSettings) =>
      request<{ ok: boolean }>("/api/v1/settings", {
        method: "PUT",
        body: JSON.stringify(payload),
      }),
  },

  falsePositives: {
    list: () => request<FalsePositive[]>("/api/v1/false-positives"),
    add: (asset: string, title: string) =>
      request<FalsePositive>("/api/v1/false-positives", {
        method: "POST",
        body: JSON.stringify({ asset, title }),
      }),
    remove: (fingerprint: string) =>
      request<void>(`/api/v1/false-positives/${encodeURIComponent(fingerprint)}`, {
        method: "DELETE",
      }),
  },

  schedules: {
    list: () => request<Schedule[]>("/api/v1/schedules"),
    create: (payload: {
      client: string;
      targets: string[];
      modules: string[];
      interval_h: number;
      options?: Record<string, unknown>;
    }) =>
      request<Schedule>("/api/v1/schedules", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    toggle: (id: string, enabled: boolean) =>
      request<{ ok: boolean; enabled: boolean }>(`/api/v1/schedules/${id}`, {
        method: "PUT",
        body: JSON.stringify({ enabled }),
      }),
    delete: (id: string) =>
      request<void>(`/api/v1/schedules/${id}`, { method: "DELETE" }),
  },

  assets: {
    list: () => request<AssetEntry[]>("/api/v1/assets"),
  },

  ai: {
    query: (task: string, payload: Record<string, unknown>) =>
      request<{ result: string }>("/api/v1/ai/query", {
        method: "POST",
        body: JSON.stringify({ task, payload }),
      }),
  },
};
