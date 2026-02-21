package server

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
	"github.com/SMBullet/Survex/internal/store"
)

// clientRow is what the dashboard renders per client.
type clientRow struct {
	Client     string
	Target     string
	ScanID     string
	LastScan   time.Time
	Status     string
	ReportURL  string // browser-accessible path to the HTML report
}

// Serve starts the Survex web dashboard on addr.
// reportsDir is the directory that contains per-client scan output folders
// (e.g. "reports/"). It is served under /reports/ so HTML reports and
// screenshots are directly accessible.
func Serve(addr, reportsDir string) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/clients", handleAPIClients)
	mux.HandleFunc("/api/scan/", handleAPIScan)

	// Serve the reports directory so report.html and screenshots are accessible.
	mux.Handle("/reports/", http.StripPrefix("/reports/", http.FileServer(http.Dir(reportsDir))))

	log.Printf("[survex] web dashboard → http://%s", addr)
	return http.ListenAndServe(addr, mux)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	scans, err := store.ListAllClients()
	if err != nil {
		http.Error(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var rows []clientRow
	for _, sc := range scans {
		rows = append(rows, clientRow{
			Client:    sc.Client,
			Target:    sc.Target,
			ScanID:    sc.ID,
			LastScan:  sc.StartedAt,
			Status:    sc.Status,
			ReportURL: fmt.Sprintf("/reports/%s/%s/report.html", sc.Client, sc.ID),
		})
	}

	tmpl := template.Must(template.New("dash").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string { return t.Format("2006-01-02 15:04 UTC") },
		"statusColor": func(s string) string {
			if s == "done" {
				return "#34d399"
			}
			return "#fbbf24"
		},
	}).Parse(dashboardTemplate))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, map[string]any{
		"Clients": rows,
		"Now":     time.Now().UTC(),
	}); err != nil {
		log.Printf("[survex] dashboard template error: %v", err)
	}
}

func handleAPIClients(w http.ResponseWriter, r *http.Request) {
	scans, err := store.ListAllClients()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func handleAPIScan(w http.ResponseWriter, r *http.Request) {
	// Path pattern: /api/scan/{client}
	client := strings.TrimPrefix(r.URL.Path, "/api/scan/")
	client = strings.TrimSuffix(client, "/")
	if client == "" {
		http.Error(w, "missing client name — use /api/scan/{client}", http.StatusBadRequest)
		return
	}

	result, err := store.LoadLast(client)
	if err != nil || result == nil {
		http.Error(w, "no scan found for client: "+client, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ─── severity helpers (mirrors risk package logic without the import) ──────────

func maxSeverity(findings []models.Finding) string {
	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	max := -1
	out := "none"
	for _, f := range findings {
		if v, ok := order[f.Severity]; ok && v > max {
			max = v
			out = f.Severity
		}
	}
	return out
}

func severityColor(s string) string {
	switch s {
	case "critical":
		return "#dc2626"
	case "high":
		return "#ea580c"
	case "medium":
		return "#d97706"
	case "low":
		return "#2563eb"
	case "info":
		return "#6b7280"
	}
	return "#475569"
}

// ─── HTML template ────────────────────────────────────────────────────────────

const dashboardTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Survex Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
  a{color:#60a5fa;text-decoration:none}
  a:hover{text-decoration:underline}
  h1{font-size:1.5rem;font-weight:700}
  h2{font-size:.9rem;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px}
  .header{background:#1e293b;padding:20px 32px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}
  .header-meta{font-size:12px;color:#64748b}
  .content{max-width:1100px;margin:0 auto;padding:32px}
  .section{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:24px;margin-bottom:24px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;padding:9px 14px;border-bottom:1px solid #334155;color:#64748b;font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
  td{padding:10px 14px;border-bottom:1px solid #1e293b;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#0f172a}
  .mono{font-family:"SF Mono",Menlo,"Cascadia Code",monospace;font-size:12px}
  .badge{padding:2px 10px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}
  .empty{color:#475569;font-style:italic;font-size:13px;padding:8px 0}
  .api-box{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:16px;margin-top:16px;font-size:12px;font-family:monospace}
  .api-box a{color:#818cf8}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>Survex Dashboard</h1>
    <div style="color:#64748b;font-size:13px;margin-top:2px">Attack Surface Management — read-only view</div>
  </div>
  <div class="header-meta">{{formatTime .Now}}</div>
</div>

<div class="content">

  <div class="section">
    <h2>Clients ({{len .Clients}})</h2>
    {{if .Clients}}
    <table>
      <thead>
        <tr><th>Client</th><th>Target</th><th>Last Scan</th><th>Status</th><th>Scan ID</th><th>Report</th></tr>
      </thead>
      <tbody>
      {{range .Clients}}
      <tr>
        <td style="font-weight:600">{{.Client}}</td>
        <td class="mono">{{.Target}}</td>
        <td class="mono">{{formatTime .LastScan}}</td>
        <td><span class="badge" style="background:{{statusColor .Status}}">{{.Status}}</span></td>
        <td class="mono" style="color:#64748b;font-size:11px">{{.ScanID}}</td>
        <td><a href="{{.ReportURL}}" target="_blank">Open Report →</a></td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <p class="empty">No scans found. Run <code>survex scan</code> to get started.</p>
    {{end}}
  </div>

  <div class="section">
    <h2>API Endpoints</h2>
    <div class="api-box">
      <div style="color:#94a3b8;margin-bottom:8px">JSON API — use these to integrate with other tools:</div>
      <div><a href="/api/clients">/api/clients</a> — list all clients (latest scan per client)</div>
      <div style="margin-top:4px"><span style="color:#64748b">/api/scan/{client}</span> — full last scan result for a client</div>
    </div>
  </div>

  <div style="text-align:center;color:#334155;font-size:12px;margin-top:24px;padding-bottom:24px">
    Survex Web Dashboard &nbsp;·&nbsp; {{formatTime .Now}}
  </div>

</div>
</body>
</html>`
