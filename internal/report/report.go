package report

import (
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// WriteHTML generates a self-contained HTML report and writes it to scanDir/report.html.
func WriteHTML(scanDir string, result *models.ScanResult) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityColor": severityColor,
		"severityBadge": severityBadge,
		"formatTime":    func(t time.Time) string { return t.Format("2006-01-02 15:04 UTC") },
		"wafDetected": func(waf []models.WAFDetection) []models.WAFDetection {
			var out []models.WAFDetection
			for _, w := range waf {
				if w.Detected {
					out = append(out, w)
				}
			}
			return out
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	// Sort findings by severity (critical first)
	sorted := make([]models.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return severityOrder(sorted[i].Severity) > severityOrder(sorted[j].Severity)
	})

	data := struct {
		Result   *models.ScanResult
		Findings []models.Finding
		Now      time.Time
	}{
		Result:   result,
		Findings: sorted,
		Now:      time.Now().UTC(),
	}

	f, err := os.Create(filepath.Join(scanDir, "report.html"))
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func severityOrder(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
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
	return "#6b7280"
}

func severityBadge(s string) template.HTML {
	color := severityColor(s)
	return template.HTML(`<span style="background:` + color + `;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;text-transform:uppercase;">` + s + `</span>`)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Survex Report — {{.Result.Scan.Client}}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}
  a{color:#60a5fa}
  h1{font-size:1.6rem;font-weight:700}
  h2{font-size:1.1rem;font-weight:600;margin-bottom:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em}
  .header{background:#1e293b;padding:24px 32px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}
  .header-meta{font-size:13px;color:#94a3b8;text-align:right}
  .content{max-width:1200px;margin:0 auto;padding:32px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;text-align:center}
  .card-value{font-size:2rem;font-weight:700;color:#f8fafc}
  .card-label{font-size:13px;color:#94a3b8;margin-top:4px}
  .section{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:24px;margin-bottom:24px}
  table{width:100%;border-collapse:collapse;font-size:14px}
  th{text-align:left;padding:10px 12px;border-bottom:1px solid #334155;color:#94a3b8;font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
  td{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#0f172a}
  .mono{font-family:"SF Mono",Menlo,monospace;font-size:13px}
  .new-badge{background:#166534;color:#86efac;padding:1px 6px;border-radius:3px;font-size:11px;margin-left:6px}
  .waf-detected{color:#34d399;font-weight:600}
  .tls-expired{color:#f87171}
  .tls-warning{color:#fbbf24}
  .tls-ok{color:#34d399}
  .diff-box{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .diff-list{list-style:none;font-size:13px}
  .diff-list li{padding:4px 0;font-family:monospace}
  .diff-list li::before{margin-right:6px}
  .diff-new li::before{content:"+ ";color:#34d399}
  .diff-removed li::before{content:"− ";color:#f87171}
  .empty{color:#475569;font-style:italic;font-size:13px}
  .finding-detail{color:#94a3b8;font-size:13px;margin-top:2px}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Survex — Attack Surface Report</h1>
    <div style="color:#94a3b8;font-size:14px;margin-top:4px">{{.Result.Scan.Target}} &nbsp;·&nbsp; Client: {{.Result.Scan.Client}}</div>
  </div>
  <div class="header-meta">
    Scan ID: {{.Result.Scan.ID}}<br>
    Started: {{formatTime .Result.Scan.StartedAt}}<br>
    Generated: {{formatTime .Now}}
  </div>
</div>

<div class="content">

  <!-- Summary Cards -->
  <div class="grid">
    <div class="card"><div class="card-value">{{len .Result.Subdomains}}</div><div class="card-label">Subdomains</div></div>
    <div class="card"><div class="card-value">{{len .Result.Services}}</div><div class="card-label">Open Ports</div></div>
    <div class="card"><div class="card-value">{{len .Result.HTTP}}</div><div class="card-label">HTTP Services</div></div>
    <div class="card"><div class="card-value">{{len .Result.TLS}}</div><div class="card-label">TLS Certs</div></div>
    <div class="card"><div class="card-value">{{len .Result.Vulnerabilities}}</div><div class="card-label">Vulnerabilities</div></div>
    <div class="card"><div class="card-value">{{len .Findings}}</div><div class="card-label">Total Findings</div></div>
  </div>

  <!-- Findings -->
  <div class="section">
    <h2>Findings</h2>
    {{if .Findings}}
    <table>
      <thead><tr><th>Severity</th><th>Asset</th><th>Title</th><th>Detail</th></tr></thead>
      <tbody>
      {{range .Findings}}
      <tr>
        <td>{{severityBadge .Severity}}</td>
        <td class="mono">{{.Asset}}{{if .Port}}:{{.Port}}{{end}}{{if .New}}<span class="new-badge">NEW</span>{{end}}</td>
        <td>{{.Title}}</td>
        <td class="finding-detail">{{.Detail}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No findings.</p>{{end}}
  </div>

  <!-- Diff -->
  {{if .Result.Diff}}
  <div class="section">
    <h2>Changes Since Last Scan</h2>
    <div class="diff-box">
      <div>
        <h2 style="color:#34d399;margin-bottom:8px">New ({{len .Result.Diff.NewSubdomains}})</h2>
        {{if .Result.Diff.NewSubdomains}}
        <ul class="diff-list diff-new">
          {{range .Result.Diff.NewSubdomains}}<li>{{.}}</li>{{end}}
        </ul>
        {{else}}<p class="empty">No new subdomains.</p>{{end}}
      </div>
      <div>
        <h2 style="color:#f87171;margin-bottom:8px">Removed ({{len .Result.Diff.RemovedSubdomains}})</h2>
        {{if .Result.Diff.RemovedSubdomains}}
        <ul class="diff-list diff-removed">
          {{range .Result.Diff.RemovedSubdomains}}<li>{{.}}</li>{{end}}
        </ul>
        {{else}}<p class="empty">No removed subdomains.</p>{{end}}
      </div>
    </div>
    {{if .Result.Diff.NewOpenPorts}}
    <div style="margin-top:16px">
      <h2 style="margin-bottom:8px">New Open Ports</h2>
      <table>
        <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th></tr></thead>
        <tbody>
        {{range .Result.Diff.NewOpenPorts}}
        <tr>
          <td class="mono">{{.Host}}</td>
          <td class="mono">{{.Port}}</td>
          <td>{{.Protocol}}</td>
          <td>{{.ServiceName}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
    </div>
    {{end}}
  </div>
  {{end}}

  <!-- TLS Certificates -->
  {{if .Result.TLS}}
  <div class="section">
    <h2>TLS Certificates</h2>
    <table>
      <thead><tr><th>Host</th><th>Issuer</th><th>Expiry</th><th>Days Left</th><th>Version</th><th>Status</th></tr></thead>
      <tbody>
      {{range .Result.TLS}}
      <tr>
        <td class="mono">{{.Host}}</td>
        <td>{{.Issuer}}</td>
        <td class="mono">{{formatTime .Expiry}}</td>
        <td class="mono {{if .Expired}}tls-expired{{else if le .DaysLeft 30}}tls-warning{{else}}tls-ok{{end}}">{{.DaysLeft}}</td>
        <td>{{.Version}}</td>
        <td>{{if .Expired}}<span class="tls-expired">EXPIRED</span>{{else if .SelfSigned}}<span class="tls-warning">SELF-SIGNED</span>{{else}}<span class="tls-ok">OK</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- WAF -->
  <div class="section">
    <h2>WAF Detection</h2>
    {{$detected := wafDetected .Result.WAF}}
    {{if $detected}}
    <table>
      <thead><tr><th>Host</th><th>WAF</th><th>Evidence</th></tr></thead>
      <tbody>
      {{range $detected}}
      <tr>
        <td class="mono">{{.Host}}</td>
        <td class="waf-detected">{{.Name}}</td>
        <td class="finding-detail">{{.Evidence}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}<p class="empty">No WAFs detected.</p>{{end}}
  </div>

  <!-- Subdomains -->
  <div class="section">
    <h2>Subdomains ({{len .Result.Subdomains}})</h2>
    <table>
      <thead><tr><th>Name</th><th>IP Address</th><th>Sources</th></tr></thead>
      <tbody>
      {{range .Result.Subdomains}}
      <tr>
        <td class="mono">{{.Name}}</td>
        <td class="mono">{{.IPAddress}}</td>
        <td class="finding-detail">{{range $i,$s := .Sources}}{{if $i}}, {{end}}{{$s}}{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>

  <!-- Open Services -->
  {{if .Result.Services}}
  <div class="section">
    <h2>Open Services ({{len .Result.Services}})</h2>
    <table>
      <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th></tr></thead>
      <tbody>
      {{range .Result.Services}}
      <tr>
        <td class="mono">{{.Host}}</td>
        <td class="mono">{{.Port}}</td>
        <td>{{.Protocol}}</td>
        <td>{{.ServiceName}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- HTTP Services -->
  {{if .Result.HTTP}}
  <div class="section">
    <h2>HTTP Services ({{len .Result.HTTP}})</h2>
    <table>
      <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Web Server</th><th>Tech Stack</th></tr></thead>
      <tbody>
      {{range .Result.HTTP}}
      <tr>
        <td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
        <td class="mono">{{.StatusCode}}</td>
        <td>{{.Title}}</td>
        <td>{{.WebServer}}</td>
        <td class="finding-detail">{{range $i,$t := .TechStack}}{{if $i}}, {{end}}{{$t}}{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- Vulnerabilities -->
  {{if .Result.Vulnerabilities}}
  <div class="section">
    <h2>Vulnerabilities ({{len .Result.Vulnerabilities}})</h2>
    <table>
      <thead><tr><th>Severity</th><th>Host</th><th>Name</th><th>Template</th><th>URL</th></tr></thead>
      <tbody>
      {{range .Result.Vulnerabilities}}
      <tr>
        <td>{{severityBadge .Severity}}</td>
        <td class="mono">{{.Host}}</td>
        <td>{{.Name}}</td>
        <td class="mono finding-detail">{{.TemplateID}}</td>
        <td class="mono finding-detail"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <div style="text-align:center;color:#334155;font-size:12px;margin-top:32px">
    Generated by Survex &nbsp;·&nbsp; {{formatTime .Now}}
  </div>

</div>
</body>
</html>`
