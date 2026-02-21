package report

import (
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// WriteHTML generates a self-contained HTML report and writes it to scanDir/report.html.
func WriteHTML(scanDir string, result *models.ScanResult) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"severityColor": severityColor,
		"severityBadge": severityBadge,
		"formatTime":    func(t time.Time) string { return t.Format("2006-01-02 15:04 UTC") },
		"join":          func(sep string, items []string) string { return strings.Join(items, sep) },
		"wafDetected": func(waf []models.WAFDetection) []models.WAFDetection {
			var out []models.WAFDetection
			for _, w := range waf {
				if w.Detected {
					out = append(out, w)
				}
			}
			return out
		},
		"corsVulnerable": func(cors []models.CORSResult) []models.CORSResult {
			var out []models.CORSResult
			for _, c := range cors {
				if c.Vulnerable {
					out = append(out, c)
				}
			}
			return out
		},
		"publicBuckets": func(buckets []models.S3Bucket) []models.S3Bucket {
			var out []models.S3Bucket
			for _, b := range buckets {
				if b.Public || b.Listable {
					out = append(out, b)
				}
			}
			return out
		},
		"headerGradeColor": func(grade string) string {
			switch grade {
			case "A+", "A":
				return "#34d399"
			case "B":
				return "#60a5fa"
			case "C":
				return "#fbbf24"
			case "D":
				return "#f97316"
			}
			return "#f87171"
		},
		"corsIssueBadge": func(issue string) template.HTML {
			labels := map[string]string{
				"reflects_origin_with_credentials": "CRITICAL: Origin+Credentials",
				"wildcard_with_credentials":        "CRITICAL: Wildcard+Credentials",
				"wildcard":                         "HIGH: Wildcard ACAO",
				"reflects_origin":                  "MEDIUM: Origin Reflected",
				"null_origin":                      "MEDIUM: Null Origin",
			}
			colors := map[string]string{
				"reflects_origin_with_credentials": "#dc2626",
				"wildcard_with_credentials":        "#dc2626",
				"wildcard":                         "#ea580c",
				"reflects_origin":                  "#d97706",
				"null_origin":                      "#d97706",
			}
			label := labels[issue]
			if label == "" {
				label = issue
			}
			color := colors[issue]
			if color == "" {
				color = "#6b7280"
			}
			return template.HTML(`<span style="background:` + color + `;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">` + label + `</span>`)
		},
		"maxSeverity": func(findings []models.Finding) string {
			order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
			max := -1
			result := "none"
			for _, f := range findings {
				if v, ok := order[f.Severity]; ok && v > max {
					max = v
					result = f.Severity
				}
			}
			return result
		},
		"countVulnCORS": func(cors []models.CORSResult) int {
			n := 0
			for _, c := range cors {
				if c.Vulnerable {
					n++
				}
			}
			return n
		},
		"countDetectedWAF": func(waf []models.WAFDetection) int {
			n := 0
			for _, w := range waf {
				if w.Detected {
					n++
				}
			}
			return n
		},
		"countVulnTakeovers": func(takeovers []models.TakeoverResult) int {
			n := 0
			for _, t := range takeovers {
				if t.Vulnerable {
					n++
				}
			}
			return n
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
  h2{font-size:1rem;font-weight:600;margin-bottom:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em}
  .header{background:#1e293b;padding:24px 32px;border-bottom:1px solid #334155;display:flex;justify-content:space-between;align-items:center}
  .header-meta{font-size:13px;color:#94a3b8;text-align:right;line-height:1.8}
  .content{max-width:1300px;margin:0 auto;padding:32px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin-bottom:32px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:18px;text-align:center}
  .card-value{font-size:1.8rem;font-weight:700;color:#f8fafc}
  .card-label{font-size:11px;color:#94a3b8;margin-top:4px;text-transform:uppercase;letter-spacing:.04em}
  .section{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:24px;margin-bottom:24px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;padding:9px 12px;border-bottom:1px solid #334155;color:#64748b;font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.06em}
  td{padding:9px 12px;border-bottom:1px solid #1e293b;vertical-align:top;word-break:break-word}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#0f172a}
  .mono{font-family:"SF Mono",Menlo,"Cascadia Code",monospace;font-size:12px}
  .new-badge{background:#166534;color:#86efac;padding:1px 6px;border-radius:3px;font-size:10px;margin-left:6px}
  .waf-detected{color:#34d399;font-weight:600}
  .tls-expired{color:#f87171}
  .tls-warning{color:#fbbf24}
  .tls-ok{color:#34d399}
  .diff-box{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .diff-list{list-style:none;font-size:12px}
  .diff-list li{padding:4px 0;font-family:monospace}
  .diff-new li::before{content:"+ ";color:#34d399}
  .diff-removed li::before{content:"- ";color:#f87171}
  .empty{color:#475569;font-style:italic;font-size:13px;padding:4px 0}
  .finding-detail{color:#94a3b8;font-size:12px;margin-top:2px}
  .screenshot-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px;margin-top:12px}
  .screenshot-card{background:#0f172a;border:1px solid #334155;border-radius:6px;overflow:hidden}
  .screenshot-card img{width:100%;height:150px;object-fit:cover;display:block}
  .sc-url{padding:8px;font-size:11px;color:#94a3b8;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .tag-aws{background:#1d4e89;color:#93c5fd;padding:1px 6px;border-radius:3px;font-size:11px}
  .tag-gcs{background:#1e3a5f;color:#7dd3fc;padding:1px 6px;border-radius:3px;font-size:11px}
  .tag-azure{background:#1e3a8a;color:#a5b4fc;padding:1px 6px;border-radius:3px;font-size:11px}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Survex — Attack Surface Report</h1>
    <div style="color:#94a3b8;font-size:14px;margin-top:4px">
      {{.Result.Scan.Target}} &nbsp;·&nbsp; Client: <strong>{{.Result.Scan.Client}}</strong>
      &nbsp;·&nbsp; Max Severity: {{severityBadge (maxSeverity .Findings)}}
    </div>
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
    <div class="card"><div class="card-value">{{countDetectedWAF .Result.WAF}}</div><div class="card-label">WAFs</div></div>
    <div class="card"><div class="card-value">{{countVulnCORS .Result.CORS}}</div><div class="card-label">CORS Vulns</div></div>
    <div class="card"><div class="card-value">{{len .Result.S3Buckets}}</div><div class="card-label">Cloud Buckets</div></div>
    <div class="card"><div class="card-value">{{len .Result.Vulnerabilities}}</div><div class="card-label">Nuclei Vulns</div></div>
    <div class="card"><div class="card-value">{{countVulnTakeovers .Result.Takeovers}}</div><div class="card-label">Takeovers</div></div>
    <div class="card"><div class="card-value">{{len .Findings}}</div><div class="card-label">Total Findings</div></div>
    <div class="card"><div class="card-value">{{len .Result.Screenshots}}</div><div class="card-label">Screenshots</div></div>
  </div>

  <!-- Findings -->
  <div class="section">
    <h2>Findings ({{len .Findings}})</h2>
    {{if .Findings}}
    <table>
      <thead><tr><th>Severity</th><th>Asset</th><th>Title</th><th>Detail</th><th></th></tr></thead>
      <tbody>
      {{range .Findings}}
      <tr>
        <td>{{severityBadge .Severity}}</td>
        <td class="mono">{{.Asset}}{{if .Port}}:{{.Port}}{{end}}</td>
        <td>{{.Title}}</td>
        <td class="finding-detail">{{.Detail}}</td>
        <td>{{if .New}}<span class="new-badge">NEW</span>{{end}}</td>
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
        <div style="color:#34d399;font-weight:600;margin-bottom:8px">New Subdomains ({{len .Result.Diff.NewSubdomains}})</div>
        {{if .Result.Diff.NewSubdomains}}
        <ul class="diff-list diff-new">{{range .Result.Diff.NewSubdomains}}<li>{{.}}</li>{{end}}</ul>
        {{else}}<p class="empty">None.</p>{{end}}
      </div>
      <div>
        <div style="color:#f87171;font-weight:600;margin-bottom:8px">Removed Subdomains ({{len .Result.Diff.RemovedSubdomains}})</div>
        {{if .Result.Diff.RemovedSubdomains}}
        <ul class="diff-list diff-removed">{{range .Result.Diff.RemovedSubdomains}}<li>{{.}}</li>{{end}}</ul>
        {{else}}<p class="empty">None.</p>{{end}}
      </div>
    </div>
    {{if .Result.Diff.NewOpenPorts}}
    <div style="margin-top:16px">
      <div style="font-weight:600;margin-bottom:8px;color:#fbbf24">New Open Ports</div>
      <table>
        <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th></tr></thead>
        <tbody>
        {{range .Result.Diff.NewOpenPorts}}
        <tr><td class="mono">{{.Host}}</td><td class="mono">{{.Port}}</td><td>{{.Protocol}}</td><td>{{.ServiceName}}</td></tr>
        {{end}}
        </tbody>
      </table>
    </div>
    {{end}}
  </div>
  {{end}}

  <!-- Security Headers -->
  {{if .Result.SecurityHeaders}}
  <div class="section">
    <h2>Security Headers ({{len .Result.SecurityHeaders}} URLs audited)</h2>
    <table>
      <thead><tr><th>Host</th><th>URL</th><th>Grade</th><th>Missing Headers</th></tr></thead>
      <tbody>
      {{range .Result.SecurityHeaders}}
      <tr>
        <td class="mono">{{.Host}}</td>
        <td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
        <td><span style="font-weight:700;font-size:1.1em;color:{{headerGradeColor .Score}}">{{.Score}}</span></td>
        <td class="finding-detail">{{join ", " .Missing}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- CORS -->
  {{$vulnCORS := corsVulnerable .Result.CORS}}
  {{if $vulnCORS}}
  <div class="section">
    <h2>CORS Misconfigurations ({{len $vulnCORS}} vulnerable)</h2>
    <table>
      <thead><tr><th>Host</th><th>URL</th><th>Issue</th><th>Evidence</th></tr></thead>
      <tbody>
      {{range $vulnCORS}}
      <tr>
        <td class="mono">{{.Host}}</td>
        <td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
        <td>{{corsIssueBadge .Issue}}</td>
        <td class="finding-detail">{{.Evidence}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- Subdomain Takeovers -->
  {{if .Result.Takeovers}}
  <div class="section">
    <h2>Subdomain Takeovers ({{len .Result.Takeovers}} candidates, {{countVulnTakeovers .Result.Takeovers}} confirmed)</h2>
    <table>
      <thead><tr><th>Host</th><th>CNAME Target</th><th>Service</th><th>Status</th><th>Evidence</th></tr></thead>
      <tbody>
      {{range .Result.Takeovers}}
      <tr>
        <td class="mono">{{.Host}}</td>
        <td class="mono">{{.CNAME}}</td>
        <td>{{.Service}}</td>
        <td>{{if .Vulnerable}}<span style="color:#dc2626;font-weight:700">VULNERABLE</span>{{else}}<span style="color:#fbbf24">Candidate</span>{{end}}</td>
        <td class="finding-detail">{{.Evidence}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- Cookie Security -->
  {{if .Result.Cookies}}
  <div class="section">
    <h2>Cookie Security ({{len .Result.Cookies}} endpoints)</h2>
    <table>
      <thead><tr><th>Host</th><th>Cookie Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead>
      <tbody>
      {{range .Result.Cookies}}{{$host := .Host}}{{range .Cookies}}
      <tr>
        <td class="mono">{{$host}}</td>
        <td class="mono">{{.Name}}</td>
        <td>{{if .Secure}}<span style="color:#34d399">Yes</span>{{else}}<span style="color:#f87171">No</span>{{end}}</td>
        <td>{{if .HttpOnly}}<span style="color:#34d399">Yes</span>{{else}}<span style="color:#f87171">No</span>{{end}}</td>
        <td>{{if .SameSite}}<span style="color:#fbbf24">{{.SameSite}}</span>{{else}}<span style="color:#f87171">None</span>{{end}}</td>
      </tr>
      {{end}}{{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- S3 / Cloud Storage -->
  {{$pubBuckets := publicBuckets .Result.S3Buckets}}
  {{if $pubBuckets}}
  <div class="section">
    <h2>Cloud Storage Exposure ({{len $pubBuckets}} buckets)</h2>
    <table>
      <thead><tr><th>Host</th><th>Bucket URL</th><th>Provider</th><th>Public</th><th>Listable</th></tr></thead>
      <tbody>
      {{range $pubBuckets}}
      <tr>
        <td class="mono">{{.Host}}</td>
        <td class="mono"><a href="{{.BucketURL}}" target="_blank">{{.BucketURL}}</a></td>
        <td><span class="tag-{{.Provider}}">{{.Provider}}</span></td>
        <td>{{if .Public}}<span style="color:#fbbf24">Yes</span>{{else}}No{{end}}</td>
        <td>{{if .Listable}}<span style="color:#f87171;font-weight:700">YES — CRITICAL</span>{{else}}No{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- TLS Certificates -->
  {{if .Result.TLS}}
  <div class="section">
    <h2>TLS Certificates ({{len .Result.TLS}})</h2>
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

  <!-- WAF Detection -->
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

  <!-- Shodan Enrichment -->
  {{if .Result.ShodanHosts}}
  <div class="section">
    <h2>Shodan Enrichment ({{len .Result.ShodanHosts}} IPs)</h2>
    <table>
      <thead><tr><th>IP</th><th>ISP / Org</th><th>Country</th><th>CVEs Reported</th></tr></thead>
      <tbody>
      {{range .Result.ShodanHosts}}
      <tr>
        <td class="mono">{{.IP}}</td>
        <td>{{.ISP}}</td>
        <td>{{.Country}}</td>
        <td>{{if .Vulns}}<span style="color:#f87171;font-weight:600">{{len .Vulns}}</span>{{else}}<span style="color:#6b7280">0</span>{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- Email Security -->
  {{if .Result.EmailSecurity}}
  <div class="section">
    <h2>Email Security — SPF / DMARC / DKIM ({{len .Result.EmailSecurity}} domains)</h2>
    <table>
      <thead><tr><th>Domain</th><th>SPF</th><th>DMARC</th><th>DKIM</th><th>DKIM Selector</th></tr></thead>
      <tbody>
      {{range .Result.EmailSecurity}}
      <tr>
        <td class="mono">{{.Domain}}</td>
        <td>{{if .SPFPresent}}<span style="color:#34d399;font-weight:600">Present</span>{{else}}<span style="color:#f87171;font-weight:600">Missing</span>{{end}}</td>
        <td>{{if .DMARCPresent}}<span style="color:#34d399;font-weight:600">Present</span>{{else}}<span style="color:#f87171;font-weight:600">Missing</span>{{end}}</td>
        <td>{{if .DKIMPresent}}<span style="color:#34d399;font-weight:600">Found</span>{{else}}<span style="color:#6b7280">Not found</span>{{end}}</td>
        <td class="mono finding-detail">{{if .DKIMSelector}}{{.DKIMSelector}}{{else}}—{{end}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- Subdomains -->
  <div class="section">
    <h2>Subdomains / Hosts ({{len .Result.Subdomains}})</h2>
    <table>
      <thead><tr><th>Name</th><th>IP Address</th><th>Sources</th></tr></thead>
      <tbody>
      {{range .Result.Subdomains}}
      <tr>
        <td class="mono">{{.Name}}</td>
        <td class="mono">{{.IPAddress}}</td>
        <td class="finding-detail">{{join ", " .Sources}}</td>
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
        <td class="finding-detail">{{join ", " .TechStack}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <!-- Nuclei Vulnerabilities -->
  {{if .Result.Vulnerabilities}}
  <div class="section">
    <h2>Nuclei Vulnerabilities ({{len .Result.Vulnerabilities}})</h2>
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

  <!-- Screenshots -->
  {{if .Result.Screenshots}}
  <div class="section">
    <h2>Screenshots ({{len .Result.Screenshots}})</h2>
    <div class="screenshot-grid">
      {{range .Result.Screenshots}}
      <div class="screenshot-card">
        <a href="{{.Path}}" target="_blank">
          <img src="{{.Path}}" alt="Screenshot of {{.URL}}" loading="lazy">
        </a>
        <div class="sc-url" title="{{.URL}}"><a href="{{.URL}}" target="_blank">{{.URL}}</a></div>
      </div>
      {{end}}
    </div>
  </div>
  {{end}}

  <!-- Historical URLs -->
  {{if .Result.HistoricalURLs}}
  <div class="section">
    <h2>Historical URLs ({{len .Result.HistoricalURLs}})</h2>
    <table>
      <thead><tr><th>URL</th><th>Source</th></tr></thead>
      <tbody>
      {{range .Result.HistoricalURLs}}
      <tr>
        <td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
        <td class="finding-detail">{{.Source}}</td>
      </tr>
      {{end}}
      </tbody>
    </table>
  </div>
  {{end}}

  <div style="text-align:center;color:#334155;font-size:12px;margin-top:32px;padding-bottom:24px">
    Generated by <strong>Survex</strong> &nbsp;·&nbsp; {{formatTime .Now}}
  </div>

</div>
</body>
</html>`
