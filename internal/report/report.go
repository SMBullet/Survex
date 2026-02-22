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
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Survex Report — {{.Result.Scan.Client}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --mustard: #d4a017;
    --mustard-light: #e8b82f;
    --mustard-dim: #a07a10;
    --amber: #f59e0b;
    --amber-soft: #fbbf24;
    --rust: #c2410c;
    --sage: #22c55e;
    --coral: #ef4444;
    --sky: #38bdf8;
    --lavender: #a78bfa;
    --radius: 10px;
    --transition: 0.25s cubic-bezier(.4,0,.2,1);
  }
  [data-theme="dark"] {
    --bg-primary: #0c0c0e;
    --bg-secondary: #16161a;
    --bg-card: #1c1c21;
    --bg-hover: #24242a;
    --border: #2a2a32;
    --text-primary: #f0ece4;
    --text-secondary: #9e9a8f;
    --text-muted: #6b6760;
    --header-bg: #111113;
    --sidebar-bg: #111113;
    --badge-bg: rgba(212,160,23,0.12);
    --input-bg: #1c1c21;
  }
  [data-theme="light"] {
    --bg-primary: #faf8f3;
    --bg-secondary: #f2efe8;
    --bg-card: #ffffff;
    --bg-hover: #f5f2eb;
    --border: #e5e0d5;
    --text-primary: #1a1815;
    --text-secondary: #6b6560;
    --text-muted: #9e9890;
    --header-bg: #ffffff;
    --sidebar-bg: #ffffff;
    --badge-bg: rgba(212,160,23,0.08);
    --input-bg: #f2efe8;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:var(--bg-primary);color:var(--text-primary);line-height:1.6;transition:background var(--transition),color var(--transition)}
  a{color:var(--mustard);text-decoration:none;transition:color var(--transition)}
  a:hover{color:var(--mustard-light);text-decoration:underline}

  /* ── Header ─────────────────────────────── */
  .header{
    position:sticky;top:0;z-index:100;
    background:var(--header-bg);
    border-bottom:1px solid var(--border);
    padding:16px 28px;
    display:flex;justify-content:space-between;align-items:center;
    backdrop-filter:blur(12px);
    -webkit-backdrop-filter:blur(12px);
    transition:background var(--transition);
  }
  .logo{display:flex;align-items:center;gap:10px}
  .logo-mark{width:32px;height:32px;background:linear-gradient(135deg,var(--mustard),var(--amber));border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;color:#000;font-size:16px}
  .logo h1{font-size:1.1rem;font-weight:700;letter-spacing:-0.02em}
  .logo .target{font-size:13px;color:var(--text-secondary);font-weight:400}
  .header-right{display:flex;align-items:center;gap:16px}
  .header-meta{font-size:12px;color:var(--text-muted);text-align:right;line-height:1.7}
  .theme-toggle{
    width:40px;height:40px;border-radius:10px;border:1px solid var(--border);
    background:var(--bg-card);color:var(--text-primary);cursor:pointer;
    display:flex;align-items:center;justify-content:center;font-size:18px;
    transition:all var(--transition);
  }
  .theme-toggle:hover{border-color:var(--mustard);background:var(--badge-bg)}

  /* ── Layout ─────────────────────────────── */
  .layout{display:flex;min-height:calc(100vh - 65px)}
  .sidebar{
    width:220px;min-width:220px;
    background:var(--sidebar-bg);border-right:1px solid var(--border);
    padding:20px 0;position:sticky;top:65px;height:calc(100vh - 65px);overflow-y:auto;
    transition:background var(--transition);
  }
  .sidebar::-webkit-scrollbar{width:3px}
  .sidebar::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px}
  .nav-group{padding:0 12px;margin-bottom:16px}
  .nav-group-title{font-size:10px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.1em;padding:0 8px 6px}
  .nav-link{
    display:flex;align-items:center;gap:8px;
    padding:7px 10px;border-radius:6px;font-size:12px;font-weight:500;
    color:var(--text-secondary);cursor:pointer;transition:all var(--transition);
    text-decoration:none;
  }
  .nav-link:hover{background:var(--bg-hover);color:var(--text-primary);text-decoration:none}
  .nav-link.active{background:var(--badge-bg);color:var(--mustard)}
  .nav-count{
    margin-left:auto;font-size:10px;font-weight:600;
    background:var(--bg-hover);color:var(--text-muted);
    padding:1px 6px;border-radius:10px;min-width:20px;text-align:center;
  }
  .main{flex:1;padding:28px 32px;max-width:1200px;overflow-x:hidden}

  /* ── Summary Cards ──────────────────────── */
  .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:12px;margin-bottom:28px}
  .card{
    background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
    padding:16px 18px;transition:all var(--transition);position:relative;overflow:hidden;
  }
  .card:hover{border-color:var(--mustard-dim);transform:translateY(-1px)}
  .card-value{font-size:1.7rem;font-weight:800;color:var(--text-primary);letter-spacing:-0.03em}
  .card-label{font-size:10px;color:var(--text-muted);margin-top:2px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}
  .card-accent{position:absolute;top:0;left:0;right:0;height:2px}
  .card-accent-mustard{background:linear-gradient(90deg,var(--mustard),var(--amber))}
  .card-accent-coral{background:linear-gradient(90deg,var(--coral),#fb923c)}
  .card-accent-sage{background:linear-gradient(90deg,var(--sage),#4ade80)}
  .card-accent-sky{background:linear-gradient(90deg,var(--sky),#7dd3fc)}

  /* ── Sections ───────────────────────────── */
  .section{
    background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
    margin-bottom:20px;overflow:hidden;transition:border-color var(--transition);
  }
  .section:hover{border-color:color-mix(in srgb, var(--border) 50%, var(--mustard-dim) 50%)}
  .section-header{
    padding:16px 20px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;
    user-select:none;transition:background var(--transition);
  }
  .section-header:hover{background:var(--bg-hover)}
  .section-title{display:flex;align-items:center;gap:10px}
  .section-title h2{font-size:13px;font-weight:600;color:var(--text-primary);text-transform:uppercase;letter-spacing:.04em}
  .section-count{
    font-size:11px;font-weight:600;color:var(--mustard);
    background:var(--badge-bg);padding:2px 8px;border-radius:12px;
  }
  .section-chevron{
    width:20px;height:20px;color:var(--text-muted);
    transition:transform var(--transition);display:flex;align-items:center;
  }
  .section.collapsed .section-chevron{transform:rotate(-90deg)}
  .section-body{padding:0 20px 16px;transition:all var(--transition)}
  .section.collapsed .section-body{display:none}

  /* ── Tables ─────────────────────────────── */
  table{width:100%;border-collapse:collapse;font-size:12px}
  th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);color:var(--text-muted);font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap}
  td{padding:8px 10px;border-bottom:1px solid color-mix(in srgb, var(--border) 50%, transparent 50%);vertical-align:top;word-break:break-word;transition:background var(--transition)}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:var(--bg-hover)}
  .mono{font-family:'JetBrains Mono',monospace;font-size:11px}

  /* ── Badges ─────────────────────────────── */
  .badge{padding:3px 9px;border-radius:5px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;display:inline-block}
  .badge-critical{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.2)}
  .badge-high{background:rgba(245,158,11,0.12);color:#f59e0b;border:1px solid rgba(245,158,11,0.2)}
  .badge-medium{background:rgba(212,160,23,0.12);color:var(--mustard-light);border:1px solid rgba(212,160,23,0.2)}
  .badge-low{background:rgba(56,189,248,0.1);color:var(--sky);border:1px solid rgba(56,189,248,0.15)}
  .badge-info{background:rgba(167,139,250,0.1);color:var(--lavender);border:1px solid rgba(167,139,250,0.15)}
  .badge-ok{background:rgba(34,197,94,0.1);color:var(--sage);border:1px solid rgba(34,197,94,0.15)}
  .badge-danger{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.25)}
  .badge-warn{background:rgba(245,158,11,0.1);color:#fbbf24;border:1px solid rgba(245,158,11,0.15)}
  .new-tag{background:rgba(34,197,94,0.1);color:var(--sage);border:1px solid rgba(34,197,94,0.15);padding:2px 6px;border-radius:4px;font-size:9px;font-weight:700;margin-left:6px}
  .detail{color:var(--text-secondary);font-size:11px}

  /* ── Diff ────────────────────────────────── */
  .diff-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .diff-list{list-style:none;font-size:11px;font-family:'JetBrains Mono',monospace}
  .diff-list li{padding:3px 0}
  .diff-add li::before{content:"+ ";color:var(--sage)}
  .diff-rem li::before{content:"- ";color:var(--coral)}
  .empty{color:var(--text-muted);font-style:italic;font-size:12px;padding:8px 0}

  /* ── Screenshots ────────────────────────── */
  .shots{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px;margin-top:10px}
  .shot{background:var(--bg-primary);border:1px solid var(--border);border-radius:8px;overflow:hidden;transition:border-color var(--transition)}
  .shot:hover{border-color:var(--mustard-dim)}
  .shot img{width:100%;height:140px;object-fit:cover;display:block}
  .shot-url{padding:8px;font-size:10px;color:var(--text-muted);font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

  /* ── Search ─────────────────────────────── */
  .search-box{
    width:100%;padding:9px 14px;border-radius:8px;border:1px solid var(--border);
    background:var(--input-bg);color:var(--text-primary);font-size:12px;
    font-family:'Inter',sans-serif;margin-bottom:12px;outline:none;
    transition:border-color var(--transition);
  }
  .search-box:focus{border-color:var(--mustard)}
  .search-box::placeholder{color:var(--text-muted)}

  /* ── Footer ─────────────────────────────── */
  .footer{text-align:center;color:var(--text-muted);font-size:11px;padding:24px 0 20px;border-top:1px solid var(--border);margin-top:16px}

  /* ── Tags ────────────────────────────────── */
  .tag{padding:1px 7px;border-radius:4px;font-size:10px;font-weight:600}
  .tag-aws{background:rgba(245,158,11,0.1);color:var(--amber)}
  .tag-gcs{background:rgba(56,189,248,0.1);color:var(--sky)}
  .tag-azure{background:rgba(167,139,250,0.1);color:var(--lavender)}

  /* ── Grade ───────────────────────────────── */
  .grade{font-size:1.1em;font-weight:800;display:inline-block;min-width:28px;text-align:center}
  .grade-a{color:var(--sage)} .grade-b{color:var(--sky)} .grade-c{color:var(--amber-soft)} .grade-d{color:#fb923c} .grade-f{color:var(--coral)}

  /* ── Responsive ─────────────────────────── */
  @media(max-width:900px){
    .sidebar{display:none}
    .main{padding:16px}
    .cards{grid-template-columns:repeat(auto-fill,minmax(120px,1fr))}
    .diff-grid{grid-template-columns:1fr}
  }
</style>
</head>
<body>
<div class="header">
  <div class="logo">
    <div class="logo-mark">S</div>
    <div>
      <h1>Survex</h1>
      <div class="target">{{.Result.Scan.Target}} · {{.Result.Scan.Client}}</div>
    </div>
  </div>
  <div class="header-right">
    <div class="header-meta">
      ID: {{.Result.Scan.ID}}<br>
      {{formatTime .Result.Scan.StartedAt}}
    </div>
    <button class="theme-toggle" onclick="toggleTheme()" title="Toggle dark/light mode" id="themeBtn">🌙</button>
  </div>
</div>

<div class="layout">
<!-- Sidebar Navigation -->
<nav class="sidebar">
  <div class="nav-group">
    <div class="nav-group-title">Overview</div>
    <a class="nav-link active" href="#summary" onclick="scrollTo(event,'summary')">📊 Dashboard</a>
    <a class="nav-link" href="#findings" onclick="scrollTo(event,'findings')">🎯 Findings <span class="nav-count">{{len .Findings}}</span></a>
    {{if .Result.Diff}}<a class="nav-link" href="#diff" onclick="scrollTo(event,'diff')">🔄 Changes</a>{{end}}
  </div>
  <div class="nav-group">
    <div class="nav-group-title">Vulnerabilities</div>
    {{if .Result.Vulnerabilities}}<a class="nav-link" href="#vulns" onclick="scrollTo(event,'vulns')">💀 Nuclei <span class="nav-count">{{len .Result.Vulnerabilities}}</span></a>{{end}}
    {{if .Result.Takeovers}}<a class="nav-link" href="#takeovers" onclick="scrollTo(event,'takeovers')">🏴 Takeover <span class="nav-count">{{countVulnTakeovers .Result.Takeovers}}</span></a>{{end}}
    {{if .Result.XSSResults}}<a class="nav-link" href="#xss" onclick="scrollTo(event,'xss')">⚡ XSS <span class="nav-count">{{len .Result.XSSResults}}</span></a>{{end}}
    {{if .Result.SQLiResults}}<a class="nav-link" href="#sqli" onclick="scrollTo(event,'sqli')">💉 SQLi <span class="nav-count">{{len .Result.SQLiResults}}</span></a>{{end}}
    {{if .Result.OpenRedirects}}<a class="nav-link" href="#redirects" onclick="scrollTo(event,'redirects')">↗️ Redirects <span class="nav-count">{{len .Result.OpenRedirects}}</span></a>{{end}}
    {{if .Result.JSSecrets}}<a class="nav-link" href="#jssecrets" onclick="scrollTo(event,'jssecrets')">🔑 JS Secrets <span class="nav-count">{{len .Result.JSSecrets}}</span></a>{{end}}
    {{if .Result.GitHubExposures}}<a class="nav-link" href="#github" onclick="scrollTo(event,'github')">🐙 GitHub <span class="nav-count">{{len .Result.GitHubExposures}}</span></a>{{end}}
    {{if .Result.ZoneTransfers}}<a class="nav-link" href="#axfr" onclick="scrollTo(event,'axfr')">📋 Zone AXFR <span class="nav-count">{{len .Result.ZoneTransfers}}</span></a>{{end}}
  </div>
  <div class="nav-group">
    <div class="nav-group-title">Security</div>
    <a class="nav-link" href="#headers" onclick="scrollTo(event,'headers')">🛡️ Headers</a>
    {{if .Result.CORS}}<a class="nav-link" href="#cors" onclick="scrollTo(event,'cors')">🌐 CORS</a>{{end}}
    {{if .Result.EmailSecurity}}<a class="nav-link" href="#email" onclick="scrollTo(event,'email')">📧 Email</a>{{end}}
    {{if .Result.Cookies}}<a class="nav-link" href="#cookies" onclick="scrollTo(event,'cookies')">🍪 Cookies</a>{{end}}
    <a class="nav-link" href="#tls" onclick="scrollTo(event,'tls')">🔒 TLS</a>
    <a class="nav-link" href="#waf" onclick="scrollTo(event,'waf')">🧱 WAF</a>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">Discovery</div>
    <a class="nav-link" href="#hosts" onclick="scrollTo(event,'hosts')">🌎 Hosts <span class="nav-count">{{len .Result.Subdomains}}</span></a>
    <a class="nav-link" href="#http" onclick="scrollTo(event,'http')">🌐 HTTP <span class="nav-count">{{len .Result.HTTP}}</span></a>
    <a class="nav-link" href="#ports" onclick="scrollTo(event,'ports')">🔌 Ports <span class="nav-count">{{len .Result.Services}}</span></a>
    {{if .Result.FFUFResults}}<a class="nav-link" href="#ffuf" onclick="scrollTo(event,'ffuf')">📂 Paths <span class="nav-count">{{len .Result.FFUFResults}}</span></a>{{end}}
    {{if .Result.APIEndpoints}}<a class="nav-link" href="#api" onclick="scrollTo(event,'api')">🔗 APIs <span class="nav-count">{{len .Result.APIEndpoints}}</span></a>{{end}}
    {{if .Result.GraphQL}}<a class="nav-link" href="#graphql" onclick="scrollTo(event,'graphql')">◆ GraphQL <span class="nav-count">{{len .Result.GraphQL}}</span></a>{{end}}
    {{if .Result.S3Buckets}}<a class="nav-link" href="#s3" onclick="scrollTo(event,'s3')">☁️ Buckets</a>{{end}}
    {{if .Result.Screenshots}}<a class="nav-link" href="#screenshots" onclick="scrollTo(event,'screenshots')">📸 Shots <span class="nav-count">{{len .Result.Screenshots}}</span></a>{{end}}
  </div>
</nav>

<!-- Main Content -->
<div class="main">

  <!-- Summary Cards -->
  <div id="summary" class="cards">
    <div class="card"><div class="card-accent card-accent-mustard"></div><div class="card-value">{{len .Result.Subdomains}}</div><div class="card-label">Hosts</div></div>
    <div class="card"><div class="card-accent card-accent-sky"></div><div class="card-value">{{len .Result.Services}}</div><div class="card-label">Open Ports</div></div>
    <div class="card"><div class="card-accent card-accent-sage"></div><div class="card-value">{{len .Result.HTTP}}</div><div class="card-label">HTTP Live</div></div>
    <div class="card"><div class="card-accent card-accent-coral"></div><div class="card-value">{{len .Result.Vulnerabilities}}</div><div class="card-label">Vulns</div></div>
    <div class="card"><div class="card-value">{{len .Findings}}</div><div class="card-label">Findings</div></div>
    <div class="card"><div class="card-value">{{countVulnTakeovers .Result.Takeovers}}</div><div class="card-label">Takeovers</div></div>
    <div class="card"><div class="card-value">{{len .Result.TLS}}</div><div class="card-label">TLS Certs</div></div>
    <div class="card"><div class="card-value">{{countDetectedWAF .Result.WAF}}</div><div class="card-label">WAFs</div></div>
    <div class="card"><div class="card-value">{{len .Result.JSSecrets}}</div><div class="card-label">JS Secrets</div></div>
    <div class="card"><div class="card-value">{{len .Result.XSSResults}}</div><div class="card-label">XSS</div></div>
    <div class="card"><div class="card-value">{{len .Result.SQLiResults}}</div><div class="card-label">SQLi</div></div>
    <div class="card"><div class="card-value">{{len .Result.FFUFResults}}</div><div class="card-label">Paths</div></div>
  </div>

  <!-- Findings -->
  <div id="findings" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🎯 Risk Findings</h2><span class="section-count">{{len .Findings}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <input type="text" class="search-box" placeholder="Filter findings by asset, title, or severity…" onkeyup="filterTable(this,'findings-tbl')">
      {{if .Findings}}
      <table id="findings-tbl">
        <thead><tr><th>Severity</th><th>Asset</th><th>Title</th><th>Detail</th><th></th></tr></thead>
        <tbody>
        {{range .Findings}}
        <tr>
          <td>{{severityBadge .Severity}}</td>
          <td class="mono">{{.Asset}}{{if .Port}}:{{.Port}}{{end}}</td>
          <td>{{.Title}}</td>
          <td class="detail">{{.Detail}}</td>
          <td>{{if .New}}<span class="new-tag">NEW</span>{{end}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      {{else}}<p class="empty">No findings — looking clean! ✨</p>{{end}}
    </div>
  </div>

  <!-- Diff -->
  {{if .Result.Diff}}
  <div id="diff" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🔄 Changes Since Last Scan</h2></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <div class="diff-grid">
        <div>
          <div style="color:var(--sage);font-weight:600;margin-bottom:6px;font-size:12px">+ New Subdomains ({{len .Result.Diff.NewSubdomains}})</div>
          {{if .Result.Diff.NewSubdomains}}<ul class="diff-list diff-add">{{range .Result.Diff.NewSubdomains}}<li>{{.}}</li>{{end}}</ul>
          {{else}}<p class="empty">None</p>{{end}}
        </div>
        <div>
          <div style="color:var(--coral);font-weight:600;margin-bottom:6px;font-size:12px">- Removed Subdomains ({{len .Result.Diff.RemovedSubdomains}})</div>
          {{if .Result.Diff.RemovedSubdomains}}<ul class="diff-list diff-rem">{{range .Result.Diff.RemovedSubdomains}}<li>{{.}}</li>{{end}}</ul>
          {{else}}<p class="empty">None</p>{{end}}
        </div>
      </div>
      {{if .Result.Diff.NewOpenPorts}}
      <div style="margin-top:14px">
        <div style="font-weight:600;margin-bottom:6px;color:var(--amber-soft);font-size:12px">⚡ New Open Ports</div>
        <table><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th></tr></thead><tbody>
        {{range .Result.Diff.NewOpenPorts}}<tr><td class="mono">{{.Host}}</td><td class="mono">{{.Port}}</td><td>{{.Protocol}}</td><td>{{.ServiceName}}</td></tr>{{end}}
        </tbody></table>
      </div>{{end}}
    </div>
  </div>
  {{end}}

  <!-- Nuclei Vulnerabilities -->
  {{if .Result.Vulnerabilities}}
  <div id="vulns" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>💀 Vulnerabilities</h2><span class="section-count">{{len .Result.Vulnerabilities}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Severity</th><th>Host</th><th>Name</th><th>Template</th><th>URL</th></tr></thead><tbody>
      {{range .Result.Vulnerabilities}}
      <tr><td>{{severityBadge .Severity}}</td><td class="mono">{{.Host}}</td><td>{{.Name}}</td><td class="mono detail">{{.TemplateID}}</td><td class="mono detail"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Subdomain Takeovers -->
  {{if .Result.Takeovers}}
  <div id="takeovers" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🏴 Subdomain Takeovers</h2><span class="section-count">{{countVulnTakeovers .Result.Takeovers}} vulnerable</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>CNAME</th><th>Service</th><th>Status</th><th>Evidence</th></tr></thead><tbody>
      {{range .Result.Takeovers}}
      <tr><td class="mono">{{.Host}}</td><td class="mono">{{.CNAME}}</td><td>{{.Service}}</td>
      <td>{{if .Vulnerable}}<span class="badge badge-danger">VULNERABLE</span>{{else}}<span class="badge badge-warn">Candidate</span>{{end}}</td>
      <td class="detail">{{.Evidence}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- XSS -->
  {{if .Result.XSSResults}}
  <div id="xss" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>⚡ Cross-Site Scripting</h2><span class="section-count">{{len .Result.XSSResults}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Severity</th><th>Host</th><th>Type</th><th>URL</th><th>Payload</th></tr></thead><tbody>
      {{range .Result.XSSResults}}
      <tr><td>{{severityBadge .Severity}}</td><td class="mono">{{.Host}}</td><td>{{.Type}}</td><td class="mono"><a href="{{.POC}}" target="_blank">{{.URL}}</a></td><td class="mono detail" style="word-break:break-all">{{.Payload}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- SQLi -->
  {{if .Result.SQLiResults}}
  <div id="sqli" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>💉 SQL Injection</h2><span class="section-count">{{len .Result.SQLiResults}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>URL</th><th>Parameter</th><th>Technique</th><th>DB</th></tr></thead><tbody>
      {{range .Result.SQLiResults}}
      <tr><td class="mono">{{.Host}}</td><td class="mono detail"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td><td class="mono">{{.Parameter}}</td><td class="detail">{{.Technique}}</td><td class="detail">{{.DBType}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Open Redirects -->
  {{if .Result.OpenRedirects}}
  <div id="redirects" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>↗️ Open Redirects</h2><span class="section-count">{{len .Result.OpenRedirects}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>Parameter</th><th>Redirects To</th><th>URL</th></tr></thead><tbody>
      {{range .Result.OpenRedirects}}
      <tr><td class="mono">{{.Host}}</td><td class="mono">{{.Parameter}}</td><td class="mono detail">{{.RedirectsTo}}</td><td class="mono detail"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- JS Secrets -->
  {{if .Result.JSSecrets}}
  <div id="jssecrets" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🔑 JavaScript Secrets</h2><span class="section-count">{{len .Result.JSSecrets}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>Type</th><th>File</th><th>Match</th></tr></thead><tbody>
      {{range .Result.JSSecrets}}
      <tr><td class="mono">{{.Host}}</td><td><span class="badge badge-danger">{{.Type}}</span></td><td class="mono detail">{{.URL}}</td><td class="mono detail" style="color:var(--amber-soft)">{{.Match}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- GitHub Exposures -->
  {{if .Result.GitHubExposures}}
  <div id="github" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🐙 GitHub Exposures</h2><span class="section-count">{{len .Result.GitHubExposures}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Repository</th><th>File</th><th>Query</th></tr></thead><tbody>
      {{range .Result.GitHubExposures}}
      <tr><td><a href="{{.RepoURL}}" target="_blank">{{.Repository}}</a></td><td><a href="{{.FileURL}}" target="_blank" class="mono detail">{{.FileName}}</a></td><td class="detail">{{.Query}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Zone Transfers -->
  {{if .Result.ZoneTransfers}}
  <div id="axfr" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>📋 Zone Transfers (AXFR)</h2><span class="section-count badge badge-danger">CRITICAL</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Domain</th><th>Records Dumped</th><th>Severity</th></tr></thead><tbody>
      {{range .Result.ZoneTransfers}}
      <tr><td class="mono">{{.Domain}}</td><td style="color:var(--coral);font-weight:700">{{.Records}}</td><td><span class="badge badge-critical">CRITICAL</span></td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Security Headers -->
  {{if .Result.SecurityHeaders}}
  <div id="headers" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🛡️ Security Headers</h2><span class="section-count">{{len .Result.SecurityHeaders}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>URL</th><th>Grade</th><th>Missing</th></tr></thead><tbody>
      {{range .Result.SecurityHeaders}}
      <tr><td class="mono">{{.Host}}</td><td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
      <td><span class="grade {{if or (eq .Score "A+") (eq .Score "A")}}grade-a{{else if eq .Score "B"}}grade-b{{else if eq .Score "C"}}grade-c{{else if eq .Score "D"}}grade-d{{else}}grade-f{{end}}">{{.Score}}</span></td>
      <td class="detail">{{join ", " .Missing}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- CORS -->
  {{$vulnCORS := corsVulnerable .Result.CORS}}
  {{if $vulnCORS}}
  <div id="cors" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🌐 CORS Misconfigurations</h2><span class="section-count">{{len $vulnCORS}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>URL</th><th>Issue</th><th>Evidence</th></tr></thead><tbody>
      {{range $vulnCORS}}
      <tr><td class="mono">{{.Host}}</td><td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td><td>{{corsIssueBadge .Issue}}</td><td class="detail">{{.Evidence}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Email Security -->
  {{if .Result.EmailSecurity}}
  <div id="email" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>📧 Email Security</h2><span class="section-count">{{len .Result.EmailSecurity}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Domain</th><th>SPF</th><th>DMARC</th><th>DKIM</th></tr></thead><tbody>
      {{range .Result.EmailSecurity}}
      <tr><td class="mono">{{.Domain}}</td>
      <td>{{if .SPFPresent}}<span class="badge badge-ok">Present</span>{{else}}<span class="badge badge-danger">Missing</span>{{end}}</td>
      <td>{{if .DMARCPresent}}<span class="badge badge-ok">Present</span>{{else}}<span class="badge badge-danger">Missing</span>{{end}}</td>
      <td>{{if .DKIMPresent}}<span class="badge badge-ok">Found</span>{{else}}<span class="badge badge-info">Not found</span>{{end}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Cookies -->
  {{if .Result.Cookies}}
  <div id="cookies" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🍪 Cookie Security</h2><span class="section-count">{{len .Result.Cookies}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead><tbody>
      {{range .Result.Cookies}}{{$host := .Host}}{{range .Cookies}}
      <tr><td class="mono">{{$host}}</td><td class="mono">{{.Name}}</td>
      <td>{{if .Secure}}<span class="badge badge-ok">Yes</span>{{else}}<span class="badge badge-danger">No</span>{{end}}</td>
      <td>{{if .HttpOnly}}<span class="badge badge-ok">Yes</span>{{else}}<span class="badge badge-danger">No</span>{{end}}</td>
      <td>{{if .SameSite}}<span class="badge badge-warn">{{.SameSite}}</span>{{else}}<span class="badge badge-danger">None</span>{{end}}</td></tr>
      {{end}}{{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- TLS -->
  {{if .Result.TLS}}
  <div id="tls" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🔒 TLS Certificates</h2><span class="section-count">{{len .Result.TLS}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>Issuer</th><th>Expiry</th><th>Days Left</th><th>Version</th><th>Status</th></tr></thead><tbody>
      {{range .Result.TLS}}
      <tr><td class="mono">{{.Host}}</td><td>{{.Issuer}}</td><td class="mono">{{formatTime .Expiry}}</td>
      <td class="mono">{{if .Expired}}<span style="color:var(--coral)">{{.DaysLeft}}</span>{{else if le .DaysLeft 30}}<span style="color:var(--amber-soft)">{{.DaysLeft}}</span>{{else}}<span style="color:var(--sage)">{{.DaysLeft}}</span>{{end}}</td>
      <td>{{.Version}}</td>
      <td>{{if .Expired}}<span class="badge badge-danger">EXPIRED</span>{{else if .SelfSigned}}<span class="badge badge-warn">SELF-SIGNED</span>{{else}}<span class="badge badge-ok">OK</span>{{end}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- WAF -->
  <div id="waf" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🧱 WAF Detection</h2><span class="section-count">{{countDetectedWAF .Result.WAF}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      {{$detected := wafDetected .Result.WAF}}
      {{if $detected}}
      <table><thead><tr><th>Host</th><th>WAF</th><th>Evidence</th></tr></thead><tbody>
      {{range $detected}}<tr><td class="mono">{{.Host}}</td><td style="color:var(--sage);font-weight:600">{{.Name}}</td><td class="detail">{{.Evidence}}</td></tr>{{end}}
      </tbody></table>
      {{else}}<p class="empty">No WAFs detected.</p>{{end}}
    </div>
  </div>

  <!-- S3 Buckets -->
  {{$pubBuckets := publicBuckets .Result.S3Buckets}}
  {{if $pubBuckets}}
  <div id="s3" class="section">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>☁️ Cloud Storage</h2><span class="section-count">{{len $pubBuckets}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>Bucket</th><th>Provider</th><th>Public</th><th>Listable</th></tr></thead><tbody>
      {{range $pubBuckets}}
      <tr><td class="mono">{{.Host}}</td><td class="mono"><a href="{{.BucketURL}}" target="_blank">{{.BucketURL}}</a></td>
      <td><span class="tag tag-{{.Provider}}">{{.Provider}}</span></td>
      <td>{{if .Public}}<span class="badge badge-warn">Yes</span>{{else}}No{{end}}</td>
      <td>{{if .Listable}}<span class="badge badge-danger">YES</span>{{else}}No{{end}}</td></tr>
      {{end}}</tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Hosts -->
  <div id="hosts" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🌎 Hosts</h2><span class="section-count">{{len .Result.Subdomains}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Name</th><th>IP</th><th>Sources</th></tr></thead><tbody>
      {{range .Result.Subdomains}}<tr><td class="mono">{{.Name}}</td><td class="mono">{{.IPAddress}}</td><td class="detail">{{join ", " .Sources}}</td></tr>{{end}}
      </tbody></table>
    </div>
  </div>

  <!-- HTTP -->
  {{if .Result.HTTP}}
  <div id="http" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🌐 HTTP Services</h2><span class="section-count">{{len .Result.HTTP}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Tech</th></tr></thead><tbody>
      {{range .Result.HTTP}}<tr><td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td><td class="mono">{{.StatusCode}}</td><td>{{.Title}}</td><td>{{.WebServer}}</td><td class="detail">{{join ", " .TechStack}}</td></tr>{{end}}
      </tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Ports -->
  {{if .Result.Services}}
  <div id="ports" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🔌 Open Ports</h2><span class="section-count">{{len .Result.Services}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th></tr></thead><tbody>
      {{range .Result.Services}}<tr><td class="mono">{{.Host}}</td><td class="mono">{{.Port}}</td><td>{{.Protocol}}</td><td>{{.ServiceName}}</td></tr>{{end}}
      </tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Content Discovery (ffuf) -->
  {{if .Result.FFUFResults}}
  <div id="ffuf" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>📂 Content Discovery</h2><span class="section-count">{{len .Result.FFUFResults}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Type</th><th>URL</th><th>Status</th><th>Size</th></tr></thead><tbody>
      {{range .Result.FFUFResults}}<tr><td>{{.ResultType}}</td><td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td><td class="mono">{{.StatusCode}}</td><td class="mono detail">{{.ContentLen}}b</td></tr>{{end}}
      </tbody></table>
    </div>
  </div>
  {{end}}

  <!-- API Endpoints -->
  {{if .Result.APIEndpoints}}
  <div id="api" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🔗 API Endpoints</h2><span class="section-count">{{len .Result.APIEndpoints}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>Type</th><th>URL</th><th>Status</th></tr></thead><tbody>
      {{range .Result.APIEndpoints}}<tr><td class="mono">{{.Host}}</td><td><span class="badge badge-medium">{{.Type}}</span></td><td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td><td class="mono">{{.StatusCode}}</td></tr>{{end}}
      </tbody></table>
    </div>
  </div>
  {{end}}

  <!-- GraphQL -->
  {{if .Result.GraphQL}}
  <div id="graphql" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>◆ GraphQL</h2><span class="section-count">{{len .Result.GraphQL}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>Host</th><th>URL</th><th>Introspection</th><th>Types</th></tr></thead><tbody>
      {{range .Result.GraphQL}}<tr><td class="mono">{{.Host}}</td><td class="mono"><a href="{{.URL}}" target="_blank">{{.URL}}</a></td>
      <td>{{if .IntrospectionEnabled}}<span class="badge badge-danger">ENABLED</span>{{else}}<span class="badge badge-ok">Disabled</span>{{end}}</td>
      <td class="detail">{{join ", " .Types}}</td></tr>{{end}}
      </tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Shodan -->
  {{if .Result.ShodanHosts}}
  <div id="shodan" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>🔍 Shodan</h2><span class="section-count">{{len .Result.ShodanHosts}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <table><thead><tr><th>IP</th><th>ISP / Org</th><th>Country</th><th>CVEs</th></tr></thead><tbody>
      {{range .Result.ShodanHosts}}<tr><td class="mono">{{.IP}}</td><td>{{.ISP}}</td><td>{{.Country}}</td>
      <td>{{if .Vulns}}<span style="color:var(--coral);font-weight:700">{{len .Vulns}}</span>{{else}}<span style="color:var(--text-muted)">0</span>{{end}}</td></tr>{{end}}
      </tbody></table>
    </div>
  </div>
  {{end}}

  <!-- Screenshots -->
  {{if .Result.Screenshots}}
  <div id="screenshots" class="section collapsed">
    <div class="section-header" onclick="toggle(this)">
      <div class="section-title"><h2>📸 Screenshots</h2><span class="section-count">{{len .Result.Screenshots}}</span></div>
      <div class="section-chevron">▼</div>
    </div>
    <div class="section-body">
      <div class="shots">
        {{range .Result.Screenshots}}
        <div class="shot"><a href="{{.Path}}" target="_blank"><img src="{{.Path}}" alt="{{.URL}}" loading="lazy"></a><div class="shot-url"><a href="{{.URL}}" target="_blank">{{.URL}}</a></div></div>
        {{end}}
      </div>
    </div>
  </div>
  {{end}}

  <div class="footer">Generated by <strong>Survex</strong> · {{formatTime .Now}}</div>
</div>
</div>

<script>
function toggleTheme(){
  const html=document.documentElement;
  const t=html.getAttribute('data-theme')==='dark'?'light':'dark';
  html.setAttribute('data-theme',t);
  document.getElementById('themeBtn').textContent=t==='dark'?'🌙':'☀️';
  localStorage.setItem('survex-theme',t);
}
(function(){
  const saved=localStorage.getItem('survex-theme');
  if(saved){document.documentElement.setAttribute('data-theme',saved);document.getElementById('themeBtn').textContent=saved==='dark'?'🌙':'☀️'}
})();

function toggle(el){el.closest('.section').classList.toggle('collapsed')}

function scrollTo(e,id){
  e.preventDefault();
  const el=document.getElementById(id);
  if(!el)return;
  const section=el.closest('.section');
  if(section&&section.classList.contains('collapsed'))section.classList.remove('collapsed');
  el.scrollIntoView({behavior:'smooth',block:'start'});
  document.querySelectorAll('.nav-link').forEach(n=>n.classList.remove('active'));
  e.currentTarget.classList.add('active');
}

function filterTable(input,tableId){
  const filter=input.value.toLowerCase();
  const rows=document.getElementById(tableId).querySelectorAll('tbody tr');
  rows.forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(filter)?'':'none'});
}
</script>
</body>
</html>` + "\n"
