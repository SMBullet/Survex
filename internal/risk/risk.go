package risk

import (
	"fmt"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// portRules maps open port numbers to [severity, description] findings.
var portRules = map[int][2]string{
	// ── Cleartext / legacy protocols ──────────────────────────────────────────
	21:  {"medium", "FTP exposed (cleartext credentials)"},
	22:  {"medium", "SSH exposed"},
	23:  {"high", "Telnet exposed (cleartext, unauthenticated)"},
	25:  {"medium", "SMTP exposed"},
	53:  {"low", "DNS port exposed"},
	69:  {"high", "TFTP exposed (unauthenticated file transfer)"},
	79:  {"low", "Finger service exposed"},
	110: {"medium", "POP3 exposed"},
	143: {"medium", "IMAP exposed"},
	389: {"medium", "LDAP exposed (cleartext)"},
	636: {"low", "LDAPS exposed"},

	// ── Remote access ────────────────────────────────────────────────────────
	512: {"high", "RSH exposed (unauthenticated remote shell)"},
	513: {"high", "rlogin exposed (unauthenticated)"},
	514: {"high", "RSH/syslog exposed"},
	623: {"high", "IPMI/BMC exposed (remote server management)"},
	873: {"medium", "rsync exposed (may allow unauthenticated access)"},
	902: {"medium", "VMware ESXi exposed"},
	903: {"medium", "VMware ESXi web console exposed"},
	3389: {"high", "RDP exposed (common brute-force target)"},
	5900: {"high", "VNC exposed (often unauthenticated)"},
	5985: {"medium", "WinRM HTTP exposed"},
	5986: {"medium", "WinRM HTTPS exposed"},

	// ── Databases ────────────────────────────────────────────────────────────
	1433:  {"critical", "MSSQL database exposed to internet"},
	1521:  {"critical", "Oracle database exposed to internet"},
	3306:  {"critical", "MySQL/MariaDB database exposed to internet"},
	5432:  {"critical", "PostgreSQL database exposed to internet"},
	5984:  {"critical", "CouchDB exposed (often unauthenticated)"},
	6379:  {"critical", "Redis exposed (unauthenticated by default)"},
	9200:  {"critical", "Elasticsearch HTTP exposed (unauthenticated)"},
	9300:  {"critical", "Elasticsearch cluster transport exposed"},
	11211: {"critical", "Memcached exposed (unauthenticated, amplification risk)"},
	27017: {"critical", "MongoDB exposed (unauthenticated by default)"},
	27018: {"critical", "MongoDB shard server exposed"},
	27019: {"critical", "MongoDB config server exposed"},

	// ── Message queues / streaming ────────────────────────────────────────────
	5672:  {"high", "RabbitMQ AMQP exposed"},
	9092:  {"high", "Apache Kafka exposed (often no auth by default)"},
	15672: {"high", "RabbitMQ management UI exposed"},
	61616: {"high", "Apache ActiveMQ broker exposed"},

	// ── Container / orchestration ─────────────────────────────────────────────
	2375: {"critical", "Docker daemon exposed (unauthenticated API — full host compromise)"},
	2376: {"high", "Docker daemon TLS port exposed"},
	2379: {"critical", "etcd exposed (Kubernetes secret store)"},
	2380: {"critical", "etcd cluster port exposed"},
	6443: {"medium", "Kubernetes API server exposed"},
	8443: {"low", "Alternate HTTPS / Kubernetes API"},
	10250: {"high", "Kubernetes kubelet API exposed (code execution risk)"},
	10255: {"high", "Kubernetes kubelet read-only API exposed"},

	// ── ICS / SCADA ───────────────────────────────────────────────────────────
	102: {"high", "Siemens S7 PLC exposed (ICS/SCADA)"},
	502: {"critical", "Modbus TCP exposed (ICS/SCADA — no authentication)"},

	// ── Application servers / admin ───────────────────────────────────────────
	4444:  {"critical", "Common reverse shell / Metasploit default port"},
	4848:  {"high", "GlassFish admin console exposed"},
	7001:  {"high", "WebLogic admin port exposed"},
	7002:  {"high", "WebLogic HTTPS admin port exposed"},
	8009:  {"high", "Apache AJP (Ghostcat vulnerability vector)"},
	8080:  {"low", "Alternate HTTP port"},
	8161:  {"high", "Apache ActiveMQ admin console exposed"},
	8888:  {"medium", "Jupyter Notebook (may be unauthenticated)"},
	9090:  {"medium", "Prometheus / alternative admin port exposed"},
	16992: {"high", "Intel AMT web interface exposed (remote management)"},
	50000: {"high", "Apache Spark / SAP HANA port exposed"},

	// ── Coordination / discovery ──────────────────────────────────────────────
	2181: {"critical", "Apache Zookeeper exposed (unauthenticated)"},
	4369: {"medium", "Erlang Port Mapper (EPMD) exposed"},
	8500: {"high", "Consul HTTP API exposed (cluster coordination)"},
	8600: {"medium", "Consul DNS exposed"},
}

// adminKeywords matches page titles that likely indicate an admin interface.
var adminKeywords = []string{
	"admin", "administrator", "panel", "dashboard", "manage", "management",
	"control", "wp-admin", "phpmyadmin", "cpanel", "webmin", "kibana",
	"grafana", "portainer", "jenkins", "sonarqube", "nexus", "artifactory",
	"consul", "vault", "traefik", "prometheus", "zabbix", "nagios", "splunk",
	"rundeck", "airflow", "flower", "celery", "pgadmin", "adminer",
}

// Score evaluates a full scan result and returns all findings sorted by severity.
func Score(result *models.ScanResult) []models.Finding {
	var findings []models.Finding
	now := time.Now()

	newPorts := make(map[string]bool)
	newHTTP := make(map[string]bool)
	if result.Diff != nil {
		for _, s := range result.Diff.NewOpenPorts {
			newPorts[fmt.Sprintf("%s:%d", s.Host, s.Port)] = true
		}
		for _, u := range result.Diff.NewHTTPURLs {
			newHTTP[u] = true
		}
	}
	firstScan := result.Diff == nil

	// ── Port-based rules ──────────────────────────────────────────────────────
	for _, svc := range result.Services {
		rule, ok := portRules[svc.Port]
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%d", svc.Host, svc.Port)
		findings = append(findings, models.Finding{
			Asset:     svc.Host,
			Port:      svc.Port,
			Severity:  rule[0],
			Title:     rule[1],
			Detail:    fmt.Sprintf("Port %d/%s open — service: %s", svc.Port, svc.Protocol, svc.ServiceName),
			FirstSeen: now,
			New:       newPorts[key] || firstScan,
		})
	}

	// ── HTTP-based rules ──────────────────────────────────────────────────────
	for _, h := range result.HTTP {
		titleLower := strings.ToLower(h.Title)
		for _, kw := range adminKeywords {
			if strings.Contains(titleLower, kw) {
				findings = append(findings, models.Finding{
					Asset:     h.Host,
					Severity:  "high",
					Title:     "Admin panel exposed",
					Detail:    fmt.Sprintf("Page title '%s' at %s suggests an administrative interface", h.Title, h.URL),
					FirstSeen: now,
					New:       firstScan || newHTTP[h.URL],
				})
				break
			}
		}

		if strings.HasPrefix(h.URL, "http://") && h.StatusCode > 0 {
			findings = append(findings, models.Finding{
				Asset:     h.Host,
				Severity:  "low",
				Title:     "Unencrypted HTTP service",
				Detail:    fmt.Sprintf("%s is accessible over plain HTTP without TLS", h.URL),
				FirstSeen: now,
				New:       firstScan || newHTTP[h.URL],
			})
		}
	}

	// ── TLS-based rules ───────────────────────────────────────────────────────
	for _, t := range result.TLS {
		if t.Expired {
			findings = append(findings, models.Finding{
				Asset:     t.Host,
				Severity:  "high",
				Title:     "TLS certificate expired",
				Detail:    fmt.Sprintf("Certificate expired on %s (issuer: %s)", t.Expiry.Format("2006-01-02"), t.Issuer),
				FirstSeen: now,
				New:       firstScan,
			})
		} else if t.DaysLeft <= 14 {
			findings = append(findings, models.Finding{
				Asset:     t.Host,
				Severity:  "high",
				Title:     "TLS certificate expiring in under 14 days",
				Detail:    fmt.Sprintf("Certificate expires in %d days (%s)", t.DaysLeft, t.Expiry.Format("2006-01-02")),
				FirstSeen: now,
				New:       firstScan,
			})
		} else if t.DaysLeft <= 30 {
			findings = append(findings, models.Finding{
				Asset:     t.Host,
				Severity:  "medium",
				Title:     "TLS certificate expiring within 30 days",
				Detail:    fmt.Sprintf("Certificate expires in %d days (%s)", t.DaysLeft, t.Expiry.Format("2006-01-02")),
				FirstSeen: now,
				New:       firstScan,
			})
		}

		if t.SelfSigned {
			findings = append(findings, models.Finding{
				Asset:     t.Host,
				Severity:  "medium",
				Title:     "Self-signed TLS certificate",
				Detail:    fmt.Sprintf("Certificate on %s is self-signed (subject: %s)", t.Host, t.Subject),
				FirstSeen: now,
				New:       firstScan,
			})
		}

		if t.Version == "TLS 1.0" || t.Version == "TLS 1.1" {
			findings = append(findings, models.Finding{
				Asset:     t.Host,
				Severity:  "medium",
				Title:     fmt.Sprintf("Weak TLS version negotiated: %s", t.Version),
				Detail:    fmt.Sprintf("%s supports %s which is deprecated and considered insecure", t.Host, t.Version),
				FirstSeen: now,
				New:       firstScan,
			})
		}
	}

	// ── Security Headers rules ────────────────────────────────────────────────
	for _, h := range result.SecurityHeaders {
		for _, missing := range h.Missing {
			sev, title, detail := headerFinding(missing, h.URL)
			if sev == "" {
				continue
			}
			findings = append(findings, models.Finding{
				Asset:     h.Host,
				Severity:  sev,
				Title:     title,
				Detail:    detail,
				FirstSeen: now,
				New:       firstScan,
			})
		}
	}

	// ── CORS rules ────────────────────────────────────────────────────────────
	for _, c := range result.CORS {
		if !c.Vulnerable {
			continue
		}
		sev := corsIssueSeverity(c.Issue)
		findings = append(findings, models.Finding{
			Asset:     c.Host,
			Severity:  sev,
			Title:     fmt.Sprintf("CORS misconfiguration: %s", corsIssueTitle(c.Issue)),
			Detail:    c.Evidence + " — URL: " + c.URL,
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── Cookie security rules ─────────────────────────────────────────────────
	for _, cr := range result.Cookies {
		for _, cookie := range cr.Cookies {
			if !cookie.Secure {
				findings = append(findings, models.Finding{
					Asset:     cr.Host,
					Severity:  "medium",
					Title:     "Cookie missing Secure flag",
					Detail:    fmt.Sprintf("Cookie '%s' at %s lacks the Secure flag — transmittable over HTTP", cookie.Name, cr.URL),
					FirstSeen: now,
					New:       firstScan,
				})
			}
			if !cookie.HttpOnly {
				findings = append(findings, models.Finding{
					Asset:     cr.Host,
					Severity:  "low",
					Title:     "Cookie missing HttpOnly flag",
					Detail:    fmt.Sprintf("Cookie '%s' at %s is accessible to JavaScript (XSS-readable)", cookie.Name, cr.URL),
					FirstSeen: now,
					New:       firstScan,
				})
			}
			if cookie.SameSite == "" {
				findings = append(findings, models.Finding{
					Asset:     cr.Host,
					Severity:  "info",
					Title:     "Cookie missing SameSite attribute",
					Detail:    fmt.Sprintf("Cookie '%s' at %s has no SameSite attribute (CSRF risk)", cookie.Name, cr.URL),
					FirstSeen: now,
					New:       firstScan,
				})
			}
		}
	}

	// ── S3 / Cloud storage rules ──────────────────────────────────────────────
	for _, b := range result.S3Buckets {
		if b.Listable {
			findings = append(findings, models.Finding{
				Asset:     b.Host,
				Severity:  "critical",
				Title:     fmt.Sprintf("Cloud storage bucket publicly listable (%s)", strings.ToUpper(b.Provider)),
				Detail:    fmt.Sprintf("Bucket %s is publicly listable — all stored objects can be enumerated", b.BucketURL),
				FirstSeen: now,
				New:       firstScan,
			})
		} else if b.Public {
			findings = append(findings, models.Finding{
				Asset:     b.Host,
				Severity:  "high",
				Title:     fmt.Sprintf("Cloud storage bucket publicly accessible (%s)", strings.ToUpper(b.Provider)),
				Detail:    fmt.Sprintf("Bucket %s is publicly accessible (listing disabled but objects may be guessable)", b.BucketURL),
				FirstSeen: now,
				New:       firstScan,
			})
		}
	}

	// ── Shodan CVE findings ───────────────────────────────────────────────────
	for _, sh := range result.ShodanHosts {
		for _, vuln := range sh.Vulns {
			findings = append(findings, models.Finding{
				Asset:     sh.IP,
				Severity:  "high",
				Title:     fmt.Sprintf("Shodan: CVE reported for host — %s", vuln),
				Detail:    fmt.Sprintf("Shodan reports %s affecting %s (ISP: %s, Country: %s)", vuln, sh.IP, sh.ISP, sh.Country),
				FirstSeen: now,
				New:       firstScan,
			})
		}
	}

	// ── Subdomain takeover findings ───────────────────────────────────────────
	for _, t := range result.Takeovers {
		if t.Vulnerable {
			findings = append(findings, models.Finding{
				Asset:     t.Host,
				Severity:  "critical",
				Title:     fmt.Sprintf("Subdomain takeover confirmed: %s", t.Service),
				Detail:    fmt.Sprintf("CNAME → %s | %s", t.CNAME, t.Evidence),
				FirstSeen: now,
				New:       firstScan,
			})
		} else if t.CNAME != "" {
			findings = append(findings, models.Finding{
				Asset:     t.Host,
				Severity:  "info",
				Title:     fmt.Sprintf("Subdomain CNAME to %s (takeover candidate)", t.Service),
				Detail:    fmt.Sprintf("CNAME → %s | %s", t.CNAME, t.Evidence),
				FirstSeen: now,
				New:       firstScan,
			})
		}
	}

	// ── Email security findings ────────────────────────────────────────────────
	for _, e := range result.EmailSecurity {
		if !e.SPFPresent {
			findings = append(findings, models.Finding{
				Asset:     e.Domain,
				Severity:  "medium",
				Title:     "Missing SPF record",
				Detail:    fmt.Sprintf("No SPF TXT record found for %s — anyone can spoof email from this domain", e.Domain),
				FirstSeen: now,
				New:       firstScan,
			})
		}
		if !e.DMARCPresent {
			findings = append(findings, models.Finding{
				Asset:     e.Domain,
				Severity:  "medium",
				Title:     "Missing DMARC record",
				Detail:    fmt.Sprintf("No DMARC policy at _dmarc.%s — no enforcement against spoofed email", e.Domain),
				FirstSeen: now,
				New:       firstScan,
			})
		}
		if !e.DKIMPresent {
			findings = append(findings, models.Finding{
				Asset:     e.Domain,
				Severity:  "low",
				Title:     "No DKIM record detected",
				Detail:    fmt.Sprintf("No DKIM TXT record found for %s — email integrity cannot be cryptographically verified", e.Domain),
				FirstSeen: now,
				New:       firstScan,
			})
		}
	}

	// ── Zone transfer findings ────────────────────────────────────────────────
	for _, zt := range result.ZoneTransfers {
		findings = append(findings, models.Finding{
			Asset:     zt.Domain,
			Severity:  "critical",
			Title:     "DNS zone transfer allowed (AXFR)",
			Detail:    fmt.Sprintf("Nameserver for %s permitted a zone transfer — %d DNS records exposed (full internal DNS structure)", zt.Domain, zt.Records),
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── JavaScript secret findings ─────────────────────────────────────────────
	for _, js := range result.JSSecrets {
		findings = append(findings, models.Finding{
			Asset:     js.Host,
			Severity:  jsSecretSeverity(js.Type),
			Title:     fmt.Sprintf("Secret exposed in JavaScript: %s", js.Type),
			Detail:    fmt.Sprintf("Found in %s — match: %s", js.URL, js.Match),
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── GitHub exposure findings ───────────────────────────────────────────────
	for _, gh := range result.GitHubExposures {
		sev := "high"
		nameLower := strings.ToLower(gh.FileName)
		if strings.Contains(nameLower, "password") || strings.Contains(nameLower, "secret") ||
			strings.Contains(nameLower, "credential") || strings.HasSuffix(nameLower, ".env") {
			sev = "critical"
		}
		findings = append(findings, models.Finding{
			Asset:     gh.Repository,
			Severity:  sev,
			Title:     "Target domain found in public GitHub repository",
			Detail:    fmt.Sprintf("File: %s in %s | query: %s | %s", gh.FileName, gh.Repository, gh.Query, gh.FileURL),
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── ffuf content discovery findings ───────────────────────────────────────
	for _, f := range result.FFUFResults {
		sev := "info"
		title := "Content discovery: " + f.ResultType + " found"
		detail := fmt.Sprintf("URL: %s | HTTP %d | %d bytes", f.URL, f.StatusCode, f.ContentLen)
		switch f.ResultType {
		case "admin":
			sev = "high"
			title = "Admin panel exposed"
			detail = fmt.Sprintf("Admin interface discovered at %s (HTTP %d)", f.URL, f.StatusCode)
		case "backup":
			sev = "critical"
			title = "Backup/sensitive file exposed"
			detail = fmt.Sprintf("Potentially sensitive file at %s (HTTP %d, %d bytes)", f.URL, f.StatusCode, f.ContentLen)
		case "config":
			sev = "critical"
			title = "Configuration file exposed"
			detail = fmt.Sprintf("Configuration file at %s (HTTP %d)", f.URL, f.StatusCode)
		case "api":
			sev = "medium"
			title = "API endpoint discovered"
			detail = fmt.Sprintf("API path at %s (HTTP %d)", f.URL, f.StatusCode)
		}
		// Only surface admin, backup, config as findings — other types are info
		if sev == "info" {
			continue
		}
		findings = append(findings, models.Finding{
			Asset:     f.Host,
			Severity:  sev,
			Title:     title,
			Detail:    detail,
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── XSS findings (dalfox) ─────────────────────────────────────────────────
	for _, x := range result.XSSResults {
		findings = append(findings, models.Finding{
			Asset:    x.Host,
			Severity: "high",
			Title:    fmt.Sprintf("Cross-Site Scripting (%s)", x.Type),
			Detail:   fmt.Sprintf("Confirmed XSS at %s | Payload: %s | POC: %s", x.URL, x.Payload, x.POC),
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── SQLi findings (sqlmap) ─────────────────────────────────────────────────
	for _, s := range result.SQLiResults {
		findings = append(findings, models.Finding{
			Asset:    s.Host,
			Severity: "critical",
			Title:    "SQL Injection",
			Detail:   fmt.Sprintf("SQLi via parameter '%s' at %s | technique: %s | db: %s", s.Parameter, s.URL, s.Technique, s.DBType),
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── Open redirect findings ─────────────────────────────────────────────────
	for _, r := range result.OpenRedirects {
		findings = append(findings, models.Finding{
			Asset:    r.Host,
			Severity: "medium",
			Title:    "Open Redirect",
			Detail:   fmt.Sprintf("Parameter '%s' redirects to %s | URL: %s | payload: %s", r.Parameter, r.RedirectsTo, r.URL, r.Payload),
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── GraphQL findings ──────────────────────────────────────────────────────
	for _, gql := range result.GraphQL {
		if gql.IntrospectionEnabled {
			findings = append(findings, models.Finding{
				Asset:    gql.Host,
				Severity: "medium",
				Title:    "GraphQL introspection enabled",
				Detail:   fmt.Sprintf("Full schema exposed at %s — %d types leaked", gql.URL, len(gql.Types)),
				FirstSeen: now,
				New:       firstScan,
			})
		} else {
			findings = append(findings, models.Finding{
				Asset:    gql.Host,
				Severity: "info",
				Title:    "GraphQL endpoint detected",
				Detail:   fmt.Sprintf("GraphQL at %s (introspection disabled)", gql.URL),
				FirstSeen: now,
				New:       firstScan,
			})
		}
	}

	// ── API endpoint findings ─────────────────────────────────────────────────
	for _, api := range result.APIEndpoints {
		sev := "info"
		title := "API endpoint discovered"
		detail := fmt.Sprintf("%s endpoint at %s (HTTP %d)", api.Type, api.URL, api.StatusCode)
		switch api.Type {
		case "swagger", "openapi":
			sev = "medium"
			title = "API documentation publicly exposed"
			detail = fmt.Sprintf("Swagger/OpenAPI spec at %s — full API schema is public (HTTP %d)", api.URL, api.StatusCode)
		case "wsdl":
			sev = "medium"
			title = "WSDL/SOAP service exposed"
			detail = fmt.Sprintf("WSDL at %s — SOAP service interface is public (HTTP %d)", api.URL, api.StatusCode)
		case "rest":
			// Spring Boot actuator endpoints are high severity
			if strings.Contains(api.URL, "actuator") || strings.Contains(api.URL, "heapdump") {
				sev = "high"
				title = "Spring Boot actuator exposed"
				detail = fmt.Sprintf("Actuator endpoint at %s (HTTP %d) — may expose env, beans, heap dump", api.URL, api.StatusCode)
			}
		}
		if sev == "info" {
			continue // skip pure info-level discoveries from findings
		}
		findings = append(findings, models.Finding{
			Asset:    api.Host,
			Severity: sev,
			Title:    title,
			Detail:   detail,
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── Nuclei vulnerability findings ─────────────────────────────────────────
	for _, v := range result.Vulnerabilities {
		detail := fmt.Sprintf("Template: %s | URL: %s", v.TemplateID, v.URL)
		if v.Detail != "" {
			detail += " | " + v.Detail
		}
		findings = append(findings, models.Finding{
			Asset:     v.Host,
			Severity:  v.Severity,
			Title:     fmt.Sprintf("[nuclei] %s", v.Name),
			Detail:    detail,
			FirstSeen: now,
			New:       firstScan,
		})
	}

	// ── Diff-based informational findings ─────────────────────────────────────
	if result.Diff != nil {
		for _, sub := range result.Diff.NewSubdomains {
			findings = append(findings, models.Finding{
				Asset:     sub,
				Severity:  "info",
				Title:     "New subdomain discovered",
				Detail:    fmt.Sprintf("%s was not present in the previous scan", sub),
				FirstSeen: now,
				New:       true,
			})
		}
		for _, sub := range result.Diff.RemovedSubdomains {
			findings = append(findings, models.Finding{
				Asset:     sub,
				Severity:  "info",
				Title:     "Subdomain removed",
				Detail:    fmt.Sprintf("%s was present previously but is no longer reachable", sub),
				FirstSeen: now,
				New:       true,
			})
		}
		for _, change := range result.Diff.TLSChanges {
			findings = append(findings, models.Finding{
				Asset:     "TLS",
				Severity:  "medium",
				Title:     "TLS certificate changed",
				Detail:    change,
				FirstSeen: now,
				New:       true,
			})
		}
	}

	return sortFindings(findings)
}

// headerFinding returns severity/title/detail for a missing security header.
func headerFinding(header, url string) (sev, title, detail string) {
	switch header {
	case "Strict-Transport-Security":
		return "medium", "Missing Strict-Transport-Security (HSTS)",
			fmt.Sprintf("HSTS not set at %s — susceptible to HTTPS downgrade attacks", url)
	case "X-Frame-Options":
		return "low", "Missing X-Frame-Options",
			fmt.Sprintf("No clickjacking protection at %s — page can be embedded in iframes", url)
	case "X-Content-Type-Options":
		return "low", "Missing X-Content-Type-Options",
			fmt.Sprintf("MIME sniffing not disabled at %s — potential content-type confusion attacks", url)
	case "Content-Security-Policy":
		return "info", "Missing Content-Security-Policy",
			fmt.Sprintf("No CSP header at %s — increases XSS risk and lacks resource restriction", url)
	case "Referrer-Policy":
		return "info", "Missing Referrer-Policy",
			fmt.Sprintf("No Referrer-Policy at %s — referrer data may be leaked to third parties", url)
	case "Permissions-Policy":
		return "info", "Missing Permissions-Policy",
			fmt.Sprintf("No Permissions-Policy at %s — browser features (camera, mic, geolocation) unrestricted", url)
	}
	return "", "", ""
}

func corsIssueSeverity(issue string) string {
	switch issue {
	case "reflects_origin_with_credentials":
		return "critical"
	case "wildcard_with_credentials":
		return "critical"
	case "wildcard":
		return "high"
	case "reflects_origin":
		return "medium"
	case "null_origin":
		return "medium"
	}
	return "low"
}

func corsIssueTitle(issue string) string {
	switch issue {
	case "reflects_origin_with_credentials":
		return "Arbitrary origin reflected with credentials allowed"
	case "wildcard_with_credentials":
		return "Wildcard ACAO with credentials (ACAC: true)"
	case "wildcard":
		return "Wildcard Access-Control-Allow-Origin"
	case "reflects_origin":
		return "Arbitrary origin reflected (no credentials)"
	case "null_origin":
		return "Null origin accepted"
	}
	return issue
}

// sortFindings orders findings by severity descending (critical first).
func sortFindings(findings []models.Finding) []models.Finding {
	order := severityOrder()
	// Stable insertion sort to preserve source ordering within same severity
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && order[findings[j].Severity] > order[findings[j-1].Severity]; j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
	return findings
}

func severityOrder() map[string]int {
	return map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
}

// MaxSeverity returns the highest severity level in a list of findings.
func MaxSeverity(findings []models.Finding) string {
	order := severityOrder()
	max := -1
	result := ""
	for _, f := range findings {
		if v, ok := order[f.Severity]; ok && v > max {
			max = v
			result = f.Severity
		}
	}
	return result
}

// MeetsThreshold returns true if maxSeverity is at or above threshold.
func MeetsThreshold(maxSeverity, threshold string) bool {
	order := severityOrder()
	return order[maxSeverity] >= order[threshold]
}

// jsSecretSeverity maps a JS secret pattern type to a finding severity.
func jsSecretSeverity(secretType string) string {
	switch {
	case strings.Contains(secretType, "Private Key"),
		strings.Contains(secretType, "AWS Access Key"),
		strings.Contains(secretType, "AWS Secret"),
		strings.Contains(secretType, "Stripe Secret"),
		strings.Contains(secretType, "GitHub Fine-grained"),
		strings.Contains(secretType, "GitHub Classic"),
		strings.Contains(secretType, "GitHub Actions"):
		return "critical"
	case strings.Contains(secretType, "Google API"),
		strings.Contains(secretType, "Slack Token"),
		strings.Contains(secretType, "Slack Webhook"),
		strings.Contains(secretType, "SendGrid"),
		strings.Contains(secretType, "Twilio"),
		strings.Contains(secretType, "NPM Token"),
		strings.Contains(secretType, "JWT Token"),
		strings.Contains(secretType, "Hardcoded Password"),
		strings.Contains(secretType, "Hardcoded DB"):
		return "high"
	case strings.Contains(secretType, "Hardcoded API Key"),
		strings.Contains(secretType, "Hardcoded Secret"),
		strings.Contains(secretType, "Hardcoded Auth"),
		strings.Contains(secretType, "Firebase"),
		strings.Contains(secretType, "Discord Webhook"),
		strings.Contains(secretType, "S3 Bucket"),
		strings.Contains(secretType, "Azure Storage"),
		strings.Contains(secretType, "GCS Bucket"):
		return "medium"
	default:
		return "low"
	}
}
