package risk

import (
	"fmt"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

var portRules = map[int][2]string{
	21:    {"medium", "FTP exposed"},
	22:    {"medium", "SSH exposed"},
	23:    {"high", "Telnet exposed (unencrypted protocol)"},
	25:    {"medium", "SMTP exposed"},
	53:    {"low", "DNS port exposed"},
	110:   {"medium", "POP3 exposed"},
	143:   {"medium", "IMAP exposed"},
	389:   {"medium", "LDAP exposed"},
	445:   {"high", "SMB exposed (common ransomware vector)"},
	512:   {"high", "RSH exposed (unauthenticated remote shell)"},
	513:   {"high", "rlogin exposed"},
	514:   {"high", "RSH/syslog exposed"},
	1433:  {"critical", "MSSQL database exposed to internet"},
	1521:  {"critical", "Oracle database exposed to internet"},
	2375:  {"critical", "Docker daemon exposed (unauthenticated API)"},
	2376:  {"high", "Docker daemon exposed (TLS)"},
	2379:  {"critical", "etcd exposed (Kubernetes secret store)"},
	3306:  {"critical", "MySQL/MariaDB database exposed to internet"},
	3389:  {"high", "RDP exposed (common attack target)"},
	4444:  {"critical", "Common reverse shell / Metasploit port open"},
	5432:  {"critical", "PostgreSQL database exposed to internet"},
	5672:  {"high", "RabbitMQ AMQP exposed"},
	5900:  {"high", "VNC exposed (often unauthenticated)"},
	6379:  {"critical", "Redis exposed (unauthenticated by default)"},
	7001:  {"high", "WebLogic admin port exposed"},
	8080:  {"low", "Alternate HTTP port"},
	8443:  {"low", "Alternate HTTPS port"},
	8888:  {"medium", "Jupyter Notebook port (may be unauthenticated)"},
	9200:  {"critical", "Elasticsearch exposed (unauthenticated by default)"},
	9300:  {"critical", "Elasticsearch cluster port exposed"},
	11211: {"critical", "Memcached exposed (unauthenticated, amplification risk)"},
	27017: {"critical", "MongoDB exposed (unauthenticated by default)"},
	27018: {"critical", "MongoDB shard exposed"},
	50000: {"high", "Apache Spark / SAP port exposed"},
}

var adminKeywords = []string{
	"admin", "administrator", "panel", "dashboard", "manage", "management",
	"control", "wp-admin", "phpmyadmin", "cpanel", "webmin", "kibana",
	"grafana", "portainer", "jenkins", "sonarqube", "nexus", "artifactory",
	"consul", "vault", "traefik", "prometheus",
}

// Score evaluates a full scan result and returns all findings.
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

	// Port-based rules
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

	// HTTP-based rules
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

	// TLS-based rules
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

	// Nuclei vulnerability findings
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

	// Diff-based informational findings
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

	return findings
}

// MaxSeverity returns the highest severity level in a list of findings.
func MaxSeverity(findings []models.Finding) string {
	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
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
	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	return order[maxSeverity] >= order[threshold]
}
