package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// RunWPScan runs wpscan against the given WordPress URLs and returns findings
// as Vulnerability objects so they merge cleanly into result.Vulnerabilities.
// Gracefully skips if wpscan is not in PATH.
func RunWPScan(targets []string, timeoutSec int) ([]models.Vulnerability, error) {
	if _, err := exec.LookPath("wpscan"); err != nil {
		return nil, fmt.Errorf("wpscan not installed (gem install wpscan)")
	}
	if len(targets) == 0 {
		return nil, nil
	}

	var all []models.Vulnerability
	for _, target := range targets {
		vulns, err := runWPScanTarget(target, timeoutSec)
		if err != nil {
			log.Printf("[survex]   wpscan [%s]: %v", target, err)
			continue
		}
		all = append(all, vulns...)
	}
	return all, nil
}

func runWPScanTarget(target string, timeoutSec int) ([]models.Vulnerability, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	args := []string{
		"--url", target,
		"--format", "json",
		"--no-update",
		"--random-user-agent",
		"--disable-tls-checks",
	}

	out, err := exec.CommandContext(ctx, "wpscan", args...).Output()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("wpscan failed: %w", err)
	}

	// wpscan exits with code 5 when vulnerabilities are found — treat as success.
	return parseWPScanJSON(target, out), nil
}

// wpscanReport is a partial decode of wpscan's --format json output.
type wpscanReport struct {
	Version *struct {
		Number          string `json:"number"`
		Vulnerabilities []wpscanVuln `json:"vulnerabilities"`
	} `json:"version"`
	InterestingFindings []struct {
		ToS string `json:"to_s"`
		URL string `json:"url"`
	} `json:"interesting_findings"`
	Plugins map[string]struct {
		Version *struct {
			Number string `json:"number"`
		} `json:"version"`
		Vulnerabilities []wpscanVuln `json:"vulnerabilities"`
	} `json:"plugins"`
	MainTheme *struct {
		Slug            string       `json:"slug"`
		Vulnerabilities []wpscanVuln `json:"vulnerabilities"`
	} `json:"main_theme"`
}

type wpscanVuln struct {
	Title   string `json:"title"`
	FixedIn string `json:"fixed_in"`
	References struct {
		CVE []string `json:"cve"`
		URL []string `json:"url"`
	} `json:"references"`
}

func parseWPScanJSON(target string, data []byte) []models.Vulnerability {
	var report wpscanReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil
	}

	host := hostFromURL(target)
	var vulns []models.Vulnerability

	// WordPress core version vulnerabilities
	if report.Version != nil {
		for _, v := range report.Version.Vulnerabilities {
			vuln := wpscanVulnToModel(host, target, v, "WordPress Core "+report.Version.Number)
			vulns = append(vulns, vuln)
		}
	}

	// Plugin vulnerabilities
	for slug, plugin := range report.Plugins {
		ver := ""
		if plugin.Version != nil {
			ver = plugin.Version.Number
		}
		for _, v := range plugin.Vulnerabilities {
			label := "WordPress Plugin: " + slug
			if ver != "" {
				label += " " + ver
			}
			vuln := wpscanVulnToModel(host, target, v, label)
			vulns = append(vulns, vuln)
		}
	}

	// Theme vulnerabilities
	if report.MainTheme != nil {
		for _, v := range report.MainTheme.Vulnerabilities {
			label := "WordPress Theme: " + report.MainTheme.Slug
			vuln := wpscanVulnToModel(host, target, v, label)
			vulns = append(vulns, vuln)
		}
	}

	// Interesting findings (info severity)
	for _, f := range report.InterestingFindings {
		if f.ToS == "" {
			continue
		}
		vulns = append(vulns, models.Vulnerability{
			Host:       host,
			TemplateID: "wpscan-info",
			Name:       "WordPress: " + truncate(f.ToS, 120),
			Severity:   "info",
			URL:        f.URL,
			Detail:     "Discovered by wpscan",
		})
	}

	return vulns
}

func wpscanVulnToModel(host, url string, v wpscanVuln, component string) models.Vulnerability {
	sev := "medium"
	detail := fmt.Sprintf("Component: %s", component)
	if v.FixedIn != "" {
		detail += fmt.Sprintf(" | Fixed in: %s", v.FixedIn)
	}
	if len(v.References.CVE) > 0 {
		detail += " | CVEs: " + strings.Join(v.References.CVE, ", ")
		sev = "high"
	}
	templateID := "wpscan-vuln"
	if len(v.References.CVE) > 0 {
		templateID = "wpscan-cve-" + v.References.CVE[0]
	}
	return models.Vulnerability{
		Host:       host,
		TemplateID: templateID,
		Name:       v.Title,
		Severity:   sev,
		URL:        url,
		Detail:     detail,
	}
}

func hostFromURL(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	if idx := strings.IndexByte(rawURL, '/'); idx != -1 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
