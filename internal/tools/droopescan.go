package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// RunDroopeScan runs droopescan against a Drupal or Joomla target.
// cms must be "drupal" or "joomla". Gracefully skips if droopescan is not in PATH.
func RunDroopeScan(cms, target string, timeoutSec int) ([]models.Vulnerability, error) {
	if _, err := exec.LookPath("droopescan"); err != nil {
		return nil, fmt.Errorf("droopescan not installed (pip3 install droopescan)")
	}
	if target == "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	args := []string{"scan", cms, "-u", target, "--quiet"}
	out, err := exec.CommandContext(ctx, "droopescan", args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("droopescan failed: %w", err)
	}

	return parseDroopeScanOutput(cms, target, out), nil
}

// RunJoomScan runs joomscan against a Joomla target.
// Gracefully skips if joomscan is not in PATH.
func RunJoomScan(target string, timeoutSec int) ([]models.Vulnerability, error) {
	if _, err := exec.LookPath("joomscan"); err != nil {
		// Try perl joomscan as fallback
		if _, err2 := exec.LookPath("perl"); err2 != nil {
			return nil, fmt.Errorf("joomscan not installed")
		}
	}
	if target == "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "joomscan", "-u", target).CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("joomscan failed: %w", err)
	}

	return parseJoomScanOutput(target, out), nil
}

// parseDroopeScanOutput extracts vulnerability mentions from droopescan text output.
func parseDroopeScanOutput(cms, target string, data []byte) []models.Vulnerability {
	host := hostFromURL(target)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var vulns []models.Vulnerability
	var inVulnSection bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Section headers
		lc := strings.ToLower(line)
		if strings.Contains(lc, "vulnerabilit") {
			inVulnSection = true
			continue
		}
		if strings.HasPrefix(line, "[+]") || strings.HasPrefix(line, "[-]") {
			inVulnSection = false
		}

		// Vulnerability lines inside vuln section
		if inVulnSection && (strings.HasPrefix(line, "-") || strings.HasPrefix(line, "*")) {
			title := strings.TrimLeft(line, "-* ")
			if title == "" {
				continue
			}
			sev := "medium"
			if strings.Contains(strings.ToLower(title), "critical") {
				sev = "critical"
			} else if strings.Contains(strings.ToLower(title), "high") {
				sev = "high"
			}
			vulns = append(vulns, models.Vulnerability{
				Host:       host,
				TemplateID: "droopescan-vuln",
				Name:       strings.ToUpper(cms[:1]) + cms[1:] + ": " + title,
				Severity:   sev,
				URL:        target,
				Detail:     "Discovered by droopescan",
			})
			continue
		}

		// Version-is-vulnerable lines (droopescan emits "  [+] Version ... is vulnerable")
		if strings.Contains(lc, "is vulnerable") || strings.Contains(lc, "vulnerable version") {
			vulns = append(vulns, models.Vulnerability{
				Host:       host,
				TemplateID: "droopescan-version",
				Name:       strings.ToUpper(cms[:1]) + cms[1:] + " Vulnerable Version Detected",
				Severity:   "high",
				URL:        target,
				Detail:     line,
			})
		}
	}

	return vulns
}

// parseJoomScanOutput extracts findings from joomscan text output.
func parseJoomScanOutput(target string, data []byte) []models.Vulnerability {
	host := hostFromURL(target)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var vulns []models.Vulnerability

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lc := strings.ToLower(line)

		if strings.Contains(lc, "vulnerable") || strings.Contains(lc, "exploit") {
			sev := "medium"
			if strings.Contains(lc, "critical") {
				sev = "critical"
			} else if strings.Contains(lc, "high") {
				sev = "high"
			}
			vulns = append(vulns, models.Vulnerability{
				Host:       host,
				TemplateID: "joomscan-vuln",
				Name:       "Joomla: " + truncate(line, 120),
				Severity:   sev,
				URL:        target,
				Detail:     "Discovered by joomscan",
			})
		}
	}

	return vulns
}

// RunCMSScans detects installed CMS tools and runs the appropriate scanner.
// Returns additional vulnerabilities to merge into result.Vulnerabilities.
func RunCMSScans(technologies []models.Technology, httpServices []models.HTTPService, timeoutSec int) []models.Vulnerability {
	// Build a lookup: techName (lowercase) → set of target URLs
	techURLs := make(map[string][]string)
	techSet := make(map[string]bool)
	for _, t := range technologies {
		techSet[strings.ToLower(t.Name)] = true
	}

	if len(techSet) == 0 {
		return nil
	}

	// Map live HTTP services to their detected technologies.
	hostTech := make(map[string][]string)
	for _, t := range technologies {
		hostTech[t.Host] = append(hostTech[t.Host], strings.ToLower(t.Name))
	}
	for _, svc := range httpServices {
		for _, tech := range hostTech[svc.Host] {
			techURLs[tech] = append(techURLs[tech], svc.URL)
		}
	}

	// Deduplicate URLs per tech.
	for k, urls := range techURLs {
		seen := make(map[string]bool)
		var deduped []string
		for _, u := range urls {
			if !seen[u] {
				seen[u] = true
				deduped = append(deduped, u)
			}
		}
		techURLs[k] = deduped
	}

	var all []models.Vulnerability

	// WordPress → wpscan
	if wpURLs := techURLs["wordpress"]; len(wpURLs) > 0 {
		log.Printf("[survex]   cms-scan: WordPress detected on %d URL(s) — running wpscan", len(wpURLs))
		vulns, err := RunWPScan(wpURLs, timeoutSec)
		if err != nil {
			log.Printf("[survex]   wpscan: %v", err)
		} else {
			log.Printf("[survex]   wpscan: %d findings", len(vulns))
			all = append(all, vulns...)
		}
	}

	// Drupal → droopescan
	if drupalURLs := techURLs["drupal"]; len(drupalURLs) > 0 {
		log.Printf("[survex]   cms-scan: Drupal detected on %d URL(s) — running droopescan", len(drupalURLs))
		for _, u := range drupalURLs {
			vulns, err := RunDroopeScan("drupal", u, timeoutSec)
			if err != nil {
				log.Printf("[survex]   droopescan [%s]: %v", u, err)
				continue
			}
			log.Printf("[survex]   droopescan [%s]: %d findings", u, len(vulns))
			all = append(all, vulns...)
		}
	}

	// Joomla → joomscan (preferred) or droopescan
	if joomlaURLs := techURLs["joomla"]; len(joomlaURLs) > 0 {
		log.Printf("[survex]   cms-scan: Joomla detected on %d URL(s) — running joomscan", len(joomlaURLs))
		for _, u := range joomlaURLs {
			vulns, err := RunJoomScan(u, timeoutSec)
			if err != nil {
				// Fallback to droopescan for joomla
				log.Printf("[survex]   joomscan unavailable, trying droopescan [%s]", u)
				vulns, err = RunDroopeScan("joomla", u, timeoutSec)
				if err != nil {
					log.Printf("[survex]   droopescan [%s]: %v", u, err)
					continue
				}
			}
			log.Printf("[survex]   cms-scan joomla [%s]: %d findings", u, len(vulns))
			all = append(all, vulns...)
		}
	}

	return all
}
