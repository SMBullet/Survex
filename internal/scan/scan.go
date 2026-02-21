package scan

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/diff"
	"github.com/SMBullet/Survex/internal/models"
	"github.com/SMBullet/Survex/internal/report"
	"github.com/SMBullet/Survex/internal/risk"
	"github.com/SMBullet/Survex/internal/store"
	"github.com/SMBullet/Survex/internal/tools"
)

// Run executes the full ASM pipeline for the given config.
func Run(cfg *config.Config) (*models.ScanResult, error) {
	startedAt := time.Now()
	scanID := startedAt.UTC().Format("2006-01-02T15-04-05")

	result := &models.ScanResult{
		Scan: models.Scan{
			ID:        scanID,
			Client:    cfg.Client,
			Target:    cfg.Target,
			StartedAt: startedAt,
			Status:    "running",
		},
	}

	log.Printf("[survex] scan started: %s (id: %s)", cfg.Target, scanID)

	// ── Step 1: Subdomain Enumeration ─────────────────────────────────────────
	if len(cfg.Scan.Targets) > 0 {
		// Explicit target list — skip all enumeration, use exactly what was specified.
		log.Printf("[survex] using %d explicit targets (skipping enumeration)", len(cfg.Scan.Targets))
		for _, host := range cfg.Scan.Targets {
			result.Subdomains = append(result.Subdomains, models.Subdomain{
				Name:      host,
				IPAddress: tools.ResolveIP(host),
				Sources:   []string{"config"},
			})
		}
	} else if cfg.Scan.Subdomains {
		log.Printf("[survex] enumerating subdomains")
		hostSources := make(map[string][]string)

		// Always include root domain
		hostSources[cfg.Target] = append(hostSources[cfg.Target], "root")

		// subfinder
		if subs, err := tools.RunSubfinder(cfg.Target); err != nil {
			log.Printf("[survex]   subfinder: %v", err)
		} else {
			for _, s := range subs {
				hostSources[s] = append(hostSources[s], "subfinder")
			}
			log.Printf("[survex]   subfinder: %d subdomains", len(subs))
		}

		// crt.sh (certificate transparency — no external tool needed)
		if subs, err := tools.RunCRTs(cfg.Target); err != nil {
			log.Printf("[survex]   crt.sh: %v", err)
		} else {
			for _, s := range subs {
				hostSources[s] = append(hostSources[s], "crts")
			}
			log.Printf("[survex]   crt.sh: %d subdomains", len(subs))
		}

		// TLS SAN expansion: connect to root domain and extract SANs
		if tlsInfo, err := tools.AnalyzeTLS(cfg.Target); err == nil {
			for _, san := range tools.ExtractSANDomains(tlsInfo, cfg.Target) {
				hostSources[san] = append(hostSources[san], "tls-san")
			}
		}

		for host, sources := range hostSources {
			result.Subdomains = append(result.Subdomains, models.Subdomain{
				Name:      host,
				IPAddress: tools.ResolveIP(host),
				Sources:   sources,
			})
		}
		log.Printf("[survex]   total unique subdomains: %d", len(result.Subdomains))
	}

	// ── Step 2: DNS Resolution ────────────────────────────────────────────────
	if cfg.Scan.DNS {
		log.Printf("[survex] resolving DNS records")
		for _, sub := range result.Subdomains {
			records := tools.ResolveDNS(sub.Name)
			result.DNS = append(result.DNS, records...)
		}
		log.Printf("[survex]   %d DNS records collected", len(result.DNS))
	}

	// ── Step 3: Port Scanning ─────────────────────────────────────────────────
	if cfg.Scan.Ports {
		log.Printf("[survex] scanning ports (%d hosts)", len(result.Subdomains))
		var hosts []string
		for _, sub := range result.Subdomains {
			hosts = append(hosts, sub.Name)
		}
		services, err := tools.RunNmap(hosts)
		if err != nil {
			log.Printf("[survex]   nmap: %v", err)
		} else {
			result.Services = services
			log.Printf("[survex]   %d open services found", len(result.Services))
		}
	}

	// ── Step 4: HTTP Probing ──────────────────────────────────────────────────
	if cfg.Scan.HTTP {
		log.Printf("[survex] probing HTTP/S services")
		var hosts []string
		for _, sub := range result.Subdomains {
			hosts = append(hosts, sub.Name)
		}
		httpResults, err := tools.RunHTTPx(hosts)
		if err != nil {
			log.Printf("[survex]   httpx: %v", err)
		} else {
			result.HTTP = httpResults
			log.Printf("[survex]   %d live HTTP services found", len(result.HTTP))
		}
	}

	// ── Step 5: TLS Deep Analysis ─────────────────────────────────────────────
	log.Printf("[survex] analyzing TLS certificates")
	{
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10)

		for _, sub := range result.Subdomains {
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// AnalyzeTLS dials host:443 itself; no need to pre-check with
				// HasPort443 (which would block the loop sequentially and double
				// the per-host timeout cost). Errors are silently dropped — if
				// the host has no 443 or an unresolvable cert, we just skip it.
				info, err := tools.AnalyzeTLS(host)
				if err != nil {
					return
				}
				mu.Lock()
				result.TLS = append(result.TLS, *info)
				mu.Unlock()
			}(sub.Name)
		}
		wg.Wait()
		log.Printf("[survex]   %d TLS certs analyzed", len(result.TLS))
	}

	// ── Step 6: WAF Detection ─────────────────────────────────────────────────
	log.Printf("[survex] detecting WAFs")
	{
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10)

		for _, sub := range result.Subdomains {
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				waf, err := tools.DetectWAF(host)
				if err != nil {
					return
				}
				mu.Lock()
				result.WAF = append(result.WAF, *waf)
				mu.Unlock()
			}(sub.Name)
		}
		wg.Wait()

		detected := 0
		for _, w := range result.WAF {
			if w.Detected {
				detected++
			}
		}
		log.Printf("[survex]   %d WAFs detected across %d hosts", detected, len(result.WAF))
	}

	// ── Step 7: Vulnerability Scanning (nuclei) ───────────────────────────────
	if cfg.Scan.Nuclei {
		log.Printf("[survex] running nuclei vulnerability scan")

		// Feed nuclei a combined target list:
		//   - Live HTTP/S URLs (for http/* templates — most specific, preferred)
		//   - All subdomain hostnames (for ssl/, dns/, network/* templates)
		// Deduplication is done by a set; nuclei handles both URLs and bare hostnames.
		targetSet := make(map[string]struct{})
		for _, h := range result.HTTP {
			targetSet[h.URL] = struct{}{}
		}
		for _, sub := range result.Subdomains {
			targetSet[sub.Name] = struct{}{}
		}
		var targets []string
		for t := range targetSet {
			targets = append(targets, t)
		}

		vulns, err := tools.RunNuclei(targets)
		if err != nil {
			log.Printf("[survex]   nuclei: %v", err)
		} else {
			result.Vulnerabilities = vulns
			log.Printf("[survex]   %d vulnerabilities found", len(result.Vulnerabilities))
		}
	}

	// ── Step 8: Diff ──────────────────────────────────────────────────────────
	prev, err := store.LoadLast(cfg.Client)
	if err != nil {
		log.Printf("[survex] no previous scan for diff: %v", err)
	}
	result.Diff = diff.Compute(prev, result)

	// ── Step 9: Risk Scoring ──────────────────────────────────────────────────
	result.Findings = risk.Score(result)
	log.Printf("[survex] %d findings generated (max: %s)", len(result.Findings), risk.MaxSeverity(result.Findings))

	// ── Step 10: Persist ──────────────────────────────────────────────────────
	now := time.Now()
	result.Scan.FinishedAt = &now
	result.Scan.Status = "done"

	if err := store.Save(cfg.Client, result); err != nil {
		log.Printf("[survex] warning: could not save scan: %v", err)
	}

	// ── Step 11: Write Output ─────────────────────────────────────────────────
	if err := writeOutput(cfg, result); err != nil {
		return result, fmt.Errorf("writing output: %w", err)
	}

	log.Printf("[survex] scan complete in %s", time.Since(startedAt).Round(time.Second))
	return result, nil
}

func writeOutput(cfg *config.Config, result *models.ScanResult) error {
	outDir := cfg.Output.Dir
	if outDir == "" {
		outDir = filepath.Join("reports", cfg.Client)
	}
	scanDir := filepath.Join(outDir, result.Scan.ID)

	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	files := map[string]any{
		"subdomains.json":      result.Subdomains,
		"services.json":        result.Services,
		"http.json":            result.HTTP,
		"dns.json":             result.DNS,
		"tls.json":             result.TLS,
		"waf.json":             result.WAF,
		"vulnerabilities.json": result.Vulnerabilities,
		"findings.json":        result.Findings,
		"diff.json":            result.Diff,
		"summary.json": map[string]any{
			"scan":             result.Scan,
			"subdomain_count":  len(result.Subdomains),
			"service_count":    len(result.Services),
			"http_count":       len(result.HTTP),
			"tls_count":        len(result.TLS),
			"vuln_count":       len(result.Vulnerabilities),
			"finding_count":    len(result.Findings),
			"max_severity":     risk.MaxSeverity(result.Findings),
		},
	}

	for name, data := range files {
		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return fmt.Errorf("marshalling %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(scanDir, name), b, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", name, err)
		}
	}

	// Write HTML report
	if err := report.WriteHTML(scanDir, result); err != nil {
		log.Printf("[survex] warning: HTML report failed: %v", err)
	}

	log.Printf("[survex] output written to %s", scanDir)
	return nil
}
