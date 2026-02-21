package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// Run executes the ASM pipeline for the given config.
// Which steps run is determined entirely by cfg.Modules (after profile resolution).
func Run(cfg *config.Config) (*models.ScanResult, error) {
	// Resolve profile → module list (no-op if modules already set)
	cfg.ResolveProfile()

	startedAt := time.Now()
	scanID := startedAt.UTC().Format("2006-01-02T15-04-05")

	// Use the first target as the canonical label for single-target scans.
	label := cfg.Client
	if t := cfg.AllTargets(); len(t) == 1 {
		label = t[0]
	}

	result := &models.ScanResult{
		Scan: models.Scan{
			ID:        scanID,
			Client:    cfg.Client,
			Target:    label,
			StartedAt: startedAt,
			Status:    "running",
		},
	}

	log.Printf("[survex] scan started: %s (id: %s)", label, scanID)
	log.Printf("[survex] modules: %s", strings.Join(cfg.Modules, ", "))

	timeout := cfg.EffectiveTimeout()

	// ── Step 1: Seed host list ─────────────────────────────────────────────────
	rawTargets := expandTargets(cfg.AllTargets())
	domains, _ := classifyTargets(rawTargets)

	hostSources := make(map[string][]string)
	for _, t := range rawTargets {
		hostSources[t] = append(hostSources[t], "config")
	}
	log.Printf("[survex] %d target(s) after expansion", len(rawTargets))

	// ── Step 2: Subdomain Enumeration (skip if --no-subs or passive) ──────────
	if !cfg.Scan.NoSubs && !cfg.Scan.Passive {
		if cfg.HasModule("subfinder") {
			if len(domains) == 0 {
				log.Printf("[survex] subfinder: skipped (no domain targets)")
			} else {
				for _, domain := range domains {
					subs, err := tools.RunSubfinder(domain)
					if err != nil {
						log.Printf("[survex]   subfinder [%s]: %v", domain, err)
						continue
					}
					for _, s := range subs {
						hostSources[s] = append(hostSources[s], "subfinder")
					}
					log.Printf("[survex]   subfinder [%s]: %d subdomains", domain, len(subs))
				}
			}
		}

		if cfg.HasModule("amass") {
			if len(domains) == 0 {
				log.Printf("[survex] amass: skipped (no domain targets)")
			} else {
				for _, domain := range domains {
					subs, err := tools.RunAmass(domain)
					if err != nil {
						log.Printf("[survex]   amass [%s]: %v", domain, err)
						continue
					}
					for _, s := range subs {
						hostSources[s] = append(hostSources[s], "amass")
					}
					log.Printf("[survex]   amass [%s]: %d subdomains", domain, len(subs))
				}
			}
		}

		if cfg.HasModule("crts") {
			if len(domains) == 0 {
				log.Printf("[survex] crts: skipped (no domain targets)")
			} else {
				for _, domain := range domains {
					subs, err := tools.RunCRTs(domain)
					if err != nil {
						log.Printf("[survex]   crt.sh [%s]: %v", domain, err)
						continue
					}
					for _, s := range subs {
						hostSources[s] = append(hostSources[s], "crts")
					}
					log.Printf("[survex]   crt.sh [%s]: %d subdomains", domain, len(subs))
				}
			}
		}

		// TLS SAN expansion during seeding
		if cfg.HasModule("tls") {
			for _, domain := range domains {
				tlsInfo, err := tools.AnalyzeTLS(domain)
				if err != nil {
					continue
				}
				for _, san := range tools.ExtractSANDomains(tlsInfo, domain) {
					hostSources[san] = append(hostSources[san], "tls-san")
				}
			}
		}
	} else {
		log.Printf("[survex] subdomain enumeration: skipped (no-subs=%v, passive=%v)", cfg.Scan.NoSubs, cfg.Scan.Passive)
	}

	// Build the deduplicated host list
	for host, sources := range hostSources {
		result.Subdomains = append(result.Subdomains, models.Subdomain{
			Name:      host,
			IPAddress: tools.ResolveIP(host),
			Sources:   sources,
		})
	}
	log.Printf("[survex] %d unique hosts in scope", len(result.Subdomains))

	// ── Step 3: DNS Resolution ─────────────────────────────────────────────────
	if cfg.HasModule("dns") {
		log.Printf("[survex] resolving DNS records")
		for _, sub := range result.Subdomains {
			if !isDomain(sub.Name) {
				continue
			}
			records := tools.ResolveDNS(sub.Name)
			result.DNS = append(result.DNS, records...)
		}
		log.Printf("[survex]   %d DNS records collected", len(result.DNS))
	}

	// ── Step 4: Port Scanning ──────────────────────────────────────────────────
	if cfg.HasModule("nmap") && !cfg.Scan.Passive {
		log.Printf("[survex] scanning ports (%d hosts, profile: %s)", len(result.Subdomains), cfg.EffectivePorts())
		var hosts []string
		for _, sub := range result.Subdomains {
			hosts = append(hosts, sub.Name)
		}
		services, err := tools.RunNmap(hosts, cfg.EffectivePorts())
		if err != nil {
			log.Printf("[survex]   nmap: %v", err)
		} else {
			result.Services = services
			log.Printf("[survex]   %d open services found", len(result.Services))
		}
	}

	// ── Step 5: HTTP Probing ───────────────────────────────────────────────────
	if cfg.HasModule("httpx") && !cfg.Scan.Passive {
		log.Printf("[survex] probing HTTP/S services (%d hosts)", len(result.Subdomains))
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

	// ── Step 6: TLS Deep Analysis ──────────────────────────────────────────────
	if cfg.HasModule("tls") && !cfg.Scan.Passive {
		log.Printf("[survex] analyzing TLS certificates")
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 10)

		for _, sub := range result.Subdomains {
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

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

	// ── Step 7: WAF Detection ──────────────────────────────────────────────────
	if cfg.HasModule("waf") && !cfg.Scan.Passive {
		log.Printf("[survex] detecting WAFs")
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

	// ── Step 8: Security Headers Analysis ─────────────────────────────────────
	if cfg.HasModule("headers") && !cfg.Scan.Passive && len(result.HTTP) > 0 {
		log.Printf("[survex] analyzing security headers (%d URLs)", len(result.HTTP))
		result.SecurityHeaders = tools.AnalyzeHeaders(result.HTTP, timeout)
		log.Printf("[survex]   %d header analyses complete", len(result.SecurityHeaders))
	}

	// ── Step 9: CORS Testing ───────────────────────────────────────────────────
	if cfg.HasModule("cors") && !cfg.Scan.Passive && len(result.HTTP) > 0 {
		log.Printf("[survex] testing CORS configurations (%d URLs)", len(result.HTTP))
		result.CORS = tools.TestCORS(result.HTTP, timeout)
		vulnCount := 0
		for _, c := range result.CORS {
			if c.Vulnerable {
				vulnCount++
			}
		}
		log.Printf("[survex]   %d CORS vulnerabilities found", vulnCount)
	}

	// ── Step 10: Cookie Security Analysis ─────────────────────────────────────
	if cfg.HasModule("cookies") && !cfg.Scan.Passive && len(result.HTTP) > 0 {
		log.Printf("[survex] analyzing cookie security (%d URLs)", len(result.HTTP))
		result.Cookies = tools.AnalyzeCookies(result.HTTP, timeout)
		log.Printf("[survex]   %d cookie results collected", len(result.Cookies))
	}

	// ── Step 11: S3 / Cloud Storage Detection ─────────────────────────────────
	if cfg.HasModule("s3") && !cfg.Scan.Passive {
		log.Printf("[survex] scanning for cloud storage exposure")
		result.S3Buckets = tools.DetectS3Buckets(result.Subdomains, result.HTTP, timeout)
		log.Printf("[survex]   %d cloud storage buckets found", len(result.S3Buckets))
	}

	// ── Step 12: Historical URLs (GAU) ────────────────────────────────────────
	if cfg.HasModule("gau") {
		log.Printf("[survex] collecting historical URLs")
		for _, domain := range domains {
			urls, err := tools.RunGAU(domain)
			if err != nil {
				log.Printf("[survex]   gau [%s]: %v", domain, err)
				continue
			}
			result.HistoricalURLs = append(result.HistoricalURLs, urls...)
			log.Printf("[survex]   gau [%s]: %d historical URLs", domain, len(urls))
		}
	}

	// ── Step 13: Katana Crawler ────────────────────────────────────────────────
	if cfg.HasModule("katana") && !cfg.Scan.Passive && len(result.HTTP) > 0 {
		log.Printf("[survex] crawling with katana (%d seed URLs)", len(result.HTTP))
		var seedURLs []string
		for _, h := range result.HTTP {
			seedURLs = append(seedURLs, h.URL)
		}
		crawled, err := tools.RunKatana(seedURLs, timeout)
		if err != nil {
			log.Printf("[survex]   katana: %v", err)
		} else {
			result.HistoricalURLs = append(result.HistoricalURLs, crawled...)
			log.Printf("[survex]   katana: %d additional URLs crawled", len(crawled))
		}
	}

	// ── Step 14: Vulnerability Scanning (nuclei) ───────────────────────────────
	if cfg.HasModule("nuclei") && !cfg.Scan.Passive {
		// Update templates before scan if configured
		if cfg.Nuclei.UpdateBefore {
			log.Printf("[survex] updating nuclei templates...")
			if err := tools.UpdateTemplates(); err != nil {
				log.Printf("[survex]   nuclei update: %v", err)
			}
		}

		log.Printf("[survex] running nuclei vulnerability scan")

		// Feed nuclei: live HTTP URLs + bare hostnames + historical URLs
		targetSet := make(map[string]struct{})
		for _, h := range result.HTTP {
			targetSet[h.URL] = struct{}{}
		}
		for _, sub := range result.Subdomains {
			targetSet[sub.Name] = struct{}{}
		}
		// Add historical URLs from GAU/katana for deeper coverage
		for _, hu := range result.HistoricalURLs {
			targetSet[hu.URL] = struct{}{}
		}
		var nucleiTargets []string
		for t := range targetSet {
			nucleiTargets = append(nucleiTargets, t)
		}

		vulns, err := tools.RunNuclei(nucleiTargets, cfg.Nuclei)
		if err != nil {
			log.Printf("[survex]   nuclei: %v", err)
		} else {
			result.Vulnerabilities = vulns
			log.Printf("[survex]   %d vulnerabilities found", len(result.Vulnerabilities))
		}
	}

	// ── Step 15: Screenshots ───────────────────────────────────────────────────
	if cfg.HasModule("screenshot") && !cfg.Scan.Passive && len(result.HTTP) > 0 {
		// Need output dir for screenshots — build it now temporarily
		outDir := cfg.Output.Dir
		if outDir == "" {
			outDir = filepath.Join("reports", cfg.Client)
		}
		scanDir := filepath.Join(outDir, scanID)
		_ = os.MkdirAll(scanDir, 0755)

		log.Printf("[survex] capturing screenshots (%d URLs)", len(result.HTTP))
		shots, err := tools.RunScreenshots(result.HTTP, scanDir, timeout)
		if err != nil {
			log.Printf("[survex]   screenshot: %v", err)
		} else {
			result.Screenshots = shots
			log.Printf("[survex]   %d screenshots captured", len(result.Screenshots))
		}
	}

	// ── Step 16: Shodan Enrichment ────────────────────────────────────────────
	if cfg.HasModule("shodan") && cfg.ShodanEnabled() {
		log.Printf("[survex] enriching IPs with Shodan")
		var ips []string
		seen := make(map[string]bool)
		for _, sub := range result.Subdomains {
			if sub.IPAddress != "" && !seen[sub.IPAddress] {
				seen[sub.IPAddress] = true
				ips = append(ips, sub.IPAddress)
			}
		}
		result.ShodanHosts = tools.LookupShodan(ips, cfg.Shodan.APIKey)
		log.Printf("[survex]   %d Shodan host records retrieved", len(result.ShodanHosts))
	}

	// ── Step 17: Diff ──────────────────────────────────────────────────────────
	prev, err := store.LoadLast(cfg.Client)
	if err != nil {
		log.Printf("[survex] no previous scan for diff: %v", err)
	}
	result.Diff = diff.Compute(prev, result)

	// ── Step 18: Risk Scoring ──────────────────────────────────────────────────
	result.Findings = risk.Score(result)
	log.Printf("[survex] %d findings generated (max: %s)", len(result.Findings), risk.MaxSeverity(result.Findings))

	// ── Step 19: Persist ───────────────────────────────────────────────────────
	now := time.Now()
	result.Scan.FinishedAt = &now
	result.Scan.Status = "done"

	if err := store.Save(cfg.Client, result); err != nil {
		log.Printf("[survex] warning: could not save scan: %v", err)
	}

	// ── Step 20: Write Output ──────────────────────────────────────────────────
	if err := writeOutput(cfg, result); err != nil {
		return result, fmt.Errorf("writing output: %w", err)
	}

	log.Printf("[survex] scan complete in %s", time.Since(startedAt).Round(time.Second))
	return result, nil
}

// expandTargets takes raw target strings and returns a flat, deduplicated list.
// Supports domains, bare IPs, CIDR ranges (max /16), and .txt file paths.
func expandTargets(targets []string) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || strings.HasPrefix(h, "#") {
			return
		}
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// File target
		if strings.HasSuffix(t, ".txt") || fileExists(t) {
			lines, err := loadFile(t)
			if err != nil {
				log.Printf("[survex] warning: could not load target file %s: %v", t, err)
				continue
			}
			for _, line := range lines {
				add(line)
			}
			continue
		}

		// CIDR target
		if _, ipNet, err := net.ParseCIDR(t); err == nil {
			ones, bits := ipNet.Mask.Size()
			if bits-ones > 16 {
				log.Printf("[survex] warning: CIDR %s is too large (>65535 hosts) — use /16 or smaller", t)
				continue
			}
			for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); incrementIP(ip) {
				add(ip.String())
			}
			continue
		}

		add(t)
	}

	return out
}

// classifyTargets splits targets into domains (hostnames) and IPs.
func classifyTargets(targets []string) (domains []string, ips []string) {
	for _, t := range targets {
		if net.ParseIP(t) != nil {
			ips = append(ips, t)
		} else {
			domains = append(domains, t)
		}
	}
	return
}

// isDomain returns true if host is a hostname rather than a bare IP.
func isDomain(host string) bool {
	return net.ParseIP(host) == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
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
		"subdomains.json":       result.Subdomains,
		"services.json":         result.Services,
		"http.json":             result.HTTP,
		"dns.json":              result.DNS,
		"tls.json":              result.TLS,
		"waf.json":              result.WAF,
		"security_headers.json": result.SecurityHeaders,
		"cors.json":             result.CORS,
		"cookies.json":          result.Cookies,
		"s3.json":               result.S3Buckets,
		"historical_urls.json":  result.HistoricalURLs,
		"screenshots.json":      result.Screenshots,
		"shodan.json":           result.ShodanHosts,
		"vulnerabilities.json":  result.Vulnerabilities,
		"findings.json":         result.Findings,
		"diff.json":             result.Diff,
		"summary.json": map[string]any{
			"scan":            result.Scan,
			"modules":         cfg.Modules,
			"subdomain_count": len(result.Subdomains),
			"service_count":   len(result.Services),
			"http_count":      len(result.HTTP),
			"tls_count":       len(result.TLS),
			"cors_vuln_count": func() int {
				n := 0
				for _, c := range result.CORS {
					if c.Vulnerable {
						n++
					}
				}
				return n
			}(),
			"s3_count":         len(result.S3Buckets),
			"historical_count": len(result.HistoricalURLs),
			"screenshot_count": len(result.Screenshots),
			"shodan_count":     len(result.ShodanHosts),
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

	if err := report.WriteHTML(scanDir, result); err != nil {
		log.Printf("[survex] warning: HTML report failed: %v", err)
	}

	log.Printf("[survex] output written to %s", scanDir)
	return nil
}
