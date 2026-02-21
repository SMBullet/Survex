package tools

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// nucleiJSON is the JSONL output structure of nuclei v3.
type nucleiJSON struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
}

// asmTemplates are the template directories we run for every ASM scan.
// Order follows priority: takeovers first (highest business impact), then exposure,
// then panels, credentials, misconfigs, and protocol-level checks.
var asmTemplates = []string{
	// Subdomain takeovers — often tagged "info" or "high" but critical for ASM
	"http/takeovers/",

	// Exposed sensitive files: .env, docker-compose, SSH keys, AWS creds, .git/config, DB configs
	"http/exposures/",

	// Admin and management panels exposed to the internet
	"http/exposed-panels/",

	// Default credentials across 190+ vendors (Jira, Jenkins, Grafana, Kibana, Tomcat, WebLogic…)
	"http/default-logins/",

	// Security misconfigurations: CORS, open redirects, security headers, exposed debug endpoints
	"http/misconfiguration/",

	// TLS/SSL: deprecated versions, weak ciphers, expired/self-signed/revoked/wildcard certs, SAN enum
	"ssl/",

	// DNS-based takeovers (Azure, ElasticBeanstalk) and DNS misconfigurations
	"dns/",

	// Network-level default credentials: Redis, FTP, MSSQL, PostgreSQL, SMTP
	"network/default-login/",

	// Network-level misconfigurations: exposed memcached, open proxy, etc.
	"network/misconfig/",

	// Network-level data exposure
	"network/exposures/",
}

// RunNuclei runs nuclei against a list of targets using ASM-focused template coverage.
//
// Severity includes "info" — this is intentional. Subdomain takeover templates,
// panel detection, and SSL SAN enumeration are all tagged info/medium but are
// critical for ASM completeness.
//
// Requires nuclei v3+: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
func RunNuclei(targets []string) ([]models.Vulnerability, error) {
	if _, err := exec.LookPath("nuclei"); err != nil {
		return nil, fmt.Errorf("nuclei not found in PATH: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
	}
	if len(targets) == 0 {
		return nil, nil
	}

	// Write targets to a temp file (more reliable than stdin for nuclei)
	tmpIn, err := os.CreateTemp("", "survex-nuclei-in-*.txt")
	if err != nil {
		return nil, fmt.Errorf("creating nuclei input file: %w", err)
	}
	defer os.Remove(tmpIn.Name())
	if _, err := tmpIn.WriteString(strings.Join(targets, "\n")); err != nil {
		return nil, fmt.Errorf("writing nuclei targets: %w", err)
	}
	tmpIn.Close()

	// Write JSON output to a temp file via -je (json-export).
	// This avoids the stdout-capture conflict that occurs with -json-export /dev/stdout.
	tmpOut, err := os.CreateTemp("", "survex-nuclei-out-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("creating nuclei output file: %w", err)
	}
	tmpOutName := tmpOut.Name()
	tmpOut.Close()
	defer os.Remove(tmpOutName)

	args := buildNucleiArgs(tmpIn.Name(), tmpOutName)
	cmd := exec.Command("nuclei", args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// nuclei exits 1 when it finds vulnerabilities — that is normal, not an error.
	// Only treat it as an error if the output file is missing entirely.
	_ = cmd.Run()

	data, err := os.ReadFile(tmpOutName)
	if err != nil {
		// Output file not created means nuclei itself failed (not "no findings")
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("nuclei failed: %s", stderr.String())
		}
		return nil, nil
	}

	return parseNucleiOutput(data), nil
}

func buildNucleiArgs(inputFile, outputFile string) []string {
	args := []string{
		// Input / output
		"-l", inputFile,
		"-je", outputFile, // json-export to file (JSONL format)
		"-silent",
		"-no-interactsh", // disable OAST callbacks (safer for CI, no external dependencies)
		"-duc",           // disable update check on every run (saves 10-30s)

		// Severity: include "info" — required for subdomain takeovers,
		// panel detection, and SSL SAN enumeration templates
		"-severity", "critical,high,medium,info",

		// Exclude templates that are destructive, too noisy, or cause false positives
		"-exclude-tags", "dos,fuzz,generic-tokens,tls-sni-proxy",

		// Performance — balanced for ASM scanning (not too aggressive)
		"-rl", "150",  // max requests/second across all templates
		"-c", "25",    // parallel template execution count
		"-bs", "25",   // hosts per template batch
		"-timeout", "10",
		"-retries", "1",
		"-mhe", "10",  // drop a host after 10 errors (was 30) — faster on dead/filtered hosts
		"-ss", "host-spray", // run all templates against one host before moving to next
	}

	// Add each template directory as a separate -t flag
	for _, t := range asmTemplates {
		args = append(args, "-t", t)
	}

	return args
}

func parseNucleiOutput(data []byte) []models.Vulnerability {
	var vulns []models.Vulnerability
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 512*1024), 512*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var out nucleiJSON
		if err := json.Unmarshal(line, &out); err != nil {
			continue
		}

		detail := ""
		if len(out.ExtractedResults) > 0 {
			detail = strings.Join(out.ExtractedResults, " | ")
		}

		vulns = append(vulns, models.Vulnerability{
			Host:       out.Host,
			TemplateID: out.TemplateID,
			Name:       out.Info.Name,
			Severity:   out.Info.Severity,
			URL:        out.MatchedAt,
			Detail:     detail,
		})
	}
	return vulns
}

// UpdateTemplates runs nuclei -update-templates to pull the latest community templates.
// Call this before scanning to ensure coverage is current.
func UpdateTemplates() error {
	if _, err := exec.LookPath("nuclei"); err != nil {
		return fmt.Errorf("nuclei not found in PATH")
	}

	cmd := exec.Command("nuclei", "-update-templates", "-silent")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nuclei template update failed: %w\n%s", err, stderr.String())
	}
	return nil
}
