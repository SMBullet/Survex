package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/models"
)

// nucleiJSON is the JSONL output structure of nuclei v3.
type nucleiJSON struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
		// Classification holds optional CVSS data embedded in the template.
		Classification struct {
			CVSSScore   float64  `json:"cvss-score"`
			CVSSMetrics string   `json:"cvss-metrics"`
			CVEID       []string `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
}

// asmTemplates are the template directories run for every ASM scan.
// Order follows priority: takeovers first (highest business impact), then
// CVEs, exposures, panels, credentials, misconfigs, cloud, and protocol checks.
var asmTemplates = []string{
	// Subdomain takeovers — often tagged "info" but critical for ASM
	"http/takeovers/",

	// Actual CVE templates — Log4j, Spring4Shell, MOVEit, Confluence, etc.
	// This is the single biggest improvement over the original template set.
	"http/cves/",

	// Generic vulnerability checks: XSS, SQLi, SSRF, path traversal, RCE
	"http/vulnerabilities/",

	// Exposed sensitive files: .env, docker-compose, SSH keys, .git/config
	"http/exposures/",

	// Token and API key exposure in HTTP responses
	"http/exposures/tokens/",

	// File inclusion / path traversal
	"http/file-inclusion/",

	// Admin and management panels exposed to the internet
	"http/exposed-panels/",

	// Default credentials (190+ vendors: Jira, Jenkins, Grafana, Kibana, Tomcat…)
	"http/default-logins/",

	// Security misconfigurations: CORS, open redirects, headers, debug endpoints
	"http/misconfiguration/",

	// Technology identification for asset mapping
	"http/technologies/",

	// TLS/SSL: deprecated versions, weak ciphers, expired/self-signed certs, SAN enum
	"ssl/",

	// DNS-based takeovers (Azure, ElasticBeanstalk) and DNS misconfigurations
	"dns/",

	// Cloud storage and service misconfigurations (S3, GCS, Azure)
	"cloud/",

	// Network-level default credentials: Redis, FTP, MSSQL, PostgreSQL, SMTP
	"network/default-login/",

	// Network-level misconfigurations: exposed memcached, open proxy, etc.
	"network/misconfig/",

	// Network-level data exposure
	"network/exposures/",

	// Network-level service detection
	"network/detection/",
}

// RunNuclei runs nuclei against a list of targets using ASM-focused template coverage.
// NucleiOptions from the config allow per-client customization of severity, tags, and templates.
//
// Requires nuclei v3+: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
func RunNuclei(ctx context.Context, targets []string, opts config.NucleiOptions) ([]models.Vulnerability, error) {
	nucleiPath, err := findNuclei()
	if err != nil {
		return nil, err
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
	tmpOut, err := os.CreateTemp("", "survex-nuclei-out-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("creating nuclei output file: %w", err)
	}
	tmpOutName := tmpOut.Name()
	tmpOut.Close()
	defer os.Remove(tmpOutName)

	args := buildNucleiArgs(tmpIn.Name(), tmpOutName, opts)
	cmd := exec.CommandContext(ctx, nucleiPath, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// nuclei exits 1 when it finds vulnerabilities — that is normal, not an error.
	_ = cmd.Run()

	data, err := os.ReadFile(tmpOutName)
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("nuclei failed: %s", stderr.String())
		}
		return nil, nil
	}

	return parseNucleiOutput(data), nil
}

func buildNucleiArgs(inputFile, outputFile string, opts config.NucleiOptions) []string {
	// Resolve effective severity
	severity := opts.Severity
	if severity == "" {
		severity = "critical,high,medium,info"
	}

	// Resolve exclude tags
	excludeTags := opts.ExcludeTags
	if len(excludeTags) == 0 {
		excludeTags = []string{"dos", "fuzz", "generic-tokens", "tls-sni-proxy"}
	}

	args := []string{
		// Input / output
		"-l", inputFile,
		"-je", outputFile,
		"-silent",
		"-no-interactsh",
		"-duc",

		// Severity
		"-severity", severity,

		// Exclude noisy/destructive tags
		"-exclude-tags", strings.Join(excludeTags, ","),

		// Performance — balanced for ASM scanning
		"-rl", "150",
		"-c", "25",
		"-bs", "25",
		"-timeout", "10",
		"-retries", "1",
		"-mhe", "10",
		"-ss", "host-spray",
	}

	// Include specific tags if configured
	if len(opts.Tags) > 0 {
		args = append(args, "-tags", strings.Join(opts.Tags, ","))
	}

	// Exclude specific templates if configured
	for _, et := range opts.ExcludeTemplates {
		args = append(args, "-exclude-templates", et)
	}

	// Built-in ASM template set
	for _, t := range asmTemplates {
		args = append(args, "-t", t)
	}

	// User-supplied additional template directories
	for _, t := range opts.Templates {
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

		vuln := models.Vulnerability{
			Host:       out.Host,
			TemplateID: out.TemplateID,
			Name:       out.Info.Name,
			Severity:   out.Info.Severity,
			URL:        out.MatchedAt,
			Detail:     detail,
		}

		// Populate CVSS from the template's embedded classification block.
		cl := out.Info.Classification
		if cl.CVSSScore > 0 {
			vuln.CVSSScore = cl.CVSSScore
			vuln.CVSSVector = cl.CVSSMetrics
		} else if cl.CVSSMetrics != "" {
			// Calculate from vector if only the vector is present.
			vuln.CVSSScore = CalculateCVSSScore(cl.CVSSMetrics)
			vuln.CVSSVector = cl.CVSSMetrics
		}
		if len(cl.CVEID) > 0 {
			vuln.CVEID = cl.CVEID[0]
		}

		vulns = append(vulns, vuln)
	}
	return vulns
}

// UpdateTemplates runs nuclei -update-templates to pull the latest community templates.
func UpdateTemplates() error {
	nucleiPath, err := findNuclei()
	if err != nil {
		return err
	}

	cmd := exec.Command(nucleiPath, "-update-templates", "-silent")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nuclei template update failed: %w\n%s", err, stderr.String())
	}
	return nil
}

// findNuclei locates the ProjectDiscovery nuclei binary.
// Delegates to the centralized FindBinary which checks ~/go/bin and $GOPATH/bin
// before falling back to PATH.
func findNuclei() (string, error) {
	return FindBinary("nuclei", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
}
