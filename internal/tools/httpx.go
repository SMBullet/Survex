package tools

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// httpxResult covers the JSON output of modern httpx versions (v1.x).
// Field names match what httpx actually emits.
type httpxResult struct {
	URL        string   `json:"url"`
	Input      string   `json:"input"`
	Host       string   `json:"host"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	WebServer  string   `json:"webserver"`
	Tech       []string `json:"tech"`
	TLS        *struct {
		Host    string `json:"host"`
		Issuer  struct {
			CommonName string `json:"common_name"`
		} `json:"issuer"`
		NotAfter   string `json:"not_after"`
		SelfSigned bool   `json:"self_signed"`
	} `json:"tls"`
}

// RunHTTPx probes a list of hosts for live HTTP/S services.
// httpx automatically tries both HTTP and HTTPS.
func RunHTTPx(hosts []string) ([]models.HTTPService, error) {
	if _, err := exec.LookPath("httpx"); err != nil {
		return nil, fmt.Errorf("httpx not found in PATH: install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
	}
	if len(hosts) == 0 {
		return nil, nil
	}

	input := strings.Join(hosts, "\n")

	// Use flags compatible across httpx v1.x releases.
	// -json: machine-readable output
	// -silent: suppress banner
	// -title: include page title
	// -tech-detect: fingerprint technologies
	// -status-code: include HTTP status
	// -fr: follow redirects (short form; -follow-redirects is invalid in modern httpx)
	// -threads 50: parallel probing
	cmd := exec.Command(
		"httpx",
		"-json",
		"-silent",
		"-title",
		"-tech-detect",
		"-status-code",
		"-fr",
		"-threads", "50",
		"-timeout", "10",
	)
	cmd.Stdin = strings.NewReader(input)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// httpx exits non-zero when no hosts respond — not a real error.
	// Capture the error so we can log stderr on empty output for diagnostics.
	runErr := cmd.Run()

	if stdout.Len() == 0 {
		// Distinguish "httpx ran but found nothing" from "httpx failed entirely".
		// If stderr has content, surface it so callers can log it.
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("httpx produced no output (exit: %v): %s", runErr, stderr.String())
		}
		return nil, nil
	}

	var results []models.HTTPService
	scanner := bufio.NewScanner(&stdout)
	// httpx output lines can be long with base64 bodies; increase buffer
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r httpxResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if r.URL == "" {
			continue
		}

		svc := models.HTTPService{
			Host:       r.Host,
			URL:        r.URL,
			StatusCode: r.StatusCode,
			Title:      r.Title,
			TechStack:  r.Tech,
			WebServer:  r.WebServer,
		}

		if r.TLS != nil {
			svc.TLSIssuer = r.TLS.Issuer.CommonName
			svc.TLSExpiry = r.TLS.NotAfter
		}

		results = append(results, svc)
	}

	return results, nil
}
