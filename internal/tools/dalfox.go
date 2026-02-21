package tools

import (
	"bufio"
	"encoding/json"
	"log"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// RunDalfox runs XSS scanning against a list of URLs using dalfox.
// Input URLs should already contain query parameters (from gau/katana).
// If dalfox is not installed, it gracefully returns nil.
func RunDalfox(urls []string, timeoutSecs int) []models.XSSResult {
	bin, err := FindBinary("dalfox", "go install github.com/hahwul/dalfox/v2@latest")
	if err != nil {
		log.Printf("[survex] dalfox: %v — skipping XSS scan", err)
		return nil
	}

	// Filter: only URLs with query parameters (otherwise dalfox has nothing to test)
	var paramURLs []string
	seen := make(map[string]struct{})
	for _, u := range urls {
		if !strings.Contains(u, "?") {
			continue
		}
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		paramURLs = append(paramURLs, u)
	}

	if len(paramURLs) == 0 {
		log.Printf("[survex] dalfox: no parametrized URLs to test")
		return nil
	}

	// Cap at 200 URLs to avoid unbounded runtime
	if len(paramURLs) > 200 {
		paramURLs = paramURLs[:200]
	}

	log.Printf("[survex] dalfox: testing %d parametrized URLs for XSS", len(paramURLs))

	// Write URL list to temp file
	listFile, err := os.CreateTemp("", "survex-dalfox-*.txt")
	if err != nil {
		log.Printf("[survex] dalfox: cannot write URL list: %v", err)
		return nil
	}
	defer os.Remove(listFile.Name())
	for _, u := range paramURLs {
		listFile.WriteString(u + "\n")
	}
	listFile.Close()

	outFile, err := os.CreateTemp("", "survex-dalfox-out-*.json")
	if err != nil {
		return nil
	}
	outPath := outFile.Name()
	outFile.Close()
	defer os.Remove(outPath)

	args := []string{
		"file", listFile.Name(),
		"--silence",
		"--no-color",
		"--format", "json",
		"--output", outPath,
		"--timeout", "10",
		"--delay", "0",
		"--worker", "20",
		"--skip-mining-dom",   // skip DOM mining (faster for mass scan)
		"--skip-bav",          // skip blind XSS (requires OOB server)
	}

	cmd := exec.Command(bin, args...)
	deadline := time.Duration(timeoutSecs) * time.Second
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()

	select {
	case <-time.After(deadline):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		log.Printf("[survex] dalfox: timeout after %ds", timeoutSecs)
	case <-done:
	}

	results := parseDalfoxOutput(outPath)
	log.Printf("[survex] dalfox: %d XSS findings", len(results))
	return results
}

// parseDalfoxOutput reads the dalfox JSON output and returns XSSResult entries.
func parseDalfoxOutput(path string) []models.XSSResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var results []models.XSSResult
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 512*1024), 512*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var item struct {
			Type    string `json:"type"`
			Inject  string `json:"inject_type"` // "toHTML" | "inJS" | "inAttr"
			Poc     string `json:"poc"`
			Param   string `json:"param"`
			Payload string `json:"payload"`
			Data    string `json:"data"`
		}
		// dalfox outputs one JSON object per line
		if err := json.Unmarshal(sc.Bytes(), &item); err != nil {
			continue
		}

		if item.Poc == "" {
			continue
		}

		xssType := "reflected"
		if strings.Contains(strings.ToLower(item.Type), "dom") {
			xssType = "dom"
		}

		host := ""
		if u, err := url.Parse(item.Poc); err == nil {
			host = u.Hostname()
		}

		results = append(results, models.XSSResult{
			URL:      item.Poc,
			Host:     host,
			Payload:  item.Payload,
			POC:      item.Poc,
			Type:     xssType,
			Severity: "high",
		})
	}

	return results
}
