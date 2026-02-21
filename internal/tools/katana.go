package tools

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// katanaOutput is the JSON structure emitted by katana -json.
type katanaOutput struct {
	Timestamp string `json:"timestamp"`
	Request   struct {
		URL string `json:"url"`
	} `json:"request"`
}

// RunKatana runs ProjectDiscovery's katana web crawler against a list of URLs.
// It performs JavaScript-aware crawling to discover endpoints that GAU may miss.
// Falls back gracefully if katana is not installed.
//
// Install: go install github.com/projectdiscovery/katana/cmd/katana@latest
func RunKatana(urls []string, timeoutSecs int) ([]models.HistoricalURL, error) {
	if _, err := exec.LookPath("katana"); err != nil {
		log.Printf("[survex]   katana: not found in PATH — skipping (install: go install github.com/projectdiscovery/katana/cmd/katana@latest)")
		return nil, nil
	}
	if len(urls) == 0 {
		return nil, nil
	}

	// Write target URLs to temp file
	tmpIn, err := os.CreateTemp("", "survex-katana-in-*.txt")
	if err != nil {
		return nil, fmt.Errorf("creating katana input file: %w", err)
	}
	defer os.Remove(tmpIn.Name())
	if _, err := tmpIn.WriteString(strings.Join(urls, "\n")); err != nil {
		return nil, err
	}
	tmpIn.Close()

	tmpOut, err := os.CreateTemp("", "survex-katana-out-*.json")
	if err != nil {
		return nil, fmt.Errorf("creating katana output file: %w", err)
	}
	tmpOutName := tmpOut.Name()
	tmpOut.Close()
	defer os.Remove(tmpOutName)

	// -jc: JavaScript crawling    -js-crawl: extract URLs from JS files
	// -d 2: max depth 2           -aff: automatically follow subdomains
	// -silent: no banner          -timeout: per-request timeout
	cmd := exec.Command("katana",
		"-list", tmpIn.Name(),
		"-jc",
		"-js-crawl",
		"-d", "2",
		"-aff",
		"-silent",
		"-json",
		"-o", tmpOutName,
		"-timeout", fmt.Sprintf("%d", timeoutSecs),
		"-c", "10", // parallel goroutines
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run()

	data, err := os.ReadFile(tmpOutName)
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var results []models.HistoricalURL

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 512*1024), 512*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var out katanaOutput
		if err := json.Unmarshal(line, &out); err != nil {
			// katana can also output plain URLs
			rawURL := strings.TrimSpace(string(line))
			if rawURL != "" && !seen[rawURL] {
				seen[rawURL] = true
				results = append(results, models.HistoricalURL{URL: rawURL, Source: "katana"})
			}
			continue
		}
		if out.Request.URL == "" || seen[out.Request.URL] {
			continue
		}
		seen[out.Request.URL] = true
		results = append(results, models.HistoricalURL{
			URL:    out.Request.URL,
			Source: "katana",
		})
	}

	return results, nil
}
