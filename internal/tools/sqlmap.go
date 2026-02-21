package tools

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// RunSQLMap runs SQL injection testing against parametrized URLs using sqlmap.
// Uses --batch (non-interactive), --level=1 --risk=1 (safe for authorized testing).
// If sqlmap is not installed or not in PATH, it gracefully returns nil.
func RunSQLMap(urls []string, timeoutSecs int) []models.SQLiResult {
	bin, err := findSQLMap()
	if err != nil {
		log.Printf("[survex] sqlmap: %v — skipping SQLi scan", err)
		return nil
	}

	// Only test URLs with query parameters
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
		log.Printf("[survex] sqlmap: no parametrized URLs to test")
		return nil
	}

	// Cap at 50 URLs — sqlmap is slow; prioritize quality over quantity
	if len(paramURLs) > 50 {
		paramURLs = paramURLs[:50]
	}

	log.Printf("[survex] sqlmap: testing %d parametrized URLs for SQLi", len(paramURLs))

	// Write URL list to temp file for -m (multiple targets)
	listFile, err := os.CreateTemp("", "survex-sqlmap-urls-*.txt")
	if err != nil {
		log.Printf("[survex] sqlmap: cannot write URL list: %v", err)
		return nil
	}
	defer os.Remove(listFile.Name())
	for _, u := range paramURLs {
		listFile.WriteString(u + "\n")
	}
	listFile.Close()

	// Output directory for sqlmap results
	outDir, err := os.MkdirTemp("", "survex-sqlmap-out-*")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(outDir)

	args := []string{
		"-m", listFile.Name(),    // multiple targets from file
		"--batch",                // non-interactive (auto-answer all prompts)
		"--level=1",              // lowest crawl level (safe)
		"--risk=1",               // lowest risk (safe, no heavy payloads)
		"--random-agent",         // random User-Agent per request
		"--output-dir", outDir,   // results directory
		"--timeout=15",           // per-request timeout
		"--retries=1",            // minimal retries
		"--threads=5",            // moderate concurrency
		"--results-file", outDir + "/results.csv", // CSV summary
		"-q",                     // quiet (reduce noise)
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
		log.Printf("[survex] sqlmap: timeout after %ds", timeoutSecs)
	case err := <-done:
		if err != nil {
			log.Printf("[survex] sqlmap: %v", err)
		}
	}

	results := parseSQLMapOutput(outDir, paramURLs)
	log.Printf("[survex] sqlmap: %d SQLi findings", len(results))
	return results
}

// parseSQLMapOutput walks the sqlmap output directory for JSON session files.
func parseSQLMapOutput(dir string, testedURLs []string) []models.SQLiResult {
	var results []models.SQLiResult

	// sqlmap creates a subdirectory per target host with a log file
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		sessionFile := fmt.Sprintf("%s/%s/session.sqlite", dir, entry.Name())
		logFile := fmt.Sprintf("%s/%s/log", dir, entry.Name())

		// Try parsing the human-readable log first (more reliable across versions)
		hits := parseSQLMapLog(logFile)
		_ = sessionFile // session parsing requires SQLite; use log instead
		results = append(results, hits...)
	}

	// Fallback: check CSV results file
	if len(results) == 0 {
		csvPath := dir + "/results.csv"
		results = parseSQLMapCSV(csvPath)
	}

	return results
}

// parseSQLMapLog parses a sqlmap log file for vulnerability lines.
func parseSQLMapLog(path string) []models.SQLiResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var results []models.SQLiResult
	var currentURL, currentParam, currentTech, currentDB string
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := sc.Text()
		lower := strings.ToLower(line)

		if strings.Contains(lower, "testing url") || strings.Contains(lower, "target url:") {
			// Extract URL from line like "testing URL: https://..."
			if idx := strings.Index(lower, "url:"); idx != -1 {
				currentURL = strings.TrimSpace(line[idx+4:])
				currentParam = ""
				currentTech = ""
				currentDB = ""
			}
		}

		if strings.Contains(lower, "parameter ") && strings.Contains(lower, "is vulnerable") {
			// "Parameter: id (GET) is vulnerable"
			parts := strings.Fields(line)
			for i, p := range parts {
				if strings.ToLower(p) == "parameter:" && i+1 < len(parts) {
					currentParam = parts[i+1]
					break
				}
			}
		}

		if strings.Contains(lower, "type:") {
			if idx := strings.Index(lower, "type:"); idx != -1 {
				currentTech = strings.TrimSpace(line[idx+5:])
			}
		}

		if strings.Contains(lower, "back-end dbms:") {
			if idx := strings.Index(lower, "back-end dbms:"); idx != -1 {
				currentDB = strings.TrimSpace(line[idx+14:])
			}
		}

		if strings.Contains(lower, "sqlmap identified the following injection") {
			if currentURL != "" && currentParam != "" {
				host := ""
				if u, err := url.Parse(currentURL); err == nil {
					host = u.Hostname()
				}
				results = append(results, models.SQLiResult{
					URL:       currentURL,
					Host:      host,
					Parameter: currentParam,
					Technique: currentTech,
					DBType:    currentDB,
					Detail:    fmt.Sprintf("Parameter '%s' injectable via %s", currentParam, currentTech),
				})
			}
		}
	}
	return results
}

// parseSQLMapCSV parses the sqlmap CSV results summary file.
func parseSQLMapCSV(path string) []models.SQLiResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var results []models.SQLiResult
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // skip header
		}
		fields := strings.Split(sc.Text(), ",")
		if len(fields) < 5 {
			continue
		}
		targetURL := strings.Trim(fields[0], `"`)
		place := strings.Trim(fields[1], `"`)
		param := strings.Trim(fields[2], `"`)
		tech := strings.Trim(fields[3], `"`)
		note := strings.Trim(fields[4], `"`)

		if strings.Contains(strings.ToLower(note), "vulnerable") || tech != "" {
			host := ""
			if u, err := url.Parse(targetURL); err == nil {
				host = u.Hostname()
			}
			results = append(results, models.SQLiResult{
				URL:       targetURL,
				Host:      host,
				Parameter: fmt.Sprintf("%s (%s)", param, place),
				Technique: tech,
				Detail:    note,
			})
		}
	}

	// Try JSON session files as well
	var jsonResult struct {
		Data []struct {
			URL       string `json:"url"`
			Parameter string `json:"parameter"`
			Technique string `json:"technique"`
			DBName    string `json:"dbms"`
		} `json:"data"`
	}
	jsonBytes, err := os.ReadFile(strings.Replace(path, "results.csv", "results.json", 1))
	if err == nil {
		if err := json.Unmarshal(jsonBytes, &jsonResult); err == nil {
			for _, d := range jsonResult.Data {
				host := ""
				if u, err := url.Parse(d.URL); err == nil {
					host = u.Hostname()
				}
				results = append(results, models.SQLiResult{
					URL:       d.URL,
					Host:      host,
					Parameter: d.Parameter,
					Technique: d.Technique,
					DBType:    d.DBName,
				})
			}
		}
	}

	return results
}

// findSQLMap locates the sqlmap binary (python3 -m sqlmap or sqlmap in PATH).
func findSQLMap() (string, error) {
	// Check for sqlmap directly in PATH
	if p, err := exec.LookPath("sqlmap"); err == nil {
		return p, nil
	}

	// Check for python3 -c "import sqlmap" — sqlmap installed as Python package
	py3, err := exec.LookPath("python3")
	if err != nil {
		py3, err = exec.LookPath("python")
	}
	if err != nil {
		return "", fmt.Errorf("sqlmap not found (install: pip install sqlmap or apt install sqlmap)")
	}

	// Verify sqlmap module is accessible
	out, _ := exec.Command(py3, "-c", "import sqlmap; print('ok')").Output()
	if strings.TrimSpace(string(out)) == "ok" {
		return py3 + " -m sqlmap", nil
	}

	return "", fmt.Errorf("sqlmap not found (install: pip install sqlmap or apt install sqlmap)")
}
