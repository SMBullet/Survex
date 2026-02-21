package tools

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "embed"

	"github.com/SMBullet/Survex/internal/models"
)

//go:embed ffuf_wordlist.txt
var ffufWordlist []byte

// RunFFUF runs content discovery against all live HTTP services using ffuf.
// It returns discovered paths, directories, admin panels, backup files, and API endpoints.
// If ffuf is not installed, it gracefully returns nil.
func RunFFUF(httpServices []models.HTTPService, timeoutSecs int) []models.FFUFResult {
	bin, err := FindBinary("ffuf", "go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest")
	if err != nil {
		log.Printf("[survex] ffuf: %v — skipping content discovery", err)
		return nil
	}

	// Write wordlist to a temp file
	wlFile, err := os.CreateTemp("", "survex-ffuf-wl-*.txt")
	if err != nil {
		log.Printf("[survex] ffuf: cannot write wordlist: %v", err)
		return nil
	}
	defer os.Remove(wlFile.Name())
	if _, err := wlFile.Write(ffufWordlist); err != nil {
		wlFile.Close()
		log.Printf("[survex] ffuf: cannot write wordlist: %v", err)
		return nil
	}
	wlFile.Close()

	var allResults []models.FFUFResult
	seen := make(map[string]struct{})

	for _, svc := range httpServices {
		baseURL := strings.TrimRight(svc.URL, "/")

		outFile, err := os.CreateTemp("", "survex-ffuf-out-*.json")
		if err != nil {
			continue
		}
		outPath := outFile.Name()
		outFile.Close()
		defer os.Remove(outPath)

		target := baseURL + "/FUZZ"

		args := []string{
			"-u", target,
			"-w", wlFile.Name(),
			"-mc", "200,201,204,301,302,307,401,403,405",
			"-of", "json",
			"-o", outPath,
			"-t", "30",         // threads
			"-timeout", fmt.Sprintf("%d", timeoutSecs),
			"-recursion",       // recurse into found directories
			"-recursion-depth", "1",
			"-ic",              // ignore comments in wordlist
			"-ac",              // auto-calibrate filtering
			"-s",               // silent (no banner)
		}

		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ())

		deadline := time.Duration(timeoutSecs*3) * time.Second
		done := make(chan error, 1)
		go func() { done <- cmd.Run() }()

		select {
		case <-time.After(deadline):
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
			log.Printf("[survex] ffuf [%s]: timeout", svc.Host)
		case <-done:
		}

		hits := parseFFUFOutput(outPath, svc.Host)
		for _, h := range hits {
			key := h.URL
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			allResults = append(allResults, h)
		}
	}

	return allResults
}

// parseFFUFOutput reads the ffuf JSON output file and returns structured results.
func parseFFUFOutput(path, host string) []models.FFUFResult {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	var out struct {
		Results []struct {
			Input     map[string]string `json:"input"`
			URL       string            `json:"url"`
			Status    int               `json:"status"`
			Length    int               `json:"length"`
			Words     int               `json:"words"`
			Lines     int               `json:"lines"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		// Try JSONL fallback
		return parseFFUFJSONL(path, host)
	}

	var results []models.FFUFResult
	for _, r := range out.Results {
		results = append(results, models.FFUFResult{
			Host:       host,
			URL:        r.URL,
			StatusCode: r.Status,
			ContentLen: r.Length,
			Words:      r.Words,
			Lines:      r.Lines,
			ResultType: classifyFFUFHit(r.URL),
		})
	}
	return results
}

// parseFFUFJSONL handles line-delimited JSON output as a fallback.
func parseFFUFJSONL(path, host string) []models.FFUFResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var results []models.FFUFResult
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Length int    `json:"length"`
			Words  int    `json:"words"`
			Lines  int    `json:"lines"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil || r.URL == "" {
			continue
		}
		results = append(results, models.FFUFResult{
			Host:       host,
			URL:        r.URL,
			StatusCode: r.Status,
			ContentLen: r.Length,
			Words:      r.Words,
			Lines:      r.Lines,
			ResultType: classifyFFUFHit(r.URL),
		})
	}
	return results
}

// classifyFFUFHit categorises a discovered URL by its path.
func classifyFFUFHit(rawURL string) string {
	lower := strings.ToLower(rawURL)
	ext := strings.ToLower(filepath.Ext(rawURL))

	adminKeywords := []string{
		"/admin", "/administrator", "/manager", "/console", "/dashboard",
		"/panel", "/cp", "/backend", "/adm", "/wp-admin", "/phpmyadmin",
		"/adminer", "/_admin", "/cms",
	}
	for _, kw := range adminKeywords {
		if strings.Contains(lower, kw) {
			return "admin"
		}
	}

	backupExts := []string{".bak", ".old", ".backup", ".tar", ".gz", ".zip", ".sql", ".dump", ".log"}
	for _, bx := range backupExts {
		if ext == bx || strings.Contains(lower, bx) {
			return "backup"
		}
	}

	apiKeywords := []string{"/api", "/v1", "/v2", "/v3", "/graphql", "/rest", "/swagger", "/openapi"}
	for _, kw := range apiKeywords {
		if strings.Contains(lower, kw) {
			return "api"
		}
	}

	configKeywords := []string{".env", "config.", "settings.", ".git", ".svn", ".htpasswd", ".htaccess"}
	for _, kw := range configKeywords {
		if strings.Contains(lower, kw) {
			return "config"
		}
	}

	if strings.HasSuffix(lower, "/") || ext == "" {
		return "directory"
	}
	return "file"
}
