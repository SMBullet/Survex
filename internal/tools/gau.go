package tools

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// RunGAU runs gau (Get All URLs) to collect historical URLs for a domain
// from Wayback Machine, Common Crawl, and other passive sources.
// Falls back gracefully if gau is not installed.
//
// Install: go install github.com/lc/gau/v2/cmd/gau@latest
func RunGAU(domain string) ([]models.HistoricalURL, error) {
	if _, err := exec.LookPath("gau"); err != nil {
		log.Printf("[survex]   gau: not found in PATH — skipping (install: go install github.com/lc/gau/v2/cmd/gau@latest)")
		return nil, nil
	}

	// --subs includes subdomains, --threads 5 limits concurrency,
	// --blacklist filters out noisy file extensions
	cmd := exec.Command("gau",
		domain,
		"--subs",
		"--threads", "5",
		"--timeout", "60",
		"--blacklist", "png,jpg,jpeg,gif,svg,ico,css,woff,woff2,ttf,eot,mp4,mp3,pdf,zip,tar,gz",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("gau failed: %w — %s", err, stderr.String())
		}
		// gau often exits non-zero even when results were found
	}

	seen := make(map[string]bool)
	var results []models.HistoricalURL

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		rawURL := strings.TrimSpace(scanner.Text())
		if rawURL == "" || seen[rawURL] {
			continue
		}
		seen[rawURL] = true
		results = append(results, models.HistoricalURL{
			URL:    rawURL,
			Source: "gau",
		})
	}

	return results, nil
}
