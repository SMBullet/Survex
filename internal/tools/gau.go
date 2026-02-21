package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// DefaultGAUMaxResults is the maximum number of URLs collected from GAU per domain.
// Large domains (tesla.com, google.com) can return 200K+ URLs which makes downstream
// processing (especially nuclei) extremely slow. 5,000 provides good coverage without
// the performance penalty.
const DefaultGAUMaxResults = 5000

// RunGAU runs gau (Get All URLs) to collect historical URLs for a domain
// from Wayback Machine, Common Crawl, and other passive sources.
// Falls back gracefully if gau is not installed.
//
// maxResults caps the number of URLs collected (0 = use DefaultGAUMaxResults).
// Install: go install github.com/lc/gau/v2/cmd/gau@latest
func RunGAU(ctx context.Context, domain string, maxResults int) ([]models.HistoricalURL, error) {
	gauPath, err := FindBinary("gau", "go install github.com/lc/gau/v2/cmd/gau@latest")
	if err != nil {
		log.Printf("[survex]   gau: not found in ~/go/bin or PATH — skipping (install: go install github.com/lc/gau/v2/cmd/gau@latest)")
		return nil, nil
	}

	if maxResults <= 0 {
		maxResults = DefaultGAUMaxResults
	}

	// --subs includes subdomains, --threads 5 limits concurrency,
	// --blacklist filters out noisy file extensions
	cmd := exec.CommandContext(ctx, gauPath,
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
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("gau failed: %w — %s", err, stderr.String())
		}
		// gau often exits non-zero even when results were found
	}

	seen := make(map[string]bool)
	var results []models.HistoricalURL
	truncated := false

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
		if len(results) >= maxResults {
			truncated = true
			break
		}
	}

	if truncated {
		log.Printf("[survex]   gau [%s]: capped at %d URLs (more available — increase with config)", domain, maxResults)
	}

	return results, nil
}
