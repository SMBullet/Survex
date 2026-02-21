package tools

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// RunScreenshots uses gowitness to capture screenshots of all live HTTP services.
// Screenshots are stored in scanDir/screenshots/ and metadata is returned.
// Falls back gracefully if gowitness is not installed.
//
// Install: go install github.com/sensepost/gowitness@latest
// Requires: Google Chrome or Chromium to be installed.
func RunScreenshots(httpServices []models.HTTPService, scanDir string, timeoutSecs int) ([]models.Screenshot, error) {
	gowitnessPath, err := FindBinary("gowitness", "go install github.com/sensepost/gowitness@latest")
	if err != nil {
		log.Printf("[survex]   gowitness: not found in ~/go/bin or PATH — skipping (install: go install github.com/sensepost/gowitness@latest)")
		return nil, nil
	}
	if len(httpServices) == 0 {
		return nil, nil
	}

	screenshotDir := filepath.Join(scanDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		return nil, fmt.Errorf("creating screenshot dir: %w", err)
	}

	// Write target URLs to temp file
	tmpIn, err := os.CreateTemp("", "survex-gowitness-*.txt")
	if err != nil {
		return nil, fmt.Errorf("creating gowitness input file: %w", err)
	}
	defer os.Remove(tmpIn.Name())

	var urls []string
	for _, svc := range httpServices {
		urls = append(urls, svc.URL)
	}
	if _, err := tmpIn.WriteString(strings.Join(urls, "\n")); err != nil {
		return nil, err
	}
	tmpIn.Close()

	dbPath := filepath.Join(screenshotDir, "gowitness.sqlite3")

	cmd := exec.Command(gowitnessPath, "scan", "file",
		"-f", tmpIn.Name(),
		"--screenshot-path", screenshotDir,
		"--db-location", dbPath,
		"--timeout", fmt.Sprintf("%d", timeoutSecs),
	)

	log.Printf("[survex]   gowitness: capturing %d screenshots", len(urls))
	if err := cmd.Run(); err != nil {
		// gowitness exits non-zero when some URLs fail — not a fatal error
		log.Printf("[survex]   gowitness: completed with errors (some screenshots may be missing)")
	}

	// Build result list from files actually created
	entries, err := os.ReadDir(screenshotDir)
	if err != nil {
		return nil, nil
	}

	// Build a URL→filename lookup
	urlToFile := make(map[string]string)
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".png") || strings.HasSuffix(entry.Name(), ".jpeg")) {
			urlToFile[entry.Name()] = entry.Name()
		}
	}

	var results []models.Screenshot
	for _, svc := range httpServices {
		// gowitness names files by sanitizing the URL
		sanitized := sanitizeURLForFilename(svc.URL) + ".png"
		if _, exists := urlToFile[sanitized]; exists {
			results = append(results, models.Screenshot{
				Host: svc.Host,
				URL:  svc.URL,
				Path: filepath.Join("screenshots", sanitized),
			})
		}
	}

	return results, nil
}

// sanitizeURLForFilename converts a URL to the filename gowitness uses.
// gowitness replaces ://, /, :, ? and other special chars with underscores.
func sanitizeURLForFilename(rawURL string) string {
	r := strings.NewReplacer(
		"://", "_",
		"/", "_",
		":", "_",
		"?", "_",
		"&", "_",
		"=", "_",
		"#", "_",
	)
	return r.Replace(rawURL)
}
