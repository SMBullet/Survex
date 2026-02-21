package tools

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/SMBullet/Survex/internal/models"
)

// secretPattern pairs a human-readable type name with a compiled regex.
type secretPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

// secretPatterns is the list of patterns used to detect secrets in JS files.
// Patterns are intentionally conservative to reduce false positives.
var secretPatterns = []secretPattern{
	// Cloud provider keys
	{Name: "AWS Access Key ID", Pattern: regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{Name: "AWS Secret Access Key", Pattern: regexp.MustCompile(`(?i)(aws.?secret.?access.?key|aws_secret)[^a-zA-Z0-9_\-]{0,3}["']?([A-Za-z0-9/+=]{40})["']?`)},
	{Name: "Google API Key", Pattern: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{Name: "Google OAuth Client ID", Pattern: regexp.MustCompile(`[0-9]{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com`)},

	// GitHub tokens
	{Name: "GitHub Fine-grained Token", Pattern: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,255}\b`)},
	{Name: "GitHub Classic Token", Pattern: regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{Name: "GitHub Actions Token", Pattern: regexp.MustCompile(`\bghs_[A-Za-z0-9]{36}\b`)},

	// Communication / SaaS
	{Name: "Slack Token", Pattern: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b`)},
	{Name: "Slack Webhook", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`)},
	{Name: "Discord Webhook", Pattern: regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+`)},
	{Name: "Twilio API Key", Pattern: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)},
	{Name: "SendGrid API Key", Pattern: regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`)},
	{Name: "Mailchimp API Key", Pattern: regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`)},

	// Payment
	{Name: "Stripe Secret Key", Pattern: regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`)},
	{Name: "Stripe Publishable Key", Pattern: regexp.MustCompile(`\bpk_live_[A-Za-z0-9]{24,}\b`)},
	{Name: "PayPal Client ID", Pattern: regexp.MustCompile(`(?i)paypal.*client.?id["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{15,})["']`)},

	// Private keys and certificates
	{Name: "RSA Private Key", Pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`)},
	{Name: "EC Private Key", Pattern: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`)},
	{Name: "OpenSSH Private Key", Pattern: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`)},
	{Name: "PGP Private Key", Pattern: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`)},
	{Name: "PKCS8 Private Key", Pattern: regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`)},

	// Tokens and secrets (generic but anchored to likely variable names)
	{Name: "JWT Token", Pattern: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
	{Name: "Bearer Token", Pattern: regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9_\-.+/=]{20,})`)},
	{Name: "Firebase URL", Pattern: regexp.MustCompile(`https?://[a-z0-9_\-]+\.firebaseio\.com`)},
	{Name: "Firebase Token", Pattern: regexp.MustCompile(`(?i)firebase.*[Kk]ey["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']`)},
	{Name: "Heroku API Key", Pattern: regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)},
	{Name: "NPM Token", Pattern: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{Name: "PyPI Token", Pattern: regexp.MustCompile(`\bpypi-AgEI[A-Za-z0-9_\-]{50,}\b`)},

	// Hardcoded credentials (variable-name anchored)
	{Name: "Hardcoded Password", Pattern: regexp.MustCompile(`(?i)(?:password|passwd|pass)\s*[:=]\s*["']([^"'\s]{6,})["']`)},
	{Name: "Hardcoded API Key", Pattern: regexp.MustCompile(`(?i)(?:api.?key|apikey|api_token)\s*[:=]\s*["']([A-Za-z0-9_\-/.]{10,})["']`)},
	{Name: "Hardcoded Secret", Pattern: regexp.MustCompile(`(?i)(?:secret|secret.?key|secret_key)\s*[:=]\s*["']([A-Za-z0-9_\-/.]{8,})["']`)},
	{Name: "Hardcoded Auth Token", Pattern: regexp.MustCompile(`(?i)(?:auth.?token|access.?token|bearer.?token)\s*[:=]\s*["']([A-Za-z0-9_\-.]{15,})["']`)},
	{Name: "Hardcoded DB Connection", Pattern: regexp.MustCompile(`(?i)(?:connection.?string|db.?url|database.?url)\s*[:=]\s*["']([^"']{15,})["']`)},
	{Name: "Hardcoded Private Key", Pattern: regexp.MustCompile(`(?i)private.?key\s*[:=]\s*["']([A-Za-z0-9_\-/.+]{20,})["']`)},

	// Internal URLs (may expose internal infrastructure)
	{Name: "Internal IP in JS", Pattern: regexp.MustCompile(`(?:https?://)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`)},
	{Name: "Localhost in JS", Pattern: regexp.MustCompile(`(?:https?://)localhost(?::\d+)?`)},

	// Cloud storage
	{Name: "S3 Bucket URL", Pattern: regexp.MustCompile(`s3\.amazonaws\.com/[a-z0-9\-._]{3,63}|[a-z0-9\-._]{3,63}\.s3\.amazonaws\.com`)},
	{Name: "Azure Storage URL", Pattern: regexp.MustCompile(`[a-z0-9]{3,24}\.blob\.core\.windows\.net`)},
	{Name: "GCS Bucket URL", Pattern: regexp.MustCompile(`storage\.googleapis\.com/[a-z0-9\-._]{3,63}|[a-z0-9\-._]{3,63}\.storage\.googleapis\.com`)},
}

// isJSURL returns true if the URL looks like a JavaScript file.
func isJSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	return strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".mjs") ||
		strings.HasSuffix(path, ".jsx") ||
		strings.Contains(path, "/js/") ||
		strings.Contains(path, "/javascript/") ||
		strings.Contains(path, "/bundle") ||
		strings.Contains(path, "/chunk") ||
		strings.Contains(path, "/dist/")
}

// ScanJS fetches JavaScript URLs discovered during crawling and scans them
// for hardcoded secrets using regex pattern matching.
// It accepts a mixed list of URLs (only JS URLs are processed).
// Up to 200 JS URLs are scanned (to keep scan time reasonable).
func ScanJS(urls []string, timeoutSecs int) []models.JSSecret {
	if timeoutSecs <= 0 {
		timeoutSecs = 10
	}

	// Filter to JS URLs only, capped at 200
	var jsURLs []string
	seen := make(map[string]struct{})
	for _, u := range urls {
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		if isJSURL(u) {
			jsURLs = append(jsURLs, u)
			if len(jsURLs) >= 200 {
				break
			}
		}
	}

	if len(jsURLs) == 0 {
		return nil
	}

	log.Printf("[survex] jsscan: scanning %d JavaScript files for secrets", len(jsURLs))

	var (
		mu      sync.Mutex
		results []models.JSSecret
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 10) // 10 concurrent fetches
	)

	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	for _, jsURL := range jsURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			secrets := fetchAndScan(client, u)
			if len(secrets) > 0 {
				mu.Lock()
				results = append(results, secrets...)
				mu.Unlock()
			}
		}(jsURL)
	}

	wg.Wait()
	return results
}

// fetchAndScan fetches the content of a URL and scans it for secrets.
func fetchAndScan(client *http.Client, rawURL string) []models.JSSecret {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Survex/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	// Read at most 2MB per JS file
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}

	if !utf8.Valid(body) {
		return nil // skip binary / non-UTF8 files
	}

	content := string(body)

	host := ""
	if u, err := url.Parse(rawURL); err == nil {
		host = u.Hostname()
	}

	var secrets []models.JSSecret
	seen := make(map[string]struct{})

	for _, p := range secretPatterns {
		matches := p.Pattern.FindAllString(content, -1)
		for _, match := range matches {
			// Deduplicate by (pattern, match)
			key := p.Name + "|" + match
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			// Truncate match to 80 chars for display
			displayMatch := match
			if len(displayMatch) > 80 {
				displayMatch = displayMatch[:77] + "..."
			}

			secrets = append(secrets, models.JSSecret{
				URL:     rawURL,
				Host:    host,
				Type:    p.Name,
				Match:   displayMatch,
				Pattern: p.Name,
			})
		}
	}

	return secrets
}
