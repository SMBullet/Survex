package tools

import (
	"crypto/tls"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// securityHeaderNames lists the HTTP security response headers we audit.
// Order is used for consistent reporting and grade computation.
var securityHeaderNames = []string{
	"Strict-Transport-Security",
	"Content-Security-Policy",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"X-XSS-Protection",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
}

// AnalyzeHeaders checks each live HTTP service for security response headers.
// It runs concurrently across all provided URLs using a 10-connection semaphore.
func AnalyzeHeaders(httpServices []models.HTTPService, timeoutSecs int) []models.SecurityHeaders {
	if len(httpServices) == 0 {
		return nil
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Do not follow redirects — we want headers from the original response.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	var results []models.SecurityHeaders

	for _, svc := range httpServices {
		wg.Add(1)
		go func(url, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := checkHeaders(client, url, host)
			if result == nil {
				return
			}
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()
		}(svc.URL, svc.Host)
	}

	wg.Wait()

	// Sort for deterministic output
	sort.Slice(results, func(i, j int) bool {
		return results[i].URL < results[j].URL
	})

	return results
}

func checkHeaders(client *http.Client, url, host string) *models.SecurityHeaders {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Survex-ASM/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	present := make(map[string]string)
	var missing []string

	for _, name := range securityHeaderNames {
		val := resp.Header.Get(name)
		if val != "" {
			present[name] = val
		} else {
			missing = append(missing, name)
		}
	}

	score := gradeHeaders(len(present))

	return &models.SecurityHeaders{
		Host:    host,
		URL:     url,
		Present: present,
		Missing: missing,
		Score:   score,
	}
}

// gradeHeaders returns a letter grade based on how many security headers are present.
// A = all 10, B = 7-9, C = 4-6, D = 2-3, F = 0-1
func gradeHeaders(count int) string {
	switch {
	case count >= 10:
		return "A+"
	case count >= 8:
		return "A"
	case count >= 7:
		return "B"
	case count >= 5:
		return "C"
	case count >= 3:
		return "D"
	default:
		return "F"
	}
}

// HeaderScore returns a numeric score (0–10) for sorting/comparison.
func HeaderScore(grade string) int {
	grades := map[string]int{"A+": 10, "A": 9, "B": 7, "C": 5, "D": 3, "F": 0}
	if v, ok := grades[strings.ToUpper(grade)]; ok {
		return v
	}
	return 0
}
