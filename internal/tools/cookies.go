package tools

import (
	"crypto/tls"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// AnalyzeCookies fetches each live HTTP URL and audits Set-Cookie headers for
// missing security flags (Secure, HttpOnly, SameSite).
// Runs concurrently with a 10-connection semaphore.
func AnalyzeCookies(httpServices []models.HTTPService, timeoutSecs int) []models.CookieResult {
	if len(httpServices) == 0 {
		return nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	var results []models.CookieResult

	for _, svc := range httpServices {
		wg.Add(1)
		go func(rawURL, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cookies := fetchCookies(rawURL, host, timeoutSecs)
			if len(cookies) == 0 {
				return
			}
			mu.Lock()
			results = append(results, models.CookieResult{
				Host:    host,
				URL:     rawURL,
				Cookies: cookies,
			})
			mu.Unlock()
		}(svc.URL, svc.Host)
	}

	wg.Wait()
	return results
}

func fetchCookies(rawURL, host string, timeoutSecs int) []models.CookieDetail {
	jar, _ := cookiejar.New(nil)

	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Survex-ASM/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Collect cookies from both Set-Cookie headers and the cookie jar.
	seen := make(map[string]bool)
	var details []models.CookieDetail

	// Parse raw Set-Cookie headers for accurate flag detection.
	for _, raw := range resp.Header["Set-Cookie"] {
		detail := parseCookieHeader(raw)
		if detail == nil || seen[detail.Name] {
			continue
		}
		seen[detail.Name] = true
		details = append(details, *detail)
	}

	// Also check cookies set by intermediate redirects via the jar.
	if u, err := url.Parse(rawURL); err == nil {
		for _, c := range jar.Cookies(u) {
			if seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			details = append(details, models.CookieDetail{
				Name:     c.Name,
				Secure:   c.Secure,
				HttpOnly: c.HttpOnly,
				SameSite: sameSiteString(int(c.SameSite)),
			})
		}
	}

	return details
}

// parseCookieHeader parses a raw Set-Cookie header string for security flags.
func parseCookieHeader(raw string) *models.CookieDetail {
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return nil
	}

	// First part is name=value
	namePart := strings.TrimSpace(parts[0])
	eqIdx := strings.Index(namePart, "=")
	var name string
	if eqIdx >= 0 {
		name = strings.TrimSpace(namePart[:eqIdx])
	} else {
		name = namePart
	}
	if name == "" {
		return nil
	}

	detail := &models.CookieDetail{Name: name}

	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)
		switch {
		case lower == "secure":
			detail.Secure = true
		case lower == "httponly":
			detail.HttpOnly = true
		case strings.HasPrefix(lower, "samesite="):
			detail.SameSite = strings.TrimPrefix(part, strings.ToLower(strings.SplitN(part, "=", 2)[0])+"=")
			// Normalize case
			switch strings.ToLower(detail.SameSite) {
			case "strict":
				detail.SameSite = "Strict"
			case "lax":
				detail.SameSite = "Lax"
			case "none":
				detail.SameSite = "None"
			}
		}
	}

	return detail
}

func sameSiteString(ss int) string {
	switch ss {
	case 1:
		return "Default"
	case 2:
		return "Lax"
	case 3:
		return "Strict"
	case 4:
		return "None"
	}
	return ""
}
