package tools

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// openRedirectPayloads are common open redirect test values.
var openRedirectPayloads = []string{
	"https://evil.com",
	"//evil.com",
	"///evil.com",
	"////evil.com",
	"/\\evil.com",
	"\\\\evil.com",
	"https:evil.com",
	"http://evil.com",
	"//evil.com/%2F..",
	"https://evil.com?trusted.com",
	"https://trusted.com.evil.com",
	"//%09/evil.com",
	"//google.com/%2F%2F",
}

// redirectParams are parameter names commonly used for redirects.
var redirectParams = []string{
	"redirect", "redirect_uri", "redirect_url", "return", "return_url",
	"returnurl", "next", "url", "goto", "dest", "destination", "target",
	"redir", "ref", "referer", "continue", "forward", "location",
	"callback", "success_url", "cancel_url", "to", "link",
}

// ExtractParamURLs extracts URLs with query parameters from a list.
// Used to feed dalfox and sqlmap with a clean, deduplicated parameter list.
func ExtractParamURLs(rawURLs []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, raw := range rawURLs {
		if !strings.Contains(raw, "?") {
			continue
		}
		// Normalise: remove fragment, lowercase scheme+host
		u, err := url.Parse(raw)
		if err != nil || u.RawQuery == "" {
			continue
		}
		norm := fmt.Sprintf("%s://%s%s?%s", u.Scheme, strings.ToLower(u.Host), u.Path, u.RawQuery)
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		result = append(result, norm)
	}
	return result
}

// CheckOpenRedirects tests discovered URLs for open redirect vulnerabilities.
// It checks both existing parameters named like redirect params AND injects
// redirect params into URLs that don't have them.
func CheckOpenRedirects(urls []string, timeoutSecs int) []models.OpenRedirectResult {
	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow — we detect the redirect ourselves
			return http.ErrUseLastResponse
		},
	}

	// Build test cases: (url, param, payload)
	type testCase struct {
		baseURL string
		param   string
		payload string
	}

	var cases []testCase
	seenBase := make(map[string]struct{})

	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}

		// Avoid duplicate base URLs
		base := u.Scheme + "://" + u.Host + u.Path
		if _, dup := seenBase[base]; dup {
			continue
		}
		seenBase[base] = struct{}{}

		q := u.Query()

		// Check existing parameters that look like redirect params
		for _, p := range redirectParams {
			if _, exists := q[p]; exists {
				for _, payload := range openRedirectPayloads {
					cases = append(cases, testCase{raw, p, payload})
				}
			}
		}

		// Also inject known redirect params that aren't already there
		for _, p := range redirectParams[:5] { // only top 5 to avoid explosion
			if _, exists := q[p]; !exists {
				newQ := url.Values{}
				for k, v := range q {
					newQ[k] = v
				}
				newQ.Set(p, "https://evil.com")
				injected := *u
				injected.RawQuery = newQ.Encode()
				cases = append(cases, testCase{injected.String(), p, "https://evil.com"})
			}
		}
	}

	if len(cases) == 0 {
		return nil
	}

	// Cap test cases
	if len(cases) > 500 {
		cases = cases[:500]
	}

	log.Printf("[survex] open-redirect: testing %d cases across %d URLs", len(cases), len(seenBase))

	sem := make(chan struct{}, 20)
	var mu sync.Mutex
	var results []models.OpenRedirectResult
	seenResult := make(map[string]struct{})

	var wg sync.WaitGroup
	for _, tc := range cases {
		wg.Add(1)
		go func(tc testCase) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Build test URL with the payload
			u, err := url.Parse(tc.baseURL)
			if err != nil {
				return
			}
			q := u.Query()
			q.Set(tc.param, tc.payload)
			u.RawQuery = q.Encode()
			testURL := u.String()

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Survex/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()

			// Check for redirect to evil.com
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := resp.Header.Get("Location")
				if loc == "" {
					io.Discard.Write(nil)
					return
				}
				if strings.Contains(loc, "evil.com") || strings.HasPrefix(loc, "//") {
					key := u.Host + "|" + tc.param
					mu.Lock()
					if _, dup := seenResult[key]; !dup {
						seenResult[key] = struct{}{}
						results = append(results, models.OpenRedirectResult{
							URL:         tc.baseURL,
							Host:        u.Hostname(),
							Parameter:   tc.param,
							Payload:     tc.payload,
							RedirectsTo: loc,
						})
					}
					mu.Unlock()
				}
			}
		}(tc)
	}
	wg.Wait()

	log.Printf("[survex] open-redirect: %d confirmed", len(results))
	return results
}
