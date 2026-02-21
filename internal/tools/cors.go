package tools

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// corsProbeDomain is the external origin we use to test for CORS misconfigurations.
// It is intentionally set to a domain that will never exist legitimately on a target.
const corsProbeDomain = "https://evil-cors-probe.survex.internal"

// TestCORS sends CORS probe requests to each live HTTP service and returns any
// misconfigured endpoints. It runs concurrently with a 10-connection semaphore.
func TestCORS(httpServices []models.HTTPService, timeoutSecs int) []models.CORSResult {
	if len(httpServices) == 0 {
		return nil
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	var results []models.CORSResult

	for _, svc := range httpServices {
		wg.Add(1)
		go func(url, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := probeCORS(client, url, host)
			if result == nil {
				return
			}
			mu.Lock()
			results = append(results, *result)
			mu.Unlock()
		}(svc.URL, svc.Host)
	}

	wg.Wait()
	return results
}

func probeCORS(client *http.Client, url, host string) *models.CORSResult {
	// Test 1: Arbitrary external origin
	if r := corsProbe(client, url, host, corsProbeDomain); r != nil {
		return r
	}

	// Test 2: Null origin (common iframe/sandbox bypass)
	if r := corsProbe(client, url, host, "null"); r != nil {
		return r
	}

	// Test 3: Subdomain of the target (e.g. evil.target.com)
	// This catches suffix-match implementations that don't validate properly.
	crafted := fmt.Sprintf("https://evil.%s", host)
	if r := corsProbe(client, url, host, crafted); r != nil {
		return r
	}

	return nil
}

// corsProbe sends a single OPTIONS/GET request with the specified Origin header
// and analyses the Access-Control-* response headers.
func corsProbe(client *http.Client, url, host, origin string) *models.CORSResult {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "Survex-ASM/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

	if acao == "" {
		return nil // No CORS headers — not misconfigured
	}

	withCreds := acac == "true"

	// Wildcard with credentials is technically spec-invalid but some servers do it
	if acao == "*" && withCreds {
		return &models.CORSResult{
			Host:       host,
			URL:        url,
			Vulnerable: true,
			Issue:      "wildcard_with_credentials",
			Evidence:   fmt.Sprintf("ACAO: * with ACAC: true — credentials may be sent cross-origin"),
		}
	}

	// Wildcard without credentials — high but not critical
	if acao == "*" {
		return &models.CORSResult{
			Host:       host,
			URL:        url,
			Vulnerable: true,
			Issue:      "wildcard",
			Evidence:   fmt.Sprintf("ACAO: * — any origin can make credentialless cross-origin requests"),
		}
	}

	// Origin reflected and credentials allowed — critical
	if strings.EqualFold(acao, origin) && withCreds {
		return &models.CORSResult{
			Host:       host,
			URL:        url,
			Vulnerable: true,
			Issue:      "reflects_origin_with_credentials",
			Evidence:   fmt.Sprintf("ACAO reflects '%s' with ACAC: true — full cross-origin credential bypass", origin),
		}
	}

	// Origin reflected without credentials — medium
	if strings.EqualFold(acao, origin) {
		return &models.CORSResult{
			Host:       host,
			URL:        url,
			Vulnerable: true,
			Issue:      "reflects_origin",
			Evidence:   fmt.Sprintf("ACAO reflects arbitrary origin '%s' (no credentials)", origin),
		}
	}

	return nil
}
