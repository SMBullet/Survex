package tools

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// wafSignatures maps WAF name to a detection function.
// Each function receives the HTTP response and returns true if that WAF is detected.
var wafSignatures = []struct {
	Name   string
	Detect func(resp *http.Response) (bool, string)
}{
	{
		Name: "Cloudflare",
		Detect: func(r *http.Response) (bool, string) {
			if r.Header.Get("CF-Ray") != "" {
				return true, "CF-Ray header present"
			}
			if strings.Contains(r.Header.Get("Server"), "cloudflare") {
				return true, "Server: cloudflare"
			}
			return false, ""
		},
	},
	{
		Name: "Akamai",
		Detect: func(r *http.Response) (bool, string) {
			if strings.Contains(r.Header.Get("Server"), "AkamaiGHost") {
				return true, "Server: AkamaiGHost"
			}
			if r.Header.Get("X-Check-Cacheable") != "" {
				return true, "X-Check-Cacheable header"
			}
			return false, ""
		},
	},
	{
		Name: "Sucuri",
		Detect: func(r *http.Response) (bool, string) {
			if r.Header.Get("X-Sucuri-ID") != "" {
				return true, "X-Sucuri-ID header"
			}
			if r.Header.Get("X-Sucuri-Cache") != "" {
				return true, "X-Sucuri-Cache header"
			}
			return false, ""
		},
	},
	{
		Name: "AWS WAF / CloudFront",
		Detect: func(r *http.Response) (bool, string) {
			if strings.Contains(r.Header.Get("Server"), "CloudFront") {
				return true, "Server: CloudFront"
			}
			if r.Header.Get("X-Amz-Cf-Id") != "" {
				return true, "X-Amz-Cf-Id header"
			}
			return false, ""
		},
	},
	{
		Name: "Fastly",
		Detect: func(r *http.Response) (bool, string) {
			if r.Header.Get("X-Served-By") != "" && strings.Contains(r.Header.Get("X-Served-By"), "cache") {
				return true, "X-Served-By (Fastly cache)"
			}
			if r.Header.Get("Fastly-Debug-Digest") != "" {
				return true, "Fastly-Debug-Digest header"
			}
			return false, ""
		},
	},
	{
		Name: "F5 BIG-IP",
		Detect: func(r *http.Response) (bool, string) {
			cookie := r.Header.Get("Set-Cookie")
			if strings.Contains(cookie, "BIGipServer") {
				return true, "BIGipServer cookie"
			}
			if strings.Contains(r.Header.Get("Server"), "BigIP") {
				return true, "Server: BigIP"
			}
			return false, ""
		},
	},
	{
		Name: "Imperva / Incapsula",
		Detect: func(r *http.Response) (bool, string) {
			if r.Header.Get("X-Iinfo") != "" {
				return true, "X-Iinfo header"
			}
			if strings.Contains(r.Header.Get("Set-Cookie"), "incap_ses") {
				return true, "incap_ses cookie"
			}
			return false, ""
		},
	},
}

// DetectWAF sends a probe request and fingerprints the WAF in front of the host.
func DetectWAF(host string) (*models.WAFDetection, error) {
	result := &models.WAFDetection{Host: host, Detected: false}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects — headers matter
		},
	}

	// Try HTTPS first, fall back to HTTP
	var resp *http.Response
	var err error
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, host)
		resp, err = client.Get(url)
		if err == nil {
			break
		}
	}
	if err != nil {
		return result, nil // host not reachable, not an error for WAF detection
	}
	defer resp.Body.Close()

	for _, sig := range wafSignatures {
		detected, evidence := sig.Detect(resp)
		if detected {
			result.Detected = true
			result.Name = sig.Name
			result.Evidence = evidence
			return result, nil
		}
	}

	return result, nil
}
