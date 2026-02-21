package tools

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// s3Patterns matches cloud storage hostnames in subdomain names and HTTP response bodies.
var s3Patterns = []struct {
	pattern  *regexp.Regexp
	provider string
}{
	{regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-\.]+)\.s3\.amazonaws\.com`), "aws"},
	{regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-\.]+)\.s3\-[a-z0-9\-]+\.amazonaws\.com`), "aws"},
	{regexp.MustCompile(`(?i)s3\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]+)`), "aws"},
	{regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-\.]+)\.storage\.googleapis\.com`), "gcs"},
	{regexp.MustCompile(`(?i)storage\.googleapis\.com/([a-z0-9][a-z0-9\-\.]+)`), "gcs"},
	{regexp.MustCompile(`(?i)([a-z0-9][a-z0-9\-\.]+)\.blob\.core\.windows\.net`), "azure"},
}

// DetectS3Buckets finds cloud storage bucket references in subdomains and HTTP services,
// then checks each discovered bucket for public access.
func DetectS3Buckets(subdomains []models.Subdomain, httpServices []models.HTTPService, timeoutSecs int) []models.S3Bucket {
	type candidate struct {
		host      string
		bucketURL string
		provider  string
	}

	seen := make(map[string]bool)
	var candidates []candidate

	addCandidate := func(host, bucketURL, provider string) {
		key := bucketURL
		if seen[key] {
			return
		}
		seen[key] = true
		candidates = append(candidates, candidate{host: host, bucketURL: bucketURL, provider: provider})
	}

	// Check subdomain names
	for _, sub := range subdomains {
		for _, pat := range s3Patterns {
			if m := pat.pattern.FindStringSubmatch(sub.Name); m != nil {
				bucketURL := buildBucketURL(pat.provider, m)
				addCandidate(sub.Name, bucketURL, pat.provider)
			}
		}
	}

	// Check HTTP service URLs and response bodies
	httpClient := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, svc := range httpServices {
		for _, pat := range s3Patterns {
			if m := pat.pattern.FindStringSubmatch(svc.URL); m != nil {
				bucketURL := buildBucketURL(pat.provider, m)
				addCandidate(svc.Host, bucketURL, pat.provider)
			}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	// Check each candidate bucket concurrently
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	var results []models.S3Bucket

	for _, c := range candidates {
		wg.Add(1)
		go func(cand candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			bucket := checkBucketAccess(httpClient, cand.host, cand.bucketURL, cand.provider)
			if bucket == nil {
				return
			}
			mu.Lock()
			results = append(results, *bucket)
			mu.Unlock()
		}(c)
	}

	wg.Wait()
	return results
}

// checkBucketAccess probes a bucket URL to determine public access status.
func checkBucketAccess(client *http.Client, host, bucketURL, provider string) *models.S3Bucket {
	result := &models.S3Bucket{
		Host:      host,
		BucketURL: bucketURL,
		Provider:  provider,
	}

	// HEAD check — does the bucket exist and is it accessible?
	headResp, err := client.Head(bucketURL)
	if err != nil {
		return nil
	}
	headResp.Body.Close()

	if headResp.StatusCode == 403 || headResp.StatusCode == 401 {
		// Exists but private — not a finding
		return nil
	}

	if headResp.StatusCode == 404 || headResp.StatusCode >= 500 {
		return nil
	}

	result.Public = true

	// GET check — can we list the bucket contents?
	listURL := bucketListURL(bucketURL, provider)
	getResp, err := client.Get(listURL)
	if err == nil {
		defer getResp.Body.Close()
		if getResp.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(getResp.Body, 4096))
			bodyStr := string(body)
			// AWS S3 listing responses contain <ListBucketResult> or <Contents>
			// GCS listing responses contain <ListBucketResult> or "kind":"storage#objects"
			if strings.Contains(bodyStr, "ListBucketResult") ||
				strings.Contains(bodyStr, "<Contents>") ||
				strings.Contains(bodyStr, `"kind":"storage#objects"`) ||
				strings.Contains(bodyStr, "<EnumerationResults>") {
				result.Listable = true
			}
		}
	}

	return result
}

func buildBucketURL(provider string, match []string) string {
	if len(match) < 2 {
		return ""
	}
	name := match[1]
	switch provider {
	case "aws":
		return fmt.Sprintf("https://%s.s3.amazonaws.com", name)
	case "gcs":
		return fmt.Sprintf("https://storage.googleapis.com/%s", name)
	case "azure":
		return fmt.Sprintf("https://%s.blob.core.windows.net", name)
	}
	return ""
}

func bucketListURL(bucketURL, provider string) string {
	switch provider {
	case "aws":
		return bucketURL + "?list-type=2&max-keys=10"
	case "gcs":
		return bucketURL + "?maxResults=10"
	case "azure":
		return bucketURL + "?restype=container&comp=list&maxresults=10"
	}
	return bucketURL
}
