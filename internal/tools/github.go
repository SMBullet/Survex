package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// CheckGitHubExposure searches GitHub for code files that reference the given
// domain. It runs a set of targeted queries to surface hardcoded credentials,
// secrets, and source code leaks. token is a GitHub personal access token
// (empty string = unauthenticated, rate-limited to 10 req/min).
//
// To stay within rate limits, at most 3 queries are made per domain.
func CheckGitHubExposure(domains []string, token string) []models.GitHubExposure {
	if len(domains) == 0 {
		return nil
	}

	client := &http.Client{Timeout: 20 * time.Second}

	var results []models.GitHubExposure
	seen := make(map[string]struct{}) // deduplicate by repo+file

	for _, domain := range domains {
		// 3 targeted queries per domain: secrets, config files, source code
		queries := []string{
			fmt.Sprintf(`"%s" password OR secret OR api_key OR token`, domain),
			fmt.Sprintf(`"%s" filename:config OR filename:.env OR filename:credentials`, domain),
			fmt.Sprintf(`"%s" language:python OR language:ruby OR language:go`, domain),
		}

		for i, q := range queries {
			hits, err := githubCodeSearch(client, q, token)
			if err != nil {
				log.Printf("[survex] github search [%s] query %d: %v", domain, i+1, err)
				break // stop querying this domain on error (likely rate-limited)
			}

			for _, hit := range hits {
				key := hit.Repository + "|" + hit.FileURL
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				hit.Query = q
				results = append(results, hit)
			}

			// Respect GitHub rate limits: 1 second between requests
			// (unauthenticated: 10/min; authenticated: 30/min)
			time.Sleep(1100 * time.Millisecond)
		}
	}

	return results
}

// githubCodeSearch calls the GitHub Search API for code matching the query.
// Returns at most 10 results per query (first page only).
func githubCodeSearch(client *http.Client, query, token string) ([]models.GitHubExposure, error) {
	apiURL := "https://api.github.com/search/code?q=" + url.QueryEscape(query) + "&per_page=10"

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Survex/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited (HTTP %d) — try adding a GitHub token via --github-token", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var searchResp struct {
		TotalCount int `json:"total_count"`
		Items      []struct {
			Name       string `json:"name"`
			Path       string `json:"path"`
			HTMLURL    string `json:"html_url"`
			Repository struct {
				FullName string `json:"full_name"`
				HTMLURL  string `json:"html_url"`
			} `json:"repository"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &searchResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	var results []models.GitHubExposure
	for _, item := range searchResp.Items {
		results = append(results, models.GitHubExposure{
			Repository: item.Repository.FullName,
			RepoURL:    item.Repository.HTMLURL,
			FileURL:    item.HTMLURL,
			FileName:   item.Name,
		})
	}

	return results, nil
}
