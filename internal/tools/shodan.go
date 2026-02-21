package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

const shodanAPIBase = "https://api.shodan.io/shodan/host"

// shodanResponse is the subset of the Shodan /shodan/host/{ip} response we use.
type shodanResponse struct {
	IP        string   `json:"ip_str"`
	Ports     []int    `json:"ports"`
	Hostnames []string `json:"hostnames"`
	Vulns     map[string]interface{} `json:"vulns"` // map of CVE ID → details
	Tags      []string `json:"tags"`
	ISP       string   `json:"isp"`
	Country   string   `json:"country_name"`
	Org       string   `json:"org"`
}

// LookupShodan enriches a list of IP addresses with data from the Shodan API.
// Skips gracefully if the API key is empty.
// Rate: 1 request per second (free tier) — adjust for paid plans.
func LookupShodan(ips []string, apiKey string) []models.ShodanHost {
	if apiKey == "" || len(ips) == 0 {
		return nil
	}

	client := &http.Client{Timeout: 15 * time.Second}
	seen := make(map[string]bool)
	var results []models.ShodanHost

	for i, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true

		host, err := shodanLookupIP(client, ip, apiKey)
		if err != nil {
			log.Printf("[survex]   shodan [%s]: %v", ip, err)
			// Continue — don't abort the whole enrichment for one failure
		} else if host != nil {
			results = append(results, *host)
		}

		// Respect Shodan rate limit: 1 req/s on free tier.
		// Skip sleep after the last IP.
		if i < len(ips)-1 {
			time.Sleep(1100 * time.Millisecond)
		}
	}

	return results
}

func shodanLookupIP(client *http.Client, ip, apiKey string) (*models.ShodanHost, error) {
	url := fmt.Sprintf("%s/%s?key=%s", shodanAPIBase, ip, apiKey)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil // IP not in Shodan — not an error
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("invalid API key (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var sr shodanResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// Extract CVE IDs from the vulns map
	var vulns []string
	for cve := range sr.Vulns {
		vulns = append(vulns, cve)
	}

	return &models.ShodanHost{
		IP:        ip,
		Ports:     sr.Ports,
		Hostnames: sr.Hostnames,
		Vulns:     vulns,
		Tags:      sr.Tags,
		ISP:       sr.ISP,
		Country:   sr.Country,
		Org:       sr.Org,
	}, nil
}
