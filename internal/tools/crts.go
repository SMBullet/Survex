package tools

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type crtEntry struct {
	NameValue string `json:"name_value"`
}

// RunCRTs queries the crt.sh certificate transparency log API for subdomains
// of the given domain. No external tool required — pure HTTP.
func RunCRTs(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading crt.sh response: %w", err)
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing crt.sh response: %w", err)
	}

	seen := make(map[string]bool)
	var subdomains []string

	for _, e := range entries {
		// name_value may contain multiple entries separated by newlines
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			// Skip wildcards and the root domain itself
			if name == "" || strings.HasPrefix(name, "*") || name == domain {
				continue
			}
			// Only include subdomains of the target
			if !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if !seen[name] {
				seen[name] = true
				subdomains = append(subdomains, name)
			}
		}
	}

	return subdomains, nil
}
