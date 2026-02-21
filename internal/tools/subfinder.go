package tools

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

type subfindResult struct {
	Host string `json:"host"`
}

// RunSubfinder runs subfinder against the given domain and returns a deduplicated
// list of discovered subdomains.
func RunSubfinder(domain string) ([]string, error) {
	if _, err := exec.LookPath("subfinder"); err != nil {
		return nil, fmt.Errorf("subfinder not found in PATH: install with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	}

	cmd := exec.Command("subfinder", "-d", domain, "-json", "-silent")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("subfinder error: %w\nstderr: %s", err, stderr.String())
	}

	seen := make(map[string]bool)
	var subdomains []string

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		var r subfindResult
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			continue
		}
		if r.Host != "" && !seen[r.Host] {
			seen[r.Host] = true
			subdomains = append(subdomains, r.Host)
		}
	}

	return subdomains, nil
}
