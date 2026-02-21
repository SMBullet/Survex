package tools

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// amassOutput is the JSONL structure emitted by amass enum -json.
type amassOutput struct {
	Name string `json:"name"`
}

// RunAmass runs amass in passive enumeration mode for a single domain.
// Falls back gracefully if amass is not installed.
//
// Install: go install -v github.com/owasp-amass/amass/v4/...@master
func RunAmass(domain string) ([]string, error) {
	amassPath, err := FindBinary("amass", "go install github.com/owasp-amass/amass/v4/...@master")
	if err != nil {
		log.Printf("[survex]   amass: not found in ~/go/bin or PATH — skipping (install: go install github.com/owasp-amass/amass/v4/...@master)")
		return nil, nil
	}

	tmpOut, err := os.CreateTemp("", "survex-amass-*.json")
	if err != nil {
		return nil, fmt.Errorf("creating amass output file: %w", err)
	}
	tmpOutName := tmpOut.Name()
	tmpOut.Close()
	defer os.Remove(tmpOutName)

	// amass enum -passive: uses only OSINT/DNS sources, no brute-force
	cmd := exec.Command(amassPath, "enum",
		"-passive",
		"-d", domain,
		"-json", tmpOutName,
		"-timeout", "5", // minutes
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting amass: %w", err)
	}

	go func() { done <- cmd.Wait() }()

	// Enforce a hard wall-clock timeout of 6 minutes
	select {
	case <-time.After(6 * time.Minute):
		_ = cmd.Process.Kill()
		log.Printf("[survex]   amass [%s]: timed out after 6 minutes", domain)
	case <-done:
	}

	data, err := os.ReadFile(tmpOutName)
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	seen := make(map[string]bool)
	var subs []string

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var out amassOutput
		if err := json.Unmarshal(line, &out); err != nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(out.Name))
		if name == "" || seen[name] {
			continue
		}
		// Only include subdomains of the target domain
		if !strings.HasSuffix(name, "."+domain) && name != domain {
			continue
		}
		seen[name] = true
		subs = append(subs, name)
	}

	return subs, nil
}
