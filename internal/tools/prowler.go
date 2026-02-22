package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
)

// prowlerFinding is the OCSF schema object prowler v4 writes per check.
type prowlerFinding struct {
	FindingInfo struct {
		Title string `json:"title"`
		Desc  string `json:"desc"`
	} `json:"finding_info"`
	Severity string `json:"severity"` // critical|high|medium|low|informational
	Status   string `json:"status"`   // PASS|FAIL|MANUAL|MUTED
	Resources []struct {
		UID  string `json:"uid"`
		Name string `json:"name"`
		Group struct {
			Name string `json:"name"`
		} `json:"group"`
	} `json:"resources"`
	Remediation struct {
		Desc string `json:"desc"`
	} `json:"remediation"`
	Cloud struct {
		Provider string `json:"provider"`
		Account  struct {
			UID string `json:"uid"`
		} `json:"account"`
		Service struct {
			Name string `json:"name"`
		} `json:"service"`
	} `json:"cloud"`
}

// RunProwler runs prowler against the given provider and returns security findings.
// Prowler must be installed: pip install prowler
//
// Exit code 3 from prowler means "FAIL findings exist" — that is expected, not an error.
func RunProwler(ctx context.Context, provider string, creds map[string]string, logFn func(string)) ([]models.CloudFinding, string, error) {
	prowlerPath, err := FindBinary("prowler", "pip install prowler")
	if err != nil {
		return nil, "", fmt.Errorf("prowler not found; install with: pip install prowler")
	}

	outDir, err := os.MkdirTemp("", "prowler-out-*")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(outDir)

	// Base args — write JSON-OCSF to outDir, suppress banner, exit-code 3 is OK.
	args := []string{
		provider,
		"--output-formats", "json-ocsf",
		"--output-directory", outDir,
		"--output-filename", "findings",
	}

	env := append([]string{}, os.Environ()...)
	var cleanup func()

	switch provider {
	case "aws":
		if v := creds["access_key_id"]; v != "" {
			env = append(env, "AWS_ACCESS_KEY_ID="+v)
		}
		if v := creds["secret_access_key"]; v != "" {
			env = append(env, "AWS_SECRET_ACCESS_KEY="+v)
		}
		if v := creds["session_token"]; v != "" {
			env = append(env, "AWS_SESSION_TOKEN="+v)
		}
		if v := creds["region"]; v != "" {
			args = append(args, "--region", v)
		}
		if v := creds["role_arn"]; v != "" {
			args = append(args, "--role", v)
		}

	case "azure":
		args = append(args, "--sp-env-auth")
		if v := creds["tenant_id"]; v != "" {
			env = append(env, "AZURE_TENANT_ID="+v)
		}
		if v := creds["client_id"]; v != "" {
			env = append(env, "AZURE_CLIENT_ID="+v)
		}
		if v := creds["client_secret"]; v != "" {
			env = append(env, "AZURE_CLIENT_SECRET="+v)
		}
		if v := creds["subscription_id"]; v != "" {
			args = append(args, "--subscription-ids", v)
		}

	case "gcp":
		saFile, err := os.CreateTemp("", "prowler-sa-*.json")
		if err != nil {
			return nil, "", err
		}
		if _, err = saFile.WriteString(creds["service_account_json"]); err != nil {
			saFile.Close()
			os.Remove(saFile.Name())
			return nil, "", err
		}
		saFile.Close()
		cleanup = func() { os.Remove(saFile.Name()) }
		env = append(env, "GOOGLE_APPLICATION_CREDENTIALS="+saFile.Name())
		if v := creds["project_id"]; v != "" {
			args = append(args, "--project-ids", v)
		}

	default:
		return nil, "", fmt.Errorf("prowler: unsupported provider %q", provider)
	}

	logFn(fmt.Sprintf("prowler: starting %s audit — this may take several minutes…", strings.ToUpper(provider)))

	cmd := exec.CommandContext(ctx, prowlerPath, args...)
	cmd.Env = env

	stderrPipe, _ := cmd.StderrPipe()
	stdoutPipe, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, "", fmt.Errorf("prowler: failed to start: %w", err)
	}

	// Stream progress output to the job log.
	streamLines := func(pipe *bufio.Scanner) {
		for pipe.Scan() {
			line := strings.TrimSpace(pipe.Text())
			if line == "" || strings.Contains(line, "****") {
				continue
			}
			logFn("prowler: " + line)
		}
	}
	if stderrPipe != nil {
		go streamLines(bufio.NewScanner(stderrPipe))
	}
	if stdoutPipe != nil {
		go streamLines(bufio.NewScanner(stdoutPipe))
	}

	waitErr := cmd.Wait()
	if cleanup != nil {
		cleanup()
	}

	// Exit code 3 means prowler found FAIL results — perfectly normal.
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); !ok || exitErr.ExitCode() != 3 {
			return nil, "", fmt.Errorf("prowler: %w", waitErr)
		}
	}

	// Parse output JSON files from outDir.
	entries, _ := os.ReadDir(outDir)
	var findings []models.CloudFinding
	accountID := ""

	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			continue
		}

		// Prowler v4 writes a JSON array; older/edge builds use JSON Lines.
		var pfList []prowlerFinding
		if err := json.Unmarshal(raw, &pfList); err != nil {
			// Try JSON Lines.
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var pf prowlerFinding
				if json.Unmarshal([]byte(line), &pf) == nil {
					pfList = append(pfList, pf)
				}
			}
		}

		for _, pf := range pfList {
			if pf.Status != "FAIL" {
				continue
			}
			if accountID == "" && pf.Cloud.Account.UID != "" {
				accountID = pf.Cloud.Account.UID
			}

			sev := strings.ToLower(pf.Severity)
			if sev == "informational" {
				sev = "info"
			}

			resource := ""
			if len(pf.Resources) > 0 {
				resource = pf.Resources[0].Name
				if resource == "" {
					resource = pf.Resources[0].UID
				}
			}

			service := pf.Cloud.Service.Name
			if service == "" && len(pf.Resources) > 0 {
				service = pf.Resources[0].Group.Name
			}

			findings = append(findings, models.CloudFinding{
				Provider:    provider,
				Service:     service,
				Resource:    resource,
				Check:       pf.FindingInfo.Title,
				Detail:      pf.FindingInfo.Desc,
				Severity:    sev,
				Remediation: pf.Remediation.Desc,
			})
		}
	}

	logFn(fmt.Sprintf("prowler: %d FAIL findings", len(findings)))
	return findings, accountID, nil
}
