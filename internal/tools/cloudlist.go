package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/SMBullet/Survex/internal/models"
	"gopkg.in/yaml.v3"
)

// cloudlistProviderCfg matches the YAML schema that cloudlist expects.
type cloudlistProviderCfg struct {
	Provider           string `yaml:"provider"`
	ID                 string `yaml:"id"`
	// AWS
	AWSAccessKey       string `yaml:"aws_access_key,omitempty"`
	AWSSecretKey       string `yaml:"aws_secret_key,omitempty"`
	AWSSessionToken    string `yaml:"aws_session_token,omitempty"`
	AssumeRoleName     string `yaml:"assume_role_name,omitempty"`
	AccountID          string `yaml:"account_id,omitempty"`
	// Azure
	ClientID           string `yaml:"client_id,omitempty"`
	ClientSecret       string `yaml:"client_secret,omitempty"`
	TenantID           string `yaml:"tenant_id,omitempty"`
	SubscriptionID     string `yaml:"subscription_id,omitempty"`
	// GCP
	ServiceAccountPath string `yaml:"service_account_path,omitempty"`
}

// RunCloudlist enumerates cloud assets using projectdiscovery/cloudlist.
// Returns discovered assets or an error if cloudlist is not installed.
func RunCloudlist(ctx context.Context, provider string, creds map[string]string, logFn func(string)) ([]models.CloudAsset, error) {
	cloudlistPath, err := FindBinary("cloudlist", "go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest")
	if err != nil {
		return nil, fmt.Errorf("cloudlist not found; install with: go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest")
	}

	cfg := cloudlistProviderCfg{Provider: provider, ID: "survex"}

	var saFile *os.File
	switch provider {
	case "aws":
		cfg.AWSAccessKey = creds["access_key_id"]
		cfg.AWSSecretKey = creds["secret_access_key"]
		if v := creds["session_token"]; v != "" {
			cfg.AWSSessionToken = v
		}
		if v := creds["role_arn"]; v != "" {
			cfg.AssumeRoleName = v
		}
	case "azure":
		cfg.ClientID = creds["client_id"]
		cfg.ClientSecret = creds["client_secret"]
		cfg.TenantID = creds["tenant_id"]
		cfg.SubscriptionID = creds["subscription_id"]
	case "gcp":
		saFile, err = os.CreateTemp("", "cloudlist-sa-*.json")
		if err != nil {
			return nil, fmt.Errorf("cloudlist: temp file: %w", err)
		}
		if _, err = saFile.WriteString(creds["service_account_json"]); err != nil {
			saFile.Close()
			os.Remove(saFile.Name())
			return nil, err
		}
		saFile.Close()
		defer os.Remove(saFile.Name())
		cfg.ServiceAccountPath = saFile.Name()
	default:
		return nil, fmt.Errorf("cloudlist: unsupported provider %q", provider)
	}

	// Write provider YAML config to temp file.
	cfgFile, err := os.CreateTemp("", "cloudlist-cfg-*.yaml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(cfgFile.Name())

	data, err := yaml.Marshal([]cloudlistProviderCfg{cfg})
	if err != nil {
		cfgFile.Close()
		return nil, err
	}
	if _, err = cfgFile.Write(data); err != nil {
		cfgFile.Close()
		return nil, err
	}
	cfgFile.Close()

	logFn(fmt.Sprintf("cloudlist: enumerating %s assets…", strings.ToUpper(provider)))

	cmd := exec.CommandContext(ctx, cloudlistPath,
		"-config", cfgFile.Name(),
		"-provider", provider,
		"-json",
		"-silent",
	)

	pr, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cloudlist: %w", err)
	}

	if stderrPipe != nil {
		go func() {
			sc := bufio.NewScanner(stderrPipe)
			for sc.Scan() {
				if line := strings.TrimSpace(sc.Text()); line != "" {
					logFn("cloudlist: " + line)
				}
			}
		}()
	}

	var assets []models.CloudAsset
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var raw struct {
			IP      string `json:"ip"`
			Host    string `json:"host"`
			Public  bool   `json:"public"`
			Private bool   `json:"private"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err == nil {
			if raw.Host != "" || raw.IP != "" {
				assets = append(assets, models.CloudAsset{
					Provider: provider,
					IP:       raw.IP,
					Host:     raw.Host,
					Public:   raw.Public,
				})
			}
		} else {
			// Plain-text fallback (no -json flag response).
			if !strings.HasPrefix(line, "[") {
				assets = append(assets, models.CloudAsset{
					Provider: provider,
					Host:     line,
					Public:   true,
				})
			}
		}
	}

	_ = cmd.Wait() // non-zero exit is fine if assets were returned
	logFn(fmt.Sprintf("cloudlist: discovered %d assets", len(assets)))
	return assets, nil
}
