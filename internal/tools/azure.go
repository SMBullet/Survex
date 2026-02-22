package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// AzureCreds holds the service principal credentials needed to authenticate
// against the Azure Resource Manager REST API.
type AzureCreds struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
}

// RunAzureReview authenticates with Azure using client_credentials OAuth2 flow
// and runs a set of configuration-review checks across Storage, App Services,
// SQL, Key Vault, and Network Security Groups.
func RunAzureReview(ctx context.Context, creds AzureCreds, logFn func(string)) ([]models.CloudFinding, error) {
	if creds.TenantID == "" || creds.ClientID == "" || creds.ClientSecret == "" || creds.SubscriptionID == "" {
		return nil, fmt.Errorf("azure credentials incomplete: tenant_id, client_id, client_secret, and subscription_id are required")
	}

	logFn("authenticating with Azure…")
	token, err := azureGetToken(ctx, creds.TenantID, creds.ClientID, creds.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("azure authentication failed: %w", err)
	}
	logFn("authenticated — running checks…")

	client := &http.Client{Timeout: 30 * time.Second}
	sub := creds.SubscriptionID
	var findings []models.CloudFinding

	logFn("checking Storage accounts…")
	f, err := azureCheckStorage(ctx, client, token, sub)
	if err != nil {
		logFn("storage check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking App Services…")
	f, err = azureCheckAppServices(ctx, client, token, sub)
	if err != nil {
		logFn("app services check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking SQL Servers…")
	f, err = azureCheckSQL(ctx, client, token, sub)
	if err != nil {
		logFn("sql check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking Key Vaults…")
	f, err = azureCheckKeyVaults(ctx, client, token, sub)
	if err != nil {
		logFn("key vault check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking Network Security Groups…")
	f, err = azureCheckNSGs(ctx, client, token, sub)
	if err != nil {
		logFn("nsg check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn(fmt.Sprintf("done — %d findings", len(findings)))
	return findings, nil
}

// ── Authentication ─────────────────────────────────────────────────────────────

// azureGetToken fetches a Bearer token via the client_credentials OAuth2 grant.
func azureGetToken(ctx context.Context, tenantID, clientID, clientSecret string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("scope", "https://management.azure.com/.default")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	if tok.Error != "" {
		return "", fmt.Errorf("%s: %s", tok.Error, tok.ErrorDesc)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}
	return tok.AccessToken, nil
}

// azureGET is a convenience wrapper for ARM REST API GET calls.
func azureGET(ctx context.Context, client *http.Client, token, urlStr string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, azureTruncate(string(body), 200))
	}
	return body, nil
}

// ── Storage ───────────────────────────────────────────────────────────────────

func azureCheckStorage(ctx context.Context, client *http.Client, token, sub string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
		sub,
	)
	body, err := azureGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				AllowBlobPublicAccess bool   `json:"allowBlobPublicAccess"`
				EnableHTTPSTrafficOnly bool  `json:"supportsHttpsTrafficOnly"`
				MinimumTLSVersion     string `json:"minimumTlsVersion"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse storage accounts: %w", err)
	}

	var findings []models.CloudFinding
	for _, acct := range resp.Value {
		name := acct.Name
		if acct.Properties.AllowBlobPublicAccess {
			findings = append(findings, models.CloudFinding{
				Provider:    "azure",
				Service:     "Storage",
				Resource:    name,
				Check:       "Public blob access enabled",
				Detail:      "allowBlobPublicAccess is true — blobs in public containers are readable by anyone",
				Severity:    "high",
				Remediation: "Disable public blob access: set allowBlobPublicAccess=false on the storage account",
			})
		}
		if !acct.Properties.EnableHTTPSTrafficOnly {
			findings = append(findings, models.CloudFinding{
				Provider:    "azure",
				Service:     "Storage",
				Resource:    name,
				Check:       "HTTP traffic not restricted",
				Detail:      "supportsHttpsTrafficOnly is false — data can be transferred over unencrypted HTTP",
				Severity:    "high",
				Remediation: "Enable HTTPS-only: set supportsHttpsTrafficOnly=true",
			})
		}
		minTLS := acct.Properties.MinimumTLSVersion
		if minTLS == "" || minTLS == "TLS1_0" || minTLS == "TLS1_1" {
			findings = append(findings, models.CloudFinding{
				Provider:    "azure",
				Service:     "Storage",
				Resource:    name,
				Check:       "Minimum TLS version below 1.2",
				Detail:      fmt.Sprintf("minimumTlsVersion=%q — older TLS versions have known vulnerabilities", minTLS),
				Severity:    "medium",
				Remediation: "Set minimumTlsVersion=TLS1_2 on the storage account",
			})
		}
	}
	return findings, nil
}

// ── App Services ──────────────────────────────────────────────────────────────

func azureCheckAppServices(ctx context.Context, client *http.Client, token, sub string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Web/sites?api-version=2022-03-01",
		sub,
	)
	body, err := azureGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				HTTPSOnly bool `json:"httpsOnly"`
				SiteConfig struct {
					MinTLSVersion string `json:"minTlsVersion"`
				} `json:"siteConfig"`
			} `json:"properties"`
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse app services: %w", err)
	}

	var findings []models.CloudFinding
	for _, site := range resp.Value {
		name := site.Name
		if !site.Properties.HTTPSOnly {
			findings = append(findings, models.CloudFinding{
				Provider:    "azure",
				Service:     "App Services",
				Resource:    name,
				Check:       "HTTPS-only not enforced",
				Detail:      "httpsOnly is false — the app accepts plain HTTP requests",
				Severity:    "high",
				Remediation: "Enable httpsOnly=true on the App Service",
			})
		}
		minTLS := site.Properties.SiteConfig.MinTLSVersion
		if minTLS == "" || minTLS == "1.0" || minTLS == "1.1" {
			findings = append(findings, models.CloudFinding{
				Provider:    "azure",
				Service:     "App Services",
				Resource:    name,
				Check:       "Minimum TLS version below 1.2",
				Detail:      fmt.Sprintf("minTlsVersion=%q", minTLS),
				Severity:    "medium",
				Remediation: "Set minTlsVersion=1.2 in the App Service site config",
			})
		}

		// Check auth settings via nested API
		authBody, err := azureGET(ctx, client, token,
			fmt.Sprintf("https://management.azure.com%s/config/authsettingsV2?api-version=2022-03-01", site.ID))
		if err == nil {
			var auth struct {
				Properties struct {
					Platform struct {
						Enabled bool `json:"enabled"`
					} `json:"platform"`
				} `json:"properties"`
			}
			if json.Unmarshal(authBody, &auth) == nil && !auth.Properties.Platform.Enabled {
				findings = append(findings, models.CloudFinding{
					Provider:    "azure",
					Service:     "App Services",
					Resource:    name,
					Check:       "Authentication not configured",
					Detail:      "App Service has no built-in authentication/authorization provider enabled",
					Severity:    "medium",
					Remediation: "Enable App Service Authentication (EasyAuth) or implement auth at the application layer",
				})
			}
		}
	}
	return findings, nil
}

// ── SQL Servers ───────────────────────────────────────────────────────────────

func azureCheckSQL(ctx context.Context, client *http.Client, token, sub string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview",
		sub,
	)
	body, err := azureGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Value []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse sql servers: %w", err)
	}

	var findings []models.CloudFinding
	for _, srv := range resp.Value {
		name := srv.Name

		// Check firewall rules
		fwBody, err := azureGET(ctx, client, token,
			fmt.Sprintf("https://management.azure.com%s/firewallRules?api-version=2022-05-01-preview", srv.ID))
		if err == nil {
			var fw struct {
				Value []struct {
					Name       string `json:"name"`
					Properties struct {
						StartIPAddress string `json:"startIpAddress"`
						EndIPAddress   string `json:"endIpAddress"`
					} `json:"properties"`
				} `json:"value"`
			}
			if json.Unmarshal(fwBody, &fw) == nil {
				for _, rule := range fw.Value {
					start := rule.Properties.StartIPAddress
					end := rule.Properties.EndIPAddress
					if start == "0.0.0.0" && end == "0.0.0.0" {
						// Azure "Allow all Azure services" rule
						continue
					}
					if start == "0.0.0.0" || start == "0.0.0.0" && end == "255.255.255.255" {
						findings = append(findings, models.CloudFinding{
							Provider:    "azure",
							Service:     "SQL",
							Resource:    name,
							Check:       "SQL firewall allows access from any IP",
							Detail:      fmt.Sprintf("Firewall rule %q: %s–%s", rule.Name, start, end),
							Severity:    "critical",
							Remediation: "Restrict SQL Server firewall rules to known IP ranges; avoid 0.0.0.0/0 rules",
						})
					}
				}
			}
		}

		// Check auditing settings
		auditBody, err := azureGET(ctx, client, token,
			fmt.Sprintf("https://management.azure.com%s/auditingSettings/default?api-version=2022-05-01-preview", srv.ID))
		if err == nil {
			var audit struct {
				Properties struct {
					State string `json:"state"`
				} `json:"properties"`
			}
			if json.Unmarshal(auditBody, &audit) == nil && audit.Properties.State != "Enabled" {
				findings = append(findings, models.CloudFinding{
					Provider:    "azure",
					Service:     "SQL",
					Resource:    name,
					Check:       "SQL auditing disabled",
					Detail:      "Auditing is not enabled on the SQL Server — access and query logs are not retained",
					Severity:    "medium",
					Remediation: "Enable SQL Server auditing and configure a retention period of at least 90 days",
				})
			}
		}
	}
	return findings, nil
}

// ── Key Vaults ────────────────────────────────────────────────────────────────

func azureCheckKeyVaults(ctx context.Context, client *http.Client, token, sub string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01",
		sub,
	)
	body, err := azureGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				EnableSoftDelete      *bool `json:"enableSoftDelete"`
				EnablePurgeProtection *bool `json:"enablePurgeProtection"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse key vaults: %w", err)
	}

	var findings []models.CloudFinding
	for _, kv := range resp.Value {
		name := kv.Name
		if kv.Properties.EnableSoftDelete == nil || !*kv.Properties.EnableSoftDelete {
			findings = append(findings, models.CloudFinding{
				Provider:    "azure",
				Service:     "Key Vault",
				Resource:    name,
				Check:       "Soft delete disabled",
				Detail:      "Deleted keys, secrets, and certificates cannot be recovered — accidental or malicious deletion is permanent",
				Severity:    "high",
				Remediation: "Enable soft delete on the Key Vault (enableSoftDelete=true)",
			})
		}
		if kv.Properties.EnablePurgeProtection == nil || !*kv.Properties.EnablePurgeProtection {
			findings = append(findings, models.CloudFinding{
				Provider:    "azure",
				Service:     "Key Vault",
				Resource:    name,
				Check:       "Purge protection disabled",
				Detail:      "Secrets in soft-delete state can be immediately purged, bypassing the retention period",
				Severity:    "high",
				Remediation: "Enable purge protection on the Key Vault (enablePurgeProtection=true)",
			})
		}
	}
	return findings, nil
}

// ── Network Security Groups ───────────────────────────────────────────────────

func azureCheckNSGs(ctx context.Context, client *http.Client, token, sub string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01",
		sub,
	)
	body, err := azureGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Value []struct {
			Name       string `json:"name"`
			Properties struct {
				SecurityRules []struct {
					Name       string `json:"name"`
					Properties struct {
						Direction              string `json:"direction"`
						Access                 string `json:"access"`
						Protocol               string `json:"protocol"`
						SourceAddressPrefix    string `json:"sourceAddressPrefix"`
						DestinationPortRange   string `json:"destinationPortRange"`
						DestinationPortRanges  []string `json:"destinationPortRanges"`
					} `json:"properties"`
				} `json:"securityRules"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse NSGs: %w", err)
	}

	var findings []models.CloudFinding
	for _, nsg := range resp.Value {
		name := nsg.Name
		for _, rule := range nsg.Properties.SecurityRules {
			p := rule.Properties
			if p.Direction != "Inbound" || p.Access != "Allow" {
				continue
			}
			src := p.SourceAddressPrefix
			if src != "*" && src != "0.0.0.0/0" && src != "Internet" && src != "Any" {
				continue
			}
			// Collect destination ports
			ports := p.DestinationPortRanges
			if p.DestinationPortRange != "" {
				ports = append(ports, p.DestinationPortRange)
			}
			for _, port := range ports {
				switch port {
				case "22":
					findings = append(findings, models.CloudFinding{
						Provider:    "azure",
						Service:     "NSG",
						Resource:    name,
						Check:       "NSG allows SSH from any IP",
						Detail:      fmt.Sprintf("Rule %q allows inbound TCP port 22 from %s", rule.Name, src),
						Severity:    "critical",
						Remediation: "Restrict SSH access to specific IP ranges or use Azure Bastion",
					})
				case "3389":
					findings = append(findings, models.CloudFinding{
						Provider:    "azure",
						Service:     "NSG",
						Resource:    name,
						Check:       "NSG allows RDP from any IP",
						Detail:      fmt.Sprintf("Rule %q allows inbound TCP port 3389 from %s", rule.Name, src),
						Severity:    "critical",
						Remediation: "Restrict RDP access to specific IP ranges or use Azure Bastion",
					})
				case "*":
					findings = append(findings, models.CloudFinding{
						Provider:    "azure",
						Service:     "NSG",
						Resource:    name,
						Check:       "NSG allows all inbound traffic from any IP",
						Detail:      fmt.Sprintf("Rule %q allows all inbound ports from %s", rule.Name, src),
						Severity:    "high",
						Remediation: "Replace the catch-all allow rule with specific rules for required ports and sources",
					})
				}
			}
		}
	}
	return findings, nil
}

// azureTruncate shortens a string to at most n runes for error messages.
func azureTruncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
