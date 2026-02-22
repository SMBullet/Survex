package tools

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// GCPCreds holds the service account JSON and optional project override.
type GCPCreds struct {
	ServiceAccountJSON string // Full service account JSON key file contents
	ProjectID          string // Optional — auto-parsed from JSON if empty
}

// serviceAccountKey is the parsed structure of a GCP service account JSON key.
type serviceAccountKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// RunGCPReview authenticates using a service account JSON key (JWT → OAuth2 exchange)
// and runs configuration-review checks across GCS, Compute, BigQuery, Cloud SQL,
// Cloud Functions, and IAM.
func RunGCPReview(ctx context.Context, creds GCPCreds, logFn func(string)) ([]models.CloudFinding, string, error) {
	if creds.ServiceAccountJSON == "" {
		return nil, "", fmt.Errorf("service_account_json is required")
	}

	var sa serviceAccountKey
	if err := json.Unmarshal([]byte(creds.ServiceAccountJSON), &sa); err != nil {
		return nil, "", fmt.Errorf("parse service account JSON: %w", err)
	}
	if sa.Type != "service_account" {
		return nil, "", fmt.Errorf("expected type=service_account, got %q", sa.Type)
	}

	projectID := creds.ProjectID
	if projectID == "" {
		projectID = sa.ProjectID
	}
	if projectID == "" {
		return nil, "", fmt.Errorf("project_id could not be determined from credentials")
	}

	logFn("authenticating with GCP…")
	token, err := gcpGetToken(ctx, sa)
	if err != nil {
		return nil, "", fmt.Errorf("GCP authentication failed: %w", err)
	}
	logFn("authenticated — running checks…")

	client := &http.Client{Timeout: 30 * time.Second}
	var findings []models.CloudFinding

	logFn("checking GCS buckets…")
	f, err := gcpCheckGCS(ctx, client, token, projectID)
	if err != nil {
		logFn("GCS check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking Compute firewall rules…")
	f, err = gcpCheckFirewalls(ctx, client, token, projectID)
	if err != nil {
		logFn("firewall check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking Compute instances…")
	f, err = gcpCheckInstances(ctx, client, token, projectID)
	if err != nil {
		logFn("compute instances check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking BigQuery datasets…")
	f, err = gcpCheckBigQuery(ctx, client, token, projectID)
	if err != nil {
		logFn("BigQuery check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking Cloud SQL instances…")
	f, err = gcpCheckCloudSQL(ctx, client, token, projectID)
	if err != nil {
		logFn("Cloud SQL check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking Cloud Functions…")
	f, err = gcpCheckFunctions(ctx, client, token, projectID)
	if err != nil {
		logFn("Cloud Functions check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn("checking IAM policies…")
	f, err = gcpCheckIAM(ctx, client, token, projectID)
	if err != nil {
		logFn("IAM check error: " + err.Error())
	}
	findings = append(findings, f...)

	logFn(fmt.Sprintf("done — %d findings", len(findings)))
	return findings, projectID, nil
}

// ── Authentication ─────────────────────────────────────────────────────────────

// gcpGetToken builds and signs a JWT for the service account, then exchanges
// it for a short-lived OAuth2 access token.
func gcpGetToken(ctx context.Context, sa serviceAccountKey) (string, error) {
	now := time.Now().Unix()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(map[string]interface{}{
		"iss":   sa.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   sa.TokenURI,
		"iat":   now,
		"exp":   now + 3600,
	})
	payload := header + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Parse the RSA private key
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block from private key")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, 0, []byte(payload))
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	jwt := payload + "." + base64.RawURLEncoding.EncodeToString(sig)

	// Exchange JWT for access token
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jwt},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sa.TokenURI, strings.NewReader(form.Encode()))
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
		return "", fmt.Errorf("parse token: %w", err)
	}
	if tok.Error != "" {
		return "", fmt.Errorf("%s: %s", tok.Error, tok.ErrorDesc)
	}
	return tok.AccessToken, nil
}

// gcpGET performs an authenticated GET against a GCP REST API.
func gcpGET(ctx context.Context, client *http.Client, token, apiURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

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
		return nil, fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, string(body))
	}
	return body, nil
}

// ── GCS ───────────────────────────────────────────────────────────────────────

func gcpCheckGCS(ctx context.Context, client *http.Client, token, projectID string) ([]models.CloudFinding, error) {
	body, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://storage.googleapis.com/storage/v1/b?project=%s&maxResults=100", url.QueryEscape(projectID)))
	if err != nil {
		return nil, err
	}

	var resp struct {
		Items []struct {
			Name    string `json:"name"`
			IAMConfiguration struct {
				UniformBucketLevelAccess struct {
					Enabled bool `json:"enabled"`
				} `json:"uniformBucketLevelAccess"`
			} `json:"iamConfiguration"`
			Versioning struct {
				Enabled bool `json:"enabled"`
			} `json:"versioning"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse GCS buckets: %w", err)
	}

	var findings []models.CloudFinding
	for _, bucket := range resp.Items {
		name := bucket.Name

		// Check IAM policy for allUsers / allAuthenticatedUsers
		iamBody, err := gcpGET(ctx, client, token,
			fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/iam", url.PathEscape(name)))
		if err == nil {
			var iam struct {
				Bindings []struct {
					Role    string   `json:"role"`
					Members []string `json:"members"`
				} `json:"bindings"`
			}
			if json.Unmarshal(iamBody, &iam) == nil {
				for _, binding := range iam.Bindings {
					for _, member := range binding.Members {
						if member == "allUsers" || member == "allAuthenticatedUsers" {
							findings = append(findings, models.CloudFinding{
								Provider:    "gcp",
								Service:     "GCS",
								Resource:    name,
								Check:       "Bucket is publicly accessible",
								Detail:      fmt.Sprintf("IAM binding: %s has role %s", member, binding.Role),
								Severity:    "critical",
								Remediation: "Remove allUsers and allAuthenticatedUsers from the bucket IAM policy",
							})
						}
					}
				}
			}
		}

		if !bucket.IAMConfiguration.UniformBucketLevelAccess.Enabled {
			findings = append(findings, models.CloudFinding{
				Provider:    "gcp",
				Service:     "GCS",
				Resource:    name,
				Check:       "Uniform bucket-level access disabled",
				Detail:      "ACLs can be set on individual objects, allowing inconsistent access control",
				Severity:    "medium",
				Remediation: "Enable uniform bucket-level access to prevent per-object ACLs",
			})
		}

		if !bucket.Versioning.Enabled {
			findings = append(findings, models.CloudFinding{
				Provider:    "gcp",
				Service:     "GCS",
				Resource:    name,
				Check:       "Versioning disabled",
				Detail:      "Object versioning is off — deleted or overwritten objects cannot be recovered",
				Severity:    "info",
				Remediation: "Enable versioning on the bucket for data recovery",
			})
		}
	}
	return findings, nil
}

// ── Compute Firewall Rules ────────────────────────────────────────────────────

func gcpCheckFirewalls(ctx context.Context, client *http.Client, token, projectID string) ([]models.CloudFinding, error) {
	body, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls", url.PathEscape(projectID)))
	if err != nil {
		return nil, err
	}

	var resp struct {
		Items []struct {
			Name        string   `json:"name"`
			Direction   string   `json:"direction"`
			Disabled    bool     `json:"disabled"`
			SourceRanges []string `json:"sourceRanges"`
			Allowed     []struct {
				IPProtocol string   `json:"IPProtocol"`
				Ports      []string `json:"ports"`
			} `json:"allowed"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse firewall rules: %w", err)
	}

	var findings []models.CloudFinding
	for _, rule := range resp.Items {
		if rule.Disabled || rule.Direction != "INGRESS" {
			continue
		}
		hasOpenSource := false
		for _, src := range rule.SourceRanges {
			if src == "0.0.0.0/0" || src == "::/0" {
				hasOpenSource = true
				break
			}
		}
		if !hasOpenSource {
			continue
		}
		for _, allow := range rule.Allowed {
			proto := strings.ToLower(allow.IPProtocol)
			if proto == "all" {
				findings = append(findings, models.CloudFinding{
					Provider:    "gcp",
					Service:     "Compute",
					Resource:    rule.Name,
					Check:       "Firewall allows all traffic from any IP",
					Detail:      "Inbound rule allows all protocols from 0.0.0.0/0",
					Severity:    "high",
					Remediation: "Remove the catch-all firewall rule and replace with specific port/source restrictions",
				})
				continue
			}
			for _, port := range allow.Ports {
				switch port {
				case "22":
					findings = append(findings, models.CloudFinding{
						Provider:    "gcp",
						Service:     "Compute",
						Resource:    rule.Name,
						Check:       "Firewall allows SSH from any IP",
						Detail:      "Inbound TCP port 22 allowed from 0.0.0.0/0",
						Severity:    "critical",
						Remediation: "Restrict SSH access to known IP ranges or use IAP tunnel instead",
					})
				case "3389":
					findings = append(findings, models.CloudFinding{
						Provider:    "gcp",
						Service:     "Compute",
						Resource:    rule.Name,
						Check:       "Firewall allows RDP from any IP",
						Detail:      "Inbound TCP port 3389 allowed from 0.0.0.0/0",
						Severity:    "critical",
						Remediation: "Restrict RDP access to known IP ranges or use IAP tunnel instead",
					})
				}
			}
		}
	}
	return findings, nil
}

// ── Compute Instances ─────────────────────────────────────────────────────────

func gcpCheckInstances(ctx context.Context, client *http.Client, token, projectID string) ([]models.CloudFinding, error) {
	body, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances", url.PathEscape(projectID)))
	if err != nil {
		return nil, err
	}

	var resp struct {
		Items map[string]struct {
			Instances []struct {
				Name              string `json:"name"`
				NetworkInterfaces []struct {
					AccessConfigs []struct {
						NatIP string `json:"natIP"`
					} `json:"accessConfigs"`
				} `json:"networkInterfaces"`
				Metadata struct {
					Items []struct {
						Key   string `json:"key"`
						Value string `json:"value"`
					} `json:"items"`
				} `json:"metadata"`
			} `json:"instances"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse compute instances: %w", err)
	}

	var findings []models.CloudFinding
	// Check project-level metadata for block-project-ssh-keys
	projectMeta, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s", url.PathEscape(projectID)))
	projectSSHKeysEnabled := false
	if err == nil {
		var proj struct {
			CommonInstanceMetadata struct {
				Items []struct {
					Key   string `json:"key"`
					Value string `json:"value"`
				} `json:"items"`
			} `json:"commonInstanceMetadata"`
		}
		if json.Unmarshal(projectMeta, &proj) == nil {
			for _, item := range proj.CommonInstanceMetadata.Items {
				if item.Key == "ssh-keys" && item.Value != "" {
					projectSSHKeysEnabled = true
				}
			}
		}
	}
	if projectSSHKeysEnabled {
		findings = append(findings, models.CloudFinding{
			Provider:    "gcp",
			Service:     "Compute",
			Resource:    projectID,
			Check:       "Project-wide SSH keys enabled",
			Detail:      "Project-level SSH keys propagate to all instances, increasing lateral movement risk",
			Severity:    "medium",
			Remediation: "Use instance-level SSH keys and set block-project-ssh-keys=true on each instance",
		})
	}

	for _, zone := range resp.Items {
		for _, inst := range zone.Instances {
			name := inst.Name
			hasPublicIP := false
			for _, nic := range inst.NetworkInterfaces {
				for _, ac := range nic.AccessConfigs {
					if ac.NatIP != "" {
						hasPublicIP = true
					}
				}
			}

			// Check if OS Login is disabled on public instance
			osLoginEnabled := false
			for _, item := range inst.Metadata.Items {
				if item.Key == "enable-oslogin" && strings.EqualFold(item.Value, "true") {
					osLoginEnabled = true
				}
			}
			if hasPublicIP && !osLoginEnabled {
				findings = append(findings, models.CloudFinding{
					Provider:    "gcp",
					Service:     "Compute",
					Resource:    name,
					Check:       "Public instance without OS Login",
					Detail:      "Instance has a public IP but OS Login is not enabled — SSH key management falls to metadata",
					Severity:    "high",
					Remediation: "Enable OS Login (enable-oslogin=true) to centralize SSH access control via IAM",
				})
			}
		}
	}
	return findings, nil
}

// ── BigQuery ──────────────────────────────────────────────────────────────────

func gcpCheckBigQuery(ctx context.Context, client *http.Client, token, projectID string) ([]models.CloudFinding, error) {
	body, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://bigquery.googleapis.com/bigquery/v2/projects/%s/datasets", url.PathEscape(projectID)))
	if err != nil {
		return nil, err
	}

	var list struct {
		Datasets []struct {
			DatasetReference struct {
				DatasetID string `json:"datasetId"`
			} `json:"datasetReference"`
		} `json:"datasets"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse BQ datasets: %w", err)
	}

	var findings []models.CloudFinding
	for _, ds := range list.Datasets {
		dsID := ds.DatasetReference.DatasetID
		dsBody, err := gcpGET(ctx, client, token,
			fmt.Sprintf("https://bigquery.googleapis.com/bigquery/v2/projects/%s/datasets/%s",
				url.PathEscape(projectID), url.PathEscape(dsID)))
		if err != nil {
			continue
		}
		var dataset struct {
			Access []struct {
				Role        string `json:"role"`
				SpecialGroup string `json:"specialGroup"`
			} `json:"access"`
		}
		if err := json.Unmarshal(dsBody, &dataset); err != nil {
			continue
		}
		for _, entry := range dataset.Access {
			if entry.SpecialGroup == "allUsers" || entry.SpecialGroup == "allAuthenticatedUsers" {
				findings = append(findings, models.CloudFinding{
					Provider:    "gcp",
					Service:     "BigQuery",
					Resource:    dsID,
					Check:       "Dataset publicly accessible",
					Detail:      fmt.Sprintf("specialGroup=%s has role %s", entry.SpecialGroup, entry.Role),
					Severity:    "critical",
					Remediation: "Remove allUsers and allAuthenticatedUsers from BigQuery dataset access controls",
				})
			}
		}
	}
	return findings, nil
}

// ── Cloud SQL ─────────────────────────────────────────────────────────────────

func gcpCheckCloudSQL(ctx context.Context, client *http.Client, token, projectID string) ([]models.CloudFinding, error) {
	body, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://sqladmin.googleapis.com/sql/v1beta4/projects/%s/instances", url.PathEscape(projectID)))
	if err != nil {
		return nil, err
	}

	var resp struct {
		Items []struct {
			Name     string `json:"name"`
			Settings struct {
				IPConfiguration struct {
					AuthorizedNetworks []struct {
						Value string `json:"value"`
					} `json:"authorizedNetworks"`
					RequireSSL bool `json:"requireSsl"`
				} `json:"ipConfiguration"`
				BackupConfiguration struct {
					Enabled bool `json:"enabled"`
				} `json:"backupConfiguration"`
			} `json:"settings"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse Cloud SQL: %w", err)
	}

	var findings []models.CloudFinding
	for _, inst := range resp.Items {
		name := inst.Name
		ipcfg := inst.Settings.IPConfiguration

		for _, net := range ipcfg.AuthorizedNetworks {
			if net.Value == "0.0.0.0/0" {
				findings = append(findings, models.CloudFinding{
					Provider:    "gcp",
					Service:     "Cloud SQL",
					Resource:    name,
					Check:       "Authorized network allows 0.0.0.0/0",
					Detail:      "The Cloud SQL instance accepts connections from any IP address",
					Severity:    "critical",
					Remediation: "Remove 0.0.0.0/0 from authorized networks and restrict to known IPs",
				})
			}
		}

		if !ipcfg.RequireSSL {
			findings = append(findings, models.CloudFinding{
				Provider:    "gcp",
				Service:     "Cloud SQL",
				Resource:    name,
				Check:       "SSL not required",
				Detail:      "requireSsl is false — database connections can be made without encryption",
				Severity:    "high",
				Remediation: "Set requireSsl=true on the Cloud SQL instance",
			})
		}

		if !inst.Settings.BackupConfiguration.Enabled {
			findings = append(findings, models.CloudFinding{
				Provider:    "gcp",
				Service:     "Cloud SQL",
				Resource:    name,
				Check:       "Automated backups disabled",
				Detail:      "backupConfiguration.enabled is false — no automated backups are taken",
				Severity:    "medium",
				Remediation: "Enable automated backups on the Cloud SQL instance",
			})
		}
	}
	return findings, nil
}

// ── Cloud Functions ───────────────────────────────────────────────────────────

var gcpSecretEnvKeywords = []string{"SECRET", "KEY", "PASSWORD", "TOKEN", "PASSWD", "CREDENTIAL", "API_KEY"}

func gcpCheckFunctions(ctx context.Context, client *http.Client, token, projectID string) ([]models.CloudFinding, error) {
	body, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://cloudfunctions.googleapis.com/v1/projects/%s/locations/-/functions", url.PathEscape(projectID)))
	if err != nil {
		return nil, err
	}

	var resp struct {
		Functions []struct {
			Name        string `json:"name"`
			SourceUploadURL string `json:"sourceUploadUrl"`
			EnvironmentVariables map[string]string `json:"environmentVariables"`
		} `json:"functions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse Cloud Functions: %w", err)
	}

	var findings []models.CloudFinding
	for _, fn := range resp.Functions {
		// Extract short name from full resource path
		parts := strings.Split(fn.Name, "/")
		shortName := parts[len(parts)-1]

		for k, v := range fn.EnvironmentVariables {
			upper := strings.ToUpper(k)
			for _, keyword := range gcpSecretEnvKeywords {
				if strings.Contains(upper, keyword) && v != "" {
					findings = append(findings, models.CloudFinding{
						Provider:    "gcp",
						Service:     "Cloud Functions",
						Resource:    shortName,
						Check:       "Environment variable may contain secret",
						Detail:      fmt.Sprintf("Variable %q matches secret pattern (value redacted)", k),
						Severity:    "high",
						Remediation: "Use Secret Manager references instead of plain-text env vars for sensitive values",
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── IAM ───────────────────────────────────────────────────────────────────────

func gcpCheckIAM(ctx context.Context, client *http.Client, token, projectID string) ([]models.CloudFinding, error) {
	body, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:getIamPolicy", url.PathEscape(projectID)))
	if err != nil {
		return nil, err
	}

	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(body, &policy); err != nil {
		return nil, fmt.Errorf("parse IAM policy: %w", err)
	}

	// Highly privileged roles at project level
	dangerousRoles := map[string]bool{
		"roles/owner":  true,
		"roles/editor": true,
	}

	var findings []models.CloudFinding
	for _, binding := range policy.Bindings {
		if !dangerousRoles[binding.Role] {
			continue
		}
		for _, member := range binding.Members {
			if !strings.HasPrefix(member, "serviceAccount:") {
				continue
			}
			findings = append(findings, models.CloudFinding{
				Provider:    "gcp",
				Service:     "IAM",
				Resource:    member,
				Check:       "Service account has Owner/Editor at project level",
				Detail:      fmt.Sprintf("%s has role %s on project %s", member, binding.Role, projectID),
				Severity:    "high",
				Remediation: "Apply the principle of least privilege — grant service accounts only the specific roles they need",
			})
		}
	}

	// Check service account keys age
	saBody, err := gcpGET(ctx, client, token,
		fmt.Sprintf("https://iam.googleapis.com/v1/projects/%s/serviceAccounts", url.PathEscape(projectID)))
	if err == nil {
		var saResp struct {
			Accounts []struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"accounts"`
		}
		if json.Unmarshal(saBody, &saResp) == nil {
			for _, sa := range saResp.Accounts {
				keysBody, err := gcpGET(ctx, client, token,
					fmt.Sprintf("https://iam.googleapis.com/v1/%s/keys?keyTypes=USER_MANAGED", sa.Name))
				if err != nil {
					continue
				}
				var keys struct {
					Keys []struct {
						Name           string `json:"name"`
						ValidAfterTime string `json:"validAfterTime"`
					} `json:"keys"`
				}
				if err := json.Unmarshal(keysBody, &keys); err != nil {
					continue
				}
				for _, key := range keys.Keys {
					t, err := time.Parse(time.RFC3339, key.ValidAfterTime)
					if err != nil {
						continue
					}
					if time.Since(t) > 90*24*time.Hour {
						keyParts := strings.Split(key.Name, "/")
						keyID := keyParts[len(keyParts)-1]
						findings = append(findings, models.CloudFinding{
							Provider:    "gcp",
							Service:     "IAM",
							Resource:    sa.Email,
							Check:       "Service account key older than 90 days",
							Detail:      fmt.Sprintf("Key %s created %s ago", keyID, time.Since(t).Round(24*time.Hour)),
							Severity:    "medium",
							Remediation: "Rotate service account keys regularly (recommended: every 90 days)",
						})
					}
				}
			}
		}
	}

	return findings, nil
}
