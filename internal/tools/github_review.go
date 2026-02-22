package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

// GitHubReviewCreds holds credentials and targeting options for a GitHub config review.
type GitHubReviewCreds struct {
	Token string // Personal access token (scopes: read:org, repo)
	Org   string // Organization login (optional — scans all accessible orgs if empty)
	Repos string // Comma-separated repo names to limit review (optional)
}

// RunGitHubReview checks an org's security posture: 2FA enforcement, SSO, branch
// protection rules, secret scanning, Dependabot, webhook security, and Actions perms.
func RunGitHubReview(ctx context.Context, creds GitHubReviewCreds, logFn func(string)) ([]models.CloudFinding, error) {
	if creds.Token == "" {
		return nil, fmt.Errorf("a GitHub personal access token is required")
	}

	client := &http.Client{Timeout: 20 * time.Second}

	var findings []models.CloudFinding
	var orgs []string

	if creds.Org != "" {
		orgs = []string{creds.Org}
	} else {
		logFn("fetching accessible organizations…")
		var err error
		orgs, err = ghListOrgs(ctx, client, creds.Token)
		if err != nil {
			return nil, fmt.Errorf("list organizations: %w", err)
		}
	}

	if len(orgs) == 0 {
		return nil, fmt.Errorf("no organizations found for this token")
	}

	for _, org := range orgs {
		logFn(fmt.Sprintf("checking organization: %s", org))

		f, err := ghCheckOrg(ctx, client, creds.Token, org)
		if err != nil {
			logFn(fmt.Sprintf("org check error for %s: %v", org, err))
		}
		findings = append(findings, f...)

		logFn(fmt.Sprintf("checking webhooks for: %s", org))
		f, err = ghCheckOrgWebhooks(ctx, client, creds.Token, org)
		if err != nil {
			logFn(fmt.Sprintf("webhook check error for %s: %v", org, err))
		}
		findings = append(findings, f...)

		// Determine which repos to review
		var repoNames []string
		if creds.Repos != "" {
			for _, r := range strings.Split(creds.Repos, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					repoNames = append(repoNames, r)
				}
			}
		} else {
			logFn(fmt.Sprintf("listing repos for: %s", org))
			var err error
			repoNames, err = ghListRepos(ctx, client, creds.Token, org)
			if err != nil {
				logFn(fmt.Sprintf("repo list error for %s: %v", org, err))
				continue
			}
		}

		for _, repoName := range repoNames {
			fullName := org + "/" + repoName
			logFn(fmt.Sprintf("checking repo: %s", fullName))

			f, err := ghCheckRepo(ctx, client, creds.Token, org, repoName)
			if err != nil {
				logFn(fmt.Sprintf("repo check error for %s: %v", fullName, err))
				continue
			}
			findings = append(findings, f...)
		}
	}

	logFn(fmt.Sprintf("done — %d findings", len(findings)))
	return findings, nil
}

// ── GitHub API helpers ────────────────────────────────────────────────────────

func ghGET(ctx context.Context, client *http.Client, token, path string) ([]byte, int, error) {
	apiURL := "https://api.github.com" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "Survex/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// ── Organizations ─────────────────────────────────────────────────────────────

func ghListOrgs(ctx context.Context, client *http.Client, token string) ([]string, error) {
	body, status, err := ghGET(ctx, client, token, "/user/orgs?per_page=100")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d listing orgs", status)
	}
	var orgs []struct {
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &orgs); err != nil {
		return nil, err
	}
	var names []string
	for _, o := range orgs {
		names = append(names, o.Login)
	}
	return names, nil
}

func ghCheckOrg(ctx context.Context, client *http.Client, token, org string) ([]models.CloudFinding, error) {
	body, status, err := ghGET(ctx, client, token, "/orgs/"+org)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, fmt.Errorf("organization %q not found (check token scopes: read:org required)", org)
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d fetching org %s", status, org)
	}

	var o struct {
		Login              string `json:"login"`
		TwoFactorRequirementEnabled bool `json:"two_factor_requirement_enabled"`
		DefaultRepositoryPermission string `json:"default_repository_permission"`
		MembersCanCreateRepositories bool `json:"members_can_create_repositories"`
		MembersCanForkPrivateRepositories bool `json:"members_can_fork_private_repositories"`
	}
	if err := json.Unmarshal(body, &o); err != nil {
		return nil, err
	}

	var findings []models.CloudFinding

	if !o.TwoFactorRequirementEnabled {
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Organization",
			Resource:    org,
			Check:       "2FA not required for organization members",
			Detail:      "two_factor_requirement_enabled is false — members can access org resources without MFA",
			Severity:    "high",
			Remediation: "Enable 2FA requirement in Organization → Settings → Authentication security",
		})
	}

	if o.DefaultRepositoryPermission == "write" || o.DefaultRepositoryPermission == "admin" {
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Organization",
			Resource:    org,
			Check:       "Default member permission is too permissive",
			Detail:      fmt.Sprintf("default_repository_permission=%q — all members can write to all repos by default", o.DefaultRepositoryPermission),
			Severity:    "medium",
			Remediation: "Set default_repository_permission to 'read' or 'none' and grant write access explicitly per team",
		})
	}

	if o.MembersCanForkPrivateRepositories {
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Organization",
			Resource:    org,
			Check:       "Members can fork private repositories",
			Detail:      "members_can_fork_private_repositories is true — private code can be copied outside the org",
			Severity:    "low",
			Remediation: "Disable forking of private repositories in org settings unless explicitly needed",
		})
	}

	// Check SAML SSO via GraphQL (best effort — 403 if not Enterprise)
	body2, status2, _ := ghGET(ctx, client, token, "/orgs/"+org+"/credential-authorizations")
	if status2 == 200 {
		// SAML is configured if this endpoint returns data (it's only available with SAML/SSO)
		_ = body2 // endpoint accessible = SSO enabled
	} else {
		// If 403 or 404, SAML SSO likely not enabled
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Organization",
			Resource:    org,
			Check:       "SAML SSO not enforced",
			Detail:      "SAML/SSO credential authorizations not available — SSO may not be enforced for this org",
			Severity:    "medium",
			Remediation: "Enable and enforce SAML SSO in Organization → Settings → Authentication security (requires GitHub Enterprise)",
		})
	}

	return findings, nil
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

func ghCheckOrgWebhooks(ctx context.Context, client *http.Client, token, org string) ([]models.CloudFinding, error) {
	body, status, err := ghGET(ctx, client, token, "/orgs/"+org+"/hooks?per_page=100")
	if err != nil {
		return nil, err
	}
	if status == 403 || status == 404 {
		return nil, nil // insufficient perms — skip
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d listing org webhooks", status)
	}

	var hooks []struct {
		Name   string `json:"name"`
		Config struct {
			URL         string `json:"url"`
			ContentType string `json:"content_type"`
			Secret      string `json:"secret"`
			InsecureSSL string `json:"insecure_ssl"`
		} `json:"config"`
		Active bool `json:"active"`
	}
	if err := json.Unmarshal(body, &hooks); err != nil {
		return nil, err
	}

	var findings []models.CloudFinding
	for _, hook := range hooks {
		if !hook.Active {
			continue
		}
		hookURL := hook.Config.URL
		if strings.HasPrefix(hookURL, "http://") {
			findings = append(findings, models.CloudFinding{
				Provider:    "github",
				Service:     "Webhook",
				Resource:    org,
				Check:       "Webhook uses HTTP instead of HTTPS",
				Detail:      fmt.Sprintf("Webhook URL %q uses plain HTTP — payloads are transmitted unencrypted", hookURL),
				Severity:    "high",
				Remediation: "Update the webhook URL to use HTTPS",
			})
		}
		if hook.Config.Secret == "" {
			findings = append(findings, models.CloudFinding{
				Provider:    "github",
				Service:     "Webhook",
				Resource:    org,
				Check:       "Webhook has no secret configured",
				Detail:      fmt.Sprintf("Webhook to %q has no HMAC secret — payloads cannot be verified", hookURL),
				Severity:    "high",
				Remediation: "Add a webhook secret and verify the X-Hub-Signature-256 header in your receiver",
			})
		}
	}
	return findings, nil
}

// ── Repositories ──────────────────────────────────────────────────────────────

func ghListRepos(ctx context.Context, client *http.Client, token, org string) ([]string, error) {
	body, status, err := ghGET(ctx, client, token, "/orgs/"+org+"/repos?per_page=100&type=all&sort=updated")
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d listing repos", status)
	}
	var repos []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &repos); err != nil {
		return nil, err
	}
	var names []string
	for _, r := range repos {
		names = append(names, r.Name)
	}
	return names, nil
}

func ghCheckRepo(ctx context.Context, client *http.Client, token, org, repo string) ([]models.CloudFinding, error) {
	// Fetch repo details
	body, status, err := ghGET(ctx, client, token, "/repos/"+org+"/"+repo)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d fetching repo %s/%s", status, org, repo)
	}

	var repoInfo struct {
		DefaultBranch string `json:"default_branch"`
		SecurityAndAnalysis struct {
			SecretScanning struct {
				Status string `json:"status"`
			} `json:"secret_scanning"`
			DependabotAlerts struct {
				Status string `json:"status"`
			} `json:"dependabot_alerts_enabled"`
		} `json:"security_and_analysis"`
	}
	_ = json.Unmarshal(body, &repoInfo)

	var findings []models.CloudFinding
	fullName := org + "/" + repo

	// Check default branch protection
	if repoInfo.DefaultBranch != "" {
		f := ghCheckBranchProtection(ctx, client, token, org, repo, repoInfo.DefaultBranch, fullName)
		findings = append(findings, f...)
	}

	// Secret scanning
	if repoInfo.SecurityAndAnalysis.SecretScanning.Status == "disabled" {
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Repository",
			Resource:    fullName,
			Check:       "Secret scanning disabled",
			Detail:      "GitHub secret scanning is not enabled — committed secrets won't be automatically detected",
			Severity:    "high",
			Remediation: "Enable secret scanning in repository Settings → Security → Code security",
		})
	}

	// Dependabot
	if repoInfo.SecurityAndAnalysis.DependabotAlerts.Status == "disabled" {
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Repository",
			Resource:    fullName,
			Check:       "Dependabot alerts disabled",
			Detail:      "Dependabot is not monitoring this repo for vulnerable dependencies",
			Severity:    "medium",
			Remediation: "Enable Dependabot alerts in repository Settings → Security → Dependabot",
		})
	}

	// Check Actions default permissions
	actBody, actStatus, _ := ghGET(ctx, client, token, "/repos/"+org+"/"+repo+"/actions/permissions")
	if actStatus == 200 {
		var actPerms struct {
			DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
		}
		if json.Unmarshal(actBody, &actPerms) == nil && actPerms.DefaultWorkflowPermissions == "write" {
			findings = append(findings, models.CloudFinding{
				Provider:    "github",
				Service:     "Repository",
				Resource:    fullName,
				Check:       "GitHub Actions default permission is write",
				Detail:      "Workflows have write access to repository contents by default — a compromised action can modify code or push commits",
				Severity:    "medium",
				Remediation: "Set default workflow permissions to 'read' and grant write only where explicitly needed via 'permissions:' in workflows",
			})
		}
	}

	// Repo webhooks
	whBody, whStatus, _ := ghGET(ctx, client, token, "/repos/"+org+"/"+repo+"/hooks?per_page=100")
	if whStatus == 200 {
		var hooks []struct {
			Config struct {
				URL    string `json:"url"`
				Secret string `json:"secret"`
			} `json:"config"`
			Active bool `json:"active"`
		}
		if json.Unmarshal(whBody, &hooks) == nil {
			for _, hook := range hooks {
				if !hook.Active {
					continue
				}
				if strings.HasPrefix(hook.Config.URL, "http://") {
					findings = append(findings, models.CloudFinding{
						Provider:    "github",
						Service:     "Webhook",
						Resource:    fullName,
						Check:       "Webhook uses HTTP instead of HTTPS",
						Detail:      fmt.Sprintf("Webhook URL %q uses plain HTTP", hook.Config.URL),
						Severity:    "high",
						Remediation: "Update the webhook URL to use HTTPS",
					})
				}
				if hook.Config.Secret == "" {
					findings = append(findings, models.CloudFinding{
						Provider:    "github",
						Service:     "Webhook",
						Resource:    fullName,
						Check:       "Webhook has no secret configured",
						Detail:      fmt.Sprintf("Webhook to %q has no HMAC secret", hook.Config.URL),
						Severity:    "high",
						Remediation: "Add a webhook secret and verify X-Hub-Signature-256 in your receiver",
					})
				}
			}
		}
	}

	return findings, nil
}

func ghCheckBranchProtection(ctx context.Context, client *http.Client, token, org, repo, branch, fullName string) []models.CloudFinding {
	body, status, err := ghGET(ctx, client, token,
		"/repos/"+org+"/"+repo+"/branches/"+branch+"/protection")
	if err != nil || status == 404 {
		return []models.CloudFinding{{
			Provider:    "github",
			Service:     "Repository",
			Resource:    fullName,
			Check:       "Default branch has no protection rules",
			Detail:      fmt.Sprintf("Branch %q has no protection rules — anyone with push access can push directly", branch),
			Severity:    "high",
			Remediation: "Enable branch protection rules: require PR reviews, status checks, and disable force pushes",
		}}
	}
	if status != 200 {
		return nil
	}

	var bp struct {
		RequiredPullRequestReviews *struct {
			RequiredApprovingReviewCount int `json:"required_approving_review_count"`
		} `json:"required_pull_request_reviews"`
		AllowForcePushes struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_force_pushes"`
		AllowDeletions struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_deletions"`
	}
	if err := json.Unmarshal(body, &bp); err != nil {
		return nil
	}

	var findings []models.CloudFinding

	if bp.RequiredPullRequestReviews == nil || bp.RequiredPullRequestReviews.RequiredApprovingReviewCount == 0 {
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Repository",
			Resource:    fullName,
			Check:       "Branch has no required PR reviews",
			Detail:      fmt.Sprintf("Branch %q does not require any PR approvals before merging", branch),
			Severity:    "medium",
			Remediation: "Require at least 1 approving review before merging to the default branch",
		})
	}

	if bp.AllowForcePushes.Enabled {
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Repository",
			Resource:    fullName,
			Check:       "Branch allows force pushes",
			Detail:      fmt.Sprintf("Force pushes are allowed on branch %q — history can be rewritten", branch),
			Severity:    "high",
			Remediation: "Disable force pushes on the default branch in branch protection settings",
		})
	}

	if bp.AllowDeletions.Enabled {
		findings = append(findings, models.CloudFinding{
			Provider:    "github",
			Service:     "Repository",
			Resource:    fullName,
			Check:       "Branch can be deleted",
			Detail:      fmt.Sprintf("Branch %q can be deleted by users with push access", branch),
			Severity:    "high",
			Remediation: "Disable branch deletion on the default branch in branch protection settings",
		})
	}

	return findings
}
