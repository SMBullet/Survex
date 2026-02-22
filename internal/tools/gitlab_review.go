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

// GitLabReviewCreds holds credentials and targeting options for a GitLab config review.
type GitLabReviewCreds struct {
	Token string // Personal or Group access token (PRIVATE-TOKEN header)
	URL   string // GitLab instance URL (default: https://gitlab.com)
	Group string // Group path to scan (optional — scans all accessible groups if empty)
}

// RunGitLabReview checks a GitLab group/instance for security misconfigurations:
// 2FA enforcement, branch protection, merge approval requirements, webhook security,
// CI/CD variable exposure, and runner configuration.
func RunGitLabReview(ctx context.Context, creds GitLabReviewCreds, logFn func(string)) ([]models.CloudFinding, error) {
	if creds.Token == "" {
		return nil, fmt.Errorf("a GitLab access token is required")
	}

	baseURL := strings.TrimRight(creds.URL, "/")
	if baseURL == "" {
		baseURL = "https://gitlab.com"
	}

	client := &http.Client{Timeout: 20 * time.Second}

	var findings []models.CloudFinding
	var groupIDs []int
	var groupPaths []string

	if creds.Group != "" {
		logFn(fmt.Sprintf("fetching group: %s", creds.Group))
		g, err := glGetGroup(ctx, client, creds.Token, baseURL, creds.Group)
		if err != nil {
			return nil, fmt.Errorf("fetch group %s: %w", creds.Group, err)
		}
		groupIDs = []int{g.ID}
		groupPaths = []string{g.FullPath}
	} else {
		logFn("listing accessible groups…")
		groups, err := glListGroups(ctx, client, creds.Token, baseURL)
		if err != nil {
			return nil, fmt.Errorf("list groups: %w", err)
		}
		for _, g := range groups {
			groupIDs = append(groupIDs, g.ID)
			groupPaths = append(groupPaths, g.FullPath)
		}
	}

	for i, groupID := range groupIDs {
		groupPath := groupPaths[i]
		logFn(fmt.Sprintf("checking group: %s", groupPath))

		f, err := glCheckGroup(ctx, client, creds.Token, baseURL, groupID, groupPath)
		if err != nil {
			logFn(fmt.Sprintf("group check error for %s: %v", groupPath, err))
		}
		findings = append(findings, f...)

		logFn(fmt.Sprintf("listing projects in: %s", groupPath))
		projects, err := glListGroupProjects(ctx, client, creds.Token, baseURL, groupID)
		if err != nil {
			logFn(fmt.Sprintf("project list error for %s: %v", groupPath, err))
			continue
		}

		for _, proj := range projects {
			logFn(fmt.Sprintf("checking project: %s", proj.PathWithNamespace))
			f, err := glCheckProject(ctx, client, creds.Token, baseURL, proj)
			if err != nil {
				logFn(fmt.Sprintf("project check error for %s: %v", proj.PathWithNamespace, err))
				continue
			}
			findings = append(findings, f...)
		}
	}

	logFn(fmt.Sprintf("done — %d findings", len(findings)))
	return findings, nil
}

// ── GitLab API helpers ────────────────────────────────────────────────────────

func glGET(ctx context.Context, client *http.Client, token, apiURL string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Content-Type", "application/json")

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

// ── Groups ────────────────────────────────────────────────────────────────────

type glGroup struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
}

func glGetGroup(ctx context.Context, client *http.Client, token, baseURL, groupPath string) (glGroup, error) {
	apiURL := fmt.Sprintf("%s/api/v4/groups/%s", baseURL, url.PathEscape(groupPath))
	body, status, err := glGET(ctx, client, token, apiURL)
	if err != nil {
		return glGroup{}, err
	}
	if status == 404 {
		return glGroup{}, fmt.Errorf("group %q not found", groupPath)
	}
	if status != 200 {
		return glGroup{}, fmt.Errorf("HTTP %d fetching group", status)
	}
	var g glGroup
	err = json.Unmarshal(body, &g)
	return g, err
}

func glListGroups(ctx context.Context, client *http.Client, token, baseURL string) ([]glGroup, error) {
	apiURL := fmt.Sprintf("%s/api/v4/groups?per_page=100&top_level_only=true", baseURL)
	body, status, err := glGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d listing groups", status)
	}
	var groups []glGroup
	err = json.Unmarshal(body, &groups)
	return groups, err
}

func glCheckGroup(ctx context.Context, client *http.Client, token, baseURL string, groupID int, groupPath string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf("%s/api/v4/groups/%d", baseURL, groupID)
	body, status, err := glGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d fetching group %d", status, groupID)
	}

	var g struct {
		Name                            string `json:"name"`
		RequireTwoFactorAuthentication  bool   `json:"require_two_factor_authentication"`
		IPRestrictionRanges             string `json:"ip_restriction_ranges"`
		ProjectCreationLevel            string `json:"project_creation_level"`
		SubgroupCreationLevel           string `json:"subgroup_creation_level"`
		MembersCanCreateProjectsInGroup bool   `json:"members_can_create_projects_in_group"`
	}
	if err := json.Unmarshal(body, &g); err != nil {
		return nil, err
	}

	var findings []models.CloudFinding

	if !g.RequireTwoFactorAuthentication {
		findings = append(findings, models.CloudFinding{
			Provider:    "gitlab",
			Service:     "Group",
			Resource:    groupPath,
			Check:       "2FA not enforced for group members",
			Detail:      "require_two_factor_authentication is false — members can access group resources without MFA",
			Severity:    "high",
			Remediation: "Enable 2FA requirement in Group → Settings → General → Permissions and group features",
		})
	}

	if g.IPRestrictionRanges == "" {
		findings = append(findings, models.CloudFinding{
			Provider:    "gitlab",
			Service:     "Group",
			Resource:    groupPath,
			Check:       "No IP restriction configured",
			Detail:      "No IP allowlist is set — group resources are accessible from any IP",
			Severity:    "low",
			Remediation: "Consider configuring ip_restriction_ranges if access should be limited to specific networks",
		})
	}

	return findings, nil
}

// ── Projects ──────────────────────────────────────────────────────────────────

type glProject struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
	ContainerRegistryEnabled bool `json:"container_registry_enabled"`
	Visibility        string `json:"visibility"` // private|internal|public
}

func glListGroupProjects(ctx context.Context, client *http.Client, token, baseURL string, groupID int) ([]glProject, error) {
	apiURL := fmt.Sprintf("%s/api/v4/groups/%d/projects?per_page=100&include_subgroups=true", baseURL, groupID)
	body, status, err := glGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d listing projects", status)
	}
	var projects []glProject
	err = json.Unmarshal(body, &projects)
	return projects, err
}

func glCheckProject(ctx context.Context, client *http.Client, token, baseURL string, proj glProject) ([]models.CloudFinding, error) {
	var findings []models.CloudFinding

	// Check default branch protection
	if proj.DefaultBranch != "" {
		f, err := glCheckBranch(ctx, client, token, baseURL, proj.ID, proj.PathWithNamespace, proj.DefaultBranch)
		if err == nil {
			findings = append(findings, f...)
		}
	}

	// Check merge request approval rules
	f, err := glCheckApprovals(ctx, client, token, baseURL, proj.ID, proj.PathWithNamespace)
	if err == nil {
		findings = append(findings, f...)
	}

	// Public container registry
	if proj.ContainerRegistryEnabled && proj.Visibility == "public" {
		findings = append(findings, models.CloudFinding{
			Provider:    "gitlab",
			Service:     "Project",
			Resource:    proj.PathWithNamespace,
			Check:       "Container registry is public",
			Detail:      "The project is public with container registry enabled — images are accessible to anyone",
			Severity:    "medium",
			Remediation: "Make the project private or disable the container registry if public images are not intentional",
		})
	}

	// Check CI/CD variables
	f, err = glCheckCIVariables(ctx, client, token, baseURL, proj.ID, proj.PathWithNamespace)
	if err == nil {
		findings = append(findings, f...)
	}

	// Check webhooks
	f, err = glCheckWebhooks(ctx, client, token, baseURL, proj.ID, proj.PathWithNamespace)
	if err == nil {
		findings = append(findings, f...)
	}

	return findings, nil
}

// ── Branch Protection ──────────────────────────────────────────────────────────

func glCheckBranch(ctx context.Context, client *http.Client, token, baseURL string, projectID int, projectPath, branch string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/protected_branches/%s",
		baseURL, projectID, url.PathEscape(branch))
	body, status, err := glGET(ctx, client, token, apiURL)
	if err != nil {
		return nil, err
	}

	var findings []models.CloudFinding
	if status == 404 {
		findings = append(findings, models.CloudFinding{
			Provider:    "gitlab",
			Service:     "Project",
			Resource:    projectPath,
			Check:       "Default branch not protected",
			Detail:      fmt.Sprintf("Branch %q has no protection rules — direct pushes are allowed", branch),
			Severity:    "high",
			Remediation: "Protect the default branch in Project → Settings → Repository → Protected branches",
		})
		return findings, nil
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d checking branch protection", status)
	}

	var bp struct {
		Name              string `json:"name"`
		AllowForcePush    bool   `json:"allow_force_push"`
		PushAccessLevels  []struct {
			AccessLevel int `json:"access_level"`
		} `json:"push_access_levels"`
	}
	if err := json.Unmarshal(body, &bp); err != nil {
		return nil, err
	}

	if bp.AllowForcePush {
		findings = append(findings, models.CloudFinding{
			Provider:    "gitlab",
			Service:     "Project",
			Resource:    projectPath,
			Check:       "Protected branch allows force pushes",
			Detail:      fmt.Sprintf("Branch %q allows force pushes — history can be rewritten", branch),
			Severity:    "high",
			Remediation: "Disable force pushes in the branch protection settings",
		})
	}

	return findings, nil
}

// ── Merge Request Approvals ───────────────────────────────────────────────────

func glCheckApprovals(ctx context.Context, client *http.Client, token, baseURL string, projectID int, projectPath string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/approvals", baseURL, projectID)
	body, status, err := glGET(ctx, client, token, apiURL)
	if err != nil || status != 200 {
		return nil, nil // not available on all plans
	}

	var approvals struct {
		ApprovalsRequired int `json:"approvals_required"`
	}
	if err := json.Unmarshal(body, &approvals); err != nil {
		return nil, nil
	}

	if approvals.ApprovalsRequired == 0 {
		return []models.CloudFinding{{
			Provider:    "gitlab",
			Service:     "Project",
			Resource:    projectPath,
			Check:       "No merge request approvals required",
			Detail:      "approvals_required is 0 — anyone with Maintainer access can merge without review",
			Severity:    "medium",
			Remediation: "Set approvals_required to at least 1 in Project → Settings → Merge requests",
		}}, nil
	}
	return nil, nil
}

// ── CI/CD Variables ───────────────────────────────────────────────────────────

func glCheckCIVariables(ctx context.Context, client *http.Client, token, baseURL string, projectID int, projectPath string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/variables?per_page=100", baseURL, projectID)
	body, status, err := glGET(ctx, client, token, apiURL)
	if err != nil || status != 200 {
		return nil, nil
	}

	var vars []struct {
		Key       string `json:"key"`
		Masked    bool   `json:"masked"`
		Protected bool   `json:"protected"`
		Value     string `json:"value"`
	}
	if err := json.Unmarshal(body, &vars); err != nil {
		return nil, nil
	}

	var findings []models.CloudFinding
	for _, v := range vars {
		if !v.Masked && !v.Protected {
			upper := strings.ToUpper(v.Key)
			isSecret := false
			for _, keyword := range gcpSecretEnvKeywords {
				if strings.Contains(upper, keyword) {
					isSecret = true
					break
				}
			}
			if isSecret {
				findings = append(findings, models.CloudFinding{
					Provider:    "gitlab",
					Service:     "CI/CD",
					Resource:    projectPath,
					Check:       "CI/CD variable not masked or protected",
					Detail:      fmt.Sprintf("Variable %q matches a secret pattern but is neither masked nor protected — it may appear in job logs", v.Key),
					Severity:    "high",
					Remediation: "Mark sensitive CI/CD variables as masked and protected in Project → Settings → CI/CD → Variables",
				})
			}
		}
	}
	return findings, nil
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

func glCheckWebhooks(ctx context.Context, client *http.Client, token, baseURL string, projectID int, projectPath string) ([]models.CloudFinding, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/hooks?per_page=100", baseURL, projectID)
	body, status, err := glGET(ctx, client, token, apiURL)
	if err != nil || status != 200 {
		return nil, nil
	}

	var hooks []struct {
		URL                 string `json:"url"`
		EnableSSLVerification bool `json:"enable_ssl_verification"`
	}
	if err := json.Unmarshal(body, &hooks); err != nil {
		return nil, nil
	}

	var findings []models.CloudFinding
	for _, hook := range hooks {
		if strings.HasPrefix(hook.URL, "http://") {
			findings = append(findings, models.CloudFinding{
				Provider:    "gitlab",
				Service:     "Webhook",
				Resource:    projectPath,
				Check:       "Webhook uses HTTP instead of HTTPS",
				Detail:      fmt.Sprintf("Webhook URL %q transmits payloads unencrypted", hook.URL),
				Severity:    "high",
				Remediation: "Update the webhook URL to use HTTPS",
			})
		}
		if !hook.EnableSSLVerification {
			findings = append(findings, models.CloudFinding{
				Provider:    "gitlab",
				Service:     "Webhook",
				Resource:    projectPath,
				Check:       "Webhook SSL verification disabled",
				Detail:      fmt.Sprintf("SSL verification is disabled for webhook to %q — man-in-the-middle attacks are possible", hook.URL),
				Severity:    "high",
				Remediation: "Enable SSL verification for all webhooks",
			})
		}
	}
	return findings, nil
}
