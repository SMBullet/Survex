package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/models"
)

// SendNotifications dispatches webhook notifications based on each webhook's "on" trigger.
// It is called after risk scoring completes and after diff is computed.
func SendNotifications(webhooks []config.WebhookConfig, result *models.ScanResult) {
	if len(webhooks) == 0 {
		return
	}

	newFindings := countNewFindings(result.Findings)
	newSubs := 0
	if result.Diff != nil {
		newSubs = len(result.Diff.NewSubdomains)
	}

	for _, wh := range webhooks {
		if wh.URL == "" {
			continue
		}
		trigger := strings.ToLower(strings.TrimSpace(wh.On))
		if trigger == "" {
			trigger = "new_findings"
		}

		switch trigger {
		case "always":
			// always fire
		case "new_subdomains":
			if newSubs == 0 {
				continue
			}
		default: // "new_findings"
			if newFindings == 0 {
				continue
			}
		}

		if err := postWebhook(wh.URL, result, newFindings, newSubs); err != nil {
			log.Printf("[survex] webhook [%s]: %v", truncateURL(wh.URL), err)
		} else {
			log.Printf("[survex] webhook notification sent → %s", truncateURL(wh.URL))
		}
	}
}

// postWebhook sends a single webhook notification.
// Supports Slack (hooks.slack.com), Discord (discord.com/api/webhooks), and generic endpoints.
func postWebhook(url string, result *models.ScanResult, newFindings, newSubs int) error {
	body := buildPayload(url, result, newFindings, newSubs)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Survex/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// buildPayload constructs the JSON body appropriate for the webhook provider.
func buildPayload(url string, result *models.ScanResult, newFindings, newSubs int) []byte {
	summary := buildSummaryText(result, newFindings, newSubs)

	var payload any

	switch {
	case strings.Contains(url, "hooks.slack.com"):
		// Slack incoming webhook format
		payload = map[string]any{
			"text": summary,
			"attachments": []map[string]any{
				{
					"color": severityToColor(maxFindingSeverity(result.Findings)),
					"fields": []map[string]string{
						{"title": "Client", "value": result.Scan.Client, "short": "true"},
						{"title": "Target", "value": result.Scan.Target, "short": "true"},
						{"title": "Scan ID", "value": result.Scan.ID, "short": "true"},
						{"title": "Max Severity", "value": maxFindingSeverity(result.Findings), "short": "true"},
					},
				},
			},
		}

	case strings.Contains(url, "discord.com/api/webhooks"):
		// Discord webhook format
		payload = map[string]any{
			"content": summary,
			"embeds": []map[string]any{
				{
					"color":       severityToDiscordColor(maxFindingSeverity(result.Findings)),
					"title":       fmt.Sprintf("Survex Scan — %s", result.Scan.Target),
					"description": fmt.Sprintf("**Client:** %s\n**Scan ID:** %s", result.Scan.Client, result.Scan.ID),
					"fields": []map[string]any{
						{"name": "Subdomains", "value": fmt.Sprintf("%d", len(result.Subdomains)), "inline": true},
						{"name": "HTTP Services", "value": fmt.Sprintf("%d", len(result.HTTP)), "inline": true},
						{"name": "Findings", "value": fmt.Sprintf("%d (%d new)", len(result.Findings), newFindings), "inline": true},
						{"name": "New Subdomains", "value": fmt.Sprintf("%d", newSubs), "inline": true},
					},
					"timestamp": result.Scan.StartedAt.Format(time.RFC3339),
				},
			},
		}

	default:
		// Generic webhook: JSON body with full summary
		payload = map[string]any{
			"text":          summary,
			"client":        result.Scan.Client,
			"target":        result.Scan.Target,
			"scan_id":       result.Scan.ID,
			"max_severity":  maxFindingSeverity(result.Findings),
			"findings":      len(result.Findings),
			"new_findings":  newFindings,
			"subdomains":    len(result.Subdomains),
			"new_subdomains": newSubs,
			"timestamp":     result.Scan.StartedAt.Format(time.RFC3339),
		}
	}

	b, _ := json.Marshal(payload)
	return b
}

func buildSummaryText(result *models.ScanResult, newFindings, newSubs int) string {
	maxSev := maxFindingSeverity(result.Findings)
	emoji := severityToEmoji(maxSev)

	lines := []string{
		fmt.Sprintf("%s *Survex scan complete* — %s", emoji, result.Scan.Target),
		fmt.Sprintf("• Subdomains: %d (%d new)", len(result.Subdomains), newSubs),
		fmt.Sprintf("• HTTP services: %d", len(result.HTTP)),
		fmt.Sprintf("• Findings: %d total (%d new) — max severity: *%s*", len(result.Findings), newFindings, maxSev),
	}

	if newFindings > 0 {
		lines = append(lines, "")
		lines = append(lines, "*New findings:*")
		shown := 0
		for _, f := range result.Findings {
			if !f.New {
				continue
			}
			lines = append(lines, fmt.Sprintf("  [%s] %s — %s", strings.ToUpper(f.Severity), f.Asset, f.Title))
			shown++
			if shown >= 5 {
				remaining := newFindings - shown
				if remaining > 0 {
					lines = append(lines, fmt.Sprintf("  ... and %d more", remaining))
				}
				break
			}
		}
	}

	return strings.Join(lines, "\n")
}

func countNewFindings(findings []models.Finding) int {
	n := 0
	for _, f := range findings {
		if f.New {
			n++
		}
	}
	return n
}

func maxFindingSeverity(findings []models.Finding) string {
	order := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	max := -1
	result := "none"
	for _, f := range findings {
		if v, ok := order[f.Severity]; ok && v > max {
			max = v
			result = f.Severity
		}
	}
	return result
}

func severityToColor(sev string) string {
	// Slack attachment color (hex or "good"/"warning"/"danger")
	switch sev {
	case "critical":
		return "#dc2626"
	case "high":
		return "#ea580c"
	case "medium":
		return "#d97706"
	case "low":
		return "#2563eb"
	}
	return "#6b7280"
}

func severityToDiscordColor(sev string) int {
	// Discord embed color (decimal RGB)
	switch sev {
	case "critical":
		return 0xdc2626
	case "high":
		return 0xea580c
	case "medium":
		return 0xd97706
	case "low":
		return 0x2563eb
	}
	return 0x6b7280
}

func severityToEmoji(sev string) string {
	switch sev {
	case "critical":
		return ":rotating_light:"
	case "high":
		return ":warning:"
	case "medium":
		return ":yellow_circle:"
	case "low":
		return ":blue_circle:"
	}
	return ":white_check_mark:"
}

func truncateURL(url string) string {
	if len(url) > 60 {
		return url[:57] + "..."
	}
	return url
}
