package api

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/tools"
)

type aiQueryReq struct {
	Task    string          `json:"task"`    // explain_finding | scan_config | executive_summary
	Payload json.RawMessage `json:"payload"` // task-specific JSON
}

type explainFindingPayload struct {
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
	Asset    string `json:"asset"`
}

type scanConfigPayload struct {
	Description string `json:"description"`
}

type executiveSummaryPayload struct {
	Client       string `json:"client"`
	FindingCount int    `json:"finding_count"`
	MaxSeverity  string `json:"max_severity"`
	Findings     string `json:"findings"` // pre-formatted top findings list
}

// handleAIQuery processes AI assistance requests.
//
//	POST /api/v1/ai/query
func handleAIQuery(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)

		var req aiQueryReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
		}

		s, err := database.GetUserSettings(u.UserID)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		if s.AIProvider == "" {
			return fiber.NewError(fiber.StatusBadRequest,
				"No AI provider configured. Go to Settings → AI Assistant to set one up.")
		}

		cfg := &tools.AIConfig{
			Provider: s.AIProvider,
			APIKey:   s.AIAPIKey,
			Model:    s.AIModel,
			BaseURL:  s.AIBaseURL,
		}

		var result string
		switch req.Task {

		case "explain_finding":
			var p explainFindingPayload
			if err := json.Unmarshal(req.Payload, &p); err != nil {
				return fiber.NewError(fiber.StatusBadRequest, "invalid payload for explain_finding")
			}
			result, err = cfg.ExplainFinding(p.Title, p.Detail, p.Severity, p.Asset)

		case "scan_config":
			var p scanConfigPayload
			if err := json.Unmarshal(req.Payload, &p); err != nil {
				return fiber.NewError(fiber.StatusBadRequest, "invalid payload for scan_config")
			}
			if strings.TrimSpace(p.Description) == "" {
				return fiber.NewError(fiber.StatusBadRequest, "description is required")
			}
			result, err = cfg.SuggestScanConfig(p.Description)

		case "executive_summary":
			var p executiveSummaryPayload
			if err := json.Unmarshal(req.Payload, &p); err != nil {
				return fiber.NewError(fiber.StatusBadRequest, "invalid payload for executive_summary")
			}
			result, err = cfg.ExecutiveSummary(p.Client, p.FindingCount, p.MaxSeverity, p.Findings)

		default:
			return fiber.NewError(fiber.StatusBadRequest,
				fmt.Sprintf("unknown task: %s. Valid tasks: explain_finding, scan_config, executive_summary", req.Task))
		}

		if err != nil {
			return fiber.NewError(fiber.StatusBadGateway,
				fmt.Sprintf("AI query failed: %s", err.Error()))
		}

		return c.JSON(fiber.Map{"result": result})
	}
}
