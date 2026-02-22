package api

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"

	"github.com/SMBullet/Survex/internal/db"
)

type settingsReq struct {
	ShodanKey   string         `json:"shodan_key"`
	GitHubToken string         `json:"github_token"`
	WebhookURLs []webhookEntry `json:"webhook_urls"`
	AIProvider  string         `json:"ai_provider"`
	AIAPIKey    string         `json:"ai_api_key"`
	AIModel     string         `json:"ai_model"`
	AIBaseURL   string         `json:"ai_base_url"`
}

type webhookEntry struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// handleGetSettings returns the current user's settings.
//
//	GET /api/v1/settings
func handleGetSettings(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		s, err := database.GetUserSettings(u.UserID)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		// Parse webhook_urls JSON so the client gets a proper array.
		var webhooks []webhookEntry
		if s.WebhookURLs != "" && s.WebhookURLs != "[]" {
			_ = json.Unmarshal([]byte(s.WebhookURLs), &webhooks)
		}
		if webhooks == nil {
			webhooks = []webhookEntry{}
		}

		return c.JSON(fiber.Map{
			"shodan_key":   s.ShodanKey,
			"github_token": s.GitHubToken,
			"webhook_urls": webhooks,
			"ai_provider":  s.AIProvider,
			"ai_api_key":   s.AIAPIKey,
			"ai_model":     s.AIModel,
			"ai_base_url":  s.AIBaseURL,
		})
	}
}

// handlePutSettings saves the current user's settings.
//
//	PUT /api/v1/settings
func handlePutSettings(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)

		var req settingsReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
		}

		// Serialise webhook_urls back to JSON for storage.
		if req.WebhookURLs == nil {
			req.WebhookURLs = []webhookEntry{}
		}
		whJSON, err := json.Marshal(req.WebhookURLs)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		s := &db.UserSettings{
			UserID:      u.UserID,
			ShodanKey:   req.ShodanKey,
			GitHubToken: req.GitHubToken,
			WebhookURLs: string(whJSON),
			AIProvider:  req.AIProvider,
			AIAPIKey:    req.AIAPIKey,
			AIModel:     req.AIModel,
			AIBaseURL:   req.AIBaseURL,
		}
		if err := database.UpsertUserSettings(s); err != nil {
			return fiber.ErrInternalServerError
		}

		return c.JSON(fiber.Map{"ok": true})
	}
}
