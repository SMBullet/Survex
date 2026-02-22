package api

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/queue"
)

// ── Cloud Credentials ─────────────────────────────────────────────────────────

// handleGetCloudCredentials returns saved credentials for all cloud providers.
//
//	GET /api/v1/cloud/credentials
func handleGetCloudCredentials(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		creds, err := database.GetAllCloudCredentials(u.UserID)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		if creds == nil {
			creds = map[string]map[string]string{}
		}
		return c.JSON(creds)
	}
}

// handlePutCloudCredentials saves or replaces credentials for a specific provider.
//
//	PUT /api/v1/cloud/credentials/:provider
func handlePutCloudCredentials(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		provider := c.Params("provider")
		if !isValidProvider(provider) {
			return fiber.NewError(fiber.StatusBadRequest, "unknown provider: "+provider)
		}

		var data map[string]string
		if err := c.BodyParser(&data); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
		}
		if len(data) == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "credentials must not be empty")
		}

		// Fetch existing credentials so we don't overwrite fields not included in
		// a partial update (e.g. when the UI redacts secret fields with ••••••••).
		existing, err := database.GetCloudCredentials(u.UserID, provider)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		if existing != nil {
			// Merge: keep old value for any field that still contains the redaction marker.
			for k, v := range data {
				if v == "••••••••" {
					if old, ok := existing.Data[k]; ok {
						data[k] = old
					} else {
						delete(data, k)
					}
				}
			}
		}

		if err := database.UpsertCloudCredentials(u.UserID, provider, data); err != nil {
			return fiber.ErrInternalServerError
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	}
}

// handleDeleteCloudCredentials removes saved credentials for a provider.
//
//	DELETE /api/v1/cloud/credentials/:provider
func handleDeleteCloudCredentials(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		provider := c.Params("provider")
		if !isValidProvider(provider) {
			return fiber.NewError(fiber.StatusBadRequest, "unknown provider: "+provider)
		}
		if err := database.DeleteCloudCredentials(u.UserID, provider); err != nil {
			return fiber.ErrInternalServerError
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	}
}

// ── Cloud Scans ───────────────────────────────────────────────────────────────

// createCloudScanReq is the request body for POST /api/v1/cloud/scans.
type createCloudScanReq struct {
	Provider string                 `json:"provider"` // aws|azure|gcp|github|gitlab
	Options  map[string]interface{} `json:"options"`  // credential fields + scan options
}

// handleCreateCloudScan enqueues a new async cloud config review job.
//
//	POST /api/v1/cloud/scans
func handleCreateCloudScan(database *db.DB, cq *queue.CloudQueue) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)

		var req createCloudScanReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
		}
		if !isValidProvider(req.Provider) {
			return fiber.NewError(fiber.StatusBadRequest, "unknown provider: "+req.Provider)
		}

		// If no credentials provided in the request, load saved credentials from DB.
		if len(req.Options) == 0 {
			saved, err := database.GetCloudCredentials(u.UserID, req.Provider)
			if err != nil {
				return fiber.ErrInternalServerError
			}
			if saved != nil {
				req.Options = make(map[string]interface{})
				for k, v := range saved.Data {
					req.Options[k] = v
				}
			}
		} else {
			// Merge missing fields from saved credentials (UI may not resend secrets).
			saved, err := database.GetCloudCredentials(u.UserID, req.Provider)
			if err == nil && saved != nil {
				for k, v := range req.Options {
					if sv, ok := v.(string); ok && sv == "••••••••" {
						if old, ok := saved.Data[k]; ok {
							req.Options[k] = old
						}
					}
				}
				// Fill in fields entirely absent from the request.
				for k, v := range saved.Data {
					if _, exists := req.Options[k]; !exists {
						req.Options[k] = v
					}
				}
			}
		}

		if len(req.Options) == 0 {
			return fiber.NewError(fiber.StatusBadRequest,
				"no credentials provided and no saved credentials found for provider "+req.Provider)
		}

		optionsJSON, err := json.Marshal(req.Options)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		id := uuid.NewString()
		if err := database.CreateCloudScan(id, u.UserID, req.Provider, string(optionsJSON)); err != nil {
			return fiber.ErrInternalServerError
		}
		cq.Enqueue(id)

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": id})
	}
}

// handleListCloudScans returns the most recent cloud scans for the authenticated user.
//
//	GET /api/v1/cloud/scans?provider=aws&limit=20
func handleListCloudScans(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		provider := c.Query("provider") // optional filter
		limit := c.QueryInt("limit", 50)
		if limit > 200 {
			limit = 200
		}

		rows, err := database.ListCloudScans(u.UserID, provider, limit)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		jobs := make([]fiber.Map, 0, len(rows))
		for _, row := range rows {
			jobs = append(jobs, cloudRowToMap(row))
		}
		return c.JSON(jobs)
	}
}

// handleGetCloudScan returns a single cloud scan with full result JSON.
//
//	GET /api/v1/cloud/scans/:id
func handleGetCloudScan(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		id := c.Params("id")

		row, err := database.GetCloudScan(id, u.UserID)
		if err != nil {
			return fiber.ErrNotFound
		}
		return c.JSON(cloudRowToMap(row))
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

var validProviders = map[string]bool{
	"aws": true, "azure": true, "gcp": true, "github": true, "gitlab": true,
}

func isValidProvider(p string) bool {
	return validProviders[p]
}

// cloudRowToMap converts a DB row into the JSON shape sent to the frontend.
func cloudRowToMap(row *db.CloudScanRow) fiber.Map {
	m := fiber.Map{
		"id":         row.ID,
		"user_id":    row.UserID,
		"provider":   row.Provider,
		"status":     row.Status,
		"created_at": row.CreatedAt,
		"error":      row.ErrorMsg,
	}
	if row.StartedAt != nil {
		m["started_at"] = row.StartedAt
	}
	if row.FinishedAt != nil {
		m["finished_at"] = row.FinishedAt
	}
	// Inline result JSON if available
	if row.ResultJSON != "" && row.ResultJSON != "{}" {
		var result interface{}
		if err := json.Unmarshal([]byte(row.ResultJSON), &result); err == nil {
			m["result"] = result
		}
	}
	return m
}
