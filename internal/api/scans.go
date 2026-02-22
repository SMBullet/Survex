package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/websocket/v2"
	"github.com/google/uuid"

	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/queue"
)

// createScanReq is the JSON body for POST /api/v1/scans.
type createScanReq struct {
	Client  string   `json:"client"`
	Targets []string `json:"targets"`
	Modules []string `json:"modules"`
	Options scanOpts `json:"options"`
}

type scanOpts struct {
	NoSubs       bool     `json:"no_subs"`
	Passive      bool     `json:"passive"`
	Ports        string   `json:"ports"`
	Profile      string   `json:"profile"`
	Rate         int      `json:"rate"`
	Threads      int      `json:"threads"`
	Timeout      int      `json:"timeout"`
	Proxy        string   `json:"proxy"`
	GitHubToken  string   `json:"github_token"`
	ShodanKey    string   `json:"shodan_key"`
	// Nuclei configuration — all optional; empty means use server defaults.
	NucleiSeverity  string   `json:"nuclei_severity"`  // e.g. "critical,high,medium"
	NucleiTags      []string `json:"nuclei_tags"`      // include these tags
	NucleiExclude   []string `json:"nuclei_exclude"`   // exclude these tags
	NucleiTemplates []string `json:"nuclei_templates"` // template dirs to run (overrides defaults when set)
}

// handleListScans returns the authenticated user's scan history.
//
//	GET /api/v1/scans
func handleListScans(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		jobs, err := database.ListScanJobs(u.UserID, 100)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.JSON(jobs)
	}
}

// handleCreateScan creates and enqueues a new scan job.
//
//	POST /api/v1/scans
func handleCreateScan(database *db.DB, q *queue.Queue) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)

		var req createScanReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
		}

		if len(req.Targets) == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "at least one target required")
		}
		if req.Client == "" {
			req.Client = req.Targets[0]
		}
		// Only apply default modules when no profile is set.
		// A profile (quick/full/web/…) resolves its own module list server-side.
		if len(req.Modules) == 0 && req.Options.Profile == "" {
			req.Modules = []string{"httpx", "tls", "headers", "cors"}
		}

		// Auto-inject keys from user settings if not provided in the request.
		savedSettings, _ := database.GetUserSettings(u.UserID)
		shodanKey := req.Options.ShodanKey
		if shodanKey == "" && savedSettings != nil {
			shodanKey = savedSettings.ShodanKey
		}
		githubToken := req.Options.GitHubToken
		if githubToken == "" && savedSettings != nil {
			githubToken = savedSettings.GitHubToken
		}

		// Build a config.Config from the request.
		cfg := &config.Config{
			Client:  req.Client,
			Targets: req.Targets,
			Modules: req.Modules,
			Scan: config.ScanOptions{
				NoSubs:  req.Options.NoSubs,
				Passive: req.Options.Passive,
				Ports:   req.Options.Ports,
				Profile: req.Options.Profile,
				Rate:    req.Options.Rate,
				Threads: req.Options.Threads,
				Timeout: req.Options.Timeout,
				Proxy:   req.Options.Proxy,
			},
			Nuclei: config.NucleiOptions{
				Severity:    req.Options.NucleiSeverity,
				Tags:        req.Options.NucleiTags,
				ExcludeTags: req.Options.NucleiExclude,
				Templates:   req.Options.NucleiTemplates,
			},
			GitHub: config.GitHubOptions{
				Token: githubToken,
			},
			Shodan: config.ShodanOptions{
				APIKey:  shodanKey,
				Enabled: shodanKey != "",
			},
			Output: config.OutputOptions{
				Dir: filepath.Join("reports", req.Client),
			},
		}

		// Generate a unique job ID.
		jobID := uuid.New().String()

		// Persist the job record before enqueueing.
		dbJob := &db.ScanJob{
			ID:        jobID,
			UserID:    u.UserID,
			Client:    req.Client,
			Targets:   strings.Join(req.Targets, ","),
			Modules:   strings.Join(req.Modules, ","),
			Options:   "{}",
			Status:    "queued",
			CreatedAt: time.Now(),
		}
		if err := database.CreateScanJob(dbJob); err != nil {
			return fiber.ErrInternalServerError
		}

		qJob := &queue.Job{
			ID:     jobID,
			UserID: u.UserID,
			Config: cfg,
		}
		q.Enqueue(qJob)

		return c.Status(fiber.StatusCreated).JSON(dbJob)
	}
}

// handleGetScan returns a single scan job by ID.
//
//	GET /api/v1/scans/:id
func handleGetScan(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		id := c.Params("id")

		job, err := database.GetScanJob(id, u.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fiber.ErrNotFound
			}
			return fiber.ErrInternalServerError
		}
		return c.JSON(job)
	}
}

// handleCancelScan cancels a queued or running scan.
//
//	DELETE /api/v1/scans/:id
func handleCancelScan(database *db.DB, q *queue.Queue) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		id := c.Params("id")

		// Verify ownership.
		job, err := database.GetScanJob(id, u.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fiber.ErrNotFound
			}
			return fiber.ErrInternalServerError
		}
		if job.Status != "queued" && job.Status != "running" {
			return fiber.NewError(fiber.StatusConflict, "scan is not active")
		}

		// Immediately mark as cancelled in the DB so the UI updates without waiting
		// for the queue worker to finish the current operation.
		now := time.Now()
		_ = database.UpdateScanStatus(id, "cancelled", job.StartedAt, &now)

		// Signal the in-memory job (sets flag + cancels context).
		if qj := q.Get(id); qj != nil {
			qj.Cancel()
		}

		return c.JSON(fiber.Map{"status": "cancelled"})
	}
}

// handleScanReport serves the HTML report for a completed scan.
//
//	GET /api/v1/scans/:id/report
func handleScanReport(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		id := c.Params("id")

		job, err := database.GetScanJob(id, u.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fiber.ErrNotFound
			}
			return fiber.ErrInternalServerError
		}
		if job.ReportPath == "" {
			return fiber.NewError(fiber.StatusNotFound, "report not yet available")
		}
		if _, err := os.Stat(job.ReportPath); err != nil {
			return fiber.NewError(fiber.StatusNotFound, "report file not found")
		}

		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.SendFile(job.ReportPath)
	}
}

// handleScanLogs upgrades to WebSocket and streams live log output.
//
//	GET /api/v1/scans/:id/logs  (WebSocket)
func handleScanLogs(database *db.DB, q *queue.Queue) fiber.Handler {
	return websocket.New(func(ws *websocket.Conn) {
		id := ws.Params("id")

		// Read userID injected by jwtWsMiddleware stored in locals.
		userID, _ := ws.Locals("userID").(int64)

		// Verify ownership.
		job, err := database.GetScanJob(id, userID)
		if err != nil || job == nil {
			_ = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(4004, "not found"))
			return
		}

		qj := q.Get(id)
		if qj == nil {
			// Job not in memory (already finished) — stream stored log lines.
			_ = ws.WriteMessage(websocket.TextMessage, []byte("[no live log: scan already completed]"))
			_ = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"))
			return
		}

		ch := qj.Subscribe()
		defer qj.Unsubscribe(ch)

		for line := range ch {
			if err := ws.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
				return
			}
		}
		// Channel closed — job finished.
		_ = ws.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"))
	})
}

// handleScanFindings serves the findings.json produced by the scan.
// Accepts ?filter_fp=true to strip findings that match user's false-positive list.
//
//	GET /api/v1/scans/:id/findings
func handleScanFindings(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		id := c.Params("id")

		job, err := database.GetScanJob(id, u.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fiber.ErrNotFound
			}
			return fiber.ErrInternalServerError
		}

		if job.ReportPath == "" {
			return c.JSON([]any{})
		}

		findingsPath := filepath.Join(filepath.Dir(job.ReportPath), "findings.json")
		data, err := os.ReadFile(findingsPath)
		if err != nil {
			return c.JSON([]any{})
		}

		// When filter_fp=true, remove findings that match the user's FP suppressions.
		if c.QueryBool("filter_fp", true) {
			fpSet, err := database.GetFalsePositiveSet(u.UserID)
			if err == nil && len(fpSet) > 0 {
				var findings []map[string]any
				if json.Unmarshal(data, &findings) == nil {
					filtered := findings[:0]
					for _, f := range findings {
						asset, _ := f["asset"].(string)
						title, _ := f["title"].(string)
						fp := strings.ToLower(asset) + "|" + strings.ToLower(title)
						if _, isFP := fpSet[fp]; !isFP {
							filtered = append(filtered, f)
						}
					}
					return c.JSON(filtered)
				}
			}
		}

		var raw json.RawMessage = data
		return c.JSON(raw)
	}
}

// handleScanTechnologies serves the technologies.json produced by the scan.
//
//	GET /api/v1/scans/:id/technologies
func handleScanTechnologies(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		id := c.Params("id")

		job, err := database.GetScanJob(id, u.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fiber.ErrNotFound
			}
			return fiber.ErrInternalServerError
		}

		// Derive scan directory from the stored report path.
		// report_path = reports/<client>/<scan-id>/report.html
		// technologies = reports/<client>/<scan-id>/technologies.json
		if job.ReportPath == "" {
			return c.JSON([]any{})
		}

		techPath := filepath.Join(filepath.Dir(job.ReportPath), "technologies.json")
		data, err := os.ReadFile(techPath)
		if err != nil {
			// File doesn't exist yet (scan in progress) — return empty array.
			return c.JSON([]any{})
		}

		// Return raw JSON directly to avoid double-encoding.
		var raw json.RawMessage = data
		return c.JSON(raw)
	}
}
