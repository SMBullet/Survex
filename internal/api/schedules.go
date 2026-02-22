package api

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/SMBullet/Survex/internal/config"
	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/queue"
)

type createScheduleReq struct {
	Client    string   `json:"client"`
	Targets   []string `json:"targets"`
	Modules   []string `json:"modules"`
	IntervalH int      `json:"interval_h"` // 6 | 12 | 24 | 48 | 72 | 168
	Options   scanOpts `json:"options"`
}

// handleListSchedules returns the current user's scheduled scans.
//
//	GET /api/v1/schedules
func handleListSchedules(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		schedules, err := database.ListSchedules(u.UserID)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		if schedules == nil {
			schedules = []*db.Schedule{}
		}
		return c.JSON(schedules)
	}
}

// handleCreateSchedule creates a new recurring scan schedule.
//
//	POST /api/v1/schedules
func handleCreateSchedule(database *db.DB, q *queue.Queue) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)

		var req createScheduleReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
		}

		if len(req.Targets) == 0 {
			return fiber.NewError(fiber.StatusBadRequest, "at least one target required")
		}
		if req.Client == "" {
			req.Client = req.Targets[0]
		}
		// Clamp interval to supported values.
		validIntervals := map[int]bool{6: true, 12: true, 24: true, 48: true, 72: true, 168: true}
		if !validIntervals[req.IntervalH] {
			req.IntervalH = 24
		}

		s := &db.Schedule{
			ID:        uuid.New().String(),
			UserID:    u.UserID,
			Client:    req.Client,
			Targets:   strings.Join(req.Targets, ","),
			Modules:   strings.Join(req.Modules, ","),
			Options:   "{}",
			IntervalH: req.IntervalH,
			Enabled:   true,
			NextRun:   time.Now().Add(time.Duration(req.IntervalH) * time.Hour),
			CreatedAt: time.Now(),
		}

		if err := database.CreateSchedule(s); err != nil {
			return fiber.ErrInternalServerError
		}

		return c.Status(fiber.StatusCreated).JSON(s)
	}
}

// handleToggleSchedule enables or disables a schedule.
//
//	PUT /api/v1/schedules/:id
func handleToggleSchedule(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		id := c.Params("id")

		type toggleReq struct {
			Enabled bool `json:"enabled"`
		}
		var req toggleReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
		}

		_, err := database.GetSchedule(id, u.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fiber.ErrNotFound
			}
			return fiber.ErrInternalServerError
		}

		if err := database.UpdateScheduleEnabled(id, u.UserID, req.Enabled); err != nil {
			return fiber.ErrInternalServerError
		}
		return c.JSON(fiber.Map{"ok": true, "enabled": req.Enabled})
	}
}

// handleDeleteSchedule removes a scheduled scan.
//
//	DELETE /api/v1/schedules/:id
func handleDeleteSchedule(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		id := c.Params("id")

		_, err := database.GetSchedule(id, u.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fiber.ErrNotFound
			}
			return fiber.ErrInternalServerError
		}

		if err := database.DeleteSchedule(id, u.UserID); err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
}

// RunScheduledJob creates and enqueues a scan job for the given schedule.
// Called by the scheduler goroutine.
func RunScheduledJob(database *db.DB, q *queue.Queue, s *db.Schedule) error {
	targets := strings.Split(s.Targets, ",")
	modules := strings.Split(s.Modules, ",")

	cfg := &config.Config{
		Client:  s.Client,
		Targets: targets,
		Modules: modules,
		Output: config.OutputOptions{
			Dir: filepath.Join("reports", s.Client),
		},
	}

	jobID := uuid.New().String()
	dbJob := &db.ScanJob{
		ID:        jobID,
		UserID:    s.UserID,
		Client:    s.Client,
		Targets:   s.Targets,
		Modules:   s.Modules,
		Options:   "{}",
		Status:    "queued",
		CreatedAt: time.Now(),
	}
	if err := database.CreateScanJob(dbJob); err != nil {
		return err
	}

	q.Enqueue(&queue.Job{
		ID:     jobID,
		UserID: s.UserID,
		Config: cfg,
	})

	return nil
}
