package api

import (
	"github.com/gofiber/fiber/v2"

	"github.com/SMBullet/Survex/internal/db"
)

type fpReq struct {
	Asset string `json:"asset"`
	Title string `json:"title"`
}

// handleListFPs returns the current user's false-positive suppressions.
//
//	GET /api/v1/false-positives
func handleListFPs(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		fps, err := database.ListFalsePositives(u.UserID)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		if fps == nil {
			fps = []*db.FalsePositive{}
		}
		return c.JSON(fps)
	}
}

// handleAddFP marks a finding as a false positive.
//
//	POST /api/v1/false-positives
func handleAddFP(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)

		var req fpReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
		}
		if req.Asset == "" || req.Title == "" {
			return fiber.NewError(fiber.StatusBadRequest, "asset and title required")
		}

		fp, err := database.AddFalsePositive(u.UserID, req.Asset, req.Title)
		if err != nil {
			return fiber.ErrInternalServerError
		}
		return c.Status(fiber.StatusCreated).JSON(fp)
	}
}

// handleRemoveFP removes a false-positive suppression.
//
//	DELETE /api/v1/false-positives/:fingerprint
func handleRemoveFP(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		fingerprint := c.Params("fingerprint")
		if fingerprint == "" {
			return fiber.ErrBadRequest
		}
		if err := database.RemoveFalsePositive(u.UserID, fingerprint); err != nil {
			return fiber.ErrInternalServerError
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
}
