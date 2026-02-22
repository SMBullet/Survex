package api

import (
	"strings"

	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/websocket/v2"

	"github.com/SMBullet/Survex/internal/db"
	"github.com/SMBullet/Survex/internal/queue"
)

// New creates and configures the Fiber application.
func New(database *db.DB, q *queue.Queue, frontendDir string) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      "Survex API",
		ErrorHandler: jsonErrorHandler,
	})

	// ── Global middleware ────────────────────────────────────────────────────

	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} ${method} ${path} (${latency})\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:3000,http://localhost:3001,http://localhost:8080,http://127.0.0.1:8080,http://127.0.0.1:3000,http://127.0.0.1:3001",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Authorization",
	}))

	// ── WebSocket upgrade check ──────────────────────────────────────────────
	app.Use("/api/v1/scans/:id/logs", jwtWsUpgradeMiddleware, func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	// ── API routes ───────────────────────────────────────────────────────────
	v1 := app.Group("/api/v1")

	// Auth (public)
	auth := v1.Group("/auth")
	auth.Post("/register", handleRegister(database))
	auth.Post("/login", handleLogin(database))
	auth.Get("/me", jwtMiddleware, handleMe())

	// Scans (protected)
	scans := v1.Group("/scans", jwtMiddleware)
	scans.Get("/", handleListScans(database))
	scans.Post("/", handleCreateScan(database, q))
	scans.Get("/:id", handleGetScan(database))
	scans.Delete("/:id", handleCancelScan(database, q))
	scans.Get("/:id/report", handleScanReport(database))
	scans.Get("/:id/findings", handleScanFindings(database))
	scans.Get("/:id/technologies", handleScanTechnologies(database))

	// WebSocket for live scan logs (auth handled by jwtWsUpgradeMiddleware above)
	app.Get("/api/v1/scans/:id/logs", handleScanLogs(database, q))

	// ── Frontend static files ────────────────────────────────────────────────
	if frontendDir != "" {
		app.Static("/", frontendDir, fiber.Static{
			Index:    "index.html",
			Browse:   false,
			Compress: true,
		})
		// SPA fallback: any unmatched route serves index.html.
		app.Use(func(c *fiber.Ctx) error {
			if !strings.HasPrefix(c.Path(), "/api/") {
				return c.SendFile(frontendDir + "/index.html")
			}
			return fiber.ErrNotFound
		})
	}

	return app
}

// jwtWsUpgradeMiddleware extracts the JWT from the `token` query parameter
// (WebSocket connections cannot set headers) and stores userID in locals.
func jwtWsUpgradeMiddleware(c *fiber.Ctx) error {
	tokenStr := c.Query("token")
	if tokenStr == "" {
		// Fall back to Authorization header for non-WebSocket probes.
		auth := c.Get("Authorization")
		tokenStr = strings.TrimPrefix(auth, "Bearer ")
	}
	if tokenStr == "" {
		return fiber.ErrUnauthorized
	}
	cl, err := parseToken(tokenStr)
	if err != nil {
		return fiber.ErrUnauthorized
	}
	c.Locals("user", cl)
	c.Locals("userID", cl.UserID)
	return c.Next()
}

// jsonErrorHandler returns API errors as {"error": "message"} JSON.
func jsonErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	msg := "internal server error"

	var fe *fiber.Error
	if errors.As(err, &fe) {
		code = fe.Code
		msg = fe.Message
	}

	return c.Status(code).JSON(fiber.Map{"error": msg})
}
