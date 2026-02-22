package api

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/SMBullet/Survex/internal/db"
)

// jwtSecret is the signing key for JWTs, read from JWT_SECRET env var.
var jwtSecret = func() []byte {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return []byte(s)
	}
	return []byte("survex-default-secret-change-me")
}()

// claims is the JWT payload.
type claims struct {
	UserID int64  `json:"uid"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// issueToken creates a signed JWT for the given user.
func issueToken(userID int64, email string) (string, error) {
	c := claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 7 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(jwtSecret)
}

// parseToken validates a JWT string and returns the claims.
func parseToken(tokenStr string) (*claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := t.Claims.(*claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}

// jwtMiddleware extracts and validates the Bearer token, storing claims in c.Locals("user").
// It accepts the token from the Authorization header OR a ?token= query param so that
// browser navigation (e.g. opening the report in a new tab) works without custom headers.
func jwtMiddleware(c *fiber.Ctx) error {
	tokenStr := strings.TrimPrefix(c.Get("Authorization"), "Bearer ")
	if tokenStr == "" {
		tokenStr = c.Query("token")
	}
	if tokenStr == "" {
		return fiber.ErrUnauthorized
	}
	cl, err := parseToken(tokenStr)
	if err != nil {
		return fiber.ErrUnauthorized
	}
	c.Locals("user", cl)
	return c.Next()
}

// currentUser extracts the authenticated user claims from a request context.
func currentUser(c *fiber.Ctx) *claims {
	u, _ := c.Locals("user").(*claims)
	return u
}

// ── Handlers ────────────────────────────────────────────────────────────────

type registerReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// handleRegister creates a new user account.
//
//	POST /api/v1/auth/register
func handleRegister(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req registerReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if req.Email == "" || len(req.Password) < 8 {
			return fiber.NewError(fiber.StatusBadRequest, "email and password (min 8 chars) required")
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		id, err := database.CreateUser(req.Email, string(hash))
		if err != nil {
			// Likely a UNIQUE constraint violation.
			return fiber.NewError(fiber.StatusConflict, "email already registered")
		}

		token, err := issueToken(id, req.Email)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"token": token,
			"user":  fiber.Map{"id": id, "email": req.Email},
		})
	}
}

// handleLogin authenticates a user and returns a JWT.
//
//	POST /api/v1/auth/login
func handleLogin(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req registerReq
		if err := c.BodyParser(&req); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON")
		}

		user, err := database.GetUserByEmail(strings.ToLower(strings.TrimSpace(req.Email)))
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
		}

		token, err := issueToken(user.ID, user.Email)
		if err != nil {
			return fiber.ErrInternalServerError
		}

		return c.JSON(fiber.Map{
			"token": token,
			"user":  fiber.Map{"id": user.ID, "email": user.Email},
		})
	}
}

// handleMe returns the current authenticated user's profile.
//
//	GET /api/v1/auth/me
func handleMe() fiber.Handler {
	return func(c *fiber.Ctx) error {
		u := currentUser(c)
		return c.JSON(fiber.Map{"id": u.UserID, "email": u.Email})
	}
}
