package middleware

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

const AuthenticatedIdentityKey = "authenticated_identity"

type AuthMiddleware struct {
	authService *services.AuthService
}

func NewAuthMiddleware(
	authService *services.AuthService,
) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
	}
}

func (m *AuthMiddleware) RequireAuth(c *fiber.Ctx) error {
	header := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))

	if header == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "missing_token",
			"message": "Access token diperlukan.",
		})
	}

	parts := strings.Fields(header)

	if len(parts) != 2 ||
		!strings.EqualFold(parts[0], "Bearer") ||
		strings.TrimSpace(parts[1]) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_token",
			"message": "Format access token tidak valid.",
		})
	}

	identity, err := m.authService.AuthenticateAccessToken(
		c.UserContext(),
		parts[1],
	)
	if err != nil {
		return handleAuthError(c, err)
	}

	c.Locals(AuthenticatedIdentityKey, identity)

	return c.Next()
}

func GetAuthenticatedIdentity(
	c *fiber.Ctx,
) (*models.Identity, bool) {
	identity, ok := c.Locals(
		AuthenticatedIdentityKey,
	).(*models.Identity)

	return identity, ok
}

func handleAuthError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidToken):
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_token",
			"message": "Access token tidak valid atau sudah kedaluwarsa.",
		})

	case errors.Is(err, services.ErrAccountPending):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "account_pending",
			"message": "Akun masih menunggu persetujuan.",
		})

	case errors.Is(err, services.ErrAccountRejected):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "account_rejected",
			"message": "Akun tidak memiliki akses.",
		})

	case errors.Is(err, services.ErrAccountUnavailable):
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "account_unavailable",
			"message": "Akun tidak tersedia.",
		})

	case errors.Is(err, services.ErrAuthUnavailable):
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "auth_unavailable",
			"message": "Layanan autentikasi sedang tidak tersedia.",
		})

	default:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "internal_error",
			"message": "Terjadi kesalahan pada server.",
		})
	}
}
