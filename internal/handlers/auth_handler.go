package handlers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/middleware"
	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

type AuthHandler struct {
	authService          *services.AuthService
	klinikContextService *services.KlinikContextService
}

func NewAuthHandler(
	authService *services.AuthService,
	klinikContextService *services.KlinikContextService,
) *AuthHandler {
	return &AuthHandler{
		authService:          authService,
		klinikContextService: klinikContextService,
	}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken string       `json:"accessToken"`
	TokenType   string       `json:"tokenType"`
	ExpiresIn   int          `json:"expiresIn"`
	ExpiresAt   int64        `json:"expiresAt"`
	User        userResponse `json:"user"`
}

type meResponse struct {
	User userResponse `json:"user"`
}

type klinikContextResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type userResponse struct {
	ID       string           `json:"id"`
	Email    string           `json:"email"`
	FullName string           `json:"fullName"`
	Phone    *string          `json:"phone,omitempty"`
	Pegawai  *pegawaiResponse `json:"pegawai,omitempty"`
}

type pegawaiResponse struct {
	NIP           *string `json:"nip,omitempty"`
	Alamat        *string `json:"alamat,omitempty"`
	GelarDepan    *string `json:"gelarDepan,omitempty"`
	GelarBelakang *string `json:"gelarBelakang,omitempty"`
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var request loginRequest

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_request",
			"message": "Request body tidak valid.",
		})
	}

	request.Email = strings.TrimSpace(request.Email)

	if request.Email == "" || request.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Email dan password wajib diisi.",
		})
	}

	result, err := h.authService.Login(
		c.UserContext(),
		request.Email,
		request.Password,
	)

	if err != nil {
		return handleLoginError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(loginResponse{
		AccessToken: result.Session.AccessToken,
		TokenType:   result.Session.TokenType,
		ExpiresIn:   result.Session.ExpiresIn,
		ExpiresAt:   result.Session.ExpiresAt,
		User:        buildUserResponse(result.Identity),
	})
}

func (h *AuthHandler) Me(c *fiber.Ctx) error {
	identity, ok := middleware.GetAuthenticatedIdentity(c)
	if !ok || identity == nil || identity.User == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "internal_error",
			"message": "Identitas pengguna tidak tersedia.",
		})
	}

	return c.Status(fiber.StatusOK).JSON(meResponse{
		User: buildUserResponse(identity),
	})
}

func buildUserResponse(identity *models.Identity) userResponse {
	response := userResponse{
		ID:       identity.User.ID,
		Email:    identity.User.Email,
		FullName: identity.User.FullName,
		Phone:    identity.User.Phone,
	}

	if identity.Pegawai != nil {
		response.Pegawai = &pegawaiResponse{
			NIP:           identity.Pegawai.NIP,
			Alamat:        identity.Pegawai.Alamat,
			GelarDepan:    identity.Pegawai.GelarDepan,
			GelarBelakang: identity.Pegawai.GelarBelakang,
		}
	}

	return response
}

func (h *AuthHandler) KlinikContext(c *fiber.Ctx) error {
	identity, ok := middleware.GetAuthenticatedIdentity(c)
	if !ok ||
		identity == nil ||
		identity.User == nil {

		return c.Status(
			fiber.StatusInternalServerError,
		).JSON(fiber.Map{
			"error":   "internal_error",
			"message": "Identitas pengguna tidak tersedia.",
		})
	}

	klinikUser, err := h.klinikContextService.GetByEmail(
		c.UserContext(),
		identity.User.Email,
	)
	if err != nil {
		if errors.Is(
			err,
			services.ErrKlinikAccountUnavailable,
		) {
			return c.Status(
				fiber.StatusForbidden,
			).JSON(fiber.Map{
				"error":   "klinik_account_unavailable",
				"message": "Pengguna tidak memiliki akses aktif ke Klinik PKP.",
			})
		}

		return c.Status(
			fiber.StatusInternalServerError,
		).JSON(fiber.Map{
			"error":   "internal_error",
			"message": "Terjadi kesalahan pada server.",
		})
	}

	return c.Status(fiber.StatusOK).JSON(
		klinikContextResponse{
			ID:    klinikUser.ID,
			Email: klinikUser.Email,
			Role:  klinikUser.Role,
		},
	)
}

func handleLoginError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidCredentials):
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_credentials",
			"message": "Email atau password salah.",
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

	case errors.Is(err, services.ErrAuthRateLimited):
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":   "rate_limited",
			"message": "Terlalu banyak percobaan login. Coba kembali nanti.",
		})

	case errors.Is(err, services.ErrKlinikMigrationConflict):
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":   "identity_conflict",
			"message": "Identitas akun tidak dapat dimigrasikan secara otomatis.",
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
