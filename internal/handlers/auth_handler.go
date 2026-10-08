package handlers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/services"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken string            `json:"accessToken"`
	TokenType   string            `json:"tokenType"`
	ExpiresIn   int               `json:"expiresIn"`
	ExpiresAt   int64             `json:"expiresAt"`
	User        loginUserResponse `json:"user"`
}

type loginUserResponse struct {
	ID       string                `json:"id"`
	Email    string                `json:"email"`
	FullName string                `json:"fullName"`
	Phone    *string               `json:"phone,omitempty"`
	Pegawai  *loginPegawaiResponse `json:"pegawai,omitempty"`
}

type loginPegawaiResponse struct {
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

	response := loginResponse{
		AccessToken: result.Session.AccessToken,
		TokenType:   result.Session.TokenType,
		ExpiresIn:   result.Session.ExpiresIn,
		ExpiresAt:   result.Session.ExpiresAt,
		User: loginUserResponse{
			ID:       result.Identity.User.ID,
			Email:    result.Identity.User.Email,
			FullName: result.Identity.User.FullName,
			Phone:    result.Identity.User.Phone,
		},
	}

	if result.Identity.Pegawai != nil {
		response.User.Pegawai = &loginPegawaiResponse{
			NIP:           result.Identity.Pegawai.NIP,
			Alamat:        result.Identity.Pegawai.Alamat,
			GelarDepan:    result.Identity.Pegawai.GelarDepan,
			GelarBelakang: result.Identity.Pegawai.GelarBelakang,
		}
	}

	return c.Status(fiber.StatusOK).JSON(response)
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
