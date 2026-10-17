package handlers

import (
	"errors"
	"net/mail"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/middleware"
	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

type AuthHandler struct {
	authService               *services.AuthService
	klinikContextService      *services.KlinikContextService
	applicationContextService *services.ApplicationContextService
}

func NewAuthHandler(
	authService *services.AuthService,
	klinikContextService *services.KlinikContextService,
	applicationContextService *services.ApplicationContextService,
) *AuthHandler {
	return &AuthHandler{
		authService:               authService,
		klinikContextService:      klinikContextService,
		applicationContextService: applicationContextService,
	}
}

type loginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Application string `json:"application"`
}

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	FullName    string `json:"fullName"`
	Phone       string `json:"phone"`
	Application string `json:"application"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type forgotPasswordRequest struct {
	Email       string `json:"email"`
	Application string `json:"application"`
}

type resetPasswordRequest struct {
	TokenHash string `json:"tokenHash"`
	Password  string `json:"password"`
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type loginResponse struct {
	AccessToken  string       `json:"accessToken"`
	RefreshToken string       `json:"refreshToken"`
	TokenType    string       `json:"tokenType"`
	ExpiresIn    int          `json:"expiresIn"`
	ExpiresAt    int64        `json:"expiresAt"`
	User         userResponse `json:"user"`
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
	request.Application = strings.ToLower(
		strings.TrimSpace(request.Application),
	)

	if request.Email == "" ||
		request.Password == "" ||
		request.Application == "" {

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Email, password, dan aplikasi wajib diisi.",
		})
	}

	result, err := h.authService.Login(
		c.UserContext(),
		request.Email,
		request.Password,
		request.Application,
	)

	if err != nil {
		return handleLoginError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(loginResponse{
		AccessToken:  result.Session.AccessToken,
		RefreshToken: result.Session.RefreshToken,
		TokenType:    result.Session.TokenType,
		ExpiresIn:    result.Session.ExpiresIn,
		ExpiresAt:    result.Session.ExpiresAt,
		User:         buildUserResponse(result.Identity),
	})
}

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var request registerRequest

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_request",
			"message": "Request body tidak valid.",
		})
	}

	request.Email = strings.TrimSpace(request.Email)
	request.FullName = strings.TrimSpace(request.FullName)
	request.Phone = strings.TrimSpace(request.Phone)
	request.Application = strings.ToLower(
		strings.TrimSpace(request.Application),
	)

	if request.Email == "" ||
		request.Password == "" ||
		request.FullName == "" ||
		request.Application == "" {

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Email, password, nama lengkap, dan aplikasi wajib diisi.",
		})
	}

	parsedEmail, err := mail.ParseAddress(request.Email)
	if err != nil ||
		parsedEmail.Address == "" ||
		!strings.EqualFold(parsedEmail.Address, request.Email) {

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Format email tidak valid.",
		})
	}

	if len(request.Password) < 8 ||
		len(request.Password) > 128 {

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_password",
			"message": "Password harus terdiri dari 8 sampai 128 karakter.",
		})
	}

	identity, err := h.authService.RegisterCentralIdentity(
		c.UserContext(),
		request.Email,
		request.Password,
		request.FullName,
		request.Phone,
		request.Application,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrAccountAlreadyExists):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error":   "account_already_exists",
				"message": "Akun Balai dengan email tersebut sudah tersedia. Silakan masuk menggunakan akun yang sudah ada.",
			})

		case errors.Is(err, services.ErrRegistrationIdentityConflict):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error":   "identity_conflict",
				"message": "Identitas akun tidak dapat dibuat secara otomatis.",
			})

		case errors.Is(err, services.ErrInvalidRegistrationRequest):
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "validation_error",
				"message": "Data registrasi tidak valid.",
			})

		case errors.Is(err, services.ErrUnsupportedApplication):
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error":   "unsupported_application",
				"message": "Aplikasi tidak didukung atau sedang tidak aktif.",
			})

		case errors.Is(err, services.ErrAdminUnavailable),
			errors.Is(err, services.ErrAuthUnavailable):

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

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"user": buildUserResponse(identity),
	})
}

func (h *AuthHandler) ForgotPassword(c *fiber.Ctx) error {
	var request forgotPasswordRequest

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_request",
			"message": "Request body tidak valid.",
		})
	}

	request.Email = strings.TrimSpace(request.Email)
	request.Application = strings.TrimSpace(request.Application)

	if request.Email == "" || request.Application == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Email dan aplikasi wajib diisi.",
		})
	}

	parsedEmail, err := mail.ParseAddress(request.Email)
	if err != nil ||
		parsedEmail.Address == "" ||
		!strings.EqualFold(parsedEmail.Address, request.Email) {

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Format email tidak valid.",
		})
	}

	if err := h.authService.RequestPasswordRecovery(
		c.UserContext(),
		request.Email,
		request.Application,
	); err != nil {
		return handlePasswordRecoveryError(c, err)
	}

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"message": "Jika email terdaftar, instruksi reset password akan dikirim.",
	})
}

func (h *AuthHandler) ResetPassword(c *fiber.Ctx) error {
	var request resetPasswordRequest

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_request",
			"message": "Request body tidak valid.",
		})
	}

	request.TokenHash = strings.TrimSpace(request.TokenHash)

	if request.TokenHash == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_recovery_token",
			"message": "Sesi reset password tidak valid atau sudah kedaluwarsa.",
		})
	}

	if len(request.Password) < 8 || len(request.Password) > 128 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_password",
			"message": "Password harus terdiri dari 8 sampai 128 karakter.",
		})
	}

	if err := h.authService.ResetPassword(
		c.UserContext(),
		request.TokenHash,
		request.Password,
	); err != nil {
		return handleResetPasswordError(c, err)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AuthHandler) ChangePassword(c *fiber.Ctx) error {
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

	var request changePasswordRequest

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_request",
			"message": "Request body tidak valid.",
		})
	}

	if request.OldPassword == "" ||
		request.NewPassword == "" {

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Password lama dan password baru wajib diisi.",
		})
	}

	if len(request.NewPassword) < 8 ||
		len(request.NewPassword) > 128 {

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_password",
			"message": "Password baru harus terdiri dari 8 sampai 128 karakter.",
		})
	}

	if err := h.authService.ChangePassword(
		c.UserContext(),
		identity.User.ID,
		identity.User.Email,
		request.OldPassword,
		request.NewPassword,
	); err != nil {
		return handleChangePasswordError(c, err)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AuthHandler) Refresh(c *fiber.Ctx) error {
	var request refreshRequest

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_request",
			"message": "Request body tidak valid.",
		})
	}

	request.RefreshToken = strings.TrimSpace(request.RefreshToken)

	if request.RefreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Refresh token wajib diisi.",
		})
	}

	result, err := h.authService.Refresh(
		c.UserContext(),
		request.RefreshToken,
	)
	if err != nil {
		return handleRefreshError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(loginResponse{
		AccessToken:  result.Session.AccessToken,
		RefreshToken: result.Session.RefreshToken,
		TokenType:    result.Session.TokenType,
		ExpiresIn:    result.Session.ExpiresIn,
		ExpiresAt:    result.Session.ExpiresAt,
		User:         buildUserResponse(result.Identity),
	})
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
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

	if err := h.authService.Logout(
		c.UserContext(),
		parts[1],
	); err != nil {
		return handleLogoutError(c, err)
	}

	return c.SendStatus(fiber.StatusNoContent)
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

	appContext, err := h.applicationContextService.GetByAppUserID(
		c.UserContext(),
		identity.User.ID,
		models.ApplicationCodeKlinikPKP,
	)
	if err != nil {
		if errors.Is(err, services.ErrApplicationUnavailable) ||
			errors.Is(err, services.ErrApplicationMembershipUnavailable) {

			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
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

	if appContext.Status != models.MembershipStatusApproved {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "klinik_account_unavailable",
			"message": "Pengguna tidak memiliki akses aktif ke Klinik PKP.",
		})
	}

	klinikUser, err := h.klinikContextService.GetByAppUserID(
		c.UserContext(),
		identity.User.ID,
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
			Role:  appContext.Role,
		},
	)
}

func (h *AuthHandler) ApplicationContext(c *fiber.Ctx) error {
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

	applicationCode := strings.TrimSpace(c.Query("application"))
	if applicationCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Parameter application wajib diisi.",
		})
	}

	appContext, err := h.applicationContextService.GetByAppUserID(
		c.UserContext(),
		identity.User.ID,
		applicationCode,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrApplicationUnavailable):
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error":   "application_unavailable",
				"message": "Aplikasi tidak tersedia.",
			})

		case errors.Is(
			err,
			services.ErrApplicationMembershipUnavailable,
		):
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "application_access_unavailable",
				"message": "Pengguna tidak terdaftar pada aplikasi ini.",
			})

		default:
			return c.Status(
				fiber.StatusInternalServerError,
			).JSON(fiber.Map{
				"error":   "internal_error",
				"message": "Terjadi kesalahan pada server.",
			})
		}
	}

	return c.Status(fiber.StatusOK).JSON(appContext)
}

func handleChangePasswordError(
	c *fiber.Ctx,
	err error,
) error {
	switch {
	case errors.Is(err, services.ErrInvalidCurrentPassword):
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_password",
			"message": "Password saat ini tidak benar.",
		})

	case errors.Is(err, services.ErrSamePassword):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "same_password",
			"message": "Password baru harus berbeda dari password sebelumnya.",
		})

	case errors.Is(err, services.ErrInvalidPassword):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_password",
			"message": "Password baru tidak memenuhi ketentuan.",
		})

	case errors.Is(err, services.ErrInvalidToken):
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_token",
			"message": "Sesi autentikasi tidak valid atau sudah kedaluwarsa.",
		})

	case errors.Is(err, services.ErrAuthRateLimited):
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":   "rate_limited",
			"message": "Terlalu banyak permintaan. Coba kembali nanti.",
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

func handleResetPasswordError(
	c *fiber.Ctx,
	err error,
) error {
	switch {
	case errors.Is(err, services.ErrSamePassword):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "same_password",
			"message": "Password baru harus berbeda dari password sebelumnya.",
		})

	case errors.Is(err, services.ErrInvalidPassword):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_password",
			"message": "Password baru tidak memenuhi ketentuan.",
		})

	case errors.Is(err, services.ErrInvalidToken):
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_recovery_token",
			"message": "Sesi reset password tidak valid atau sudah kedaluwarsa.",
		})

	case errors.Is(err, services.ErrAuthRateLimited):
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":   "rate_limited",
			"message": "Terlalu banyak permintaan. Coba kembali nanti.",
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

func handlePasswordRecoveryError(
	c *fiber.Ctx,
	err error,
) error {
	switch {
	case errors.Is(err, services.ErrInvalidRecoveryRequest):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_error",
			"message": "Permintaan reset password tidak valid.",
		})

	case errors.Is(err, services.ErrUnsupportedApplication):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "unsupported_application",
			"message": "Aplikasi tidak didukung.",
		})

	case errors.Is(err, services.ErrAuthRateLimited):
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":   "rate_limited",
			"message": "Terlalu banyak permintaan reset password. Coba kembali nanti.",
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

func handleRefreshError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidToken):
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_refresh_token",
			"message": "Refresh token tidak valid atau sudah kedaluwarsa.",
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
			"message": "Terlalu banyak permintaan autentikasi. Coba kembali nanti.",
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

func handleLogoutError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, services.ErrInvalidToken):
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "invalid_token",
			"message": "Access token tidak valid atau sudah kedaluwarsa.",
		})

	case errors.Is(err, services.ErrAuthRateLimited):
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":   "rate_limited",
			"message": "Terlalu banyak permintaan autentikasi. Coba kembali nanti.",
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
