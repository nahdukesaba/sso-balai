package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/middleware"
	"github.com/nahdukesaba/sso-balai/internal/repository"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

type KlinikAdminUserHandler struct {
	service *services.KlinikAdminUserService
}

func NewKlinikAdminUserHandler(service *services.KlinikAdminUserService) *KlinikAdminUserHandler {
	return &KlinikAdminUserHandler{service: service}
}

type provisionKlinikUserRequest struct {
	Email         string `json:"email"`
	FullName      string `json:"fullName"`
	Phone         string `json:"phone"`
	NIP           string `json:"nip"`
	NIK           string `json:"nik"`
	Alamat        string `json:"alamat"`
	GelarDepan    string `json:"gelarDepan"`
	GelarBelakang string `json:"gelarBelakang"`
	Role          string `json:"role"`
	Status        string `json:"status"`
}

func (h *KlinikAdminUserHandler) Provision(c *fiber.Ctx) error {
	identity, ok := middleware.GetAuthenticatedIdentity(c)
	if !ok || identity == nil || identity.User == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized", "message": "Autentikasi diperlukan."})
	}
	var request provisionKlinikUserRequest
	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid_request", "message": "Payload pengguna tidak valid."})
	}
	result, err := h.service.Provision(c.UserContext(), identity.User.ID, services.KlinikAdminProvisioningInput{
		Email: request.Email, FullName: request.FullName, Phone: request.Phone,
		NIP: request.NIP, NIK: request.NIK, Alamat: request.Alamat,
		GelarDepan: request.GelarDepan, GelarBelakang: request.GelarBelakang,
		Role: request.Role, Status: request.Status,
	})
	if err != nil {
		switch {
		case errors.Is(err, services.ErrKlinikAdminForbidden):
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden", "message": "Akses admin Klinik diperlukan."})
		case errors.Is(err, services.ErrInvalidKlinikProvisioningRequest):
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "validation_error", "message": "Data pengguna Klinik tidak valid."})
		case errors.Is(err, repository.ErrKlinikProvisioningConflict):
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "identity_conflict", "message": "Identitas pengguna tidak dapat dipetakan dengan aman."})
		case errors.Is(err, services.ErrAuthUnavailable):
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "auth_unavailable", "message": "Layanan identitas sedang tidak tersedia."})
		case errors.Is(err, repository.ErrKlinikApplicationUnavailable):
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "klinik_application_unavailable", "message": "Aplikasi Klinik sedang tidak tersedia."})
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal_error", "message": "Terjadi kesalahan pada server."})
		}
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"data": result})
}
