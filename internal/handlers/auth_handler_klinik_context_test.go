package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/middleware"
	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

type handlerKlinikIdentityStore struct {
	identity *models.KlinikIdentity
}

func (f *handlerKlinikIdentityStore) GetByAppUserID(
	context.Context,
	string,
) (*models.KlinikIdentity, error) {
	return f.identity, nil
}

func TestKlinikContextReturnsCanonicalProjection(t *testing.T) {
	phone := "08123456789"
	nip := "198001012010011001"
	identity := &models.KlinikIdentity{
		AppUserID:       "app-user-1",
		AuthUserID:      "auth-user-1",
		Email:           "pegawai@example.com",
		FullName:        "Pegawai Klinik",
		Phone:           &phone,
		NIP:             &nip,
		ApplicationCode: models.ApplicationCodeKlinikPKP,
		Role:            "user",
		Status:          models.MembershipStatusApproved,
	}
	service := services.NewKlinikContextService(
		&handlerKlinikIdentityStore{identity: identity},
	)
	handler := NewAuthHandler(nil, service, nil)
	app := fiber.New()
	app.Get("/api/v1/auth/klinik-context", func(c *fiber.Ctx) error {
		c.Locals(middleware.AuthenticatedIdentityKey, &models.Identity{
			User: &models.AppUser{ID: identity.AppUserID},
		})
		return c.Next()
	}, handler.KlinikContext)

	response, err := app.Test(httptest.NewRequest(
		http.MethodGet,
		"/api/v1/auth/klinik-context",
		nil,
	))
	if err != nil {
		t.Fatalf("perform Klinik context request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode Klinik context response: %v", err)
	}
	for key, want := range map[string]string{
		"id":         identity.AppUserID,
		"appUserId":  identity.AppUserID,
		"authUserId": identity.AuthUserID,
		"email":      identity.Email,
		"fullName":   identity.FullName,
		"phone":      phone,
		"nip":        nip,
		"role":       identity.Role,
		"status":     identity.Status,
	} {
		if got := payload[key]; got != want {
			t.Errorf("expected %s=%q, got %#v", key, want, got)
		}
	}
	if _, exists := payload["localUserId"]; exists {
		t.Fatal("canonical Klinik context must not expose or require a local user ID")
	}
}
