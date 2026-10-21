package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/services"
)

type fakeHandlerPasswordRecoveryService struct {
	emails []string
}

func (f *fakeHandlerPasswordRecoveryService) Request(
	_ context.Context,
	email string,
) error {
	f.emails = append(f.emails, email)
	return nil
}

func (f *fakeHandlerPasswordRecoveryService) Reset(
	_ context.Context,
	_ string,
	_ string,
) error {
	return nil
}

func TestForgotPasswordUsesGenericResponse(t *testing.T) {
	recovery := &fakeHandlerPasswordRecoveryService{}
	authService := &services.AuthService{}
	authService.SetPasswordRecoveryService(recovery)
	handler := NewAuthHandler(authService, nil, nil)
	app := fiber.New()
	app.Post("/api/v1/auth/forgot-password", handler.ForgotPassword)

	requests := []string{
		`{"email":"known@example.com","application":"silapet"}`,
		`{"email":"unknown@example.com","application":"klinik_pkp"}`,
	}
	var expectedMessage string

	for _, body := range requests {
		request := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/auth/forgot-password",
			strings.NewReader(body),
		)
		request.Header.Set("Content-Type", "application/json")

		response, err := app.Test(request)
		if err != nil {
			t.Fatalf("perform forgot password request: %v", err)
		}
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", response.StatusCode)
		}

		var payload struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			t.Fatalf("decode response: %v", err)
		}

		if expectedMessage == "" {
			expectedMessage = payload.Message
		}
		if payload.Message != expectedMessage {
			t.Fatal("forgot password response varies by account or application")
		}
	}

	if len(recovery.emails) != 2 {
		t.Fatalf("expected two recovery delegations, got %d", len(recovery.emails))
	}
}
