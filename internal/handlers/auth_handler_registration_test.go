package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

type fakeHandlerRegistrationService struct {
	identity *models.Identity
	err      error
	calls    int
}

func (f *fakeHandlerRegistrationService) Register(
	_ context.Context,
	_ string,
	_ string,
	_ string,
	_ string,
	_ string,
) (*models.Identity, error) {
	f.calls++
	return f.identity, f.err
}

func TestRegisterPreservesPublicResponseContract(t *testing.T) {
	authUserID := "supabase-auth-user-id"
	registration := &fakeHandlerRegistrationService{
		identity: &models.Identity{
			User: &models.AppUser{
				ID:         "internal-app-user-id",
				AuthUserID: &authUserID,
				Email:      "employee@example.com",
				FullName:   "Employee Example",
			},
		},
	}
	authService := &services.AuthService{}
	authService.SetRegistrationService(registration)
	handler := NewAuthHandler(authService, nil, nil)
	app := fiber.New()
	app.Post("/api/v1/auth/register", handler.Register)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/register",
		strings.NewReader(`{
			"email":"employee@example.com",
			"password":"RegistrationPassword123!",
			"fullName":"Employee Example",
			"application":"silapet"
		}`),
	)
	request.Header.Set("Content-Type", "application/json")

	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("perform registration request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", response.StatusCode)
	}

	var payload struct {
		User struct {
			ID       string `json:"id"`
			Email    string `json:"email"`
			FullName string `json:"fullName"`
		} `json:"user"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode registration response: %v", err)
	}

	if registration.calls != 1 ||
		payload.User.ID != "internal-app-user-id" ||
		payload.User.ID == authUserID ||
		payload.User.Email != "employee@example.com" ||
		payload.User.FullName != "Employee Example" {

		t.Fatal("registration response contract or internal user ID changed")
	}
}

func TestRegisterPreservesPublicErrorContract(t *testing.T) {
	tests := []struct {
		name       string
		serviceErr error
		statusCode int
		errorCode  string
	}{
		{
			name:       "account already exists",
			serviceErr: services.ErrAccountAlreadyExists,
			statusCode: http.StatusConflict,
			errorCode:  "account_already_exists",
		},
		{
			name:       "identity conflict",
			serviceErr: services.ErrRegistrationIdentityConflict,
			statusCode: http.StatusConflict,
			errorCode:  "identity_conflict",
		},
		{
			name:       "unsupported application",
			serviceErr: services.ErrUnsupportedApplication,
			statusCode: http.StatusBadRequest,
			errorCode:  "unsupported_application",
		},
		{
			name:       "auth unavailable",
			serviceErr: services.ErrAuthUnavailable,
			statusCode: http.StatusServiceUnavailable,
			errorCode:  "auth_unavailable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registration := &fakeHandlerRegistrationService{
				err: test.serviceErr,
			}
			authService := &services.AuthService{}
			authService.SetRegistrationService(registration)
			handler := NewAuthHandler(authService, nil, nil)
			app := fiber.New()
			app.Post("/api/v1/auth/register", handler.Register)

			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/auth/register",
				strings.NewReader(`{
					"email":"employee@example.com",
					"password":"RegistrationPassword123!",
					"fullName":"Employee Example",
					"application":"silapet"
				}`),
			)
			request.Header.Set("Content-Type", "application/json")

			response, err := app.Test(request)
			if err != nil {
				t.Fatalf("perform registration request: %v", err)
			}
			defer response.Body.Close()

			if response.StatusCode != test.statusCode {
				t.Fatalf(
					"expected status %d, got %d",
					test.statusCode,
					response.StatusCode,
				)
			}

			var payload struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatalf("decode registration error response: %v", err)
			}

			if payload.Error != test.errorCode {
				t.Fatalf("expected error %q, got %q", test.errorCode, payload.Error)
			}
		})
	}
}
