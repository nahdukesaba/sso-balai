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

type fakeHandlerRequestAccessService struct {
	result      *models.ApplicationEnrollmentResult
	err         error
	email       string
	password    string
	application string
	calls       int
}

func (f *fakeHandlerRequestAccessService) Request(
	_ context.Context,
	email string,
	password string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	f.calls++
	f.email = email
	f.password = password
	f.application = applicationCode
	return f.result, f.err
}

func TestRequestAccessResponseDoesNotExposeSupabaseSessionOrRole(t *testing.T) {
	requestAccess := &fakeHandlerRequestAccessService{
		result: &models.ApplicationEnrollmentResult{
			Application: "silapet",
			Status:      models.MembershipStatusPending,
			Outcome:     models.ApplicationEnrollmentCreated,
		},
	}
	authService := &services.AuthService{}
	authService.SetRequestAccessService(requestAccess)
	handler := NewAuthHandler(authService, nil, nil)
	app := fiber.New()
	app.Post("/api/v1/auth/request-access", handler.RequestAccess)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/request-access",
		strings.NewReader(`{
			"email":" Employee@Example.com ",
			"password":"correct-password",
			"application":" SILAPET "
		}`),
	)
	request.Header.Set("Content-Type", "application/json")

	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("perform request-access request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.StatusCode)
	}

	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode request-access response: %v", err)
	}
	if payload["application"] != "silapet" ||
		payload["status"] != models.MembershipStatusPending ||
		payload["created"] != true ||
		payload["message"] != "Permintaan akses berhasil dikirim." {
		t.Fatalf("unexpected response payload: %#v", payload)
	}
	for _, forbidden := range []string{
		"accessToken",
		"refreshToken",
		"token",
		"app_roles",
		"role",
	} {
		if _, exists := payload[forbidden]; exists {
			t.Fatalf("response exposed %q", forbidden)
		}
	}
	if requestAccess.email != "employee@example.com" ||
		requestAccess.password != "correct-password" ||
		requestAccess.application != "silapet" {
		t.Fatal("handler did not normalize/delegate request contract")
	}
}

func TestRequestAccessCreatedFlagFollowsEnrollmentOutcome(t *testing.T) {
	tests := []struct {
		name    string
		outcome models.ApplicationEnrollmentOutcome
		created bool
	}{
		{
			name:    "soft deleted membership reopened",
			outcome: models.ApplicationEnrollmentReopened,
			created: true,
		},
		{
			name:    "existing pending membership",
			outcome: models.ApplicationEnrollmentAlreadyPending,
			created: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestAccess := &fakeHandlerRequestAccessService{
				result: &models.ApplicationEnrollmentResult{
					Application: "silapet",
					Status:      models.MembershipStatusPending,
					Outcome:     test.outcome,
				},
			}
			authService := &services.AuthService{}
			authService.SetRequestAccessService(requestAccess)
			handler := NewAuthHandler(authService, nil, nil)
			app := fiber.New()
			app.Post("/api/v1/auth/request-access", handler.RequestAccess)

			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/auth/request-access",
				strings.NewReader(`{
					"email":"employee@example.com",
					"password":"password",
					"application":"silapet"
				}`),
			)
			request.Header.Set("Content-Type", "application/json")

			response, err := app.Test(request)
			if err != nil {
				t.Fatalf("perform request: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("expected status 200, got %d", response.StatusCode)
			}

			var payload struct {
				Created bool `json:"created"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if payload.Created != test.created {
				t.Fatalf("expected created=%v, got %v", test.created, payload.Created)
			}
		})
	}
}

func TestRequestAccessErrorContract(t *testing.T) {
	tests := []struct {
		name       string
		serviceErr error
		statusCode int
		errorCode  string
	}{
		{
			name:       "invalid credentials",
			serviceErr: services.ErrInvalidCredentials,
			statusCode: http.StatusUnauthorized,
			errorCode:  "invalid_credentials",
		},
		{
			name:       "application unavailable",
			serviceErr: services.ErrApplicationEnrollmentUnavailable,
			statusCode: http.StatusNotFound,
			errorCode:  "application_unavailable",
		},
		{
			name:       "access already granted",
			serviceErr: services.ErrApplicationAccessAlreadyGranted,
			statusCode: http.StatusConflict,
			errorCode:  "application_access_exists",
		},
		{
			name:       "rejected membership",
			serviceErr: services.ErrApplicationEnrollmentBlocked,
			statusCode: http.StatusForbidden,
			errorCode:  "application_access_blocked",
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
			requestAccess := &fakeHandlerRequestAccessService{err: test.serviceErr}
			authService := &services.AuthService{}
			authService.SetRequestAccessService(requestAccess)
			handler := NewAuthHandler(authService, nil, nil)
			app := fiber.New()
			app.Post("/api/v1/auth/request-access", handler.RequestAccess)

			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/auth/request-access",
				strings.NewReader(`{
					"email":"employee@example.com",
					"password":"password",
					"application":"silapet"
				}`),
			)
			request.Header.Set("Content-Type", "application/json")
			response, err := app.Test(request)
			if err != nil {
				t.Fatalf("perform request: %v", err)
			}
			defer response.Body.Close()

			if response.StatusCode != test.statusCode {
				t.Fatalf("expected status %d, got %d", test.statusCode, response.StatusCode)
			}
			var payload struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if payload.Error != test.errorCode {
				t.Fatalf("expected error %q, got %q", test.errorCode, payload.Error)
			}
		})
	}
}
