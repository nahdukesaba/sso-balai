package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/services"
)

type fakeHandlerInviteAcceptanceService struct {
	accessToken string
	password    string
	err         error
}

func (f *fakeHandlerInviteAcceptanceService) Accept(
	_ context.Context,
	accessToken string,
	password string,
) error {
	f.accessToken = accessToken
	f.password = password
	return f.err
}

func TestAcceptInviteEndpoint(t *testing.T) {
	inviteService := &fakeHandlerInviteAcceptanceService{}
	authService := &services.AuthService{}
	authService.SetInviteAcceptanceService(inviteService)
	handler := NewAuthHandler(authService, nil, nil)
	app := fiber.New()
	app.Post("/api/v1/auth/accept-invite", handler.AcceptInvite)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/accept-invite",
		strings.NewReader(`{"accessToken":" invite-secret ","password":"valid-password"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.StatusCode)
	}
	if inviteService.accessToken != "invite-secret" || inviteService.password != "valid-password" {
		t.Fatal("handler did not delegate normalized invite request")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "invite-secret") || strings.Contains(string(body), "valid-password") {
		t.Fatal("success response exposed invite credentials")
	}
}

func TestAcceptInviteEndpointRejectsMalformedRequest(t *testing.T) {
	authService := &services.AuthService{}
	authService.SetInviteAcceptanceService(&fakeHandlerInviteAcceptanceService{})
	handler := NewAuthHandler(authService, nil, nil)
	app := fiber.New()
	app.Post("/api/v1/auth/accept-invite", handler.AcceptInvite)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/accept-invite",
		strings.NewReader(`{"accessToken":`),
	)
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", response.StatusCode)
	}
}

func TestAcceptInviteEndpointMapsErrorsWithoutSecrets(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		err        error
		statusCode int
	}{
		{name: "expired token", err: services.ErrInvalidToken, statusCode: http.StatusUnauthorized},
		{name: "invalid password", err: services.ErrInvalidPassword, statusCode: http.StatusBadRequest},
		{name: "upstream unavailable", err: services.ErrAuthUnavailable, statusCode: http.StatusServiceUnavailable},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			authService := &services.AuthService{}
			authService.SetInviteAcceptanceService(
				&fakeHandlerInviteAcceptanceService{err: testCase.err},
			)
			handler := NewAuthHandler(authService, nil, nil)
			app := fiber.New()
			app.Post("/api/v1/auth/accept-invite", handler.AcceptInvite)

			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/auth/accept-invite",
				strings.NewReader(`{"accessToken":"private-invite-token","password":"private-password"}`),
			)
			request.Header.Set("Content-Type", "application/json")
			response, err := app.Test(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()

			if response.StatusCode != testCase.statusCode {
				t.Fatalf("expected status %d, got %d", testCase.statusCode, response.StatusCode)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "private-invite-token") ||
				strings.Contains(string(body), "private-password") {

				t.Fatal("error response exposed invite credentials")
			}
		})
	}
}
