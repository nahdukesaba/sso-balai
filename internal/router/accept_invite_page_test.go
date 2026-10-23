package router

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/handlers"
	"github.com/nahdukesaba/sso-balai/internal/middleware"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

func TestCentralAcceptInvitePageIsPubliclyAvailable(t *testing.T) {
	authService := &services.AuthService{}
	authHandler := handlers.NewAuthHandler(authService, nil, nil)
	authMiddleware := middleware.NewAuthMiddleware(authService)
	app := fiber.New()
	Register(app, authHandler, authMiddleware)

	request := httptest.NewRequest(
		http.MethodGet,
		"/accept-invite?access_token=must-not-be-rendered",
		nil,
	)
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("request accept invite page: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.StatusCode)
	}
	if response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("Referrer-Policy") != "no-referrer" {

		t.Fatal("accept invite page is missing secure cache/referrer headers")
	}
	csp := response.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") ||
		!strings.Contains(csp, "base-uri 'none'") {

		t.Fatalf("accept invite page has incomplete CSP: %q", csp)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	for _, expected := range []string{
		"Aktivasi Akun Balai",
		"activation-form",
		"window.location.hash",
		"history.replaceState",
		"type')",
		"access_token",
		"/api/v1/auth/accept-invite",
		"http://localhost:3000/login",
	} {
		if !strings.Contains(html, expected) {
			t.Fatalf("accept invite page is missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"must-not-be-rendered",
		"localStorage",
		"sessionStorage",
	} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("accept invite page contains forbidden value %q", forbidden)
		}
	}
}
