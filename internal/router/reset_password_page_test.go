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

func TestCentralResetPasswordPageIsPubliclyAvailable(t *testing.T) {
	authService := &services.AuthService{}
	authHandler := handlers.NewAuthHandler(authService, nil, nil)
	authMiddleware := middleware.NewAuthMiddleware(authService)
	app := fiber.New()
	Register(app, authHandler, authMiddleware)

	request := httptest.NewRequest(
		http.MethodGet,
		"/reset-password?token_hash=secret-recovery-hash",
		nil,
	)
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("request reset page: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", response.StatusCode)
	}

	if !strings.HasPrefix(
		response.Header.Get("Content-Type"),
		"text/html",
	) {

		t.Fatalf(
			"expected HTML content type, got %q",
			response.Header.Get("Content-Type"),
		)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read reset page: %v", err)
	}

	html := string(body)
	if !strings.Contains(html, "token_hash") ||
		!strings.Contains(html, "/api/v1/auth/reset-password") {

		t.Fatal("reset page does not implement the central recovery flow")
	}

	if strings.Contains(html, "secret-recovery-hash") {
		t.Fatal("reset page rendered the recovery token")
	}

	if strings.Contains(html, "localStorage") {
		t.Fatal("reset page persists the recovery token in localStorage")
	}
}
