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

func TestCentralForgotPasswordPageUsesExistingRecoveryAPI(t *testing.T) {
	authService := &services.AuthService{}
	authHandler := handlers.NewAuthHandler(authService, nil, nil)
	authMiddleware := middleware.NewAuthMiddleware(authService)
	app := fiber.New()
	Register(app, authHandler, authMiddleware)

	response, err := app.Test(httptest.NewRequest(http.MethodGet, "/forgot-password", nil))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	if response.StatusCode != http.StatusOK ||
		!strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") ||
		!strings.Contains(html, "/api/v1/auth/forgot-password") ||
		!strings.Contains(html, "Jika email terdaftar") {
		t.Fatalf("forgot-password page is not wired to Central recovery: status=%d", response.StatusCode)
	}
	if strings.Contains(html, "RESEND") || strings.Contains(html, "localStorage") {
		t.Fatal("forgot-password page contains a legacy or persistent recovery path")
	}
}
