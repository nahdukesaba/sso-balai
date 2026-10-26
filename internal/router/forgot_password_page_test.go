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
		!strings.HasPrefix(response.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("forgot-password page is not wired to Central recovery: status=%d", response.StatusCode)
	}
	for _, expected := range []string{
		"<title>Lupa password - Akun Balai Pegawai</title>",
		"BP3KP Sumatera II · Akun Balai Pegawai",
		"<h1>Lupa Password</h1>",
		`<label for="email">Email</label>`,
		`<button id="submit" type="submit">Kirim</button>`,
		`href="/account/login">Login</a>`,
		"Mengirim...",
		"Permintaan Tidak Dapat Diproses !",
		"Jika email terdaftar, instruksi reset password akan dikirim",
		"/api/v1/auth/forgot-password",
	} {
		if !strings.Contains(html, expected) {
			t.Fatalf("forgot-password page missing %q", expected)
		}
	}
	if strings.Contains(html, "Masukkan email Akun Balai") || strings.Contains(html, "Kembali ke Akun Balai") {
		t.Fatal("forgot-password page still contains removed copy")
	}
	if strings.Contains(html, "RESEND") || strings.Contains(html, "localStorage") {
		t.Fatal("forgot-password page contains a legacy or persistent recovery path")
	}
}
