package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/services"
)

func newOIDCTestApp(t *testing.T) *fiber.App {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider, err := services.NewOIDCProvider("https://sso.example.test", keyPEM, newHandlerBrowserSSO(t, nil).service)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewOIDCHandler(provider)
	app := fiber.New()
	app.Get("/.well-known/openid-configuration", handler.Discovery)
	app.Post("/oauth/token", handler.Token)
	app.Get("/oauth/userinfo", handler.UserInfo)
	return app
}

func postToken(t *testing.T, app *fiber.App, form url.Values, basic string) *http.Response {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic != "" {
		request.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basic)))
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func oauthErrorCode(t *testing.T, response *http.Response) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body.Error
}

func TestOIDCHandlerDiscovery(t *testing.T) {
	app := newOIDCTestApp(t)
	response, err := app.Test(httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if err != nil {
		t.Fatal(err)
	}
	var discovery map[string]any
	if err := json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || discovery["issuer"] != "https://sso.example.test" ||
		response.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("unexpected discovery: %d %#v", response.StatusCode, discovery)
	}
}

func TestOIDCHandlerTokenErrors(t *testing.T) {
	app := newOIDCTestApp(t)

	response := postToken(t, app, url.Values{"grant_type": {"password"}}, "")
	if response.StatusCode != http.StatusBadRequest || oauthErrorCode(t, response) != "unsupported_grant_type" {
		t.Fatalf("unsupported grant: %d", response.StatusCode)
	}

	form := url.Values{"grant_type": {"authorization_code"}, "code": {"code"}}
	response = postToken(t, app, form, "silapet-web:wrong-secret")
	if response.StatusCode != http.StatusUnauthorized || oauthErrorCode(t, response) != "invalid_client" ||
		!strings.HasPrefix(response.Header.Get("WWW-Authenticate"), "Basic") ||
		response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("wrong basic secret: %d %q", response.StatusCode, response.Header.Get("WWW-Authenticate"))
	}

	form.Set("client_secret", "also-in-form")
	response = postToken(t, app, form, "silapet-web:handler-test-introspection-secret-0001")
	if response.StatusCode != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_request" {
		t.Fatalf("two client authentication methods accepted: %d", response.StatusCode)
	}

	form = url.Values{
		"grant_type": {"authorization_code"}, "code": {"unknown"}, "client_id": {"silapet-web"},
		"client_secret": {"handler-test-introspection-secret-0001"}, "redirect_uri": {"http://localhost:8081/auth/sso/callback"},
		"code_verifier": {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"},
	}
	response = postToken(t, app, form, "")
	if response.StatusCode != http.StatusBadRequest || oauthErrorCode(t, response) != "invalid_grant" {
		t.Fatalf("unknown code: %d", response.StatusCode)
	}
}

func TestOIDCHandlerUserInfoRequiresBearerToken(t *testing.T) {
	app := newOIDCTestApp(t)
	for _, header := range []string{"", "Basic abc", "Bearer not-a-jwt"} {
		request := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(response.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("userinfo with %q: %d", header, response.StatusCode)
		}
	}
}
