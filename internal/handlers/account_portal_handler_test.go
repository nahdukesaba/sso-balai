package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

type handlerPortalApplications struct {
	applications    []models.PortalApplicationAccess
	requestedUserID string
}

func (s *handlerPortalApplications) ListForPortalUser(
	_ context.Context,
	appUserID string,
) ([]models.PortalApplicationAccess, error) {
	s.requestedUserID = appUserID
	return s.applications, nil
}

func newAccountPortalHandler(
	t *testing.T,
	session *models.BrowserSSOSession,
	loginSession *models.SupabaseSession,
	applications []models.PortalApplicationAccess,
) (*BrowserSSOHandler, *handlerBrowserSSOStore, *handlerPortalApplications) {
	t.Helper()
	handler, store := newHandlerBrowserSSOTestSetup(
		t,
		session,
		"http://localhost:8081/auth/sso/callback",
		loginSession,
	)
	applicationStore := &handlerPortalApplications{applications: applications}
	portal, err := services.NewAccountPortalService(
		handler.service,
		applicationStore,
		"http://silapet.test:8081/api/auth/sso/start",
		"http://klinik-pkp.test:3000/api/auth/sso/start",
	)
	if err != nil {
		t.Fatalf("create account portal: %v", err)
	}
	handler.SetAccountPortalService(portal)
	return handler, store, applicationStore
}

func TestAccountPortalLoggedOutForMissingRevokedOrExpiredSession(t *testing.T) {
	tests := []struct {
		name    string
		session *models.BrowserSSOSession
		revoked bool
		cookie  bool
	}{
		{name: "missing"},
		{name: "revoked", session: &models.BrowserSSOSession{AuthUserID: "auth-user", AppUserID: "app-user"}, revoked: true, cookie: true},
		{name: "expired", session: &models.BrowserSSOSession{AuthUserID: "auth-user", AppUserID: "app-user", ExpiresAt: time.Now().Add(-time.Minute)}, cookie: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, store, _ := newAccountPortalHandler(t, test.session, nil, nil)
			store.revoked = test.revoked
			app := fiber.New()
			app.Get("/", handler.PortalHome)
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if test.cookie {
				request.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "opaque-session"})
			}
			response, err := app.Test(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			html := string(body)
			if response.StatusCode != http.StatusOK || !strings.Contains(html, "Akun Balai") ||
				!strings.Contains(html, `href="/account/login"`) || strings.Contains(html, "Pegawai Contoh") {
				t.Fatalf("unexpected logged-out portal: status=%d body=%q", response.StatusCode, html)
			}
		})
	}
}

func TestAccountPortalShowsCurrentIdentityAndApplicationSpecificAccess(t *testing.T) {
	handler, _, applicationStore := newAccountPortalHandler(
		t,
		&models.BrowserSSOSession{AuthUserID: "auth-user", AppUserID: "app-user", ExpiresAt: time.Now().Add(time.Hour)},
		nil,
		[]models.PortalApplicationAccess{
			{Code: "silapet", Name: "Raw SILAPET", Role: "admin", Status: models.MembershipStatusApproved, HasMembership: true},
			{Code: "klinik_pkp", Name: "Klinik PKP", Role: "user", Status: models.MembershipStatusPending, HasMembership: true},
			{Code: "arsiparis", Name: "Arsiparis"},
		},
	)
	app := fiber.New()
	app.Get("/", handler.PortalHome)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "opaque-session"})
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	html := string(body)
	for _, expected := range []string{
		"Pegawai Contoh", "person@example.com", "SILAPET", "Akses aktif", "Role: Admin",
		"Klinik PKP", "Menunggu persetujuan", "Role: Pengguna", "Belum memiliki akses",
		"Portal layanan informasi, konsultasi, dan pendampingan teknis BP3KP Sumatera II untuk sektor perumahan dan kawasan permukiman.",
		`href="http://silapet.test:8081/api/auth/sso/start"`, `href="/logout?portal=1"`,
	} {
		if !strings.Contains(html, expected) {
			t.Fatalf("portal missing %q: %s", expected, html)
		}
	}
	if applicationStore.requestedUserID != "app-user" {
		t.Fatalf("applications queried for wrong user: %q", applicationStore.requestedUserID)
	}
	if strings.Contains(html, "auth-user") || strings.Contains(html, "app-user") {
		t.Fatal("internal identity IDs leaked to portal HTML")
	}
	if strings.Contains(html, `href="http://klinik-pkp.test:3000/api/auth/sso/start"`) {
		t.Fatal("pending Klinik membership received a launch link")
	}
}

func TestAccountPortalLoginCreatesBrowserSession(t *testing.T) {
	handler, store, _ := newAccountPortalHandler(t, nil, &models.SupabaseSession{
		AccessToken: "transient-access",
		User:        models.SupabaseAuthUser{ID: "auth-user"},
	}, nil)
	app := fiber.New()
	app.Get("/account/login", handler.PortalLoginPage)
	app.Post("/account/login", handler.PortalLoginSubmit)

	pageResponse, err := app.Test(httptest.NewRequest(http.MethodGet, "/account/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	csrfCookie := responseCookie(pageResponse, accountPortalLoginCSRF)
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatal("portal login did not issue CSRF cookie")
	}
	form := url.Values{
		"csrf": {csrfCookie.Value}, "email": {"person@example.com"}, "password": {"password"},
	}
	request := httptest.NewRequest(http.MethodPost, "/account/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/" || store.session == nil {
		t.Fatalf("portal login failed: status=%d location=%q session=%#v", response.StatusCode, response.Header.Get("Location"), store.session)
	}
	sessionCookie := responseCookie(response, browserSSOSessionCookie)
	if sessionCookie == nil || sessionCookie.Value == "" || !sessionCookie.HttpOnly || sessionCookie.Path != "/" {
		t.Fatalf("unexpected portal session cookie: %#v", sessionCookie)
	}
}

func TestAccountPortalLoginRejectsInvalidCredentialsAndCSRF(t *testing.T) {
	handler, store, _ := newAccountPortalHandler(t, nil, nil, nil)
	app := fiber.New()
	app.Get("/account/login", handler.PortalLoginPage)
	app.Post("/account/login", handler.PortalLoginSubmit)

	invalidCSRFRequest := httptest.NewRequest(http.MethodPost, "/account/login", strings.NewReader("csrf=wrong"))
	invalidCSRFRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalidCSRFRequest.AddCookie(&http.Cookie{Name: accountPortalLoginCSRF, Value: "expected"})
	invalidCSRFResponse, err := app.Test(invalidCSRFRequest)
	if err != nil {
		t.Fatal(err)
	}
	if invalidCSRFResponse.StatusCode != http.StatusForbidden || store.session != nil {
		t.Fatalf("invalid CSRF was not rejected: %d", invalidCSRFResponse.StatusCode)
	}

	pageResponse, err := app.Test(httptest.NewRequest(http.MethodGet, "/account/login", nil))
	if err != nil {
		t.Fatal(err)
	}
	csrfCookie := responseCookie(pageResponse, accountPortalLoginCSRF)
	form := url.Values{"csrf": {csrfCookie.Value}, "email": {"person@example.com"}, "password": {"wrong"}}
	request := httptest.NewRequest(http.MethodPost, "/account/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Email atau password tidak valid") || store.session != nil {
		t.Fatalf("invalid credentials were not rejected safely: status=%d", response.StatusCode)
	}
}

func TestAccountPortalLogoutReturnsToPortal(t *testing.T) {
	handler, store, _ := newAccountPortalHandler(t,
		&models.BrowserSSOSession{AuthUserID: "auth-user", AppUserID: "app-user"}, nil, nil)
	app := fiber.New()
	app.Get("/logout", handler.LogoutPage)
	app.Post("/logout", handler.LogoutSubmit)

	pageRequest := httptest.NewRequest(http.MethodGet, "/logout?portal=1", nil)
	pageRequest.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "opaque-session"})
	pageResponse, err := app.Test(pageRequest)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, err := io.ReadAll(pageResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pageBody), `name="portal" value="1"`) ||
		!strings.Contains(string(pageBody), `href="/"`) {
		t.Fatalf("portal logout context was not preserved: %s", string(pageBody))
	}
	csrfCookie := responseCookie(pageResponse, browserSSOLogoutCSRF)
	form := url.Values{"csrf": {csrfCookie.Value}, "portal": {"1"}}
	request := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	request.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "opaque-session"})
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/" || store.revokeCalls != 1 {
		t.Fatalf("unexpected portal logout: status=%d location=%q calls=%d", response.StatusCode, response.Header.Get("Location"), store.revokeCalls)
	}
}
