package handlers

import (
	"context"
	"encoding/base64"
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

type handlerBrowserSSOStore struct {
	session         *models.BrowserSSOSession
	revoked         bool
	revokeCalls     int
	lastRevokeHash  []byte
	unrelatedActive bool
}

func (s *handlerBrowserSSOStore) CreateSession(_ context.Context, session *models.BrowserSSOSession) error {
	s.session = session
	return nil
}
func (s *handlerBrowserSSOStore) GetActiveSessionByTokenHash(context.Context, []byte) (*models.BrowserSSOSession, error) {
	if s.revoked || (s.session != nil && !s.session.ExpiresAt.IsZero() && !s.session.ExpiresAt.After(time.Now())) {
		return nil, nil
	}
	return s.session, nil
}
func (s *handlerBrowserSSOStore) GetActiveSessionByID(context.Context, string) (*models.BrowserSSOSession, error) {
	if s.revoked {
		return nil, nil
	}
	return s.session, nil
}
func (s *handlerBrowserSSOStore) RevokeSession(_ context.Context, tokenHash []byte) error {
	s.revokeCalls++
	s.lastRevokeHash = append([]byte(nil), tokenHash...)
	s.revoked = true
	return nil
}
func (s *handlerBrowserSSOStore) CreateAuthorizationCode(_ context.Context, code *models.BrowserSSOAuthorizationCode) error {
	code.ExpiresAt = time.Now().Add(time.Minute)
	return nil
}
func (s *handlerBrowserSSOStore) ConsumeAuthorizationCode(context.Context, []byte, string, string, string) (*models.BrowserSSOAuthorizationCode, error) {
	return nil, nil
}

type handlerBrowserSSOAuth struct {
	session *models.SupabaseSession
}

func (a *handlerBrowserSSOAuth) SignInWithPassword(context.Context, string, string) (*models.SupabaseSession, error) {
	return a.session, nil
}
func (*handlerBrowserSSOAuth) SignOut(context.Context, string) error { return nil }

type handlerBrowserSSOSessionIssuer struct{}

func (handlerBrowserSSOSessionIssuer) IssueSession(context.Context, string) (*models.SupabaseSession, error) {
	return nil, nil
}

type handlerBrowserSSOUsers struct{}

func (handlerBrowserSSOUsers) GetByAuthUserID(context.Context, string) (*models.AppUser, error) {
	return &models.AppUser{ID: "app-user", Email: "person@example.com"}, nil
}

type handlerBrowserSSOApplications struct{}

func (handlerBrowserSSOApplications) GetByAppUserID(context.Context, string, string) (*models.ApplicationContext, error) {
	return &models.ApplicationContext{Status: models.MembershipStatusApproved}, nil
}

type handlerBrowserSSOEnrollments struct{}

func (handlerBrowserSSOEnrollments) Request(context.Context, string, string) (*models.ApplicationEnrollmentResult, error) {
	return nil, nil
}

type handlerBrowserSSOIdentities struct{}

func (handlerBrowserSSOIdentities) GetByUserID(context.Context, string) (*models.Identity, error) {
	return &models.Identity{User: &models.AppUser{
		ID: "app-user", Email: "person@example.com", FullName: "Pegawai Contoh",
	}}, nil
}

func newHandlerBrowserSSO(t *testing.T, session *models.BrowserSSOSession) *BrowserSSOHandler {
	return newHandlerBrowserSSOWithOptions(
		t,
		session,
		"http://localhost:8081/auth/sso/callback",
		nil,
	)
}

func newHandlerBrowserSSOWithOptions(
	t *testing.T,
	browserSession *models.BrowserSSOSession,
	redirectURI string,
	loginSession *models.SupabaseSession,
) *BrowserSSOHandler {
	handler, _ := newHandlerBrowserSSOTestSetup(
		t,
		browserSession,
		redirectURI,
		loginSession,
	)
	return handler
}

func newHandlerBrowserSSOTestSetup(
	t *testing.T,
	browserSession *models.BrowserSSOSession,
	redirectURI string,
	loginSession *models.SupabaseSession,
) (*BrowserSSOHandler, *handlerBrowserSSOStore) {
	t.Helper()
	store := &handlerBrowserSSOStore{
		session: browserSession, unrelatedActive: true,
	}
	service, err := services.NewBrowserSSOService(
		store,
		&handlerBrowserSSOAuth{session: loginSession},
		handlerBrowserSSOSessionIssuer{},
		handlerBrowserSSOUsers{},
		handlerBrowserSSOApplications{},
		handlerBrowserSSOEnrollments{},
		handlerBrowserSSOIdentities{},
		services.BrowserSSOConfig{
			Clients: []services.BrowserSSOClient{
				{
					IntrospectionSecret:    "handler-test-introspection-secret-0001",
					ClientID:               "silapet-web",
					ApplicationCode:        "silapet",
					RedirectURIs:           []string{redirectURI},
					PostLogoutRedirectURIs: []string{"http://localhost:8081/login", "http://silapet.test:8080/login"},
				},
				{
					ClientID:               "klinik-pkp-web",
					ApplicationCode:        "klinik_pkp",
					IntrospectionSecret:    "klinik-test-introspection-secret-00001",
					RedirectURIs:           []string{"http://localhost:3000/auth/sso/callback"},
					PostLogoutRedirectURIs: []string{"http://localhost:3000/login", "http://klinik-pkp.test:3000/login"},
				},
			},
			SessionTTL: time.Hour, CodeTTL: 3 * time.Minute,
			EncryptionKey: base64.StdEncoding.EncodeToString(
				[]byte("01234567890123456789012345678901"),
			),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return NewBrowserSSOHandler(service, false, "Lax", time.Hour), store
}

func authorizeTarget() string {
	return authorizeTargetFor("http://localhost:8081/auth/sso/callback")
}

func mustRequestParameter(t *testing.T, location string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	value := parsed.Query().Get("request")
	if value == "" {
		t.Fatalf("missing sealed request in redirect %q", location)
	}
	return value
}

func authorizeTargetFor(redirectURI string) string {
	query := url.Values{
		"client_id":             {"silapet-web"},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"state":                 {"browser-state"},
		"code_challenge":        {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"},
		"code_challenge_method": {"S256"},
	}
	return "/authorize?" + query.Encode()
}

func TestBrowserSSOLoginPageCSPAllowsOnlyRegisteredCallbackOrigin(t *testing.T) {
	redirectURI := "http://localhost:8081/auth/sso/callback?source=central"
	handler := newHandlerBrowserSSOWithOptions(t, nil, redirectURI, nil)
	app := fiber.New()
	app.Get("/authorize", handler.Authorize)
	app.Get("/login", handler.LoginPage)

	authorizeResponse, err := app.Test(httptest.NewRequest(
		http.MethodGet,
		authorizeTargetFor(redirectURI),
		nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	loginResponse, err := app.Test(httptest.NewRequest(
		http.MethodGet,
		"/login?request="+url.QueryEscape(mustRequestParameter(t, authorizeResponse.Header.Get("Location"))),
		nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	csp := loginResponse.Header.Get("Content-Security-Policy")
	if loginResponse.StatusCode != http.StatusOK ||
		!strings.Contains(csp, "form-action 'self' http://localhost:8081;") {
		t.Fatalf("unexpected login CSP: %d %q", loginResponse.StatusCode, csp)
	}
	if strings.Contains(csp, "/auth/sso/callback") || strings.Contains(csp, "source=central") {
		t.Fatalf("CSP must contain only the callback origin: %q", csp)
	}
}

func TestBrowserSSOLoginCSPNeverUsesUnregisteredOrigin(t *testing.T) {
	handler := newHandlerBrowserSSO(t, nil)
	app := fiber.New()
	app.Get("/authorize", handler.Authorize)
	response, err := app.Test(httptest.NewRequest(
		http.MethodGet,
		authorizeTargetFor("https://evil.example/callback"),
		nil,
	))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest ||
		strings.Contains(response.Header.Get("Content-Security-Policy"), "evil.example") {
		t.Fatalf("unregistered origin reached CSP: %d %q", response.StatusCode, response.Header.Get("Content-Security-Policy"))
	}
}

func TestBrowserSSOLoginPostPreservesRedirectAndCookieFlags(t *testing.T) {
	handler := newHandlerBrowserSSOWithOptions(t, nil,
		"http://localhost:8081/auth/sso/callback",
		&models.SupabaseSession{
			AccessToken: "transient-access",
			User:        models.SupabaseAuthUser{ID: "auth-user"},
		},
	)
	app := fiber.New()
	app.Get("/authorize", handler.Authorize)
	app.Get("/login", handler.LoginPage)
	app.Post("/login", handler.LoginSubmit)

	authorizeResponse, err := app.Test(httptest.NewRequest(http.MethodGet, authorizeTarget(), nil))
	if err != nil {
		t.Fatal(err)
	}
	sealedRequest := mustRequestParameter(t, authorizeResponse.Header.Get("Location"))
	loginResponse, err := app.Test(httptest.NewRequest(http.MethodGet, "/login?request="+url.QueryEscape(sealedRequest), nil))
	if err != nil {
		t.Fatal(err)
	}
	var csrfCookie *http.Cookie
	for _, cookie := range loginResponse.Cookies() {
		if cookie.Name == browserSSOCSRFCookie {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatal("login page did not set the CSRF cookie")
	}

	form := url.Values{
		"request":  {sealedRequest},
		"csrf":     {csrfCookie.Value},
		"email":    {"person@example.com"},
		"password": {"password"},
	}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSeeOther || location.Path != "/authorize/continue" ||
		location.Query().Get("request") != sealedRequest {
		t.Fatalf("unexpected post-login redirect: %d %q", response.StatusCode, response.Header.Get("Location"))
	}

	var sessionCookie *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == browserSSOSessionCookie {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" || !sessionCookie.HttpOnly ||
		sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteLaxMode ||
		sessionCookie.Path != "/" {
		t.Fatalf("unexpected Central session cookie: %#v", sessionCookie)
	}
}

func TestBrowserSSOAuthorizeRedirectsToPortalWithoutSession(t *testing.T) {
	handler := newHandlerBrowserSSO(t, nil)
	app := fiber.New()
	app.Get("/authorize", handler.Authorize)
	response, err := app.Test(httptest.NewRequest(http.MethodGet, authorizeTarget(), nil))
	if err != nil {
		t.Fatal(err)
	}
	location := response.Header.Get("Location")
	if response.StatusCode != http.StatusFound || !strings.HasPrefix(location, "/?request=") {
		t.Fatalf("unexpected redirect: %d %q", response.StatusCode, location)
	}
}

func TestBrowserSSOAuthorizeRedirectContainsCodeButNoTokens(t *testing.T) {
	handler := newHandlerBrowserSSO(t, &models.BrowserSSOSession{
		ID: "session", AuthUserID: "auth-user", AppUserID: "app-user",
	})
	app := fiber.New()
	app.Get("/authorize", handler.Authorize)
	app.Get("/authorize/continue", handler.ContinueAuthorize)
	initialResponse, err := app.Test(httptest.NewRequest(http.MethodGet, authorizeTarget(), nil))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/authorize/continue?request="+url.QueryEscape(mustRequestParameter(t, initialResponse.Header.Get("Location"))), nil)
	request.Header.Set("Cookie", browserSSOSessionCookie+"=opaque-session")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	location := response.Header.Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if response.StatusCode != http.StatusFound || query.Get("code") == "" || query.Get("state") != "browser-state" {
		t.Fatalf("unexpected callback redirect: %d %q", response.StatusCode, location)
	}
	if query.Get("access_token") != "" || query.Get("refresh_token") != "" || strings.Contains(location, "accessToken") || strings.Contains(location, "refreshToken") {
		t.Fatalf("token leaked in redirect: %q", location)
	}
}

func TestBrowserSSOLogoutPageDoesNotMutateAndValidPostRevokesCurrentSession(t *testing.T) {
	handler, store := newHandlerBrowserSSOTestSetup(
		t,
		&models.BrowserSSOSession{ID: "current-session", AuthUserID: "auth-user", AppUserID: "app-user"},
		"http://localhost:8081/auth/sso/callback",
		nil,
	)
	app := fiber.New()
	app.Get("/logout", handler.LogoutPage)
	app.Post("/logout", handler.LogoutSubmit)
	app.Get("/authorize", handler.Authorize)

	pageURL := "/logout?client_id=silapet-web&post_logout_redirect_uri=" +
		url.QueryEscape("http://localhost:8081/login")
	pageRequest := httptest.NewRequest(http.MethodGet, pageURL, nil)
	pageRequest.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "current-browser-secret"})
	pageResponse, err := app.Test(pageRequest)
	if err != nil {
		t.Fatal(err)
	}
	if pageResponse.StatusCode != http.StatusOK || store.revokeCalls != 0 {
		t.Fatalf("GET logout mutated session: %d calls=%d", pageResponse.StatusCode, store.revokeCalls)
	}
	pageBody, err := io.ReadAll(pageResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pageBody), "current-browser-secret") {
		t.Fatal("browser session secret leaked in logout confirmation page")
	}
	logoutHTML := string(pageBody)
	for _, expected := range []string{
		"<title>Konfirmasi Keluar Akun Balai Pegawai</title>",
		"<h1>Keluar dari Akun Balai?</h1>",
		"Anda akan keluar dari semua aplikasi yang menggunakan sesi Akun Balai Pegawai!",
		`<button type="submit">Keluar</button>`,
		`href="http://localhost:8081/login">Batal</a>`,
	} {
		if !strings.Contains(logoutHTML, expected) {
			t.Fatalf("active logout page missing %q: %s", expected, logoutHTML)
		}
	}
	csrfCookie := responseCookie(pageResponse, browserSSOLogoutCSRF)
	if csrfCookie == nil || csrfCookie.Value == "" || !csrfCookie.HttpOnly ||
		csrfCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected logout CSRF cookie: %#v", csrfCookie)
	}
	pageCSP := pageResponse.Header.Get("Content-Security-Policy")
	if !strings.Contains(pageCSP, "form-action 'self' http://localhost:8081;") {
		t.Fatalf("post-logout origin missing from CSP: %q", pageCSP)
	}

	form := url.Values{
		"csrf":                     {csrfCookie.Value},
		"client_id":                {"silapet-web"},
		"post_logout_redirect_uri": {"http://localhost:8081/login"},
	}
	request := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(csrfCookie)
	request.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "current-browser-secret"})
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "http://localhost:8081/login" {
		t.Fatalf("unexpected logout redirect: %d %q", response.StatusCode, response.Header.Get("Location"))
	}
	if store.revokeCalls != 1 || len(store.lastRevokeHash) == 0 || !store.revoked || !store.unrelatedActive {
		t.Fatalf("unexpected revocation state: %#v", store)
	}
	clearedSession := responseCookie(response, browserSSOSessionCookie)
	clearedCSRF := responseCookie(response, browserSSOLogoutCSRF)
	if clearedSession == nil || clearedSession.Value != "" || !clearedSession.Expires.Before(time.Now()) ||
		clearedCSRF == nil || clearedCSRF.Value != "" || !clearedCSRF.Expires.Before(time.Now()) {
		t.Fatalf("logout cookies were not cleared: session=%#v csrf=%#v", clearedSession, clearedCSRF)
	}
	if strings.Contains(response.Header.Get("Location"), "current-browser-secret") {
		t.Fatal("browser session secret leaked in logout response")
	}

	authorizeRequest := httptest.NewRequest(http.MethodGet, authorizeTarget(), nil)
	authorizeRequest.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "current-browser-secret"})
	authorizeResponse, err := app.Test(authorizeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if authorizeResponse.StatusCode != http.StatusFound ||
		!strings.HasPrefix(authorizeResponse.Header.Get("Location"), "/?request=") {
		t.Fatalf("revoked browser cookie still authorized: %d %q", authorizeResponse.StatusCode, authorizeResponse.Header.Get("Location"))
	}
}

func TestBrowserSSOLogoutRejectsInvalidCSRFWithoutRevocation(t *testing.T) {
	handler, store := newHandlerBrowserSSOTestSetup(t, &models.BrowserSSOSession{ID: "session"},
		"http://localhost:8081/auth/sso/callback", nil)
	app := fiber.New()
	app.Post("/logout", handler.LogoutSubmit)
	request := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf=wrong"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: browserSSOLogoutCSRF, Value: "expected"})
	request.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "browser-secret"})
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden || store.revokeCalls != 0 {
		t.Fatalf("invalid CSRF was not rejected safely: %d calls=%d", response.StatusCode, store.revokeCalls)
	}
}

func TestBrowserSSOLogoutIsIdempotentWithoutOrAfterRevokedCookie(t *testing.T) {
	handler, store := newHandlerBrowserSSOTestSetup(t, &models.BrowserSSOSession{ID: "session"},
		"http://localhost:8081/auth/sso/callback", nil)
	app := fiber.New()
	app.Get("/logout", handler.LogoutPage)
	app.Post("/logout", handler.LogoutSubmit)

	pageRequest := httptest.NewRequest(http.MethodGet, "/logout", nil)
	pageRequest.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "active-cookie"})
	pageResponse, err := app.Test(pageRequest)
	if err != nil {
		t.Fatal(err)
	}
	csrfCookie := responseCookie(pageResponse, browserSSOLogoutCSRF)
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatal("active session did not receive logout CSRF")
	}

	postLogout := func(cookieValue string) *http.Response {
		form := url.Values{"csrf": {csrfCookie.Value}}
		request := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(csrfCookie)
		if cookieValue != "" {
			request.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: cookieValue})
		}
		response, err := app.Test(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	if response := postLogout(""); response.StatusCode != http.StatusOK || store.revokeCalls != 0 {
		t.Fatalf("missing cookie logout was not idempotent: %d calls=%d", response.StatusCode, store.revokeCalls)
	}
	store.revoked = true
	if response := postLogout("already-revoked"); response.StatusCode != http.StatusOK || store.revokeCalls != 1 {
		t.Fatalf("already-revoked logout was not idempotent: %d calls=%d", response.StatusCode, store.revokeCalls)
	}
}

func TestBrowserSSOLogoutPageWithoutActiveSessionUsesSafeStateOrRegisteredRedirect(t *testing.T) {
	handler, store := newHandlerBrowserSSOTestSetup(t, nil,
		"http://localhost:8081/auth/sso/callback", nil)
	app := fiber.New()
	app.Get("/logout", handler.LogoutPage)

	directResponse, err := app.Test(httptest.NewRequest(http.MethodGet, "/logout", nil))
	if err != nil {
		t.Fatal(err)
	}
	directBody, err := io.ReadAll(directResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if directResponse.StatusCode != http.StatusOK || store.revokeCalls != 0 ||
		!strings.Contains(string(directBody), "Anda sudah keluar") ||
		strings.Contains(string(directBody), "Keluar dari akun") ||
		responseCookie(directResponse, browserSSOLogoutCSRF) != nil {
		t.Fatalf("missing session rendered an active confirmation: %d %q", directResponse.StatusCode, directBody)
	}

	applicationURL := "/logout?client_id=silapet-web&post_logout_redirect_uri=" +
		url.QueryEscape("http://localhost:8081/login")
	applicationResponse, err := app.Test(httptest.NewRequest(http.MethodGet, applicationURL, nil))
	if err != nil {
		t.Fatal(err)
	}
	if applicationResponse.StatusCode != http.StatusSeeOther ||
		applicationResponse.Header.Get("Location") != "http://localhost:8081/login" ||
		store.revokeCalls != 0 {
		t.Fatalf("inactive registered flow did not return safely: %d %q",
			applicationResponse.StatusCode, applicationResponse.Header.Get("Location"))
	}

	store.session = &models.BrowserSSOSession{ID: "revoked-session"}
	store.revoked = true
	revokedRequest := httptest.NewRequest(http.MethodGet, "/logout", nil)
	revokedRequest.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "revoked-cookie"})
	revokedResponse, err := app.Test(revokedRequest)
	if err != nil {
		t.Fatal(err)
	}
	revokedBody, err := io.ReadAll(revokedResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if revokedResponse.StatusCode != http.StatusOK ||
		!strings.Contains(string(revokedBody), "Anda sudah keluar") || store.revokeCalls != 0 {
		t.Fatal("revoked session was presented as active")
	}
}

func TestBrowserSSODirectCancelUsesExistingSafeRouteWithoutRevocation(t *testing.T) {
	handler, store := newHandlerBrowserSSOTestSetup(t, &models.BrowserSSOSession{ID: "session"},
		"http://localhost:8081/auth/sso/callback", nil)
	app := fiber.New()
	app.Get("/logout", handler.LogoutPage)

	pageRequest := httptest.NewRequest(http.MethodGet, "/logout", nil)
	pageRequest.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "active-cookie"})
	pageResponse, err := app.Test(pageRequest)
	if err != nil {
		t.Fatal(err)
	}
	pageBody, err := io.ReadAll(pageResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pageBody), `href="/logout?cancelled=1"`) {
		t.Fatal("direct Central cancel target is not a stable owned route")
	}

	cancelRequest := httptest.NewRequest(http.MethodGet, "/logout?cancelled=1", nil)
	cancelRequest.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "active-cookie"})
	cancelResponse, err := app.Test(cancelRequest)
	if err != nil {
		t.Fatal(err)
	}
	cancelBody, err := io.ReadAll(cancelResponse.Body)
	if err != nil {
		t.Fatal(err)
	}
	if cancelResponse.StatusCode != http.StatusOK ||
		!strings.Contains(string(cancelBody), "Logout dibatalkan") || store.revokeCalls != 0 {
		t.Fatal("direct cancel mutated the session or returned an unsafe destination")
	}
}

func TestBrowserSSOLogoutRejectsUnregisteredRedirects(t *testing.T) {
	handler, store := newHandlerBrowserSSOTestSetup(t, &models.BrowserSSOSession{ID: "session"},
		"http://localhost:8081/auth/sso/callback", nil)
	app := fiber.New()
	app.Get("/logout", handler.LogoutPage)
	app.Post("/logout", handler.LogoutSubmit)

	for _, redirectURI := range []string{
		"http://localhost:8081/other",
		"https://evil.example/logout-complete",
	} {
		t.Run(redirectURI, func(t *testing.T) {
			pageRequest := httptest.NewRequest(http.MethodGet, "/logout", nil)
			pageRequest.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "active-cookie"})
			pageResponse, err := app.Test(pageRequest)
			if err != nil {
				t.Fatal(err)
			}
			csrfCookie := responseCookie(pageResponse, browserSSOLogoutCSRF)
			form := url.Values{
				"csrf":                     {csrfCookie.Value},
				"client_id":                {"silapet-web"},
				"post_logout_redirect_uri": {redirectURI},
			}
			request := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.AddCookie(csrfCookie)
			request.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "browser-secret"})
			response, err := app.Test(request)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusBadRequest || store.revokeCalls != 0 ||
				strings.Contains(response.Header.Get("Location"), redirectURI) {
				t.Fatalf("unregistered redirect was accepted: %d %q", response.StatusCode, redirectURI)
			}
		})
	}
}

func responseCookie(response *http.Response, name string) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
