package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

type fakeRegistration struct {
	calls   int
	appCode string
	err     error
}

func (f *fakeRegistration) Register(_ context.Context, _, _, _, _ string, applicationCode string) (*models.Identity, error) {
	f.calls++
	f.appCode = applicationCode
	return &models.Identity{User: &models.AppUser{ID: "app-user"}}, f.err
}

type fakeMembershipAdminStore struct {
	manages     bool
	memberships []models.ManagedMembership
	updateErr   error
	updated     []string
}

func (f *fakeMembershipAdminStore) ListManaged(context.Context, string) ([]models.ManagedMembership, error) {
	return f.memberships, nil
}

func (f *fakeMembershipAdminStore) ManagesAnyApplication(context.Context, string) (bool, error) {
	return f.manages, nil
}

func (f *fakeMembershipAdminStore) UpdateManaged(_ context.Context, actor, membershipID, role, status string) error {
	f.updated = []string{actor, membershipID, role, status}
	return f.updateErr
}

func sealedRequestFor(t *testing.T, handler *BrowserSSOHandler, clientID, redirectURI string) string {
	t.Helper()
	sealed, err := handler.service.SealAuthorizeRequest(models.BrowserSSOAuthorizeRequest{
		ClientID: clientID, RedirectURI: redirectURI, ResponseType: "code", State: "state",
		CodeChallengeMethod: "S256", CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func postForm(t *testing.T, app *fiber.App, target string, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestRegisterPageSignsUpPendingAccessAndResumesAuthorization(t *testing.T) {
	handler, _, _ := newAccountPortalHandler(t, nil, &models.SupabaseSession{
		AccessToken: "transient", User: models.SupabaseAuthUser{ID: "auth-user"},
	}, nil)
	registration := &fakeRegistration{}
	handler.SetRegistrationService(registration)
	app := fiber.New()
	app.Get("/authorize", handler.Authorize)
	app.Get("/account/login", handler.PortalLoginPage)
	app.Get("/account/register", handler.RegisterPage)
	app.Post("/account/register", handler.RegisterSubmit)

	// prompt=create opens signup directly for an app that accepts self-service requests.
	query := url.Values{
		"client_id": {"klinik-pkp-web"}, "redirect_uri": {"http://localhost:3000/auth/sso/callback"},
		"response_type": {"code"}, "state": {"state"}, "prompt": {"create"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
	}
	authorize, err := app.Test(httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if location := authorize.Header.Get("Location"); !strings.HasPrefix(location, "/account/register?request=") {
		t.Fatalf("prompt=create did not open signup: %q", location)
	}

	sealed := sealedRequestFor(t, handler, "klinik-pkp-web", "http://localhost:3000/auth/sso/callback")
	login, err := app.Test(httptest.NewRequest(http.MethodGet, "/account/login?request="+url.QueryEscape(sealed), nil))
	if err != nil {
		t.Fatal(err)
	}
	loginHTML, _ := io.ReadAll(login.Body)
	if !strings.Contains(string(loginHTML), "Belum punya akun? Daftar") {
		t.Fatal("login form does not offer signup")
	}

	page, err := app.Test(httptest.NewRequest(http.MethodGet, "/account/register?request="+url.QueryEscape(sealed), nil))
	if err != nil {
		t.Fatal(err)
	}
	csrf := responseCookie(page, accountRegisterCSRF)
	if page.StatusCode != http.StatusOK || csrf == nil ||
		!strings.Contains(page.Header.Get("Content-Security-Policy"), "form-action 'self' http://localhost:3000;") {
		t.Fatalf("unexpected register page: %d %q", page.StatusCode, page.Header.Get("Content-Security-Policy"))
	}

	form := url.Values{
		"csrf": {csrf.Value}, "request": {sealed}, "full_name": {"Pegawai Baru"},
		"email": {"baru@example.com"}, "password": {"password123"}, "password_confirm": {"different1"},
	}
	mismatch := postForm(t, app, "/account/register", form, csrf)
	body, _ := io.ReadAll(mismatch.Body)
	if mismatch.StatusCode != http.StatusOK || !strings.Contains(string(body), "Konfirmasi password tidak sama.") ||
		!strings.Contains(string(body), `value="baru@example.com"`) || registration.calls != 0 {
		t.Fatalf("mismatched confirmation was not rejected: %d calls=%d", mismatch.StatusCode, registration.calls)
	}

	form.Set("password_confirm", "password123")
	created := postForm(t, app, "/account/register", form, csrf)
	if created.StatusCode != http.StatusSeeOther ||
		created.Header.Get("Location") != "/authorize/continue?request="+url.QueryEscape(sealed) ||
		registration.appCode != "klinik_pkp" || responseCookie(created, browserSSOSessionCookie) == nil {
		t.Fatalf("signup did not log in and resume: %d %q app=%q", created.StatusCode, created.Header.Get("Location"), registration.appCode)
	}

	registration.err = services.ErrAccountAlreadyExists
	exists := postForm(t, app, "/account/register", form, csrf)
	body, _ = io.ReadAll(exists.Body)
	if !strings.Contains(string(body), "Email sudah terdaftar.") {
		t.Fatal("duplicate email message missing")
	}
}

func TestRegisterPageRefusesInviteOnlyApplication(t *testing.T) {
	handler, _, _ := newAccountPortalHandler(t, nil, nil, nil)
	handler.SetRegistrationService(&fakeRegistration{})
	app := fiber.New()
	app.Get("/account/register", handler.RegisterPage)
	sealed := sealedRequestFor(t, handler, "silapet-web", "http://localhost:8081/auth/sso/callback")
	response, err := app.Test(httptest.NewRequest(http.MethodGet, "/account/register?request="+url.QueryEscape(sealed), nil))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("RESTRICTED application accepted signup: %d", response.StatusCode)
	}
}

func TestAdminPageAccessAndUpdates(t *testing.T) {
	session := &models.BrowserSSOSession{ID: "session", AuthUserID: "auth-user", AppUserID: "app-user"}
	handler, _, _ := newAccountPortalHandler(t, session, nil, nil)
	store := &fakeMembershipAdminStore{memberships: []models.ManagedMembership{
		{ID: "11111111-1111-4111-8111-111111111111", ApplicationName: "Klinik PKP", AppUserID: "other-user",
			FullName: "Pemohon", Email: "pemohon@example.com", Role: "user", Status: models.MembershipStatusPending},
		{ID: "22222222-2222-4222-8222-222222222222", ApplicationName: "Klinik PKP", AppUserID: "app-user",
			FullName: "Admin", Email: "person@example.com", Role: "admin", Status: models.MembershipStatusApproved},
	}}
	handler.SetMembershipAdminService(services.NewMembershipAdminService(store))
	app := fiber.New()
	app.Get("/admin", handler.AdminPage)
	app.Post("/admin/memberships", handler.AdminUpdate)
	sessionCookie := &http.Cookie{Name: browserSSOSessionCookie, Value: "opaque-session"}

	anonymous, err := app.Test(httptest.NewRequest(http.MethodGet, "/admin", nil))
	if err != nil {
		t.Fatal(err)
	}
	if anonymous.StatusCode != http.StatusSeeOther || anonymous.Header.Get("Location") != "/account/login" {
		t.Fatalf("anonymous admin access: %d", anonymous.StatusCode)
	}

	request := httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.AddCookie(sessionCookie)
	denied, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	if denied.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin reached admin page: %d", denied.StatusCode)
	}

	store.manages = true
	request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.AddCookie(sessionCookie)
	page, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(page.Body)
	csrf := responseCookie(page, accessAdminCSRF)
	if page.StatusCode != http.StatusOK || csrf == nil || !strings.Contains(string(html), "pemohon@example.com") ||
		!strings.Contains(string(html), ">Setujui</button>") || !strings.Contains(string(html), "Akun Anda") ||
		strings.Contains(string(html), `value="22222222-2222-4222-8222-222222222222"`) {
		t.Fatalf("unexpected admin page: %d %s", page.StatusCode, html)
	}

	form := url.Values{"membership_id": {"11111111-1111-4111-8111-111111111111"}, "role": {"user"}, "status": {"approved"}}
	if noCSRF := postForm(t, app, "/admin/memberships", form, sessionCookie); noCSRF.StatusCode != http.StatusForbidden || store.updated != nil {
		t.Fatalf("update without CSRF: %d", noCSRF.StatusCode)
	}

	form.Set("csrf", csrf.Value)
	saved := postForm(t, app, "/admin/memberships", form, sessionCookie, csrf)
	if saved.Header.Get("Location") != "/admin?msg=saved" ||
		strings.Join(store.updated, ",") != "app-user,11111111-1111-4111-8111-111111111111,user,approved" {
		t.Fatalf("approve failed: %q %v", saved.Header.Get("Location"), store.updated)
	}

	store.updateErr = repository.ErrMembershipNotManaged
	forbidden := postForm(t, app, "/admin/memberships", form, sessionCookie, csrf)
	if forbidden.Header.Get("Location") != "/admin?msg=forbidden" {
		t.Fatalf("unmanaged membership: %q", forbidden.Header.Get("Location"))
	}

	form.Set("status", "pending")
	invalid := postForm(t, app, "/admin/memberships", form, sessionCookie, csrf)
	if invalid.Header.Get("Location") != "/admin?msg=invalid" {
		t.Fatalf("pending is not an admin decision: %q", invalid.Header.Get("Location"))
	}
}
