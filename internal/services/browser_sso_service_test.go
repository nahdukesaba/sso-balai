package services

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeBrowserSSOStore struct {
	session  *models.BrowserSSOSession
	code     *models.BrowserSSOAuthorizationCode
	consumed bool
}

func (f *fakeBrowserSSOStore) CreateSession(_ context.Context, session *models.BrowserSSOSession) error {
	session.ID = "11111111-1111-4111-8111-111111111111"
	f.session = session
	return nil
}
func (f *fakeBrowserSSOStore) GetActiveSessionByTokenHash(_ context.Context, hash []byte) (*models.BrowserSSOSession, error) {
	if f.session != nil && string(f.session.TokenHash) == string(hash) {
		return f.session, nil
	}
	return nil, nil
}
func (f *fakeBrowserSSOStore) GetActiveSessionByID(_ context.Context, id string) (*models.BrowserSSOSession, error) {
	if f.session != nil && f.session.ID == id {
		return f.session, nil
	}
	return nil, nil
}
func (f *fakeBrowserSSOStore) RevokeSession(context.Context, []byte) error { return nil }
func (f *fakeBrowserSSOStore) CreateAuthorizationCode(_ context.Context, code *models.BrowserSSOAuthorizationCode) error {
	f.code = code
	return nil
}
func (f *fakeBrowserSSOStore) ConsumeAuthorizationCode(
	_ context.Context,
	hash []byte,
	clientID string,
	redirectURI string,
	codeChallenge string,
) (*models.BrowserSSOAuthorizationCode, error) {
	if f.consumed || f.code == nil || string(f.code.CodeHash) != string(hash) ||
		f.code.ClientID != clientID || f.code.RedirectURI != redirectURI ||
		f.code.CodeChallenge != codeChallenge || !f.code.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	f.consumed = true
	return f.code, nil
}

type fakeBrowserSSOAuth struct {
	signIn        *models.SupabaseSession
	signedOutWith string
}

func (f *fakeBrowserSSOAuth) SignInWithPassword(context.Context, string, string) (*models.SupabaseSession, error) {
	return f.signIn, nil
}
func (f *fakeBrowserSSOAuth) SignOut(_ context.Context, accessToken string) error {
	f.signedOutWith = accessToken
	return nil
}

type fakeBrowserSSOSessionIssuer struct {
	session *models.SupabaseSession
	email   string
}

func (f *fakeBrowserSSOSessionIssuer) IssueSession(_ context.Context, email string) (*models.SupabaseSession, error) {
	f.email = email
	return f.session, nil
}

type fakeBrowserSSOUsers struct{ user *models.AppUser }

func (f *fakeBrowserSSOUsers) GetByAuthUserID(context.Context, string) (*models.AppUser, error) {
	return f.user, nil
}

type fakeBrowserSSOApps struct {
	application   *models.ApplicationContext
	err           error
	byCode        map[string]*models.ApplicationContext
	errorsByCode  map[string]error
	requestedCode []string
}

func (f *fakeBrowserSSOApps) GetByAppUserID(_ context.Context, _ string, applicationCode string) (*models.ApplicationContext, error) {
	f.requestedCode = append(f.requestedCode, applicationCode)
	if f.byCode != nil || f.errorsByCode != nil {
		return f.byCode[applicationCode], f.errorsByCode[applicationCode]
	}
	return f.application, f.err
}

type fakeBrowserSSOEnrollments struct {
	result        *models.ApplicationEnrollmentResult
	err           error
	requestedCode []string
}

func (f *fakeBrowserSSOEnrollments) Request(_ context.Context, _ string, applicationCode string) (*models.ApplicationEnrollmentResult, error) {
	f.requestedCode = append(f.requestedCode, applicationCode)
	return f.result, f.err
}

type fakeBrowserSSOIdentities struct{ identity *models.Identity }

func (f *fakeBrowserSSOIdentities) GetByUserID(context.Context, string) (*models.Identity, error) {
	return f.identity, nil
}

func newBrowserSSOTestService(t *testing.T) (*BrowserSSOService, *fakeBrowserSSOStore, *fakeBrowserSSOAuth, *fakeBrowserSSOSessionIssuer, *fakeBrowserSSOApps, *fakeBrowserSSOEnrollments) {
	t.Helper()
	store := &fakeBrowserSSOStore{}
	auth := &fakeBrowserSSOAuth{}
	issuer := &fakeBrowserSSOSessionIssuer{}
	apps := &fakeBrowserSSOApps{application: &models.ApplicationContext{
		ApplicationID: "app-id", Application: "silapet", Role: "user", Status: models.MembershipStatusApproved,
	}}
	enrollments := &fakeBrowserSSOEnrollments{}
	user := &models.AppUser{ID: "app-user-id", Email: "person@example.com"}
	service, err := NewBrowserSSOService(
		store, auth, issuer, &fakeBrowserSSOUsers{user: user}, apps, enrollments,
		&fakeBrowserSSOIdentities{identity: &models.Identity{User: user}},
		BrowserSSOConfig{
			Clients: []BrowserSSOClient{
				{
					ClientID:               "silapet-web",
					ApplicationCode:        "silapet",
					AccessPolicy:           ApplicationAccessAutoUser,
					IntrospectionSecret:    "silapet-test-introspection-secret-0001",
					RedirectURIs:           []string{"http://localhost:8081/auth/sso/callback"},
					PostLogoutRedirectURIs: []string{"http://localhost:8081/login"},
				},
				{
					ClientID:               "klinik-pkp-web",
					ApplicationCode:        "klinik_pkp",
					AccessPolicy:           ApplicationAccessAutoUser,
					IntrospectionSecret:    "klinik-test-introspection-secret-00001",
					RedirectURIs:           []string{"http://localhost:3000/auth/sso/callback"},
					PostLogoutRedirectURIs: []string{"http://localhost:3000/login"},
				},
			},
			SessionTTL: time.Hour, CodeTTL: 3 * time.Minute,
			EncryptionKey: base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")),
		},
	)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	return service, store, auth, issuer, apps, enrollments
}

func validKlinikAuthorizeRequest() models.BrowserSSOAuthorizeRequest {
	request := validAuthorizeRequest()
	request.ClientID = "klinik-pkp-web"
	request.RedirectURI = "http://localhost:3000/auth/sso/callback"
	return request
}

func TestBrowserSSOClientRegistryValidation(t *testing.T) {
	clients := []BrowserSSOClient{
		{
			ClientID:               " silapet-web ",
			ApplicationCode:        " SILAPET ",
			IntrospectionSecret:    "silapet-test-introspection-secret-0001",
			RedirectURIs:           []string{" http://localhost:8081/auth/sso/callback "},
			PostLogoutRedirectURIs: []string{" http://localhost:8081/login "},
		},
		{
			ClientID:               "klinik-pkp-web",
			ApplicationCode:        "klinik_pkp",
			IntrospectionSecret:    "klinik-test-introspection-secret-00001",
			RedirectURIs:           []string{"http://localhost:3000/auth/sso/callback"},
			PostLogoutRedirectURIs: []string{"http://localhost:3000/login"},
		},
	}
	registry, err := buildBrowserSSOClientRegistry(clients)
	if err != nil || len(registry) != 2 || registry["silapet-web"].applicationCode != "silapet" ||
		registry["klinik-pkp-web"].applicationCode != "klinik_pkp" {
		t.Fatalf("two-client registry failed: %#v, %v", registry, err)
	}

	tests := []struct {
		name    string
		clients []BrowserSSOClient
	}{
		{name: "duplicate client", clients: append(clients, clients[0])},
		{name: "empty client", clients: []BrowserSSOClient{{
			ApplicationCode: "silapet", RedirectURIs: []string{"http://localhost/callback"},
			PostLogoutRedirectURIs: []string{"http://localhost/login"},
		}}},
		{name: "empty application", clients: []BrowserSSOClient{{
			ClientID: "client", RedirectURIs: []string{"http://localhost/callback"},
			PostLogoutRedirectURIs: []string{"http://localhost/login"},
		}}},
		{name: "relative redirect", clients: []BrowserSSOClient{{
			ClientID: "client", ApplicationCode: "app", RedirectURIs: []string{"/callback"},
			PostLogoutRedirectURIs: []string{"http://localhost/login"},
		}}},
		{name: "wildcard redirect", clients: []BrowserSSOClient{{
			ClientID: "client", ApplicationCode: "app", RedirectURIs: []string{"https://*.example.com/callback"},
			PostLogoutRedirectURIs: []string{"http://localhost/login"},
		}}},
		{name: "empty post logout", clients: []BrowserSSOClient{{
			ClientID: "client", ApplicationCode: "app", RedirectURIs: []string{"http://localhost/callback"},
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildBrowserSSOClientRegistry(test.clients); err == nil {
				t.Fatal("invalid client registry was accepted")
			}
		})
	}
}

func validAuthorizeRequest() models.BrowserSSOAuthorizeRequest {
	return models.BrowserSSOAuthorizeRequest{
		ClientID: "silapet-web", RedirectURI: "http://localhost:8081/auth/sso/callback",
		ResponseType: "code", State: "strong-state", CodeChallenge: pkceChallenge("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"),
		CodeChallengeMethod: "S256",
	}
}

func TestBrowserSSOAuthorizeValidation(t *testing.T) {
	service, _, _, _, _, _ := newBrowserSSOTestService(t)
	for _, request := range []models.BrowserSSOAuthorizeRequest{validAuthorizeRequest(), validKlinikAuthorizeRequest()} {
		if err := service.ValidateAuthorizeRequest(request); err != nil {
			t.Fatalf("registered client request rejected: %#v: %v", request, err)
		}
	}
	tests := []struct {
		name   string
		mutate func(*models.BrowserSSOAuthorizeRequest)
	}{
		{"invalid client", func(r *models.BrowserSSOAuthorizeRequest) { r.ClientID = "other" }},
		{"invalid redirect", func(r *models.BrowserSSOAuthorizeRequest) { r.RedirectURI = "https://evil.example/callback" }},
		{"missing state", func(r *models.BrowserSSOAuthorizeRequest) { r.State = "" }},
		{"non S256", func(r *models.BrowserSSOAuthorizeRequest) { r.CodeChallengeMethod = "plain" }},
		{"silapet with klinik redirect", func(r *models.BrowserSSOAuthorizeRequest) { r.RedirectURI = "http://localhost:3000/auth/sso/callback" }},
		{"klinik with silapet redirect", func(r *models.BrowserSSOAuthorizeRequest) {
			r.ClientID = "klinik-pkp-web"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validAuthorizeRequest()
			test.mutate(&request)
			if !errors.Is(service.ValidateAuthorizeRequest(request), ErrInvalidAuthorizeRequest) {
				t.Fatal("expected invalid authorize request")
			}
		})
	}
}

func TestBrowserSSOPostLogoutRedirectValidation(t *testing.T) {
	service, _, _, _, _, _ := newBrowserSSOTestService(t)
	if err := service.ValidatePostLogoutRedirect("silapet-web", "http://localhost:8081/login"); err != nil {
		t.Fatalf("registered post-logout redirect rejected: %v", err)
	}
	if err := service.ValidatePostLogoutRedirect("klinik-pkp-web", "http://localhost:3000/login"); err != nil {
		t.Fatalf("registered Klinik post-logout redirect rejected: %v", err)
	}
	if err := service.ValidatePostLogoutRedirect("", ""); err != nil {
		t.Fatalf("direct Central logout rejected: %v", err)
	}
	for _, test := range []struct {
		clientID string
		redirect string
	}{
		{"wrong-client", "http://localhost:8081/login"},
		{"silapet-web", "http://localhost:8081/other"},
		{"silapet-web", "https://evil.example/login"},
		{"", "http://localhost:8081/login"},
		{"silapet-web", "http://localhost:3000/login"},
		{"klinik-pkp-web", "http://localhost:8081/login"},
	} {
		if !errors.Is(service.ValidatePostLogoutRedirect(test.clientID, test.redirect), ErrInvalidAuthorizeRequest) {
			t.Fatalf("invalid post-logout redirect accepted: %#v", test)
		}
	}
}

func TestBrowserSSOCancelReturnValidation(t *testing.T) {
	service, _, _, _, _, _ := newBrowserSSOTestService(t)

	got, err := service.ValidateCancelReturn("klinik-pkp-web", "http://localhost:3000/login", "/admin/users?page=2&status=active")
	if err != nil || got != "http://localhost:3000/admin/users?page=2&status=active" {
		t.Fatalf("valid relative cancel return failed: got=%q err=%v", got, err)
	}

	got, err = service.ValidateCancelReturn("silapet-web", "http://localhost:8081/login", "http://localhost:8081/bookings/123")
	if err != nil || got != "http://localhost:8081/bookings/123" {
		t.Fatalf("valid absolute cancel return failed: got=%q err=%v", got, err)
	}

	got, err = service.ValidateCancelReturn("klinik-pkp-web", "http://localhost:3000/login", "")
	if err != nil || got != "" {
		t.Fatalf("empty cancel return failed: got=%q err=%v", got, err)
	}

	for _, unsafe := range []string{
		"https://evil.example/login",
		"//evil.example/login",
		"/\\evil.example",
		"http://localhost:8081/bookings",
		"javascript:alert(1)",
		"/path\nwith\rnewlines",
		"/path#withfragment",
	} {
		if _, err := service.ValidateCancelReturn("klinik-pkp-web", "http://localhost:3000/login", unsafe); err == nil {
			t.Fatalf("unsafe cancel return accepted: %q", unsafe)
		}
	}
}

func TestBrowserSSOAuthorizeUsesResolvedClientApplication(t *testing.T) {
	service, store, _, _, apps, enrollments := newBrowserSSOTestService(t)
	store.session = &models.BrowserSSOSession{
		ID: "session", TokenHash: hashOpaqueToken("cookie"), AuthUserID: "auth", AppUserID: "user",
	}

	for _, test := range []struct {
		name            string
		request         models.BrowserSSOAuthorizeRequest
		applicationCode string
	}{
		{name: "silapet", request: validAuthorizeRequest(), applicationCode: "silapet"},
		{name: "klinik", request: validKlinikAuthorizeRequest(), applicationCode: "klinik_pkp"},
	} {
		t.Run(test.name, func(t *testing.T) {
			apps.requestedCode = nil
			result, err := service.Authorize(context.Background(), test.request, "cookie")
			if err != nil || result.Code == "" {
				t.Fatalf("authorize failed: %#v %v", result, err)
			}
			if len(apps.requestedCode) != 1 || apps.requestedCode[0] != test.applicationCode {
				t.Fatalf("membership checked wrong application: %#v", apps.requestedCode)
			}
		})
	}

	apps.application = nil
	apps.err = ErrApplicationMembershipUnavailable
	enrollments.result = &models.ApplicationEnrollmentResult{Status: models.MembershipStatusPending}
	enrollments.requestedCode = nil
	result, err := service.Authorize(context.Background(), validKlinikAuthorizeRequest(), "cookie")
	if err != nil || result.Status != browserSSOStatusPending {
		t.Fatalf("Klinik auto-enrollment failed: %#v %v", result, err)
	}
	if len(enrollments.requestedCode) != 1 || enrollments.requestedCode[0] != "klinik_pkp" {
		t.Fatalf("auto-enrollment used wrong application: %#v", enrollments.requestedCode)
	}
}

func TestBrowserSSONoSessionRequiresLogin(t *testing.T) {
	service, _, _, _, _, _ := newBrowserSSOTestService(t)
	result, err := service.Authorize(context.Background(), validAuthorizeRequest(), "missing")
	if err != nil || !result.LoginRequired || result.Code != "" {
		t.Fatalf("unexpected result: %#v %v", result, err)
	}
}

func TestBrowserSSOLoginCreatesOpaqueSession(t *testing.T) {
	service, store, auth, _, _, _ := newBrowserSSOTestService(t)
	auth.signIn = &models.SupabaseSession{AccessToken: "transient-access", User: models.SupabaseAuthUser{ID: "auth-user-id"}}
	raw, _, err := service.Login(context.Background(), "person@example.com", "password")
	if err != nil || raw == "" || store.session == nil {
		t.Fatalf("login failed: %v", err)
	}
	if string(store.session.TokenHash) == raw {
		t.Fatal("browser session token stored as plaintext")
	}
	if auth.signedOutWith != "transient-access" {
		t.Fatal("transient Supabase login session was not revoked")
	}
}

func TestBrowserSSOAuthorizeMembershipOutcomes(t *testing.T) {
	service, store, _, _, apps, enrollments := newBrowserSSOTestService(t)
	store.session = &models.BrowserSSOSession{ID: "session", TokenHash: hashOpaqueToken("cookie"), AuthUserID: "auth", AppUserID: "user"}
	request := validAuthorizeRequest()

	approved, err := service.Authorize(context.Background(), request, "cookie")
	if err != nil || approved.Code == "" {
		t.Fatalf("approved authorize failed: %v", err)
	}

	apps.application = nil
	apps.err = ErrApplicationMembershipUnavailable
	enrollments.result = &models.ApplicationEnrollmentResult{Status: models.MembershipStatusPending}
	pending, err := service.Authorize(context.Background(), request, "cookie")
	if err != nil || pending.Status != browserSSOStatusPending || pending.Code != "" {
		t.Fatalf("pending result: %#v %v", pending, err)
	}

	apps.err = nil
	apps.application = &models.ApplicationContext{Status: models.MembershipStatusRejected}
	denied, err := service.Authorize(context.Background(), request, "cookie")
	if err != nil || denied.Status != browserSSOStatusDenied || denied.Code != "" {
		t.Fatalf("denied result: %#v %v", denied, err)
	}
}

func TestBrowserSSORestrictedApplicationDoesNotAutoEnroll(t *testing.T) {
	service, store, _, _, apps, enrollments := newBrowserSSOTestService(t)
	client := service.clients["klinik-pkp-web"]
	client.accessPolicy = ApplicationAccessRestricted
	service.clients["klinik-pkp-web"] = client
	store.session = &models.BrowserSSOSession{
		ID: "11111111-1111-4111-8111-111111111111", TokenHash: hashOpaqueToken("cookie"),
		AuthUserID: "auth", AppUserID: "user",
	}
	apps.application = nil
	apps.err = ErrApplicationMembershipUnavailable

	result, err := service.Authorize(context.Background(), validKlinikAuthorizeRequest(), "cookie")
	if err != nil || result.Status != browserSSOStatusPending || result.Code != "" {
		t.Fatalf("unexpected restricted result: %#v %v", result, err)
	}
	if len(enrollments.requestedCode) != 0 {
		t.Fatalf("restricted application auto-enrolled user: %#v", enrollments.requestedCode)
	}
}

func TestBrowserSSOExchangeBindingsSingleUseAndSuccess(t *testing.T) {
	service, store, _, issuer, _, _ := newBrowserSSOTestService(t)
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	store.session = &models.BrowserSSOSession{ID: "session", AuthUserID: "auth", AppUserID: "app-user-id"}
	store.code = &models.BrowserSSOAuthorizationCode{
		CodeHash: hashOpaqueToken("one-time-code"), BrowserSessionID: "session", ClientID: "silapet-web",
		AuthUserID: "auth", AppUserID: "app-user-id", RedirectURI: "http://localhost:8081/auth/sso/callback",
		CodeChallenge: pkceChallenge(verifier), ExpiresAt: time.Now().Add(time.Minute),
	}
	issuer.session = &models.SupabaseSession{AccessToken: "access", RefreshToken: "independent-refresh", User: models.SupabaseAuthUser{ID: "auth"}}

	result, err := service.Exchange(context.Background(), "one-time-code", "silapet-web", "http://localhost:8081/auth/sso/callback", verifier)
	if err != nil || result.Session.AccessToken != "access" || issuer.email != "person@example.com" ||
		result.SSOSessionID != "session" {
		t.Fatalf("exchange failed: %v", err)
	}
	if _, err := service.Exchange(context.Background(), "one-time-code", "silapet-web", "http://localhost:8081/auth/sso/callback", verifier); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("expected replay rejection, got %v", err)
	}
}

func TestBrowserSSOIntrospectionAuthenticatesClientAndBindsSessionUser(t *testing.T) {
	service, store, _, _, _, _ := newBrowserSSOTestService(t)
	sid := "11111111-1111-4111-8111-111111111111"
	store.session = &models.BrowserSSOSession{ID: sid, AppUserID: "app-user-id"}

	active, err := service.Introspect(context.Background(), "silapet-web", "silapet-test-introspection-secret-0001", sid, "app-user-id")
	if err != nil || !active {
		t.Fatalf("valid session was not active: active=%v err=%v", active, err)
	}
	active, err = service.Introspect(context.Background(), "silapet-web", "silapet-test-introspection-secret-0001", sid, "different-user")
	if err != nil || active {
		t.Fatalf("session was not bound to app user: active=%v err=%v", active, err)
	}
	if _, err = service.Introspect(context.Background(), "silapet-web", "wrong-secret", sid, "app-user-id"); !errors.Is(err, ErrInvalidBrowserSession) {
		t.Fatalf("invalid client secret accepted: %v", err)
	}
	store.session = nil
	active, err = service.Introspect(context.Background(), "silapet-web", "silapet-test-introspection-secret-0001", sid, "app-user-id")
	if err != nil || active {
		t.Fatalf("revoked or expired session stayed active: active=%v err=%v", active, err)
	}
}

func TestBrowserSSOExchangeRejectsExpiredWrongBindingsAndPKCE(t *testing.T) {
	service, store, _, _, _, _ := newBrowserSSOTestService(t)
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	store.code = &models.BrowserSSOAuthorizationCode{CodeHash: hashOpaqueToken("expired"), ExpiresAt: time.Now().Add(-time.Second)}
	if _, err := service.Exchange(context.Background(), "expired", "silapet-web", "http://localhost:8081/auth/sso/callback", verifier); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := service.Exchange(context.Background(), "code", "wrong", "http://localhost:8081/auth/sso/callback", verifier); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("client: %v", err)
	}
	if _, err := service.Exchange(context.Background(), "code", "silapet-web", "https://evil.example", verifier); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("redirect: %v", err)
	}
	store.consumed = false
	store.code = &models.BrowserSSOAuthorizationCode{CodeHash: hashOpaqueToken("code"), ClientID: "silapet-web", RedirectURI: "http://localhost:8081/auth/sso/callback", CodeChallenge: pkceChallenge(verifier), ExpiresAt: time.Now().Add(time.Minute)}
	wrongVerifier := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	if _, err := service.Exchange(context.Background(), "code", "silapet-web", "http://localhost:8081/auth/sso/callback", wrongVerifier); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("pkce: %v", err)
	}
	if store.consumed {
		t.Fatal("wrong PKCE verifier must not consume the authorization code")
	}
}

func TestBrowserSSOExchangeIsolatedByClientAndApplication(t *testing.T) {
	service, store, _, issuer, apps, _ := newBrowserSSOTestService(t)
	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	store.session = &models.BrowserSSOSession{ID: "session", AuthUserID: "auth", AppUserID: "app-user-id"}
	issuer.session = &models.SupabaseSession{
		AccessToken: "access", RefreshToken: "refresh", User: models.SupabaseAuthUser{ID: "auth"},
	}
	apps.byCode = map[string]*models.ApplicationContext{
		"silapet":    {Application: "silapet", Status: models.MembershipStatusApproved},
		"klinik_pkp": {Application: "klinik_pkp", Status: models.MembershipStatusApproved},
	}

	for _, test := range []struct {
		name            string
		code            string
		clientID        string
		redirectURI     string
		applicationCode string
		wrongClientID   string
		wrongRedirect   string
	}{
		{
			name: "silapet", code: "silapet-code", clientID: "silapet-web",
			redirectURI: "http://localhost:8081/auth/sso/callback", applicationCode: "silapet",
			wrongClientID: "klinik-pkp-web", wrongRedirect: "http://localhost:3000/auth/sso/callback",
		},
		{
			name: "klinik", code: "klinik-code", clientID: "klinik-pkp-web",
			redirectURI: "http://localhost:3000/auth/sso/callback", applicationCode: "klinik_pkp",
			wrongClientID: "silapet-web", wrongRedirect: "http://localhost:8081/auth/sso/callback",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store.consumed = false
			store.code = &models.BrowserSSOAuthorizationCode{
				CodeHash: hashOpaqueToken(test.code), BrowserSessionID: "session", ClientID: test.clientID,
				AuthUserID: "auth", AppUserID: "app-user-id", RedirectURI: test.redirectURI,
				CodeChallenge: pkceChallenge(verifier), ExpiresAt: time.Now().Add(time.Minute),
			}
			if _, err := service.Exchange(
				context.Background(), test.code, test.wrongClientID, test.wrongRedirect, verifier,
			); !errors.Is(err, ErrInvalidAuthorizationCode) {
				t.Fatalf("cross-client exchange was not rejected: %v", err)
			}
			if store.consumed {
				t.Fatal("cross-client exchange consumed authorization code")
			}

			apps.requestedCode = nil
			result, err := service.Exchange(
				context.Background(), test.code, test.clientID, test.redirectURI, verifier,
			)
			if err != nil || result == nil || result.Session.AccessToken != "access" || result.SSOSessionID != "session" {
				t.Fatalf("correct client exchange failed: %#v %v", result, err)
			}
			if len(apps.requestedCode) != 1 || apps.requestedCode[0] != test.applicationCode {
				t.Fatalf("exchange checked wrong application: %#v", apps.requestedCode)
			}
		})
	}
}
