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
	session.ID = "browser-session-id"
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
	application *models.ApplicationContext
	err         error
}

func (f *fakeBrowserSSOApps) GetByAppUserID(context.Context, string, string) (*models.ApplicationContext, error) {
	return f.application, f.err
}

type fakeBrowserSSOEnrollments struct {
	result *models.ApplicationEnrollmentResult
	err    error
}

func (f *fakeBrowserSSOEnrollments) Request(context.Context, string, string) (*models.ApplicationEnrollmentResult, error) {
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
			ClientID: "silapet-web", ApplicationCode: "silapet",
			RedirectURIs:   []string{"http://localhost:8081/auth/sso/callback"},
			PostLogoutURIs: []string{"http://localhost:8081/login"},
			SessionTTL:     time.Hour, CodeTTL: 3 * time.Minute,
			EncryptionKey: base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")),
		},
	)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}
	return service, store, auth, issuer, apps, enrollments
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
	tests := []struct {
		name   string
		mutate func(*models.BrowserSSOAuthorizeRequest)
	}{
		{"invalid client", func(r *models.BrowserSSOAuthorizeRequest) { r.ClientID = "other" }},
		{"invalid redirect", func(r *models.BrowserSSOAuthorizeRequest) { r.RedirectURI = "https://evil.example/callback" }},
		{"missing state", func(r *models.BrowserSSOAuthorizeRequest) { r.State = "" }},
		{"non S256", func(r *models.BrowserSSOAuthorizeRequest) { r.CodeChallengeMethod = "plain" }},
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
	} {
		if !errors.Is(service.ValidatePostLogoutRedirect(test.clientID, test.redirect), ErrInvalidAuthorizeRequest) {
			t.Fatalf("invalid post-logout redirect accepted: %#v", test)
		}
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
	if err != nil || result.Session.AccessToken != "access" || issuer.email != "person@example.com" {
		t.Fatalf("exchange failed: %v", err)
	}
	if _, err := service.Exchange(context.Background(), "one-time-code", "silapet-web", "http://localhost:8081/auth/sso/callback", verifier); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("expected replay rejection, got %v", err)
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
