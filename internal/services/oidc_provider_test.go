package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

const (
	oidcTestSID      = "11111111-1111-4111-8111-111111111111"
	oidcTestSecret   = "silapet-test-introspection-secret-0001"
	oidcTestRedirect = "http://localhost:8081/auth/sso/callback"
	oidcTestVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)

func newOIDCTestProvider(t *testing.T) (*OIDCProvider, *fakeBrowserSSOStore, *rsa.PrivateKey) {
	t.Helper()
	service, store, _, _, _, _ := newBrowserSSOTestService(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider, err := NewOIDCProvider("https://sso.example.test/", keyPEM, service)
	if err != nil {
		t.Fatal(err)
	}
	store.session = &models.BrowserSSOSession{
		ID: oidcTestSID, AuthUserID: "auth", AppUserID: "app-user-id", CreatedAt: time.Now().Add(-time.Minute),
	}
	store.code = &models.BrowserSSOAuthorizationCode{
		CodeHash: hashOpaqueToken("oidc-code"), BrowserSessionID: oidcTestSID, ClientID: "silapet-web",
		AuthUserID: "auth", AppUserID: "app-user-id", RedirectURI: oidcTestRedirect,
		CodeChallenge: pkceChallenge(oidcTestVerifier), Nonce: "nonce-123", Scope: "openid email profile",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	return provider, store, key
}

func TestOIDCTokenIssuesVerifiableIDTokenAndUserInfo(t *testing.T) {
	provider, store, key := newOIDCTestProvider(t)
	ctx := context.Background()

	if _, err := provider.Token(ctx, "oidc-code", "silapet-web", "wrong-secret", oidcTestRedirect, oidcTestVerifier); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("wrong client secret: %v", err)
	}
	if store.consumed {
		t.Fatal("failed client authentication must not consume the code")
	}

	response, err := provider.Token(ctx, "oidc-code", "silapet-web", oidcTestSecret, oidcTestRedirect, oidcTestVerifier)
	if err != nil {
		t.Fatal(err)
	}
	if response.TokenType != "Bearer" || response.AccessToken == "" || response.IDToken == "" || response.Scope != "openid email profile" {
		t.Fatalf("unexpected token response: %#v", response)
	}

	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(response.IDToken, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("https://sso.example.test"),
		jwt.WithAudience("silapet-web"), jwt.WithExpirationRequired()); err != nil {
		t.Fatalf("id_token does not verify with the published key: %v", err)
	}
	if claims["sub"] != "app-user-id" || claims["nonce"] != "nonce-123" || claims["sid"] != oidcTestSID ||
		claims["email"] != "person@example.com" || claims["email_verified"] != true || claims["app_role"] != "user" ||
		claims["auth_time"] == nil {
		t.Fatalf("unexpected id_token claims: %#v", claims)
	}
	if provider.ClientIDFromIDTokenHint(response.IDToken) != "silapet-web" {
		t.Fatal("id_token_hint did not resolve the client")
	}

	if _, err := provider.Token(ctx, "oidc-code", "silapet-web", oidcTestSecret, oidcTestRedirect, oidcTestVerifier); !errors.Is(err, ErrInvalidAuthorizationCode) {
		t.Fatalf("code replay: %v", err)
	}

	info, err := provider.UserInfo(ctx, response.AccessToken)
	if err != nil || info["sub"] != "app-user-id" || info["email"] != "person@example.com" {
		t.Fatalf("userinfo failed: %#v %v", info, err)
	}
	if _, err := provider.UserInfo(ctx, response.IDToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("id_token accepted as access token: %v", err)
	}

	provider.now = func() time.Time { return time.Now().Add(oidcTokenTTL + time.Minute) }
	if _, err := provider.UserInfo(ctx, response.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expired access token accepted: %v", err)
	}
	provider.now = time.Now

	store.session = nil // Central logout revokes the session
	if _, err := provider.UserInfo(ctx, response.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("access token outlived the Central session: %v", err)
	}
}

func TestOIDCTokenWithoutOpenIDScopeHasNoIDToken(t *testing.T) {
	provider, store, _ := newOIDCTestProvider(t)
	store.code.Scope = ""
	response, err := provider.Token(context.Background(), "oidc-code", "silapet-web", oidcTestSecret, oidcTestRedirect, oidcTestVerifier)
	if err != nil || response.IDToken != "" || response.AccessToken == "" {
		t.Fatalf("unexpected non-OIDC response: %#v %v", response, err)
	}
}

func TestOIDCDiscoveryAndJWKSMatchSigningKey(t *testing.T) {
	provider, _, _ := newOIDCTestProvider(t)
	discovery := provider.Discovery()
	if discovery["issuer"] != "https://sso.example.test" ||
		discovery["token_endpoint"] != "https://sso.example.test/oauth/token" ||
		discovery["jwks_uri"] != "https://sso.example.test/.well-known/jwks.json" {
		t.Fatalf("unexpected discovery: %#v", discovery)
	}
	keys := provider.JWKS()["keys"].([]map[string]string)
	if len(keys) != 1 || keys[0]["kid"] != provider.kid || keys[0]["alg"] != "RS256" || keys[0]["e"] != "AQAB" {
		t.Fatalf("unexpected JWKS: %#v", keys)
	}
}

func TestNewOIDCProviderRejectsBadConfiguration(t *testing.T) {
	service, _, _, _, _, _ := newBrowserSSOTestService(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(small)})
	for name, test := range map[string]struct {
		issuer string
		key    []byte
	}{
		"relative issuer": {"/sso", smallPEM},
		"not PEM":         {"https://sso.example.test", []byte("not a key")},
		"weak key":        {"https://sso.example.test", smallPEM},
	} {
		if _, err := NewOIDCProvider(test.issuer, test.key, service); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
