package services

import (
	"context"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeMagicLinkAdmin struct {
	email string
}

func (f *fakeMagicLinkAdmin) GenerateMagicLinkToken(_ context.Context, email string) (string, error) {
	f.email = email
	return "server-only-token-hash", nil
}

type fakeMagicLinkAuth struct {
	tokenHash string
	session   *models.SupabaseSession
}

func (f *fakeMagicLinkAuth) VerifyMagicLinkToken(_ context.Context, tokenHash string) (*models.SupabaseSession, error) {
	f.tokenHash = tokenHash
	return f.session, nil
}

func TestSupabaseBrowserSSOSessionIssuerCreatesIndependentSession(t *testing.T) {
	admin := &fakeMagicLinkAdmin{}
	auth := &fakeMagicLinkAuth{session: &models.SupabaseSession{
		AccessToken: "access", RefreshToken: "refresh",
		User: models.SupabaseAuthUser{ID: "auth-user", Email: "person@example.com"},
	}}
	issuer, err := NewSupabaseBrowserSSOSessionIssuer(admin, auth)
	if err != nil {
		t.Fatal(err)
	}
	session, err := issuer.IssueSession(context.Background(), "person@example.com")
	if err != nil || session.AccessToken != "access" {
		t.Fatalf("issue session: %#v %v", session, err)
	}
	if admin.email != "person@example.com" || auth.tokenHash != "server-only-token-hash" {
		t.Fatal("magic-link token was not generated and verified server-side")
	}
}
