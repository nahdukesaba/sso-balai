package services

import (
	"context"
	"errors"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeSupabasePasswordRecoveryAuth struct {
	requestErr error
	verifyErr  error
	updateErr  error
	session    *models.SupabaseSession

	requestCalls int
	verifyCalls  int
	updateCalls  int
	email        string
	redirectURL  string
	tokenHash    string
	accessToken  string
	password     string
}

func (f *fakeSupabasePasswordRecoveryAuth) RequestPasswordRecovery(
	_ context.Context,
	email string,
	redirectURL string,
) error {
	f.requestCalls++
	f.email = email
	f.redirectURL = redirectURL

	return f.requestErr
}

func (f *fakeSupabasePasswordRecoveryAuth) VerifyPasswordRecoveryToken(
	_ context.Context,
	tokenHash string,
) (*models.SupabaseSession, error) {
	f.verifyCalls++
	f.tokenHash = tokenHash

	return f.session, f.verifyErr
}

func (f *fakeSupabasePasswordRecoveryAuth) UpdatePassword(
	_ context.Context,
	accessToken string,
	password string,
) error {
	f.updateCalls++
	f.accessToken = accessToken
	f.password = password

	return f.updateErr
}

func newTestSupabasePasswordRecoveryService(
	t *testing.T,
	auth SupabasePasswordRecoveryAuth,
) *SupabasePasswordRecoveryService {
	t.Helper()

	service, err := NewSupabasePasswordRecoveryService(
		auth,
		"https://sso.bp3kpsumatera2.com/reset-password",
	)
	if err != nil {
		t.Fatalf("create password recovery service: %v", err)
	}

	return service
}

func TestForgotPasswordDelegatesToSupabase(t *testing.T) {
	auth := &fakeSupabasePasswordRecoveryAuth{}
	service := newTestSupabasePasswordRecoveryService(t, auth)

	err := service.Request(
		context.Background(),
		" User@Example.COM ",
	)
	if err != nil {
		t.Fatalf("request recovery: %v", err)
	}

	if auth.requestCalls != 1 {
		t.Fatalf("expected one Supabase request, got %d", auth.requestCalls)
	}

	if auth.email != "user@example.com" {
		t.Fatalf("expected normalized email, got %q", auth.email)
	}

	if auth.redirectURL !=
		"https://sso.bp3kpsumatera2.com/reset-password" {

		t.Fatalf("unexpected redirect URL %q", auth.redirectURL)
	}
}

func TestPasswordRecoveryValidTokenUpdatesPassword(t *testing.T) {
	auth := &fakeSupabasePasswordRecoveryAuth{
		session: &models.SupabaseSession{
			AccessToken: "recovery-access-token",
			User: models.SupabaseAuthUser{
				ID: "auth-user-id",
			},
		},
	}
	service := newTestSupabasePasswordRecoveryService(t, auth)

	err := service.Reset(
		context.Background(),
		" recovery-token-hash ",
		"NewPassword123!",
	)
	if err != nil {
		t.Fatalf("reset password: %v", err)
	}

	if auth.verifyCalls != 1 || auth.tokenHash != "recovery-token-hash" {
		t.Fatal("recovery token hash was not verified through Supabase")
	}

	if auth.updateCalls != 1 ||
		auth.accessToken != "recovery-access-token" ||
		auth.password != "NewPassword123!" {

		t.Fatal("password was not updated with the recovery session")
	}
}

func TestPasswordRecoveryRejectsInvalidOrExpiredToken(t *testing.T) {
	auth := &fakeSupabasePasswordRecoveryAuth{
		verifyErr: ErrInvalidToken,
	}
	service := newTestSupabasePasswordRecoveryService(t, auth)

	err := service.Reset(
		context.Background(),
		"expired-token-hash",
		"NewPassword123!",
	)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected invalid token, got %v", err)
	}

	if auth.updateCalls != 0 {
		t.Fatal("password update ran after token verification failed")
	}
}

func TestPasswordRecoveryReturnsInvalidPassword(t *testing.T) {
	auth := &fakeSupabasePasswordRecoveryAuth{
		session: &models.SupabaseSession{
			AccessToken: "recovery-access-token",
		},
		updateErr: ErrInvalidPassword,
	}
	service := newTestSupabasePasswordRecoveryService(t, auth)

	err := service.Reset(
		context.Background(),
		"recovery-token-hash",
		"short",
	)
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("expected invalid password, got %v", err)
	}
}
