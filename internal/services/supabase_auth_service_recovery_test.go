package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyPasswordRecoveryToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}

			if r.URL.Path != "/auth/v1/verify" {
				t.Fatalf("unexpected path: %s", r.URL.Path)
			}

			if r.Header.Get("apikey") != "test-key" {
				t.Fatal("expected Supabase API key")
			}

			var body passwordRecoveryVerificationRequest

			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request: %v", err)
			}

			if body.Type != "recovery" {
				t.Fatalf("expected recovery type, got %q", body.Type)
			}

			if body.TokenHash != "recovery-hash" {
				t.Fatalf("unexpected token hash %q", body.TokenHash)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			_, _ = w.Write([]byte(`{
				"access_token":"verified-recovery-access",
				"token_type":"bearer",
				"expires_in":3600,
				"expires_at":1799999999,
				"refresh_token":"verified-refresh",
				"user":{
					"id":"test-user-id",
					"email":"test@example.com"
				}
			}`))
		},
	))
	defer server.Close()

	service, err := NewSupabaseAuthService(
		server.URL,
		"test-key",
	)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	session, err := service.VerifyPasswordRecoveryToken(
		context.Background(),
		"recovery-hash",
	)
	if err != nil {
		t.Fatalf("verify recovery token: %v", err)
	}

	if session.AccessToken != "verified-recovery-access" {
		t.Fatalf(
			"unexpected access token %q",
			session.AccessToken,
		)
	}

	if session.User.ID != "test-user-id" {
		t.Fatalf(
			"unexpected user id %q",
			session.User.ID,
		)
	}
}

func TestVerifyPasswordRecoveryTokenRejectsInvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		},
	))
	defer server.Close()

	service, err := NewSupabaseAuthService(
		server.URL,
		"test-key",
	)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	_, err = service.VerifyPasswordRecoveryToken(
		context.Background(),
		"invalid-recovery-hash",
	)

	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf(
			"expected ErrInvalidToken, got %v",
			err,
		)
	}
}

func TestVerifyPasswordRecoveryTokenRejectsEmptyToken(t *testing.T) {
	service, err := NewSupabaseAuthService(
		"http://example.invalid",
		"test-key",
	)
	if err != nil {
		t.Fatalf("create service: %v", err)
	}

	_, err = service.VerifyPasswordRecoveryToken(
		context.Background(),
		" ",
	)

	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf(
			"expected ErrInvalidToken, got %v",
			err,
		)
	}
}
