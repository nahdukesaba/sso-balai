package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSupabaseAdminInviteUsesAuthOwnedCredentialSetup(t *testing.T) {
	const inviteRedirectURL = "https://sso.example.test/accept-invite"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/auth/v1/invite" {
			t.Fatalf("unexpected invite request: %s %s", r.Method, r.URL.Path)
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload["email"] != "user@example.com" {
			t.Fatalf("email was not normalized: %#v", payload)
		}
		if _, exists := payload["password"]; exists {
			t.Fatal("invite request must not contain a password")
		}
		if got := r.URL.Query().Get("redirect_to"); got != inviteRedirectURL {
			t.Fatalf("unexpected invite redirect: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "auth-user-id", "email": "user@example.com"})
	}))
	defer server.Close()

	service, err := NewSupabaseAdminService(
		server.URL,
		"test-admin-key",
		inviteRedirectURL,
	)
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.InviteUser(context.Background(), " User@Example.com ", "User Example")
	if err != nil || user == nil || user.ID != "auth-user-id" {
		t.Fatalf("unexpected invite result: %#v err=%v", user, err)
	}
}

func TestSupabaseAdminServiceRejectsInvalidInviteRedirect(t *testing.T) {
	for _, redirectURL := range []string{
		"",
		"/accept-invite",
		"javascript:alert(1)",
		"https://sso.example.test/accept-invite#token",
	} {
		if _, err := NewSupabaseAdminService(
			"https://supabase.example.test",
			"test-admin-key",
			redirectURL,
		); err == nil {
			t.Fatalf("invalid invite redirect accepted: %q", redirectURL)
		}
	}
}
