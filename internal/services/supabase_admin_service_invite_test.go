package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSupabaseAdminInviteUsesAuthOwnedCredentialSetup(t *testing.T) {
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
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "auth-user-id", "email": "user@example.com"})
	}))
	defer server.Close()

	service, err := NewSupabaseAdminService(server.URL, "test-admin-key")
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.InviteUser(context.Background(), " User@Example.com ", "User Example")
	if err != nil || user == nil || user.ID != "auth-user-id" {
		t.Fatalf("unexpected invite result: %#v err=%v", user, err)
	}
}
