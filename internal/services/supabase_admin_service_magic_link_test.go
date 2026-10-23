package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGenerateMagicLinkToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/auth/v1/admin/generate_link" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("apikey") != "service-role-test" || r.Header.Get("Authorization") != "Bearer service-role-test" {
			t.Fatal("admin authorization headers missing")
		}
		var body generateMagicLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Type != "magiclink" || body.Email != "person@example.com" {
			t.Fatalf("unexpected body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hashed_token":"server-only-hash","verification_type":"magiclink"}`))
	}))
	defer server.Close()

	service, err := NewSupabaseAdminService(
		server.URL,
		"service-role-test",
		"https://sso.example.test/accept-invite",
	)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash, err := service.GenerateMagicLinkToken(context.Background(), "person@example.com")
	if err != nil || tokenHash != "server-only-hash" {
		t.Fatalf("generate token: %q %v", tokenHash, err)
	}
}
