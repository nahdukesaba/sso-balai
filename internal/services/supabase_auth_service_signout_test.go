package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSupabaseSignOutUsesLocalScope(t *testing.T) {
	var method string
	var path string
	var scope string
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		method = request.Method
		path = request.URL.Path
		scope = request.URL.Query().Get("scope")
		authorization = request.Header.Get("Authorization")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	auth, err := NewSupabaseAuthService(server.URL, "public-test-key")
	if err != nil {
		t.Fatalf("create Supabase auth service: %v", err)
	}
	if err := auth.SignOut(context.Background(), "temporary-token"); err != nil {
		t.Fatalf("local sign out: %v", err)
	}
	if method != http.MethodPost || path != "/auth/v1/logout" {
		t.Fatalf("unexpected logout request %s %s", method, path)
	}
	if scope != "local" {
		t.Fatalf("expected local logout scope, got %q", scope)
	}
	if authorization != "Bearer temporary-token" {
		t.Fatal("temporary access token was not used for local logout")
	}
}
