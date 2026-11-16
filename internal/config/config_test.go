package config

import (
	"os"
	"testing"
)

func TestLoadBrowserSSOWithoutPerApplicationVariables(t *testing.T) {
	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	t.Setenv("DATABASE_URL", "postgres://local-test-only")
	t.Setenv("SSO_BROWSER_ENABLED", "true")
	t.Setenv("SSO_BROWSER_SESSION_KEY", "test-key-validation-happens-in-service")

	// Clients come from public.sso_clients, so no per-application variables are needed.
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSOBrowserEnabled || cfg.SSOBrowserSessionKey == "" {
		t.Fatal("browser SSO settings were not loaded")
	}
}

func TestValidateConfiguredHTTPURLs(t *testing.T) {
	for _, values := range [][]string{
		{"http://localhost:8081/auth/sso/callback"},
		{"https://sso.example.test/callback", "http://127.0.0.1:3000/login"},
	} {
		if err := validateConfiguredHTTPURLs("TEST_URLS", values); err != nil {
			t.Fatalf("valid URL rejected: %#v: %v", values, err)
		}
	}

	for _, value := range []string{
		"", "/relative", "javascript:alert(1)", "https://*.example.test/callback",
		"https://user@example.test/callback", "https://example.test/callback#fragment",
	} {
		if err := validateConfiguredHTTPURLs("TEST_URLS", []string{value}); err == nil {
			t.Fatalf("invalid URL accepted: %q", value)
		}
	}
}

func TestLoadSupabaseInviteRedirectURL(t *testing.T) {
	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	t.Setenv("DATABASE_URL", "postgres://local-test-only")
	t.Setenv(
		"SUPABASE_INVITE_REDIRECT_URL",
		" http://127.0.0.1:18082/accept-invite ",
	)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SupabaseInviteRedirectURL != "http://127.0.0.1:18082/accept-invite" {
		t.Fatalf("unexpected invite redirect: %q", cfg.SupabaseInviteRedirectURL)
	}
}

func TestLoadRejectsInvalidSupabaseInviteRedirectURL(t *testing.T) {
	originalDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	t.Setenv("DATABASE_URL", "postgres://local-test-only")
	t.Setenv("SUPABASE_INVITE_REDIRECT_URL", "javascript:alert(1)")

	if _, err := Load(); err == nil {
		t.Fatal("expected invalid invite redirect to be rejected")
	}
}
