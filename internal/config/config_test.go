package config

import (
	"os"
	"testing"
)

func TestLoadBrowserSSOClients(t *testing.T) {
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
	t.Setenv("SSO_SILAPET_CLIENT_ID", " silapet-web ")
	t.Setenv("SSO_SILAPET_APPLICATION_CODE", " silapet ")
	t.Setenv("SSO_SILAPET_INTROSPECTION_SECRET", "silapet-test-introspection-secret-0001")
	t.Setenv("SSO_SILAPET_REDIRECT_URIS", " http://localhost:8081/auth/sso/callback ")
	t.Setenv("SSO_SILAPET_POST_LOGOUT_REDIRECT_URIS", " http://localhost:8081/login ")
	t.Setenv("PORTAL_SILAPET_LAUNCH_URL", "http://silapet.test:8081/api/auth/sso/start")
	t.Setenv("SSO_KLINIK_CLIENT_ID", " klinik-pkp-web ")
	t.Setenv("SSO_KLINIK_APPLICATION_CODE", " klinik_pkp ")
	t.Setenv("SSO_KLINIK_INTROSPECTION_SECRET", "klinik-test-introspection-secret-00001")
	t.Setenv("SSO_KLINIK_REDIRECT_URIS", " http://localhost:3000/auth/sso/callback ")
	t.Setenv("SSO_KLINIK_POST_LOGOUT_REDIRECT_URIS", " http://localhost:3000/login ")
	t.Setenv("PORTAL_KLINIK_LAUNCH_URL", "http://klinik-pkp.test:3000/api/auth/sso/start")
	t.Setenv("SSO_ARSIPARIS_ENABLED", "true")
	t.Setenv("SSO_ARSIPARIS_CLIENT_ID", " arsiparis-web ")
	t.Setenv("SSO_ARSIPARIS_APPLICATION_CODE", " arsiparis ")
	t.Setenv("SSO_ARSIPARIS_INTROSPECTION_SECRET", "arsiparis-test-introspection-secret-01")
	t.Setenv("SSO_ARSIPARIS_REDIRECT_URIS", " http://localhost:8083/api/auth/sso/callback ")
	t.Setenv("SSO_ARSIPARIS_POST_LOGOUT_REDIRECT_URIS", " http://localhost:5173/login ")
	t.Setenv("PORTAL_ARSIPARIS_LAUNCH_URL", "http://localhost:8083/api/auth/sso/start")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSOArsiparisEnabled ||
		cfg.SSOSilapetClientID != "silapet-web" || cfg.SSOSilapetApplicationCode != "silapet" ||
		cfg.SSOKlinikClientID != "klinik-pkp-web" || cfg.SSOKlinikApplicationCode != "klinik_pkp" ||
		cfg.SSOArsiparisClientID != "arsiparis-web" || cfg.SSOArsiparisApplicationCode != "arsiparis" ||
		len(cfg.SSOSilapetRedirectURIs) != 1 || cfg.SSOSilapetRedirectURIs[0] != "http://localhost:8081/auth/sso/callback" ||
		len(cfg.SSOKlinikRedirectURIs) != 1 || cfg.SSOKlinikRedirectURIs[0] != "http://localhost:3000/auth/sso/callback" ||
		len(cfg.SSOArsiparisRedirectURIs) != 1 || cfg.SSOArsiparisRedirectURIs[0] != "http://localhost:8083/api/auth/sso/callback" ||
		cfg.PortalSilapetLaunchURL != "http://silapet.test:8081/api/auth/sso/start" ||
		cfg.PortalKlinikLaunchURL != "http://klinik-pkp.test:3000/api/auth/sso/start" ||
		cfg.PortalArsiparisLaunchURL != "http://localhost:8083/api/auth/sso/start" {
		t.Fatal("browser SSO clients were not loaded correctly")
	}
}

func setupBaseSSOEnv(t *testing.T) {
	t.Helper()
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
	t.Setenv("SSO_SILAPET_CLIENT_ID", "silapet-web")
	t.Setenv("SSO_SILAPET_APPLICATION_CODE", "silapet")
	t.Setenv("SSO_SILAPET_INTROSPECTION_SECRET", "silapet-test-introspection-secret-0001")
	t.Setenv("SSO_SILAPET_REDIRECT_URIS", "http://localhost:8081/auth/sso/callback")
	t.Setenv("SSO_SILAPET_POST_LOGOUT_REDIRECT_URIS", "http://localhost:8081/login")
	t.Setenv("PORTAL_SILAPET_LAUNCH_URL", "http://silapet.test:8081/api/auth/sso/start")
	t.Setenv("SSO_KLINIK_CLIENT_ID", "klinik-pkp-web")
	t.Setenv("SSO_KLINIK_APPLICATION_CODE", "klinik_pkp")
	t.Setenv("SSO_KLINIK_INTROSPECTION_SECRET", "klinik-test-introspection-secret-00001")
	t.Setenv("SSO_KLINIK_REDIRECT_URIS", "http://localhost:3000/auth/sso/callback")
	t.Setenv("SSO_KLINIK_POST_LOGOUT_REDIRECT_URIS", "http://localhost:3000/login")
	t.Setenv("PORTAL_KLINIK_LAUNCH_URL", "http://klinik-pkp.test:3000/api/auth/sso/start")
}

func TestLoadBrowserSSOArsiparisOptional(t *testing.T) {
	t.Run("browser SSO aktif + Arsiparis disabled + env Arsiparis kosong = berhasil", func(t *testing.T) {
		setupBaseSSOEnv(t)
		t.Setenv("SSO_ARSIPARIS_ENABLED", "false")
		t.Setenv("SSO_ARSIPARIS_INTROSPECTION_SECRET", "")
		t.Setenv("SSO_ARSIPARIS_REDIRECT_URIS", "")
		t.Setenv("SSO_ARSIPARIS_POST_LOGOUT_REDIRECT_URIS", "")
		t.Setenv("PORTAL_ARSIPARIS_LAUNCH_URL", "")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected load to succeed with Arsiparis disabled and empty env, got err: %v", err)
		}
		if cfg.SSOArsiparisEnabled {
			t.Fatal("expected SSOArsiparisEnabled to be false")
		}
	})

	t.Run("Arsiparis enabled + config tidak lengkap = gagal", func(t *testing.T) {
		setupBaseSSOEnv(t)
		t.Setenv("SSO_ARSIPARIS_ENABLED", "true")
		t.Setenv("SSO_ARSIPARIS_INTROSPECTION_SECRET", "")
		t.Setenv("SSO_ARSIPARIS_REDIRECT_URIS", "")
		t.Setenv("SSO_ARSIPARIS_POST_LOGOUT_REDIRECT_URIS", "")
		t.Setenv("PORTAL_ARSIPARIS_LAUNCH_URL", "")

		if _, err := Load(); err == nil {
			t.Fatal("expected load to fail when Arsiparis is enabled but config is incomplete")
		}
	})

	t.Run("Arsiparis enabled + config lengkap = berhasil", func(t *testing.T) {
		setupBaseSSOEnv(t)
		t.Setenv("SSO_ARSIPARIS_ENABLED", "true")
		t.Setenv("SSO_ARSIPARIS_CLIENT_ID", "arsiparis-web")
		t.Setenv("SSO_ARSIPARIS_APPLICATION_CODE", "arsiparis")
		t.Setenv("SSO_ARSIPARIS_INTROSPECTION_SECRET", "arsiparis-test-introspection-secret-01")
		t.Setenv("SSO_ARSIPARIS_REDIRECT_URIS", "http://localhost:8083/api/auth/sso/callback")
		t.Setenv("SSO_ARSIPARIS_POST_LOGOUT_REDIRECT_URIS", "http://localhost:5173/login")
		t.Setenv("PORTAL_ARSIPARIS_LAUNCH_URL", "http://localhost:8083/api/auth/sso/start")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected load to succeed when Arsiparis is enabled and config is complete, got: %v", err)
		}
		if !cfg.SSOArsiparisEnabled {
			t.Fatal("expected SSOArsiparisEnabled to be true")
		}
		if cfg.SSOArsiparisClientID != "arsiparis-web" {
			t.Fatalf("unexpected client ID: %q", cfg.SSOArsiparisClientID)
		}
	})
}

func TestLoadBrowserSSOKompuOptional(t *testing.T) {
	setKompuEnv := func(t *testing.T, clientID string) {
		t.Helper()
		setupBaseSSOEnv(t)
		t.Setenv("SSO_KOMPU_ENABLED", "true")
		t.Setenv("SSO_KOMPU_CLIENT_ID", clientID)
		t.Setenv("SSO_KOMPU_APPLICATION_CODE", "kompu")
		t.Setenv("SSO_KOMPU_INTROSPECTION_SECRET", "kompu-test-introspection-secret-000001")
		t.Setenv("SSO_KOMPU_REDIRECT_URIS", "http://kompu.test:8084/auth/sso/callback")
		t.Setenv("SSO_KOMPU_POST_LOGOUT_REDIRECT_URIS", "http://kompu.test:8084/login")
		t.Setenv("PORTAL_KOMPU_LAUNCH_URL", "http://kompu.test:8084/api/auth/sso/start")
	}

	t.Run("Kompu disabled secara default", func(t *testing.T) {
		setupBaseSSOEnv(t)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected load to succeed with Kompu disabled, got err: %v", err)
		}
		if cfg.SSOKompuEnabled {
			t.Fatal("expected SSOKompuEnabled to be false")
		}
	})

	t.Run("Kompu enabled + config lengkap = berhasil", func(t *testing.T) {
		setKompuEnv(t, " kompu-web ")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected load to succeed, got: %v", err)
		}
		if !cfg.SSOKompuEnabled || cfg.SSOKompuClientID != "kompu-web" ||
			cfg.SSOKompuApplicationCode != "kompu" ||
			len(cfg.SSOKompuRedirectURIs) != 1 ||
			cfg.PortalKompuLaunchURL != "http://kompu.test:8084/api/auth/sso/start" {
			t.Fatal("Kompu client was not loaded correctly")
		}
	})

	t.Run("Kompu enabled + launch URL kosong = gagal", func(t *testing.T) {
		setKompuEnv(t, "kompu-web")
		t.Setenv("PORTAL_KOMPU_LAUNCH_URL", "")
		if _, err := Load(); err == nil {
			t.Fatal("expected load to fail without PORTAL_KOMPU_LAUNCH_URL")
		}
	})

	t.Run("Kompu client ID duplikat = gagal", func(t *testing.T) {
		setKompuEnv(t, "silapet-web")
		if _, err := Load(); err == nil {
			t.Fatal("expected load to fail on duplicate client ID")
		}
	})
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
