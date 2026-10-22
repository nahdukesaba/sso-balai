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
	t.Setenv("SSO_SILAPET_REDIRECT_URIS", " http://localhost:8081/auth/sso/callback ")
	t.Setenv("SSO_SILAPET_POST_LOGOUT_REDIRECT_URIS", " http://localhost:8081/login ")
	t.Setenv("PORTAL_SILAPET_LAUNCH_URL", "http://127.0.0.1:5173/")
	t.Setenv("SSO_KLINIK_CLIENT_ID", " klinik-pkp-web ")
	t.Setenv("SSO_KLINIK_APPLICATION_CODE", " klinik_pkp ")
	t.Setenv("SSO_KLINIK_REDIRECT_URIS", " http://localhost:3000/auth/sso/callback ")
	t.Setenv("SSO_KLINIK_POST_LOGOUT_REDIRECT_URIS", " http://localhost:3000/login ")
	t.Setenv("PORTAL_KLINIK_LAUNCH_URL", "http://localhost:3000/")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSOSilapetClientID != "silapet-web" || cfg.SSOSilapetApplicationCode != "silapet" ||
		cfg.SSOKlinikClientID != "klinik-pkp-web" || cfg.SSOKlinikApplicationCode != "klinik_pkp" ||
		len(cfg.SSOSilapetRedirectURIs) != 1 || cfg.SSOSilapetRedirectURIs[0] != "http://localhost:8081/auth/sso/callback" ||
		len(cfg.SSOKlinikRedirectURIs) != 1 || cfg.SSOKlinikRedirectURIs[0] != "http://localhost:3000/auth/sso/callback" ||
		cfg.PortalKlinikLaunchURL != "http://localhost:3000/" {
		t.Fatal("browser SSO clients were not loaded correctly")
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
