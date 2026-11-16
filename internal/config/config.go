package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppHost                     string
	AppPort                     string
	DatabaseURL                 string
	PasswordRecoveryRedirectURL string
	SupabaseInviteRedirectURL   string
	SSOBrowserEnabled           bool
	SSOBrowserSessionKey        string
	SSOBrowserCookieSecure      bool
	SSOBrowserCookieSameSite    string
	SSOBrowserSessionTTL        time.Duration
	SSOAuthorizationCodeTTL     time.Duration

	SupabaseURL       string
	SupabasePublicKey string
	SupabaseAdminKey  string

	BootstrapEmail    string
	BootstrapPassword string
	BootstrapName     string
	BootstrapRole     string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		AppHost:     getEnv("APP_HOST", "127.0.0.1"),
		AppPort:     getEnv("APP_PORT", "8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		PasswordRecoveryRedirectURL: getEnv(
			"PASSWORD_RECOVERY_REDIRECT_URL",
			"https://sso.bp3kpsumatera2.com/reset-password",
		),
		SupabaseInviteRedirectURL: strings.TrimSpace(getEnv(
			"SUPABASE_INVITE_REDIRECT_URL",
			"https://sso.bp3kpsumatera2.com/accept-invite",
		)),
		SSOBrowserEnabled:        getEnvBool("SSO_BROWSER_ENABLED", false),
		SSOBrowserSessionKey:     os.Getenv("SSO_BROWSER_SESSION_KEY"),
		SSOBrowserCookieSecure:   getEnvBool("SSO_BROWSER_COOKIE_SECURE", true),
		SSOBrowserCookieSameSite: getEnv("SSO_BROWSER_COOKIE_SAME_SITE", "Lax"),
		SSOBrowserSessionTTL:     getEnvDuration("SSO_BROWSER_SESSION_TTL", 8*time.Hour),
		SSOAuthorizationCodeTTL:  getEnvDuration("SSO_AUTHORIZATION_CODE_TTL", 3*time.Minute),

		SupabaseURL: os.Getenv("SUPABASE_URL"),

		SupabasePublicKey: firstNonEmpty(
			os.Getenv("SUPABASE_PUBLISHABLE_KEY"),
			os.Getenv("SUPABASE_ANON_KEY"),
		),

		SupabaseAdminKey: firstNonEmpty(
			os.Getenv("SUPABASE_SECRET_KEY"),
			os.Getenv("SUPABASE_SERVICE_ROLE_KEY"),
		),

		BootstrapEmail:    os.Getenv("BOOTSTRAP_USER_EMAIL"),
		BootstrapPassword: os.Getenv("BOOTSTRAP_USER_PASSWORD"),
		BootstrapName:     os.Getenv("BOOTSTRAP_USER_NAME"),
		BootstrapRole:     getEnv("BOOTSTRAP_USER_ROLE", "admin"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	if err := validateConfiguredHTTPURLs(
		"SUPABASE_INVITE_REDIRECT_URL",
		[]string{cfg.SupabaseInviteRedirectURL},
	); err != nil {
		return nil, err
	}

	if cfg.SSOBrowserEnabled {
		if strings.TrimSpace(cfg.SSOBrowserSessionKey) == "" {
			return nil, fmt.Errorf("SSO_BROWSER_SESSION_KEY is required when browser SSO is enabled")
		}
		sameSite := strings.ToLower(strings.TrimSpace(cfg.SSOBrowserCookieSameSite))
		if sameSite != "lax" && sameSite != "strict" && sameSite != "none" {
			return nil, fmt.Errorf("SSO_BROWSER_COOKIE_SAME_SITE must be Lax, Strict, or None")
		}
		if sameSite == "none" && !cfg.SSOBrowserCookieSecure {
			return nil, fmt.Errorf("SSO_BROWSER_COOKIE_SECURE must be true when SameSite=None")
		}
	}

	return cfg, nil
}

func validateConfiguredHTTPURLs(name string, values []string) error {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsAny(value, "*#") {
			return fmt.Errorf("%s must contain only absolute HTTP(S) URLs", name)
		}
		parsed, err := url.ParseRequestURI(value)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("%s must contain only absolute HTTP(S) URLs", name)
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("%s must contain only absolute HTTP(S) URLs", name)
		}
	}
	return nil
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}

	return parsed
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
