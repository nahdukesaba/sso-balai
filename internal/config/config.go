package config

import (
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config is the runtime configuration for cmd/api. It contains nothing
// that belongs to Supabase Auth or to bootstrap tooling.
type Config struct {
	AppHost               string
	AppPort               string
	DatabaseURL           string
	AuthAccessTokenSecret string
	SSOPublicURL          string

	// Custom SMTP, used only for password recovery delivery. These are
	// optional at startup: if they are missing or invalid, Central SSO
	// still starts and only recovery email delivery is degraded.
	SMTPHost      string
	SMTPPort      int
	SMTPUsername  string
	SMTPPassword  string
	SMTPFromName  string
	SMTPFromEmail string
}

// BootstrapConfig is used only by the explicit bootstrap tool (cmd/seed).
// It is never loaded by cmd/api.
type BootstrapConfig struct {
	DatabaseURL string

	SupabaseURL      string
	SupabaseAdminKey string

	Email    string
	Password string
	Name     string
	Role     string
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	// An unparsable SMTP_PORT must not stop authentication from starting;
	// it falls back to the default and the mailer is reported unavailable
	// if the rest of the SMTP settings are unusable.
	smtpPort, err := getEnvInt("SMTP_PORT", 587)
	if err != nil {
		smtpPort = 0
	}

	cfg := &Config{
		AppHost:               getEnv("APP_HOST", "127.0.0.1"),
		AppPort:               getEnv("APP_PORT", "8080"),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		AuthAccessTokenSecret: os.Getenv("AUTH_ACCESS_TOKEN_SECRET"),
		SSOPublicURL:          os.Getenv("SSO_PUBLIC_URL"),

		SMTPHost:      os.Getenv("SMTP_HOST"),
		SMTPPort:      smtpPort,
		SMTPUsername:  os.Getenv("SMTP_USERNAME"),
		SMTPPassword:  os.Getenv("SMTP_PASSWORD"),
		SMTPFromName:  getEnv("SMTP_FROM_NAME", "SSO Balai"),
		SMTPFromEmail: os.Getenv("SMTP_FROM_EMAIL"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	if cfg.AuthAccessTokenSecret == "" {
		return nil, fmt.Errorf("AUTH_ACCESS_TOKEN_SECRET is required")
	}

	if cfg.SSOPublicURL == "" {
		return nil, fmt.Errorf("SSO_PUBLIC_URL is required")
	}

	return cfg, nil
}

func LoadBootstrap() (*BootstrapConfig, error) {
	_ = godotenv.Load()

	cfg := &BootstrapConfig{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		SupabaseURL: os.Getenv("SUPABASE_URL"),
		SupabaseAdminKey: firstNonEmpty(
			os.Getenv("SUPABASE_SECRET_KEY"),
			os.Getenv("SUPABASE_SERVICE_ROLE_KEY"),
		),
		Email:    os.Getenv("BOOTSTRAP_USER_EMAIL"),
		Password: os.Getenv("BOOTSTRAP_USER_PASSWORD"),
		Name:     os.Getenv("BOOTSTRAP_USER_NAME"),
		Role:     getEnv("BOOTSTRAP_USER_ROLE", "admin"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func getEnvInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}

	return parsed, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}

	return ""
}
