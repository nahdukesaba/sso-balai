package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	AppHost                     string
	AppPort                     string
	DatabaseURL                 string
	AuthAccessTokenSecret       string
	PasswordRecoveryRedirectURL string

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
		AppHost:               getEnv("APP_HOST", "127.0.0.1"),
		AppPort:               getEnv("APP_PORT", "8080"),
		DatabaseURL:           os.Getenv("DATABASE_URL"),
		AuthAccessTokenSecret: os.Getenv("AUTH_ACCESS_TOKEN_SECRET"),
		PasswordRecoveryRedirectURL: getEnv(
			"PASSWORD_RECOVERY_REDIRECT_URL",
			"https://sso.bp3kpsumatera2.com/reset-password",
		),

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

	return cfg, nil
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
