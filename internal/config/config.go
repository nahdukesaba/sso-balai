package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	AppPort     string
	DatabaseURL string

	SupabaseURL        string
	SupabaseAnonKey    string
	SupabaseServiceKey string
}

func Load() (*Config, error) {
	// .env hanya digunakan untuk development lokal.
	// Jika file tidak ada, environment variable dari OS/server tetap digunakan.
	_ = godotenv.Load()

	cfg := &Config{
		AppPort:            getEnv("APP_PORT", "8080"),
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		SupabaseURL:        os.Getenv("SUPABASE_URL"),
		SupabaseAnonKey:    os.Getenv("SUPABASE_ANON_KEY"),
		SupabaseServiceKey: os.Getenv("SUPABASE_SERVICE_ROLE_KEY"),
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
