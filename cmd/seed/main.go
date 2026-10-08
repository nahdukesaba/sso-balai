package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/config"
	"github.com/nahdukesaba/sso-balai/internal/database"
	"github.com/nahdukesaba/sso-balai/internal/repository"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	adminService, err := services.NewSupabaseAdminService(
		cfg.SupabaseURL,
		cfg.SupabaseAdminKey,
	)
	if err != nil {
		log.Fatalf("failed to initialize Supabase admin service: %v", err)
	}

	db, err := database.NewPostgresPool(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	userRepository := repository.NewUserRepository(db)

	bootstrapService := services.NewBootstrapService(
		adminService,
		userRepository,
	)

	ctx, cancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	defer cancel()

	result, err := bootstrapService.Bootstrap(
		ctx,
		cfg.BootstrapEmail,
		cfg.BootstrapPassword,
		cfg.BootstrapName,
		cfg.BootstrapRole,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrBootstrapInvalid):
			log.Fatal(
				"bootstrap configuration is incomplete; check BOOTSTRAP_USER_* environment variables",
			)

		case errors.Is(err, services.ErrBootstrapConflict):
			log.Fatalf(
				"bootstrap stopped because existing identity data conflicts: %v",
				err,
			)

		default:
			log.Fatalf("bootstrap failed: %v", err)
		}
	}

	log.Printf(
		"bootstrap completed successfully: %s",
		result.Action,
	)
}
