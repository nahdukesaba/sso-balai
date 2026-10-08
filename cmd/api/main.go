package main

import (
	"log"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/config"
	"github.com/nahdukesaba/sso-balai/internal/database"
	"github.com/nahdukesaba/sso-balai/internal/handlers"
	"github.com/nahdukesaba/sso-balai/internal/middleware"
	"github.com/nahdukesaba/sso-balai/internal/repository"
	"github.com/nahdukesaba/sso-balai/internal/router"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	db, err := database.NewPostgresPool(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	log.Println("database connection established")

	userRepository := repository.NewUserRepository(db)
	pegawaiRepository := repository.NewPegawaiRepository(db)

	identityService := services.NewIdentityService(
		userRepository,
		pegawaiRepository,
	)

	supabaseAuthService, err := services.NewSupabaseAuthService(
		cfg.SupabaseURL,
		cfg.SupabaseAnonKey,
	)
	if err != nil {
		log.Fatalf("failed to initialize Supabase authentication: %v", err)
	}

	authService := services.NewAuthService(
		supabaseAuthService,
		identityService,
	)

	authHandler := handlers.NewAuthHandler(authService)
	authMiddleware := middleware.NewAuthMiddleware(authService)
	app := fiber.New()

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":   "ok",
			"service":  "sso-balai",
			"database": "connected",
		})
	})

	router.Register(
		app,
		authHandler,
		authMiddleware,
	)

	log.Printf("SSO Balai listening on port %s", cfg.AppPort)

	log.Fatal(app.Listen(":" + cfg.AppPort))
}
