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
	klinikUserRepository := repository.NewKlinikUserRepository(db)
	applicationRepository := repository.NewApplicationRepository(db)
	membershipRepository := repository.NewMembershipRepository(db)
	credentialRepository := repository.NewCredentialRepository(db)
	centralRegistrationRepository :=
		repository.NewCentralRegistrationRepository(db)

	applicationEnrollmentRepository :=
		repository.NewApplicationEnrollmentRepository(
			db,
		)

	identityService := services.NewIdentityService(
		userRepository,
		pegawaiRepository,
	)

	klinikContextService := services.NewKlinikContextService(
		klinikUserRepository,
	)

	applicationContextService := services.NewApplicationContextService(
		applicationRepository,
		membershipRepository,
	)

	credentialService := services.NewCredentialService(
		credentialRepository,
	)

	centralRegistrationService :=
		services.NewCentralRegistrationService(
			userRepository,
			applicationRepository,
			credentialService,
			centralRegistrationRepository,
		)

	supabaseAuthService, err := services.NewSupabaseAuthService(
		cfg.SupabaseURL,
		cfg.SupabasePublicKey,
	)
	if err != nil {
		log.Fatalf("failed to initialize Supabase authentication: %v", err)
	}

	activeAuthenticationService :=
		services.NewSupabaseCentralAuthService(
			supabaseAuthService,
			userRepository,
			applicationContextService,
			identityService,
		)

	passwordRecoveryService, err :=
		services.NewSupabasePasswordRecoveryService(
			supabaseAuthService,
			cfg.PasswordRecoveryRedirectURL,
		)
	if err != nil {
		log.Fatalf(
			"failed to initialize Supabase password recovery: %v",
			err,
		)
	}

	supabaseAdminService, err := services.NewSupabaseAdminService(
		cfg.SupabaseURL,
		cfg.SupabaseAdminKey,
	)
	if err != nil {
		log.Fatalf(
			"failed to initialize Supabase admin service: %v",
			err,
		)
	}

	klinikCredentialService := services.NewKlinikCredentialService(
		klinikUserRepository,
	)

	klinikMigrationService := services.NewKlinikMigrationService(
		klinikCredentialService,
		supabaseAdminService,
		userRepository,
		pegawaiRepository,
		klinikUserRepository,
	)

	applicationEnrollmentService :=
		services.NewApplicationEnrollmentService(
			applicationEnrollmentRepository,
		)

	authService := services.NewAuthService(
		supabaseAuthService,
		supabaseAdminService,
		identityService,
		userRepository,
		klinikContextService,
		applicationContextService,
		klinikMigrationService,
	)

	authService.SetCentralRegistrationService(
		centralRegistrationService,
	)

	authService.SetActiveAuthenticationService(
		activeAuthenticationService,
	)

	authService.SetPasswordRecoveryService(
		passwordRecoveryService,
	)

	authService.SetApplicationEnrollmentService(
		applicationEnrollmentService,
	)

	authHandler := handlers.NewAuthHandler(
		authService,
		klinikContextService,
		applicationContextService,
	)
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

	listenAddress := cfg.AppHost + ":" + cfg.AppPort

	log.Printf("SSO Balai listening on %s", listenAddress)

	log.Fatal(app.Listen(listenAddress))
}
