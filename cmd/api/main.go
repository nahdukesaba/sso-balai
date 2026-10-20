package main

import (
	"log"
	"time"

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
	sessionRepository := repository.NewSessionRepository(db)
	centralRegistrationRepository :=
		repository.NewCentralRegistrationRepository(db)

	passwordResetRepository :=
		repository.NewPasswordResetRepository(db)

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

	accessTokenService, err := services.NewAccessTokenService(
		cfg.AuthAccessTokenSecret,
		"sso-balai",
		15*time.Minute,
	)
	if err != nil {
		log.Fatalf(
			"failed to initialize central access token service: %v",
			err,
		)
	}

	sessionService, err := services.NewSessionService(
		sessionRepository,
		accessTokenService,
		7*24*time.Hour,
	)
	if err != nil {
		log.Fatalf(
			"failed to initialize central session service: %v",
			err,
		)
	}

	centralLoginService := services.NewCentralLoginService(
		userRepository,
		credentialService,
		applicationContextService,
		sessionService,
		identityService,
	)

	centralPasswordChangeService :=
		services.NewCentralPasswordChangeService(
			credentialService,
			sessionRepository,
		)

	// SMTP must never prevent Central SSO from starting. A missing or
	// invalid configuration degrades only recovery email delivery.
	recoveryMailer, mailerErr :=
		services.NewRecoveryMailer(
			services.SMTPConfig{
				Host:      cfg.SMTPHost,
				Port:      cfg.SMTPPort,
				Username:  cfg.SMTPUsername,
				Password:  cfg.SMTPPassword,
				FromName:  cfg.SMTPFromName,
				FromEmail: cfg.SMTPFromEmail,
			},
		)
	if mailerErr != nil {
		log.Printf(
			"WARNING: password recovery email delivery unavailable: %v",
			mailerErr,
		)
	}

	centralPasswordRecoveryService, err :=
		services.NewCentralPasswordRecoveryService(
			passwordResetRepository,
			credentialService,
			sessionRepository,
			recoveryMailer,
			cfg.SSOPublicURL,
		)
	if err != nil {
		log.Fatalf(
			"failed to initialize central password recovery: %v",
			err,
		)
	}

	applicationEnrollmentService :=
		services.NewApplicationEnrollmentService(
			applicationEnrollmentRepository,
		)

	authService := services.NewAuthService(
		identityService,
		applicationContextService,
	)

	authService.SetCentralLoginService(
		centralLoginService,
	)

	authService.SetCentralRegistrationService(
		centralRegistrationService,
	)

	authService.SetCentralSessionService(
		sessionService,
	)

	authService.SetCentralPasswordChangeService(
		centralPasswordChangeService,
	)

	authService.SetCentralPasswordRecoveryService(
		centralPasswordRecoveryService,
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
