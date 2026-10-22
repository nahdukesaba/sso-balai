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
	browserSSORepository := repository.NewBrowserSSORepository(db)

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

	applicationEnrollmentService :=
		services.NewApplicationEnrollmentService(
			applicationEnrollmentRepository,
		)

	supabaseAuthService, err := services.NewSupabaseAuthService(
		cfg.SupabaseURL,
		cfg.SupabasePublicKey,
	)
	if err != nil {
		log.Fatalf("failed to initialize Supabase authentication: %v", err)
	}

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

	activeAuthenticationService :=
		services.NewSupabaseCentralAuthService(
			supabaseAuthService,
			userRepository,
			applicationContextService,
			applicationEnrollmentService,
			identityService,
			credentialService,
			supabaseAdminService,
		)

	registrationService :=
		services.NewSupabaseRegistrationService(
			userRepository,
			applicationRepository,
			supabaseAdminService,
			centralRegistrationRepository,
		)

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

	requestAccessService :=
		services.NewCentralRequestAccessService(
			supabaseAuthService,
			userRepository,
			applicationEnrollmentService,
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

	authService.SetRegistrationService(
		registrationService,
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

	authService.SetRequestAccessService(
		requestAccessService,
	)

	authHandler := handlers.NewAuthHandler(
		authService,
		klinikContextService,
		applicationContextService,
	)

	var browserSSOService *services.BrowserSSOService
	var accountPortalService *services.AccountPortalService
	if cfg.SSOBrowserEnabled {
		browserSSOSessionIssuer, issuerErr :=
			services.NewSupabaseBrowserSSOSessionIssuer(
				supabaseAdminService,
				supabaseAuthService,
			)
		if issuerErr != nil {
			log.Fatalf("failed to initialize browser SSO session issuer: %v", issuerErr)
		}
		browserSSOService, err = services.NewBrowserSSOService(
			browserSSORepository,
			supabaseAuthService,
			browserSSOSessionIssuer,
			userRepository,
			applicationContextService,
			applicationEnrollmentService,
			identityService,
			services.BrowserSSOConfig{
				ClientID:        cfg.SSOSilapetClientID,
				ApplicationCode: cfg.SSOSilapetApplicationCode,
				RedirectURIs:    cfg.SSOSilapetRedirectURIs,
				PostLogoutURIs:  cfg.SSOSilapetPostLogoutURIs,
				SessionTTL:      cfg.SSOBrowserSessionTTL,
				CodeTTL:         cfg.SSOAuthorizationCodeTTL,
				EncryptionKey:   cfg.SSOBrowserSessionKey,
			},
		)
		if err != nil {
			log.Fatalf("failed to initialize browser SSO: %v", err)
		}
		accountPortalService, err = services.NewAccountPortalService(
			browserSSOService,
			applicationRepository,
			cfg.PortalSilapetLaunchURL,
		)
		if err != nil {
			log.Fatalf("failed to initialize account portal: %v", err)
		}
	}

	browserSSOHandler := handlers.NewBrowserSSOHandler(
		browserSSOService,
		cfg.SSOBrowserCookieSecure,
		cfg.SSOBrowserCookieSameSite,
		cfg.SSOBrowserSessionTTL,
	)
	browserSSOHandler.SetAccountPortalService(accountPortalService)
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
		browserSSOHandler,
	)

	listenAddress := cfg.AppHost + ":" + cfg.AppPort

	log.Printf("SSO Balai listening on %s", listenAddress)

	log.Fatal(app.Listen(listenAddress))
}
