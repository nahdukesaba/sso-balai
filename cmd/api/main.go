package main

import (
	"context"
	"log"
	"os"

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
	klinikIdentityRepository :=
		repository.NewKlinikIdentityRepository(db)
	applicationRepository := repository.NewApplicationRepository(db)
	membershipRepository := repository.NewMembershipRepository(db)
	credentialRepository := repository.NewCredentialRepository(db)
	centralRegistrationRepository :=
		repository.NewCentralRegistrationRepository(db)
	klinikAdminUserRepository := repository.NewKlinikAdminUserRepository(db)
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
		klinikIdentityRepository,
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

	inviteAcceptanceService, err :=
		services.NewSupabaseInviteAcceptanceService(
			supabaseAuthService,
		)
	if err != nil {
		log.Fatalf(
			"failed to initialize Supabase invite acceptance: %v",
			err,
		)
	}

	supabaseAdminService, err := services.NewSupabaseAdminService(
		cfg.SupabaseURL,
		cfg.SupabaseAdminKey,
		cfg.SupabaseInviteRedirectURL,
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

	// TODO(auth-cleanup): This legacy migration graph is still constructed even
	// though the active login path does not invoke it. Confirm production
	// migration and rollback requirements before removing it.
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

	authService.SetInviteAcceptanceService(
		inviteAcceptanceService,
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
	klinikAdminUserService := services.NewKlinikAdminUserService(
		applicationContextService,
		supabaseAdminService,
		klinikAdminUserRepository,
	)
	klinikAdminUserHandler := handlers.NewKlinikAdminUserHandler(klinikAdminUserService)

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
		// shortcut: clients load once at startup; restart after `go run ./cmd/sso-client`.
		ssoClients, clientsErr := repository.NewSSOClientRepository(db).ListActive(context.Background())
		if clientsErr != nil {
			log.Fatalf("failed to load browser SSO clients: %v", clientsErr)
		}
		if len(ssoClients) == 0 {
			log.Fatal("browser SSO is enabled but public.sso_clients has no active client; register one with `go run ./cmd/sso-client`")
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
				Clients:       ssoClients,
				SessionTTL:    cfg.SSOBrowserSessionTTL,
				CodeTTL:       cfg.SSOAuthorizationCodeTTL,
				EncryptionKey: cfg.SSOBrowserSessionKey,
			},
		)
		if err != nil {
			log.Fatalf("failed to initialize browser SSO: %v", err)
		}
		accountPortalService, err = services.NewAccountPortalService(
			browserSSOService,
			applicationRepository,
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
	browserSSOHandler.SetRegistrationService(registrationService)
	browserSSOHandler.SetMembershipAdminService(
		services.NewMembershipAdminService(repository.NewMembershipAdminRepository(db)),
	)
	var oidcProvider *services.OIDCProvider
	if cfg.OIDCIssuer != "" {
		signingKey, keyErr := os.ReadFile(cfg.OIDCSigningKeyFile)
		if keyErr != nil {
			log.Fatalf("failed to read OIDC signing key: %v", keyErr)
		}
		oidcProvider, err = services.NewOIDCProvider(cfg.OIDCIssuer, signingKey, browserSSOService)
		if err != nil {
			log.Fatalf("failed to initialize OpenID Connect: %v", err)
		}
		browserSSOHandler.SetOIDCProvider(oidcProvider)
	}
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
	router.RegisterKlinikAdminUsers(app, klinikAdminUserHandler, authMiddleware)
	if oidcProvider != nil {
		router.RegisterOIDC(app, handlers.NewOIDCHandler(oidcProvider))
		log.Printf("OpenID Connect issuer %s", oidcProvider.Issuer())
	}

	listenAddress := cfg.AppHost + ":" + cfg.AppPort

	log.Printf("SSO Balai listening on %s", listenAddress)

	log.Fatal(app.Listen(listenAddress))
}
