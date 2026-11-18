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
	klinikIdentityRepository :=
		repository.NewKlinikIdentityRepository(db)
	applicationRepository := repository.NewApplicationRepository(db)
	membershipRepository := repository.NewMembershipRepository(db)
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
		)

	registrationService :=
		services.NewSupabaseRegistrationService(
			userRepository,
			applicationRepository,
			supabaseAdminService,
			centralRegistrationRepository,
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
		ssoClients := []services.BrowserSSOClient{
			{
				ClientID:               cfg.SSOSilapetClientID,
				ApplicationCode:        cfg.SSOSilapetApplicationCode,
				AccessPolicy:           cfg.SSOSilapetAccessPolicy,
				IntrospectionSecret:    cfg.SSOSilapetIntrospectionSecret,
				RedirectURIs:           cfg.SSOSilapetRedirectURIs,
				PostLogoutRedirectURIs: cfg.SSOSilapetPostLogoutURIs,
			},
			{
				ClientID:               cfg.SSOKlinikClientID,
				ApplicationCode:        cfg.SSOKlinikApplicationCode,
				AccessPolicy:           cfg.SSOKlinikAccessPolicy,
				IntrospectionSecret:    cfg.SSOKlinikIntrospectionSecret,
				RedirectURIs:           cfg.SSOKlinikRedirectURIs,
				PostLogoutRedirectURIs: cfg.SSOKlinikPostLogoutURIs,
			},
		}
		if cfg.SSOArsiparisEnabled {
			ssoClients = append(ssoClients, services.BrowserSSOClient{
				ClientID:               cfg.SSOArsiparisClientID,
				ApplicationCode:        cfg.SSOArsiparisApplicationCode,
				AccessPolicy:           cfg.SSOArsiparisAccessPolicy,
				IntrospectionSecret:    cfg.SSOArsiparisIntrospectionSecret,
				RedirectURIs:           cfg.SSOArsiparisRedirectURIs,
				PostLogoutRedirectURIs: cfg.SSOArsiparisPostLogoutURIs,
			})
		}
		if cfg.SSOSijabuEnabled {
			ssoClients = append(ssoClients, services.BrowserSSOClient{
				ClientID:               cfg.SSOSijabuClientID,
				ApplicationCode:        cfg.SSOSijabuApplicationCode,
				AccessPolicy:           cfg.SSOSijabuAccessPolicy,
				IntrospectionSecret:    cfg.SSOSijabuIntrospectionSecret,
				RedirectURIs:           cfg.SSOSijabuRedirectURIs,
				PostLogoutRedirectURIs: cfg.SSOSijabuPostLogoutURIs,
			})
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
		var portalLaunchURLs []string
		if cfg.SSOArsiparisEnabled {
			portalLaunchURLs = append(portalLaunchURLs, cfg.PortalArsiparisLaunchURL)
		}
		accountPortalService, err = services.NewAccountPortalService(
			browserSSOService,
			applicationRepository,
			cfg.PortalSilapetLaunchURL,
			cfg.PortalKlinikLaunchURL,
			portalLaunchURLs...,
		)
		if err != nil {
			log.Fatalf("failed to initialize account portal: %v", err)
		}
		if cfg.SSOSijabuEnabled {
			if err := accountPortalService.RegisterApplication(
				cfg.SSOSijabuApplicationCode,
				"Portal BP3KP (SIJABU)",
				"Portal layanan informasi perumahan, pengaduan masyarakat, dan akses pegawai BP3KP Sumatera II",
				cfg.PortalSijabuLaunchURL,
			); err != nil {
				log.Fatalf("failed to register sijabu portal card: %v", err)
			}
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
	router.RegisterKlinikAdminUsers(app, klinikAdminUserHandler, authMiddleware)

	listenAddress := cfg.AppHost + ":" + cfg.AppPort

	log.Printf("SSO Balai listening on %s", listenAddress)

	log.Fatal(app.Listen(listenAddress))
}
