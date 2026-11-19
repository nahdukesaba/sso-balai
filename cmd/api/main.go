package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	ssoAdminRepository := repository.NewSSOAdminRepository(db)

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
			{
				ClientID:               cfg.SSOArsiparisClientID,
				ApplicationCode:        cfg.SSOArsiparisApplicationCode,
				AccessPolicy:           cfg.SSOArsiparisAccessPolicy,
				IntrospectionSecret:    cfg.SSOArsiparisIntrospectionSecret,
				RedirectURIs:           cfg.SSOArsiparisRedirectURIs,
				PostLogoutRedirectURIs: cfg.SSOArsiparisPostLogoutURIs,
			},
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
		if cfg.SSOKompuEnabled {
			ssoClients = append(ssoClients, services.BrowserSSOClient{
				ClientID:               cfg.SSOKompuClientID,
				ApplicationCode:        cfg.SSOKompuApplicationCode,
				AccessPolicy:           cfg.SSOKompuAccessPolicy,
				IntrospectionSecret:    cfg.SSOKompuIntrospectionSecret,
				RedirectURIs:           cfg.SSOKompuRedirectURIs,
				PostLogoutRedirectURIs: cfg.SSOKompuPostLogoutURIs,
			})
		}
		if cfg.SSORealisasiBSPSEnabled {
			ssoClients = append(ssoClients, services.BrowserSSOClient{
				ClientID:               cfg.SSORealisasiBSPSClientID,
				ApplicationCode:        cfg.SSORealisasiBSPSApplicationCode,
				AccessPolicy:           cfg.SSORealisasiBSPSAccessPolicy,
				IntrospectionSecret:    cfg.SSORealisasiBSPSIntrospectionSecret,
				RedirectURIs:           cfg.SSORealisasiBSPSRedirectURIs,
				PostLogoutRedirectURIs: cfg.SSORealisasiBSPSPostLogoutURIs,
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
		accountPortalService, err = services.NewAccountPortalService(
			browserSSOService,
			applicationRepository,
			cfg.PortalSilapetLaunchURL,
			cfg.PortalKlinikLaunchURL,
			cfg.PortalArsiparisLaunchURL,
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
		if cfg.SSOKompuEnabled {
			if err := accountPortalService.RegisterApplication(
				cfg.SSOKompuApplicationCode,
				"Kompu",
				"Aplikasi Kompu BP3KP Sumatera II",
				cfg.PortalKompuLaunchURL,
			); err != nil {
				log.Fatalf("failed to register kompu portal card: %v", err)
			}
		}
		if cfg.SSORealisasiBSPSEnabled {
			if err := accountPortalService.RegisterApplication(
				cfg.SSORealisasiBSPSApplicationCode,
				"Realisasi BSPS",
				"Dashboard realisasi penyaluran dana bantuan Bedah Rumah (BSPS) BP3KP Sumatera II",
				cfg.PortalRealisasiBSPSLaunchURL,
			); err != nil {
				log.Fatalf("failed to register realisasi bsps portal card: %v", err)
			}
		}

		// Load any dynamic applications registered in PostgreSQL via Admin SSO UI.
		if dbApps, err := ssoAdminRepository.ListApplications(context.Background()); err == nil {
			for _, dbApp := range dbApps {
				if !dbApp.IsActive || dbApp.ClientID == "" || len(dbApp.RedirectURIs) == 0 {
					continue
				}
				if _, existsErr := browserSSOService.ApplicationCodeForClient(dbApp.ClientID); existsErr == nil {
					continue
				}
				secretBytes := make([]byte, 24)
				_, _ = rand.Read(secretBytes)
				postLogout := dbApp.PostLogoutRedirectURIs
				if len(postLogout) == 0 && dbApp.LaunchURL != "" {
					postLogout = []string{dbApp.LaunchURL}
				}
				_ = browserSSOService.UpsertClient(services.BrowserSSOClient{
					ClientID:               dbApp.ClientID,
					ApplicationCode:        dbApp.Code,
					AccessPolicy:           dbApp.AccessPolicy,
					IntrospectionSecret:    hex.EncodeToString(secretBytes),
					RedirectURIs:           dbApp.RedirectURIs,
					PostLogoutRedirectURIs: postLogout,
				})
				if dbApp.LaunchURL != "" {
					_ = accountPortalService.RegisterApplication(
						dbApp.Code,
						dbApp.Name,
						dbApp.Description,
						dbApp.LaunchURL,
					)
				}
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
	browserSSOHandler.SetAdminRepository(ssoAdminRepository)
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
