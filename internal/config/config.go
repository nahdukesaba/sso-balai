package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppHost                         string
	AppPort                         string
	DatabaseURL                     string
	PasswordRecoveryRedirectURL     string
	SupabaseInviteRedirectURL       string
	SSOBrowserEnabled               bool
	SSOBrowserSessionKey            string
	SSOBrowserCookieSecure          bool
	SSOBrowserCookieSameSite        string
	SSOBrowserSessionTTL            time.Duration
	SSOAuthorizationCodeTTL         time.Duration
	SSOSilapetClientID              string
	SSOSilapetApplicationCode       string
	SSOSilapetAccessPolicy          string
	SSOSilapetIntrospectionSecret   string
	SSOSilapetRedirectURIs          []string
	SSOSilapetPostLogoutURIs        []string
	PortalSilapetLaunchURL          string
	SSOKlinikClientID               string
	SSOKlinikApplicationCode        string
	SSOKlinikAccessPolicy           string
	SSOKlinikIntrospectionSecret    string
	SSOKlinikRedirectURIs           []string
	SSOKlinikPostLogoutURIs         []string
	PortalKlinikLaunchURL           string
	SSOArsiparisClientID            string
	SSOArsiparisApplicationCode     string
	SSOArsiparisAccessPolicy        string
	SSOArsiparisIntrospectionSecret string
	SSOArsiparisRedirectURIs        []string
	SSOArsiparisPostLogoutURIs      []string
	PortalArsiparisLaunchURL        string
	SSOSijabuEnabled                bool
	SSOSijabuClientID               string
	SSOSijabuApplicationCode        string
	SSOSijabuAccessPolicy           string
	SSOSijabuIntrospectionSecret    string
	SSOSijabuRedirectURIs           []string
	SSOSijabuPostLogoutURIs         []string
	PortalSijabuLaunchURL           string
	SSOKompuEnabled                 bool
	SSOKompuClientID                string
	SSOKompuApplicationCode         string
	SSOKompuAccessPolicy            string
	SSOKompuIntrospectionSecret     string
	SSOKompuRedirectURIs            []string
	SSOKompuPostLogoutURIs          []string
	PortalKompuLaunchURL            string

	SSORealisasiBSPSEnabled             bool
	SSORealisasiBSPSClientID            string
	SSORealisasiBSPSApplicationCode     string
	SSORealisasiBSPSAccessPolicy        string
	SSORealisasiBSPSIntrospectionSecret string
	SSORealisasiBSPSRedirectURIs        []string
	SSORealisasiBSPSPostLogoutURIs      []string
	PortalRealisasiBSPSLaunchURL        string

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
		AppHost:     getEnv("APP_HOST", "127.0.0.1"),
		AppPort:     getEnv("APP_PORT", "8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		PasswordRecoveryRedirectURL: getEnv(
			"PASSWORD_RECOVERY_REDIRECT_URL",
			"https://sso.bp3kpsumatera2.com/reset-password",
		),
		SupabaseInviteRedirectURL: strings.TrimSpace(getEnv(
			"SUPABASE_INVITE_REDIRECT_URL",
			"https://sso.bp3kpsumatera2.com/accept-invite",
		)),
		SSOBrowserEnabled:               getEnvBool("SSO_BROWSER_ENABLED", false),
		SSOBrowserSessionKey:            os.Getenv("SSO_BROWSER_SESSION_KEY"),
		SSOBrowserCookieSecure:          getEnvBool("SSO_BROWSER_COOKIE_SECURE", true),
		SSOBrowserCookieSameSite:        getEnv("SSO_BROWSER_COOKIE_SAME_SITE", "Lax"),
		SSOBrowserSessionTTL:            getEnvDuration("SSO_BROWSER_SESSION_TTL", 8*time.Hour),
		SSOAuthorizationCodeTTL:         getEnvDuration("SSO_AUTHORIZATION_CODE_TTL", 3*time.Minute),
		SSOSilapetClientID:              strings.TrimSpace(getEnv("SSO_SILAPET_CLIENT_ID", "silapet-web")),
		SSOSilapetApplicationCode:       strings.TrimSpace(getEnv("SSO_SILAPET_APPLICATION_CODE", "silapet")),
		SSOSilapetAccessPolicy:          strings.ToUpper(strings.TrimSpace(getEnv("SSO_SILAPET_ACCESS_POLICY", "AUTO_USER"))),
		SSOSilapetIntrospectionSecret:   strings.TrimSpace(os.Getenv("SSO_SILAPET_INTROSPECTION_SECRET")),
		SSOSilapetRedirectURIs:          splitCSV(os.Getenv("SSO_SILAPET_REDIRECT_URIS")),
		SSOSilapetPostLogoutURIs:        splitCSV(os.Getenv("SSO_SILAPET_POST_LOGOUT_REDIRECT_URIS")),
		PortalSilapetLaunchURL:          strings.TrimSpace(os.Getenv("PORTAL_SILAPET_LAUNCH_URL")),
		SSOKlinikClientID:               strings.TrimSpace(getEnv("SSO_KLINIK_CLIENT_ID", "klinik-pkp-web")),
		SSOKlinikApplicationCode:        strings.TrimSpace(getEnv("SSO_KLINIK_APPLICATION_CODE", "klinik_pkp")),
		SSOKlinikAccessPolicy:           strings.ToUpper(strings.TrimSpace(getEnv("SSO_KLINIK_ACCESS_POLICY", "AUTO_USER"))),
		SSOKlinikIntrospectionSecret:    strings.TrimSpace(os.Getenv("SSO_KLINIK_INTROSPECTION_SECRET")),
		SSOKlinikRedirectURIs:           splitCSV(os.Getenv("SSO_KLINIK_REDIRECT_URIS")),
		SSOKlinikPostLogoutURIs:         splitCSV(os.Getenv("SSO_KLINIK_POST_LOGOUT_REDIRECT_URIS")),
		PortalKlinikLaunchURL:           strings.TrimSpace(os.Getenv("PORTAL_KLINIK_LAUNCH_URL")),
		SSOArsiparisClientID:            strings.TrimSpace(getEnv("SSO_ARSIPARIS_CLIENT_ID", "arsiparis-web")),
		SSOArsiparisApplicationCode:     strings.TrimSpace(getEnv("SSO_ARSIPARIS_APPLICATION_CODE", "arsiparis")),
		SSOArsiparisAccessPolicy:        strings.ToUpper(strings.TrimSpace(getEnv("SSO_ARSIPARIS_ACCESS_POLICY", "AUTO_USER"))),
		SSOArsiparisIntrospectionSecret: strings.TrimSpace(os.Getenv("SSO_ARSIPARIS_INTROSPECTION_SECRET")),
		SSOArsiparisRedirectURIs:        splitCSV(os.Getenv("SSO_ARSIPARIS_REDIRECT_URIS")),
		SSOArsiparisPostLogoutURIs:      splitCSV(os.Getenv("SSO_ARSIPARIS_POST_LOGOUT_REDIRECT_URIS")),
		PortalArsiparisLaunchURL:        strings.TrimSpace(os.Getenv("PORTAL_ARSIPARIS_LAUNCH_URL")),
		SSOSijabuEnabled:                getEnvBool("SSO_SIJABU_ENABLED", false),
		SSOSijabuClientID:               strings.TrimSpace(getEnv("SSO_SIJABU_CLIENT_ID", "sijabu-landing-web")),
		SSOSijabuApplicationCode:        strings.TrimSpace(getEnv("SSO_SIJABU_APPLICATION_CODE", "sijabu")),
		SSOSijabuAccessPolicy:           strings.ToUpper(strings.TrimSpace(getEnv("SSO_SIJABU_ACCESS_POLICY", "AUTO_USER"))),
		SSOSijabuIntrospectionSecret:    strings.TrimSpace(os.Getenv("SSO_SIJABU_INTROSPECTION_SECRET")),
		SSOSijabuRedirectURIs:           splitCSV(os.Getenv("SSO_SIJABU_REDIRECT_URIS")),
		SSOSijabuPostLogoutURIs:         splitCSV(os.Getenv("SSO_SIJABU_POST_LOGOUT_REDIRECT_URIS")),
		PortalSijabuLaunchURL:           strings.TrimSpace(getEnv("PORTAL_SIJABU_LAUNCH_URL", "https://bp3kpsumatera2.com/")),
		SSOKompuEnabled:                 getEnvBool("SSO_KOMPU_ENABLED", false),
		SSOKompuClientID:                strings.TrimSpace(getEnv("SSO_KOMPU_CLIENT_ID", "kompu-web")),
		SSOKompuApplicationCode:         strings.TrimSpace(getEnv("SSO_KOMPU_APPLICATION_CODE", "kompu")),
		SSOKompuAccessPolicy:            strings.ToUpper(strings.TrimSpace(getEnv("SSO_KOMPU_ACCESS_POLICY", "AUTO_USER"))),
		SSOKompuIntrospectionSecret:     strings.TrimSpace(os.Getenv("SSO_KOMPU_INTROSPECTION_SECRET")),
		SSOKompuRedirectURIs:            splitCSV(os.Getenv("SSO_KOMPU_REDIRECT_URIS")),
		SSOKompuPostLogoutURIs:          splitCSV(os.Getenv("SSO_KOMPU_POST_LOGOUT_REDIRECT_URIS")),
		PortalKompuLaunchURL:            strings.TrimSpace(os.Getenv("PORTAL_KOMPU_LAUNCH_URL")),

		SSORealisasiBSPSEnabled:             getEnvBool("SSO_REALISASI_BSPS_ENABLED", false),
		SSORealisasiBSPSClientID:            strings.TrimSpace(getEnv("SSO_REALISASI_BSPS_CLIENT_ID", "realisasi-bsps-web")),
		SSORealisasiBSPSApplicationCode:     strings.TrimSpace(getEnv("SSO_REALISASI_BSPS_APPLICATION_CODE", "realisasi-bsps")),
		SSORealisasiBSPSAccessPolicy:        strings.ToUpper(strings.TrimSpace(getEnv("SSO_REALISASI_BSPS_ACCESS_POLICY", "AUTO_USER"))),
		SSORealisasiBSPSIntrospectionSecret: strings.TrimSpace(os.Getenv("SSO_REALISASI_BSPS_INTROSPECTION_SECRET")),
		SSORealisasiBSPSRedirectURIs:        splitCSV(os.Getenv("SSO_REALISASI_BSPS_REDIRECT_URIS")),
		SSORealisasiBSPSPostLogoutURIs:      splitCSV(os.Getenv("SSO_REALISASI_BSPS_POST_LOGOUT_REDIRECT_URIS")),
		PortalRealisasiBSPSLaunchURL:        strings.TrimSpace(os.Getenv("PORTAL_REALISASI_BSPS_LAUNCH_URL")),

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

	if err := validateConfiguredHTTPURLs(
		"SUPABASE_INVITE_REDIRECT_URL",
		[]string{cfg.SupabaseInviteRedirectURL},
	); err != nil {
		return nil, err
	}

	if cfg.SSOBrowserEnabled {
		if strings.TrimSpace(cfg.SSOBrowserSessionKey) == "" {
			return nil, fmt.Errorf("SSO_BROWSER_SESSION_KEY is required when browser SSO is enabled")
		}
		if len(cfg.SSOSilapetRedirectURIs) == 0 {
			return nil, fmt.Errorf("SSO_SILAPET_REDIRECT_URIS is required when browser SSO is enabled")
		}
		if len(cfg.SSOSilapetPostLogoutURIs) == 0 {
			return nil, fmt.Errorf("SSO_SILAPET_POST_LOGOUT_REDIRECT_URIS is required when browser SSO is enabled")
		}
		if strings.TrimSpace(cfg.SSOSilapetClientID) == "" || strings.TrimSpace(cfg.SSOSilapetApplicationCode) == "" {
			return nil, fmt.Errorf("SILAPET browser SSO client ID and application code are required")
		}
		if err := validateSSOClientSecurity("SILAPET", cfg.SSOSilapetAccessPolicy, cfg.SSOSilapetIntrospectionSecret); err != nil {
			return nil, err
		}
		if err := validateSSOClientSecurity("KLINIK", cfg.SSOKlinikAccessPolicy, cfg.SSOKlinikIntrospectionSecret); err != nil {
			return nil, err
		}
		if err := validateSSOClientSecurity("ARSIPARIS", cfg.SSOArsiparisAccessPolicy, cfg.SSOArsiparisIntrospectionSecret); err != nil {
			return nil, err
		}
		if strings.TrimSpace(cfg.SSOKlinikClientID) == "" || strings.TrimSpace(cfg.SSOKlinikApplicationCode) == "" {
			return nil, fmt.Errorf("Klinik browser SSO client ID and application code are required")
		}
		if strings.TrimSpace(cfg.SSOArsiparisClientID) == "" || strings.TrimSpace(cfg.SSOArsiparisApplicationCode) == "" {
			return nil, fmt.Errorf("Arsiparis browser SSO client ID and application code are required")
		}
		silapetClientID := strings.TrimSpace(cfg.SSOSilapetClientID)
		klinikClientID := strings.TrimSpace(cfg.SSOKlinikClientID)
		arsiparisClientID := strings.TrimSpace(cfg.SSOArsiparisClientID)
		if silapetClientID == klinikClientID || silapetClientID == arsiparisClientID || klinikClientID == arsiparisClientID {
			return nil, fmt.Errorf("browser SSO client IDs must be unique")
		}
		if len(cfg.SSOKlinikRedirectURIs) == 0 {
			return nil, fmt.Errorf("SSO_KLINIK_REDIRECT_URIS is required when browser SSO is enabled")
		}
		if len(cfg.SSOKlinikPostLogoutURIs) == 0 {
			return nil, fmt.Errorf("SSO_KLINIK_POST_LOGOUT_REDIRECT_URIS is required when browser SSO is enabled")
		}
		if len(cfg.SSOArsiparisRedirectURIs) == 0 {
			return nil, fmt.Errorf("SSO_ARSIPARIS_REDIRECT_URIS is required when browser SSO is enabled")
		}
		if len(cfg.SSOArsiparisPostLogoutURIs) == 0 {
			return nil, fmt.Errorf("SSO_ARSIPARIS_POST_LOGOUT_REDIRECT_URIS is required when browser SSO is enabled")
		}
		if err := validateConfiguredHTTPURLs("SSO_SILAPET_REDIRECT_URIS", cfg.SSOSilapetRedirectURIs); err != nil {
			return nil, err
		}
		if err := validateConfiguredHTTPURLs("SSO_SILAPET_POST_LOGOUT_REDIRECT_URIS", cfg.SSOSilapetPostLogoutURIs); err != nil {
			return nil, err
		}
		if err := validateConfiguredHTTPURLs("SSO_KLINIK_REDIRECT_URIS", cfg.SSOKlinikRedirectURIs); err != nil {
			return nil, err
		}
		if err := validateConfiguredHTTPURLs("SSO_KLINIK_POST_LOGOUT_REDIRECT_URIS", cfg.SSOKlinikPostLogoutURIs); err != nil {
			return nil, err
		}
		if err := validateConfiguredHTTPURLs("SSO_ARSIPARIS_REDIRECT_URIS", cfg.SSOArsiparisRedirectURIs); err != nil {
			return nil, err
		}
		if err := validateConfiguredHTTPURLs("SSO_ARSIPARIS_POST_LOGOUT_REDIRECT_URIS", cfg.SSOArsiparisPostLogoutURIs); err != nil {
			return nil, err
		}
		if err := validateConfiguredHTTPURLs("PORTAL_SILAPET_LAUNCH_URL", []string{cfg.PortalSilapetLaunchURL}); err != nil {
			return nil, err
		}
		if err := validateConfiguredHTTPURLs("PORTAL_KLINIK_LAUNCH_URL", []string{cfg.PortalKlinikLaunchURL}); err != nil {
			return nil, err
		}
		if err := validateConfiguredHTTPURLs("PORTAL_ARSIPARIS_LAUNCH_URL", []string{cfg.PortalArsiparisLaunchURL}); err != nil {
			return nil, err
		}
		if cfg.SSOSijabuEnabled {
			if err := validateSSOClientSecurity("SIJABU", cfg.SSOSijabuAccessPolicy, cfg.SSOSijabuIntrospectionSecret); err != nil {
				return nil, err
			}
			if strings.TrimSpace(cfg.SSOSijabuClientID) == "" || strings.TrimSpace(cfg.SSOSijabuApplicationCode) == "" {
				return nil, fmt.Errorf("Sijabu browser SSO client ID and application code are required")
			}
			sijabuClientID := strings.TrimSpace(cfg.SSOSijabuClientID)
			if silapetClientID == sijabuClientID || klinikClientID == sijabuClientID || arsiparisClientID == sijabuClientID {
				return nil, fmt.Errorf("browser SSO client IDs must be unique")
			}
			if len(cfg.SSOSijabuRedirectURIs) == 0 {
				return nil, fmt.Errorf("SSO_SIJABU_REDIRECT_URIS is required when browser SSO is enabled")
			}
			if len(cfg.SSOSijabuPostLogoutURIs) == 0 {
				return nil, fmt.Errorf("SSO_SIJABU_POST_LOGOUT_REDIRECT_URIS is required when browser SSO is enabled")
			}
			if err := validateConfiguredHTTPURLs("SSO_SIJABU_REDIRECT_URIS", cfg.SSOSijabuRedirectURIs); err != nil {
				return nil, err
			}
			if err := validateConfiguredHTTPURLs("SSO_SIJABU_POST_LOGOUT_REDIRECT_URIS", cfg.SSOSijabuPostLogoutURIs); err != nil {
				return nil, err
			}
		}
		if cfg.SSOKompuEnabled {
			if err := validateSSOClientSecurity("KOMPU", cfg.SSOKompuAccessPolicy, cfg.SSOKompuIntrospectionSecret); err != nil {
				return nil, err
			}
			if strings.TrimSpace(cfg.SSOKompuClientID) == "" || strings.TrimSpace(cfg.SSOKompuApplicationCode) == "" {
				return nil, fmt.Errorf("Kompu browser SSO client ID and application code are required")
			}
			kompuClientID := strings.TrimSpace(cfg.SSOKompuClientID)
			if silapetClientID == kompuClientID || klinikClientID == kompuClientID ||
				arsiparisClientID == kompuClientID ||
				(cfg.SSOSijabuEnabled && strings.TrimSpace(cfg.SSOSijabuClientID) == kompuClientID) {
				return nil, fmt.Errorf("browser SSO client IDs must be unique")
			}
			if len(cfg.SSOKompuRedirectURIs) == 0 {
				return nil, fmt.Errorf("SSO_KOMPU_REDIRECT_URIS is required when browser SSO is enabled")
			}
			if len(cfg.SSOKompuPostLogoutURIs) == 0 {
				return nil, fmt.Errorf("SSO_KOMPU_POST_LOGOUT_REDIRECT_URIS is required when browser SSO is enabled")
			}
			if err := validateConfiguredHTTPURLs("SSO_KOMPU_REDIRECT_URIS", cfg.SSOKompuRedirectURIs); err != nil {
				return nil, err
			}
			if err := validateConfiguredHTTPURLs("SSO_KOMPU_POST_LOGOUT_REDIRECT_URIS", cfg.SSOKompuPostLogoutURIs); err != nil {
				return nil, err
			}
			if err := validateConfiguredHTTPURLs("PORTAL_KOMPU_LAUNCH_URL", []string{cfg.PortalKompuLaunchURL}); err != nil {
				return nil, err
			}
		}
		if cfg.SSORealisasiBSPSEnabled {
			if err := validateSSOClientSecurity("REALISASI_BSPS", cfg.SSORealisasiBSPSAccessPolicy, cfg.SSORealisasiBSPSIntrospectionSecret); err != nil {
				return nil, err
			}
			if strings.TrimSpace(cfg.SSORealisasiBSPSClientID) == "" || strings.TrimSpace(cfg.SSORealisasiBSPSApplicationCode) == "" {
				return nil, fmt.Errorf("Realisasi BSPS browser SSO client ID and application code are required")
			}
			bspsClientID := strings.TrimSpace(cfg.SSORealisasiBSPSClientID)
			if silapetClientID == bspsClientID || klinikClientID == bspsClientID ||
				(cfg.SSOArsiparisEnabled && strings.TrimSpace(cfg.SSOArsiparisClientID) == bspsClientID) ||
				(cfg.SSOSijabuEnabled && strings.TrimSpace(cfg.SSOSijabuClientID) == bspsClientID) ||
				(cfg.SSOKompuEnabled && strings.TrimSpace(cfg.SSOKompuClientID) == bspsClientID) {
				return nil, fmt.Errorf("browser SSO client IDs must be unique")
			}
			if len(cfg.SSORealisasiBSPSRedirectURIs) == 0 {
				return nil, fmt.Errorf("SSO_REALISASI_BSPS_REDIRECT_URIS is required when browser SSO is enabled")
			}
			if len(cfg.SSORealisasiBSPSPostLogoutURIs) == 0 {
				return nil, fmt.Errorf("SSO_REALISASI_BSPS_POST_LOGOUT_REDIRECT_URIS is required when browser SSO is enabled")
			}
			if err := validateConfiguredHTTPURLs("SSO_REALISASI_BSPS_REDIRECT_URIS", cfg.SSORealisasiBSPSRedirectURIs); err != nil {
				return nil, err
			}
			if err := validateConfiguredHTTPURLs("SSO_REALISASI_BSPS_POST_LOGOUT_REDIRECT_URIS", cfg.SSORealisasiBSPSPostLogoutURIs); err != nil {
				return nil, err
			}
			if err := validateConfiguredHTTPURLs("PORTAL_REALISASI_BSPS_LAUNCH_URL", []string{cfg.PortalRealisasiBSPSLaunchURL}); err != nil {
				return nil, err
			}
		}
		sameSite := strings.ToLower(strings.TrimSpace(cfg.SSOBrowserCookieSameSite))
		if sameSite != "lax" && sameSite != "strict" && sameSite != "none" {
			return nil, fmt.Errorf("SSO_BROWSER_COOKIE_SAME_SITE must be Lax, Strict, or None")
		}
		if sameSite == "none" && !cfg.SSOBrowserCookieSecure {
			return nil, fmt.Errorf("SSO_BROWSER_COOKIE_SECURE must be true when SameSite=None")
		}
	}

	return cfg, nil
}

func validateSSOClientSecurity(name, policy, secret string) error {
	if policy != "AUTO_USER" && policy != "RESTRICTED" {
		return fmt.Errorf("SSO_%s_ACCESS_POLICY must be AUTO_USER or RESTRICTED", name)
	}
	if len(strings.TrimSpace(secret)) < 32 {
		return fmt.Errorf("SSO_%s_INTROSPECTION_SECRET must be at least 32 characters", name)
	}
	return nil
}

func validateConfiguredHTTPURLs(name string, values []string) error {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsAny(value, "*#") {
			return fmt.Errorf("%s must contain only absolute HTTP(S) URLs", name)
		}
		parsed, err := url.ParseRequestURI(value)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
			return fmt.Errorf("%s must contain only absolute HTTP(S) URLs", name)
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("%s must contain only absolute HTTP(S) URLs", name)
		}
	}
	return nil
}

func getEnvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}

	return parsed
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return fallback
	}

	return parsed
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
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
