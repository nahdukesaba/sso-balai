// Command sso-client registers or updates a Browser SSO client in
// public.sso_clients. Restart the API afterwards so it loads the change.
//
// The introspection secret is read from the environment variable named by
// -secret-env (default SSO_CLIENT_SECRET, also read from .env) so it never
// appears in shell history. Only its SHA-256 hash is stored.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"strings"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/config"
	"github.com/nahdukesaba/sso-balai/internal/database"
	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

func main() {
	clientID := flag.String("client-id", "", "OAuth client ID the app sends, e.g. silapet-web (required)")
	appCode := flag.String("app", "", "application code in public.applications, e.g. silapet (required)")
	appName := flag.String("name", "", "application display name; creates or renames the application row")
	description := flag.String("description", "", "description shown on the portal card")
	launchURL := flag.String("launch-url", "", "app SSO start URL for the portal 'Buka Aplikasi' button; empty hides the button")
	redirectURIs := flag.String("redirect-uris", "", "comma-separated exact callback URLs (required)")
	postLogoutURIs := flag.String("post-logout-uris", "", "comma-separated exact post-logout URLs (required)")
	accessPolicy := flag.String("access-policy", services.ApplicationAccessRestricted,
		"AUTO_USER (users may sign up or request access; an admin approves) or RESTRICTED (invite/provisioning only)")
	secretEnv := flag.String("secret-env", "SSO_CLIENT_SECRET", "environment variable holding the introspection secret (min 32 chars)")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}
	policy := strings.ToUpper(strings.TrimSpace(*accessPolicy))
	if policy != services.ApplicationAccessAutoUser && policy != services.ApplicationAccessRestricted {
		log.Fatal("-access-policy must be AUTO_USER or RESTRICTED")
	}
	secret := strings.TrimSpace(os.Getenv(*secretEnv))
	if len(secret) < 32 {
		log.Fatalf("%s must hold an introspection secret of at least 32 characters", *secretEnv)
	}

	client := models.SSOClient{
		ClientID:                strings.TrimSpace(*clientID),
		ApplicationCode:         strings.ToLower(strings.TrimSpace(*appCode)),
		Description:             strings.TrimSpace(*description),
		LaunchURL:               strings.TrimSpace(*launchURL),
		AccessPolicy:            policy,
		IntrospectionSecretHash: services.HashIntrospectionSecret(secret),
		RedirectURIs:            splitCSV(*redirectURIs),
		PostLogoutRedirectURIs:  splitCSV(*postLogoutURIs),
	}
	if err := services.ValidateBrowserSSOClient(client); err != nil {
		log.Fatalf("invalid client: %v", err)
	}

	db, err := database.NewPostgresPool(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := repository.NewSSOClientRepository(db).Upsert(ctx, client, *appName); err != nil {
		log.Fatalf("failed to register client: %v", err)
	}
	log.Printf("registered SSO client %q for application %q; restart the API to load it", client.ClientID, client.ApplicationCode)
}

func splitCSV(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
