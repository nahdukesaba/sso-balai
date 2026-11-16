package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type SSOClientRepository struct {
	pool *pgxpool.Pool
}

func NewSSOClientRepository(pool *pgxpool.Pool) *SSOClientRepository {
	return &SSOClientRepository{pool: pool}
}

// ListActive returns every active client whose application is also active.
func (r *SSOClientRepository) ListActive(ctx context.Context) ([]models.SSOClient, error) {
	rows, err := r.pool.Query(ctx, `
SELECT c.client_id, a.code, a.name, c.description, c.launch_url,
       c.access_policy, c.introspection_secret_hash,
       c.redirect_uris, c.post_logout_redirect_uris
FROM public.sso_clients c
JOIN public.applications a ON a.id = c.application_id
WHERE c.is_active AND a.is_active
ORDER BY c.client_id
`)
	if err != nil {
		return nil, fmt.Errorf("list SSO clients: %w", err)
	}
	clients, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (models.SSOClient, error) {
		var client models.SSOClient
		err := row.Scan(
			&client.ClientID, &client.ApplicationCode, &client.ApplicationName,
			&client.Description, &client.LaunchURL, &client.AccessPolicy,
			&client.IntrospectionSecretHash, &client.RedirectURIs, &client.PostLogoutRedirectURIs,
		)
		return client, err
	})
	if err != nil {
		return nil, fmt.Errorf("scan SSO clients: %w", err)
	}
	return clients, nil
}

// Upsert registers or updates a client. A non-empty applicationName also
// creates or renames the application row, so a new system needs one command.
func (r *SSOClientRepository) Upsert(
	ctx context.Context,
	client models.SSOClient,
	applicationName string,
) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		code := strings.ToLower(strings.TrimSpace(client.ApplicationCode))
		if name := strings.TrimSpace(applicationName); name != "" {
			if _, err := tx.Exec(ctx, `
INSERT INTO public.applications (code, name) VALUES ($1, $2)
ON CONFLICT (code) DO UPDATE SET name = EXCLUDED.name
`, code, name); err != nil {
				return fmt.Errorf("upsert application: %w", err)
			}
		}
		var applicationID string
		err := tx.QueryRow(ctx, `SELECT id FROM public.applications WHERE code = $1`, code).Scan(&applicationID)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("application %q does not exist; pass -name to create it", code)
		}
		if err != nil {
			return fmt.Errorf("find application: %w", err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO public.sso_clients (
    client_id, application_id, access_policy, introspection_secret_hash,
    redirect_uris, post_logout_redirect_uris, launch_url, description
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (client_id) DO UPDATE SET
    application_id = EXCLUDED.application_id,
    access_policy = EXCLUDED.access_policy,
    introspection_secret_hash = EXCLUDED.introspection_secret_hash,
    redirect_uris = EXCLUDED.redirect_uris,
    post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
    launch_url = EXCLUDED.launch_url,
    description = EXCLUDED.description,
    is_active = true
`, strings.TrimSpace(client.ClientID), applicationID, client.AccessPolicy,
			client.IntrospectionSecretHash, client.RedirectURIs, client.PostLogoutRedirectURIs,
			client.LaunchURL, client.Description); err != nil {
			return fmt.Errorf("upsert SSO client: %w", err)
		}
		return nil
	})
}
