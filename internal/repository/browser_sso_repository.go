package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type BrowserSSORepository struct {
	pool *pgxpool.Pool
}

func NewBrowserSSORepository(pool *pgxpool.Pool) *BrowserSSORepository {
	return &BrowserSSORepository{pool: pool}
}

func (r *BrowserSSORepository) CreateSession(
	ctx context.Context,
	session *models.BrowserSSOSession,
) error {
	return r.pool.QueryRow(ctx, `
INSERT INTO public.sso_browser_sessions (
    token_hash, auth_user_id, app_user_id, expires_at
) VALUES ($1, $2, $3, $4)
RETURNING id, created_at, last_seen_at
`, session.TokenHash, session.AuthUserID, session.AppUserID,
		session.ExpiresAt,
	).Scan(&session.ID, &session.CreatedAt, &session.LastSeenAt)
}

func (r *BrowserSSORepository) GetActiveSessionByTokenHash(
	ctx context.Context,
	tokenHash []byte,
) (*models.BrowserSSOSession, error) {
	return r.scanSession(r.pool.QueryRow(ctx, `
SELECT id, token_hash, auth_user_id, app_user_id,
       created_at, expires_at, last_seen_at, revoked_at
FROM public.sso_browser_sessions
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
LIMIT 1
`, tokenHash))
}

func (r *BrowserSSORepository) GetActiveSessionByID(
	ctx context.Context,
	id string,
) (*models.BrowserSSOSession, error) {
	return r.scanSession(r.pool.QueryRow(ctx, `
SELECT id, token_hash, auth_user_id, app_user_id,
       created_at, expires_at, last_seen_at, revoked_at
FROM public.sso_browser_sessions
WHERE id = $1 AND revoked_at IS NULL AND expires_at > now()
LIMIT 1
`, id))
}

func (r *BrowserSSORepository) scanSession(row pgx.Row) (*models.BrowserSSOSession, error) {
	var session models.BrowserSSOSession
	if err := row.Scan(
		&session.ID, &session.TokenHash, &session.AuthUserID, &session.AppUserID,
		&session.CreatedAt, &session.ExpiresAt, &session.LastSeenAt,
		&session.RevokedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read browser SSO session: %w", err)
	}
	return &session, nil
}

func (r *BrowserSSORepository) RevokeSession(
	ctx context.Context,
	tokenHash []byte,
) error {
	_, err := r.pool.Exec(ctx, `
UPDATE public.sso_browser_sessions
SET revoked_at = now()
WHERE token_hash = $1 AND revoked_at IS NULL
`, tokenHash)
	return err
}

func (r *BrowserSSORepository) CreateAuthorizationCode(
	ctx context.Context,
	code *models.BrowserSSOAuthorizationCode,
) error {
	_, err := r.pool.Exec(ctx, `
INSERT INTO public.sso_authorization_codes (
    code_hash, browser_session_id, client_id, auth_user_id, app_user_id,
    redirect_uri, code_challenge, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
`, code.CodeHash, code.BrowserSessionID, code.ClientID, code.AuthUserID,
		code.AppUserID, code.RedirectURI, code.CodeChallenge, code.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create browser SSO authorization code: %w", err)
	}
	return nil
}

func (r *BrowserSSORepository) ConsumeAuthorizationCode(
	ctx context.Context,
	codeHash []byte,
	clientID string,
	redirectURI string,
	codeChallenge string,
) (*models.BrowserSSOAuthorizationCode, error) {
	row := r.pool.QueryRow(ctx, `
UPDATE public.sso_authorization_codes
SET used_at = now()
WHERE code_hash = $1
  AND client_id = $2
  AND redirect_uri = $3
  AND code_challenge = $4
  AND used_at IS NULL
  AND expires_at > now()
RETURNING code_hash, browser_session_id, client_id, auth_user_id, app_user_id,
          redirect_uri, code_challenge, expires_at, used_at, created_at
`, codeHash, clientID, redirectURI, codeChallenge)

	var code models.BrowserSSOAuthorizationCode
	if err := row.Scan(
		&code.CodeHash, &code.BrowserSessionID, &code.ClientID,
		&code.AuthUserID, &code.AppUserID, &code.RedirectURI,
		&code.CodeChallenge, &code.ExpiresAt, &code.UsedAt, &code.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("consume browser SSO authorization code: %w", err)
	}
	return &code, nil
}

func AuthorizationCodeExpired(code *models.BrowserSSOAuthorizationCode, now time.Time) bool {
	return code == nil || !code.ExpiresAt.After(now)
}
