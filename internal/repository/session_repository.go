package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type SessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(
	pool *pgxpool.Pool,
) *SessionRepository {
	return &SessionRepository{
		pool: pool,
	}
}

const sessionColumns = `
	id,
	app_user_id,
	application_id,
	refresh_token_hash,
	expires_at,
	last_used_at,
	revoked_at,
	created_at,
	updated_at
`

func scanSession(
	row pgx.Row,
) (*models.AuthSession, error) {
	var session models.AuthSession

	err := row.Scan(
		&session.ID,
		&session.AppUserID,
		&session.ApplicationID,
		&session.RefreshTokenHash,
		&session.ExpiresAt,
		&session.LastUsedAt,
		&session.RevokedAt,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (r *SessionRepository) Create(
	ctx context.Context,
	appUserID string,
	applicationID string,
	refreshTokenHash string,
	expiresAt time.Time,
) (*models.AuthSession, error) {
	appUserID = strings.TrimSpace(appUserID)
	applicationID = strings.TrimSpace(applicationID)
	refreshTokenHash = strings.TrimSpace(refreshTokenHash)

	if appUserID == "" ||
		applicationID == "" ||
		refreshTokenHash == "" {
		return nil, errors.New(
			"session user, application, and refresh token hash are required",
		)
	}

	row := r.pool.QueryRow(
		ctx,
		`
		INSERT INTO public.auth_sessions (
			app_user_id,
			application_id,
			refresh_token_hash,
			expires_at
		)
		VALUES ($1, $2, $3, $4)
		RETURNING `+sessionColumns,
		appUserID,
		applicationID,
		refreshTokenHash,
		expiresAt,
	)

	session, err := scanSession(row)
	if err != nil {
		return nil, fmt.Errorf(
			"create auth session: %w",
			err,
		)
	}

	return session, nil
}

func (r *SessionRepository) GetByID(
	ctx context.Context,
	id string,
) (*models.AuthSession, error) {
	id = strings.TrimSpace(id)

	if id == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(
		ctx,
		`
		SELECT `+sessionColumns+`
		FROM public.auth_sessions
		WHERE id = $1
		LIMIT 1
		`,
		id,
	)

	session, err := scanSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"get auth session by id: %w",
			err,
		)
	}

	return session, nil
}

func (r *SessionRepository) GetByRefreshTokenHash(
	ctx context.Context,
	refreshTokenHash string,
) (*models.AuthSession, error) {
	refreshTokenHash = strings.TrimSpace(
		refreshTokenHash,
	)

	if refreshTokenHash == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(
		ctx,
		`
		SELECT `+sessionColumns+`
		FROM public.auth_sessions
		WHERE refresh_token_hash = $1
		LIMIT 1
		`,
		refreshTokenHash,
	)

	session, err := scanSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"get auth session by refresh token hash: %w",
			err,
		)
	}

	return session, nil
}

func (r *SessionRepository) RotateRefreshToken(
	ctx context.Context,
	sessionID string,
	currentRefreshTokenHash string,
	newRefreshTokenHash string,
	expiresAt time.Time,
) (*models.AuthSession, error) {
	sessionID = strings.TrimSpace(sessionID)

	currentRefreshTokenHash = strings.TrimSpace(
		currentRefreshTokenHash,
	)

	newRefreshTokenHash = strings.TrimSpace(
		newRefreshTokenHash,
	)

	if sessionID == "" ||
		currentRefreshTokenHash == "" ||
		newRefreshTokenHash == "" {
		return nil, errors.New(
			"session and refresh token hashes are required",
		)
	}

	row := r.pool.QueryRow(
		ctx,
		`
		UPDATE public.auth_sessions
		SET
			refresh_token_hash = $3,
			expires_at = $4,
			last_used_at = NOW(),
			updated_at = NOW()
		WHERE id = $1
		  AND refresh_token_hash = $2
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		RETURNING `+sessionColumns,
		sessionID,
		currentRefreshTokenHash,
		newRefreshTokenHash,
		expiresAt,
	)

	session, err := scanSession(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"rotate auth session refresh token: %w",
			err,
		)
	}

	return session, nil
}

func (r *SessionRepository) RevokeByID(
	ctx context.Context,
	sessionID string,
) error {
	sessionID = strings.TrimSpace(sessionID)

	if sessionID == "" {
		return nil
	}

	_, err := r.pool.Exec(
		ctx,
		`
		UPDATE public.auth_sessions
		SET
			revoked_at = COALESCE(revoked_at, NOW()),
			updated_at = NOW()
		WHERE id = $1
		`,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf(
			"revoke auth session: %w",
			err,
		)
	}

	return nil
}

func (r *SessionRepository) RevokeAllByAppUserID(
	ctx context.Context,
	appUserID string,
) error {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" {
		return nil
	}

	_, err := r.pool.Exec(
		ctx,
		`
		UPDATE public.auth_sessions
		SET
			revoked_at = COALESCE(revoked_at, NOW()),
			updated_at = NOW()
		WHERE app_user_id = $1
		  AND revoked_at IS NULL
		`,
		appUserID,
	)
	if err != nil {
		return fmt.Errorf(
			"revoke central sessions by user: %w",
			err,
		)
	}

	return nil
}
