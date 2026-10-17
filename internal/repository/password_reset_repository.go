package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrPasswordResetTokenNotFound = errors.New(
	"password reset token not found",
)

type PasswordResetRepository struct {
	pool *pgxpool.Pool
}

func NewPasswordResetRepository(
	pool *pgxpool.Pool,
) *PasswordResetRepository {
	return &PasswordResetRepository{
		pool: pool,
	}
}

func (r *PasswordResetRepository) FindActiveUserByEmail(
	ctx context.Context,
	email string,
) (
	appUserID string,
	normalizedEmail string,
	found bool,
	err error,
) {
	email = strings.ToLower(
		strings.TrimSpace(email),
	)

	if email == "" {
		return "", "", false, nil
	}

	err = r.pool.QueryRow(
		ctx,
		`
		SELECT id, email
		FROM public.app_users
		WHERE LOWER(email) = LOWER($1)
		  AND deleted_at IS NULL
		LIMIT 1
		`,
		email,
	).Scan(
		&appUserID,
		&normalizedEmail,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}

	if err != nil {
		return "", "", false, fmt.Errorf(
			"find active user for password recovery: %w",
			err,
		)
	}

	return appUserID, normalizedEmail, true, nil
}

func (r *PasswordResetRepository) InvalidateUnusedByUser(
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
		UPDATE public.password_reset_tokens
		SET used_at = NOW()
		WHERE app_user_id = $1
		  AND used_at IS NULL
		`,
		appUserID,
	)
	if err != nil {
		return fmt.Errorf(
			"invalidate previous password reset tokens: %w",
			err,
		)
	}

	return nil
}

func (r *PasswordResetRepository) Create(
	ctx context.Context,
	appUserID string,
	tokenHash string,
	expiresAt time.Time,
) error {
	appUserID = strings.TrimSpace(appUserID)
	tokenHash = strings.TrimSpace(tokenHash)

	if appUserID == "" || tokenHash == "" {
		return errors.New(
			"app user id and token hash are required",
		)
	}

	_, err := r.pool.Exec(
		ctx,
		`
		INSERT INTO public.password_reset_tokens (
			app_user_id,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3)
		`,
		appUserID,
		tokenHash,
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf(
			"create password reset token: %w",
			err,
		)
	}

	return nil
}

func (r *PasswordResetRepository) InvalidateHash(
	ctx context.Context,
	tokenHash string,
) error {
	tokenHash = strings.TrimSpace(tokenHash)

	if tokenHash == "" {
		return nil
	}

	_, err := r.pool.Exec(
		ctx,
		`
		UPDATE public.password_reset_tokens
		SET used_at = COALESCE(used_at, NOW())
		WHERE token_hash = $1
		`,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf(
			"invalidate password reset token: %w",
			err,
		)
	}

	return nil
}

func (r *PasswordResetRepository) ConsumeValidByHash(
	ctx context.Context,
	tokenHash string,
) (string, error) {
	tokenHash = strings.TrimSpace(tokenHash)

	if tokenHash == "" {
		return "", ErrPasswordResetTokenNotFound
	}

	var appUserID string

	err := r.pool.QueryRow(
		ctx,
		`
		UPDATE public.password_reset_tokens
		SET used_at = NOW()
		WHERE token_hash = $1
		  AND used_at IS NULL
		  AND expires_at > NOW()
		RETURNING app_user_id
		`,
		tokenHash,
	).Scan(&appUserID)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPasswordResetTokenNotFound
	}

	if err != nil {
		return "", fmt.Errorf(
			"consume password reset token: %w",
			err,
		)
	}

	return appUserID, nil
}

func (r *PasswordResetRepository) RestoreClaimedHash(
	ctx context.Context,
	tokenHash string,
) error {
	tokenHash = strings.TrimSpace(tokenHash)

	if tokenHash == "" {
		return nil
	}

	_, err := r.pool.Exec(
		ctx,
		`
		UPDATE public.password_reset_tokens
		SET used_at = NULL
		WHERE token_hash = $1
		  AND used_at IS NOT NULL
		  AND expires_at > NOW()
		`,
		tokenHash,
	)
	if err != nil {
		return fmt.Errorf(
			"restore claimed password reset token: %w",
			err,
		)
	}

	return nil
}
