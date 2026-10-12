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

type KlinikUserRepository struct {
	pool *pgxpool.Pool
}

func NewKlinikUserRepository(pool *pgxpool.Pool) *KlinikUserRepository {
	return &KlinikUserRepository{
		pool: pool,
	}
}

func (r *KlinikUserRepository) GetActiveByEmail(
	ctx context.Context,
	email string,
) (*models.KlinikUser, error) {
	email = strings.TrimSpace(email)

	if email == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(
		ctx,
		`
		SELECT
			id,
			name,
			email,
			password,
			phone,
			nip,
			role,
			is_active
		FROM public.klinikpkp_user
		WHERE LOWER(email) = LOWER($1)
		  AND is_active = TRUE
		  AND deleted_at IS NULL
		LIMIT 1
		`,
		email,
	)

	var user models.KlinikUser

	err := row.Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.Phone,
		&user.NIP,
		&user.Role,
		&user.IsActive,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("get Klinik user by email: %w", err)
	}

	return &user, nil
}

func (r *KlinikUserRepository) GetActiveByAppUserID(
	ctx context.Context,
	appUserID string,
) (*models.KlinikUser, error) {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(
		ctx,
		`
		SELECT
			id,
			name,
			email,
			password,
			phone,
			nip,
			role,
			is_active
		FROM public.klinikpkp_user
		WHERE app_user_id = $1
		  AND is_active = TRUE
		  AND deleted_at IS NULL
		LIMIT 1
		`,
		appUserID,
	)

	var user models.KlinikUser

	err := row.Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.Phone,
		&user.NIP,
		&user.Role,
		&user.IsActive,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"get Klinik user by app user ID: %w",
			err,
		)
	}

	return &user, nil
}

func (r *KlinikUserRepository) LinkAppUserID(
	ctx context.Context,
	klinikUserID string,
	appUserID string,
) error {
	klinikUserID = strings.TrimSpace(klinikUserID)
	appUserID = strings.TrimSpace(appUserID)

	if klinikUserID == "" || appUserID == "" {
		return fmt.Errorf("Klinik user ID and app user ID are required")
	}

	commandTag, err := r.pool.Exec(
		ctx,
		`
		UPDATE public.klinikpkp_user
		SET app_user_id = $2
		WHERE id = $1
		  AND deleted_at IS NULL
		  AND (
			app_user_id IS NULL
			OR app_user_id = $2
		  )
		`,
		klinikUserID,
		appUserID,
	)
	if err != nil {
		return fmt.Errorf("link Klinik user to app user: %w", err)
	}

	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf(
			"link Klinik user to app user: Klinik user unavailable or already linked to another identity",
		)
	}

	return nil
}

func (r *KlinikUserRepository) UnlinkAppUserIDForMigration(
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
		UPDATE public.klinikpkp_user
		SET app_user_id = NULL
		WHERE app_user_id = $1
		`,
		appUserID,
	)
	if err != nil {
		return fmt.Errorf(
			"unlink Klinik user from migrated app user: %w",
			err,
		)
	}

	return nil
}
