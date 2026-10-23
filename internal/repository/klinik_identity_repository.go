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

type KlinikIdentityRepository struct {
	pool *pgxpool.Pool
}

func NewKlinikIdentityRepository(
	pool *pgxpool.Pool,
) *KlinikIdentityRepository {
	return &KlinikIdentityRepository{pool: pool}
}

func (r *KlinikIdentityRepository) GetByAppUserID(
	ctx context.Context,
	appUserID string,
) (*models.KlinikIdentity, error) {
	appUserID = strings.TrimSpace(appUserID)
	if appUserID == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(ctx, `
		SELECT
			u.id,
			u.auth_user_id,
			u.email,
			u.full_name,
			u.phone,
			p.nip,
			a.code,
			m.role,
			m.status
		FROM public.app_users AS u
		JOIN public.app_memberships AS m
			ON m.app_user_id = u.id
			AND m.deleted_at IS NULL
		JOIN public.applications AS a
			ON a.id = m.application_id
			AND a.code = $2
			AND a.is_active = TRUE
		LEFT JOIN public.app_pegawai AS p
			ON p.app_user_id = u.id
			AND p.deleted_at IS NULL
		WHERE u.id = $1
		  AND u.auth_user_id IS NOT NULL
		  AND u.deleted_at IS NULL
		LIMIT 1
	`, appUserID, models.ApplicationCodeKlinikPKP)

	var identity models.KlinikIdentity
	if err := row.Scan(
		&identity.AppUserID,
		&identity.AuthUserID,
		&identity.Email,
		&identity.FullName,
		&identity.Phone,
		&identity.NIP,
		&identity.ApplicationCode,
		&identity.Role,
		&identity.Status,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get canonical Klinik identity: %w", err)
	}

	return &identity, nil
}
