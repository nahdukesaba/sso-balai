package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrKlinikProvisioningConflict   = errors.New("Klinik provisioning conflict")
	ErrKlinikApplicationUnavailable = errors.New("Klinik application unavailable")
)

type KlinikAdminUserRepository struct {
	pool *pgxpool.Pool
}

func NewKlinikAdminUserRepository(pool *pgxpool.Pool) *KlinikAdminUserRepository {
	return &KlinikAdminUserRepository{pool: pool}
}

// Provision creates or reuses a canonical app_users identity and upserts only
// the employee profile and membership owned by Klinik. It never creates a
// local credential or writes global app_users role/status authorization.
func (r *KlinikAdminUserRepository) Provision(
	ctx context.Context,
	authUserID string,
	email string,
	fullName string,
	phone *string,
	nip *string,
	nik *string,
	alamat *string,
	gelarDepan *string,
	gelarBelakang *string,
	role string,
	status string,
) (*models.KlinikAdminUser, error) {
	authUserID = strings.TrimSpace(authUserID)
	email = strings.ToLower(strings.TrimSpace(email))
	fullName = strings.TrimSpace(fullName)
	role = strings.ToLower(strings.TrimSpace(role))
	status = strings.ToLower(strings.TrimSpace(status))
	if authUserID == "" || email == "" || fullName == "" || role == "" || status == "" {
		return nil, errors.New("canonical identity and Klinik membership are required")
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin Klinik provisioning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var appUserID string
	var existingAuthUserID *string
	err = tx.QueryRow(ctx, `
SELECT id, auth_user_id
FROM public.app_users
WHERE LOWER(email) = LOWER($1)
FOR UPDATE
`, email).Scan(&appUserID, &existingAuthUserID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("find canonical Klinik user: %w", err)
	}

	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
INSERT INTO public.app_users (
    id, auth_user_id, email, full_name, role, status, phone
)
VALUES (gen_random_uuid(), $1, $2, $3, 'user', $4, $5)
RETURNING id
`, authUserID, email, fullName, models.UserStatusApproved, phone).Scan(&appUserID)
		if err != nil {
			return nil, mapKlinikProvisioningError("create canonical Klinik user", err)
		}
	} else {
		if existingAuthUserID != nil && strings.TrimSpace(*existingAuthUserID) != authUserID {
			return nil, ErrKlinikProvisioningConflict
		}
		tag, updateErr := tx.Exec(ctx, `
UPDATE public.app_users
SET auth_user_id = COALESCE(auth_user_id, $2),
    full_name = $3,
    phone = $4,
    updated_at = NOW()
WHERE id = $1
  AND deleted_at IS NULL
`, appUserID, authUserID, fullName, phone)
		if updateErr != nil {
			return nil, mapKlinikProvisioningError("update canonical Klinik user", updateErr)
		}
		if tag.RowsAffected() != 1 {
			return nil, ErrKlinikProvisioningConflict
		}
	}

	_, err = tx.Exec(ctx, `
INSERT INTO public.app_pegawai (
    app_user_id, nip, nik, alamat, gelar_depan, gelar_belakang
)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (app_user_id) DO UPDATE
SET nip = EXCLUDED.nip,
    nik = EXCLUDED.nik,
    alamat = EXCLUDED.alamat,
    gelar_depan = EXCLUDED.gelar_depan,
    gelar_belakang = EXCLUDED.gelar_belakang,
    deleted_at = NULL,
    updated_at = NOW()
`, appUserID, nip, nik, alamat, gelarDepan, gelarBelakang)
	if err != nil {
		return nil, mapKlinikProvisioningError("upsert Klinik employee profile", err)
	}

	tag, err := tx.Exec(ctx, `
INSERT INTO public.app_memberships (
    app_user_id, application_id, role, status
)
SELECT $1, id, $2, $3
FROM public.applications
WHERE code = $4
  AND is_active = TRUE
ON CONFLICT (app_user_id, application_id) DO UPDATE
SET role = EXCLUDED.role,
    status = EXCLUDED.status,
    deleted_at = NULL,
    updated_at = NOW()
`, appUserID, role, status, models.ApplicationCodeKlinikPKP)
	if err != nil {
		return nil, mapKlinikProvisioningError("upsert Klinik membership", err)
	}
	if tag.RowsAffected() != 1 {
		return nil, ErrKlinikApplicationUnavailable
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit Klinik provisioning: %w", err)
	}
	return &models.KlinikAdminUser{
		AppUserID: appUserID, AuthUserID: &authUserID, Email: email,
		FullName: fullName, Role: role, Status: status,
	}, nil
}

func mapKlinikProvisioningError(operation string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrKlinikProvisioningConflict
	}
	return fmt.Errorf("%s: %w", operation, err)
}
