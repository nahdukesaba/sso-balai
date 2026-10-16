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

type CredentialRepository struct {
	pool *pgxpool.Pool
}

func NewCredentialRepository(
	pool *pgxpool.Pool,
) *CredentialRepository {
	return &CredentialRepository{
		pool: pool,
	}
}

const credentialColumns = `
	app_user_id,
	password_hash,
	password_algorithm,
	must_change_password,
	failed_attempts,
	locked_until,
	password_changed_at,
	created_at,
	updated_at
`

func scanCredential(
	row pgx.Row,
) (*models.AuthCredential, error) {
	var credential models.AuthCredential

	err := row.Scan(
		&credential.AppUserID,
		&credential.PasswordHash,
		&credential.PasswordAlgorithm,
		&credential.MustChangePassword,
		&credential.FailedAttempts,
		&credential.LockedUntil,
		&credential.PasswordChangedAt,
		&credential.CreatedAt,
		&credential.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &credential, nil
}

func (r *CredentialRepository) GetByAppUserID(
	ctx context.Context,
	appUserID string,
) (*models.AuthCredential, error) {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(
		ctx,
		`
		SELECT `+credentialColumns+`
		FROM public.auth_credentials
		WHERE app_user_id = $1
		LIMIT 1
		`,
		appUserID,
	)

	credential, err := scanCredential(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"get auth credential by app user id: %w",
			err,
		)
	}

	return credential, nil
}

func (r *CredentialRepository) Create(
	ctx context.Context,
	appUserID string,
	passwordHash string,
	passwordAlgorithm string,
	mustChangePassword bool,
) (*models.AuthCredential, error) {
	appUserID = strings.TrimSpace(appUserID)
	passwordHash = strings.TrimSpace(passwordHash)
	passwordAlgorithm = strings.TrimSpace(passwordAlgorithm)

	if appUserID == "" ||
		passwordHash == "" ||
		passwordAlgorithm == "" {
		return nil, errors.New(
			"credential user, password hash, and algorithm are required",
		)
	}

	row := r.pool.QueryRow(
		ctx,
		`
		INSERT INTO public.auth_credentials (
			app_user_id,
			password_hash,
			password_algorithm,
			must_change_password
		)
		VALUES ($1, $2, $3, $4)
		RETURNING `+credentialColumns,
		appUserID,
		passwordHash,
		passwordAlgorithm,
		mustChangePassword,
	)

	credential, err := scanCredential(row)
	if err != nil {
		return nil, fmt.Errorf(
			"create auth credential: %w",
			err,
		)
	}

	return credential, nil
}

func (r *CredentialRepository) UpdatePassword(
	ctx context.Context,
	appUserID string,
	passwordHash string,
	passwordAlgorithm string,
) (*models.AuthCredential, error) {
	appUserID = strings.TrimSpace(appUserID)
	passwordHash = strings.TrimSpace(passwordHash)
	passwordAlgorithm = strings.TrimSpace(passwordAlgorithm)

	if appUserID == "" ||
		passwordHash == "" ||
		passwordAlgorithm == "" {
		return nil, errors.New(
			"credential user, password hash, and algorithm are required",
		)
	}

	row := r.pool.QueryRow(
		ctx,
		`
		UPDATE public.auth_credentials
		SET
			password_hash = $2,
			password_algorithm = $3,
			must_change_password = FALSE,
			failed_attempts = 0,
			locked_until = NULL,
			password_changed_at = NOW(),
			updated_at = NOW()
		WHERE app_user_id = $1
		RETURNING `+credentialColumns,
		appUserID,
		passwordHash,
		passwordAlgorithm,
	)

	credential, err := scanCredential(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"update auth credential password: %w",
			err,
		)
	}

	return credential, nil
}
