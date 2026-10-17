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
	ErrCentralRegistrationConflict = errors.New(
		"central registration conflict",
	)

	ErrCentralRegistrationApplicationUnavailable = errors.New(
		"central registration application unavailable",
	)
)

type CentralRegistrationRepository struct {
	pool *pgxpool.Pool
}

func NewCentralRegistrationRepository(
	pool *pgxpool.Pool,
) *CentralRegistrationRepository {
	return &CentralRegistrationRepository{
		pool: pool,
	}
}

func (r *CentralRegistrationRepository) CreateNewIdentity(
	ctx context.Context,
	email string,
	fullName string,
	phone *string,
	passwordHash string,
	passwordAlgorithm string,
	applicationID string,
) (*models.AppUser, error) {
	email = strings.TrimSpace(email)
	fullName = strings.TrimSpace(fullName)
	passwordHash = strings.TrimSpace(passwordHash)
	passwordAlgorithm = strings.TrimSpace(passwordAlgorithm)
	applicationID = strings.TrimSpace(applicationID)

	if email == "" ||
		fullName == "" ||
		passwordHash == "" ||
		passwordAlgorithm == "" ||
		applicationID == "" {

		return nil, errors.New(
			"registration identity, credential, and application are required",
		)
	}

	tx, err := r.pool.BeginTx(
		ctx,
		pgx.TxOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"begin central registration transaction: %w",
			err,
		)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	row := tx.QueryRow(
		ctx,
		`
		INSERT INTO public.app_users (
			id,
			email,
			full_name,
			role,
			status,
			phone
		)
		VALUES (
			gen_random_uuid(),
			$1,
			$2,
			'user',
			$3,
			$4
		)
		RETURNING `+userColumns,
		email,
		fullName,
		models.UserStatusApproved,
		phone,
	)

	user, err := scanUser(row)
	if err != nil {
		if isCentralRegistrationUniqueViolation(err) {
			return nil, ErrCentralRegistrationConflict
		}

		return nil, fmt.Errorf(
			"create central registration user: %w",
			err,
		)
	}

	_, err = tx.Exec(
		ctx,
		`
		INSERT INTO public.auth_credentials (
			app_user_id,
			password_hash,
			password_algorithm,
			must_change_password
		)
		VALUES ($1, $2, $3, FALSE)
		`,
		user.ID,
		passwordHash,
		passwordAlgorithm,
	)
	if err != nil {
		if isCentralRegistrationUniqueViolation(err) {
			return nil, ErrCentralRegistrationConflict
		}

		return nil, fmt.Errorf(
			"create central registration credential: %w",
			err,
		)
	}

	tag, err := tx.Exec(
		ctx,
		`
		INSERT INTO public.app_memberships (
			app_user_id,
			application_id,
			role,
			status
		)
		SELECT
			$1,
			id,
			'user',
			$3
		FROM public.applications
		WHERE id = $2
		  AND is_active = TRUE
		`,
		user.ID,
		applicationID,
		models.MembershipStatusPending,
	)
	if err != nil {
		if isCentralRegistrationUniqueViolation(err) {
			return nil, ErrCentralRegistrationConflict
		}

		return nil, fmt.Errorf(
			"create central registration membership: %w",
			err,
		)
	}

	if tag.RowsAffected() != 1 {
		return nil,
			ErrCentralRegistrationApplicationUnavailable
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit central registration: %w",
			err,
		)
	}

	return user, nil
}

func isCentralRegistrationUniqueViolation(
	err error,
) bool {
	var pgErr *pgconn.PgError

	if !errors.As(err, &pgErr) {
		return false
	}

	return pgErr.Code == "23505"
}
