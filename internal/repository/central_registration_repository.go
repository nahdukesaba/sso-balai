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

// CreateNewSupabaseIdentity atomically creates the Central SSO profile and
// its initial application membership for an already-created Supabase user.
// It deliberately does not create an auth_credentials row.
func (r *CentralRegistrationRepository) CreateNewSupabaseIdentity(
	ctx context.Context,
	authUserID string,
	email string,
	fullName string,
	phone *string,
	userRole string,
	userStatus string,
	applicationID string,
	membershipRole string,
	membershipStatus string,
) (*models.AppUser, error) {
	authUserID = strings.TrimSpace(authUserID)
	email = strings.TrimSpace(email)
	fullName = strings.TrimSpace(fullName)
	userRole = strings.TrimSpace(userRole)
	userStatus = strings.TrimSpace(userStatus)
	applicationID = strings.TrimSpace(applicationID)
	membershipRole = strings.TrimSpace(membershipRole)
	membershipStatus = strings.TrimSpace(membershipStatus)

	if authUserID == "" || email == "" || fullName == "" ||
		userRole == "" || userStatus == "" ||
		applicationID == "" || membershipRole == "" ||
		membershipStatus == "" {

		return nil, errors.New(
			"Supabase identity, profile, and membership are required",
		)
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf(
			"begin Supabase registration transaction: %w",
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
			auth_user_id,
			email,
			full_name,
			phone
		)
		VALUES (
			gen_random_uuid(),
			$1,
			$2,
			$3,
			$4
		)
		RETURNING `+userColumns,
		authUserID,
		email,
		fullName,
		phone,
	)

	user, err := scanUser(row)
	if err != nil {
		if isCentralRegistrationUniqueViolation(err) {
			return nil, ErrCentralRegistrationConflict
		}

		return nil, fmt.Errorf(
			"create Supabase registration profile: %w",
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
			$3,
			$4
		FROM public.applications
		WHERE id = $2
		  AND is_active = TRUE
		`,
		user.ID,
		applicationID,
		membershipRole,
		membershipStatus,
	)
	if err != nil {
		if isCentralRegistrationUniqueViolation(err) {
			return nil, ErrCentralRegistrationConflict
		}

		return nil, fmt.Errorf(
			"create Supabase registration membership: %w",
			err,
		)
	}

	if tag.RowsAffected() != 1 {
		return nil, ErrCentralRegistrationApplicationUnavailable
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf(
			"commit Supabase registration: %w",
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
