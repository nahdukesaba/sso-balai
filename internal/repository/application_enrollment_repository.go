package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrEnrollmentApplicationUnavailable = errors.New(
		"application enrollment unavailable",
	)

	ErrEnrollmentBlocked = errors.New(
		"application enrollment blocked",
	)
)

type ApplicationEnrollmentRepository struct {
	pool *pgxpool.Pool
}

func NewApplicationEnrollmentRepository(
	pool *pgxpool.Pool,
) *ApplicationEnrollmentRepository {
	return &ApplicationEnrollmentRepository{
		pool: pool,
	}
}

func (r *ApplicationEnrollmentRepository) Request(
	ctx context.Context,
	appUserID string,
	applicationCode string,
) (string, error) {
	appUserID = strings.TrimSpace(
		appUserID,
	)

	applicationCode = strings.ToLower(
		strings.TrimSpace(applicationCode),
	)

	if appUserID == "" ||
		applicationCode == "" {

		return "", ErrEnrollmentApplicationUnavailable
	}

	var applicationID string

	err := r.pool.QueryRow(
		ctx,
		`
		SELECT id
		FROM public.applications
		WHERE LOWER(code) = LOWER($1)
		  AND is_active = TRUE
		LIMIT 1
		`,
		applicationCode,
	).Scan(
		&applicationID,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrEnrollmentApplicationUnavailable
	}

	if err != nil {
		return "", fmt.Errorf(
			"find enrollment application: %w",
			err,
		)
	}

	var status string

	// The unique (app_user_id, application_id) constraint makes this
	// operation safe when the same request arrives concurrently.
	//
	// Existing active memberships keep their current role/status.
	// A previously soft-deleted membership may be requested again
	// and returns to the normal pending/user state.
	err = r.pool.QueryRow(
		ctx,
		`
		INSERT INTO public.app_memberships (
			app_user_id,
			application_id,
			role,
			status
		)
		VALUES (
			$1,
			$2,
			'user',
			'pending'
		)
		ON CONFLICT (
			app_user_id,
			application_id
		)
		DO UPDATE SET
			role = CASE
				WHEN public.app_memberships.deleted_at
					IS NOT NULL
					THEN 'user'
				ELSE public.app_memberships.role
			END,
			status = CASE
				WHEN public.app_memberships.deleted_at
					IS NOT NULL
					THEN 'pending'
				ELSE public.app_memberships.status
			END,
			deleted_at = CASE
				WHEN public.app_memberships.deleted_at
					IS NOT NULL
					THEN NULL
				ELSE public.app_memberships.deleted_at
			END,
			updated_at = NOW()
		RETURNING status
		`,
		appUserID,
		applicationID,
	).Scan(
		&status,
	)

	if err != nil {
		return "", fmt.Errorf(
			"request application enrollment: %w",
			err,
		)
	}

	switch status {
	case "pending", "approved":
		return status, nil

	case "rejected", "disabled":
		return "", ErrEnrollmentBlocked

	default:
		return "", fmt.Errorf(
			"unexpected application membership status %q",
			status,
		)
	}
}
