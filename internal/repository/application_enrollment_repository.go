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
) (*models.ApplicationEnrollmentResult, error) {
	appUserID = strings.TrimSpace(
		appUserID,
	)

	applicationCode = strings.ToLower(
		strings.TrimSpace(applicationCode),
	)

	if appUserID == "" ||
		applicationCode == "" {

		return nil, ErrEnrollmentApplicationUnavailable
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin application enrollment: %w", err)
	}
	defer func() {
		_ = tx.Rollback(context.Background())
	}()

	var applicationID string

	err = tx.QueryRow(
		ctx,
		`
		SELECT id
		FROM public.applications
		WHERE LOWER(code) = LOWER($1)
		  AND is_active = TRUE
		LIMIT 1
		FOR SHARE
		`,
		applicationCode,
	).Scan(
		&applicationID,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEnrollmentApplicationUnavailable
	}

	if err != nil {
		return nil, fmt.Errorf(
			"find enrollment application: %w",
			err,
		)
	}

	// The unique (app_user_id, application_id) constraint serializes
	// concurrent first requests. A conflicting request observes the logical
	// membership in the SELECT FOR UPDATE below instead of inserting a second
	// row.
	tag, err := tx.Exec(
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
		DO NOTHING
		`,
		appUserID,
		applicationID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"request application enrollment: %w",
			err,
		)
	}

	if tag.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit application enrollment: %w", err)
		}

		return &models.ApplicationEnrollmentResult{
			Application: applicationCode,
			Status:      models.MembershipStatusPending,
			Outcome:     models.ApplicationEnrollmentCreated,
		}, nil
	}

	var status string
	var deletedAt *time.Time
	err = tx.QueryRow(
		ctx,
		`
		SELECT status, deleted_at
		FROM public.app_memberships
		WHERE app_user_id = $1
		  AND application_id = $2
		FOR UPDATE
		`,
		appUserID,
		applicationID,
	).Scan(&status, &deletedAt)
	if err != nil {
		return nil, fmt.Errorf(
			"read existing application enrollment: %w",
			err,
		)
	}

	if deletedAt != nil {
		_, err = tx.Exec(
			ctx,
			`
			UPDATE public.app_memberships
			SET role = 'user',
				status = 'pending',
				deleted_at = NULL,
				updated_at = NOW()
			WHERE app_user_id = $1
			  AND application_id = $2
			`,
			appUserID,
			applicationID,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"reopen application enrollment: %w",
				err,
			)
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit application enrollment: %w", err)
		}

		return &models.ApplicationEnrollmentResult{
			Application: applicationCode,
			Status:      models.MembershipStatusPending,
			Outcome:     models.ApplicationEnrollmentReopened,
		}, nil
	}

	var outcome models.ApplicationEnrollmentOutcome
	switch status {
	case models.MembershipStatusPending:
		outcome = models.ApplicationEnrollmentAlreadyPending

	case models.MembershipStatusApproved:
		outcome = models.ApplicationEnrollmentAlreadyApproved

	case models.MembershipStatusRejected,
		models.MembershipStatusDisabled:
		return nil, ErrEnrollmentBlocked

	default:
		return nil, fmt.Errorf(
			"unexpected application membership status %q",
			status,
		)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit application enrollment: %w", err)
	}

	return &models.ApplicationEnrollmentResult{
		Application: applicationCode,
		Status:      status,
		Outcome:     outcome,
	}, nil
}
