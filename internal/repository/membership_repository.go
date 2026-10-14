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

type MembershipRepository struct {
	pool *pgxpool.Pool
}

func NewMembershipRepository(pool *pgxpool.Pool) *MembershipRepository {
	return &MembershipRepository{
		pool: pool,
	}
}

func (r *MembershipRepository) GetByAppUserAndApplicationID(
	ctx context.Context,
	appUserID string,
	applicationID string,
) (*models.AppMembership, error) {
	appUserID = strings.TrimSpace(appUserID)
	applicationID = strings.TrimSpace(applicationID)

	if appUserID == "" || applicationID == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(
		ctx,
		`
SELECT
id,
app_user_id,
application_id,
role,
status,
created_at,
updated_at,
deleted_at
FROM public.app_memberships
WHERE app_user_id = $1
  AND application_id = $2
  AND deleted_at IS NULL
LIMIT 1
`,
		appUserID,
		applicationID,
	)

	var membership models.AppMembership

	err := row.Scan(
		&membership.ID,
		&membership.AppUserID,
		&membership.ApplicationID,
		&membership.Role,
		&membership.Status,
		&membership.CreatedAt,
		&membership.UpdatedAt,
		&membership.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("get application membership: %w", err)
	}

	return &membership, nil
}
