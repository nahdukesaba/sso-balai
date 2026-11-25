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

type ApplicationRepository struct {
	pool *pgxpool.Pool
}

func NewApplicationRepository(pool *pgxpool.Pool) *ApplicationRepository {
	return &ApplicationRepository{
		pool: pool,
	}
}

func (r *ApplicationRepository) GetByCode(
	ctx context.Context,
	code string,
) (*models.Application, error) {
	code = strings.ToLower(strings.TrimSpace(code))

	if code == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(
		ctx,
		`
SELECT
id,
code,
name,
is_active,
created_at,
updated_at
FROM public.applications
WHERE code = $1
LIMIT 1
`,
		code,
	)

	var application models.Application

	err := row.Scan(
		&application.ID,
		&application.Code,
		&application.Name,
		&application.IsActive,
		&application.CreatedAt,
		&application.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("get application by code: %w", err)
	}

	return &application, nil
}

func (r *ApplicationRepository) ListForPortalUser(
	ctx context.Context,
	appUserID string,
) ([]models.PortalApplicationAccess, error) {
	appUserID = strings.TrimSpace(appUserID)
	if appUserID == "" {
		return nil, errors.New("app user ID is required")
	}

	rows, err := r.pool.Query(ctx, `
SELECT
    a.code,
    a.name,
    COALESCE(m.role, ''),
    COALESCE(m.status, ''),
    m.id IS NOT NULL
FROM public.applications a
LEFT JOIN public.app_memberships m
    ON m.application_id = a.id
   AND m.app_user_id = $1
   AND m.deleted_at IS NULL
WHERE a.is_active = true
ORDER BY a.name ASC
`, appUserID)
	if err != nil {
		return nil, fmt.Errorf("list portal applications: %w", err)
	}
	defer rows.Close()

	applications := make([]models.PortalApplicationAccess, 0)
	for rows.Next() {
		var application models.PortalApplicationAccess
		if err := rows.Scan(
			&application.Code,
			&application.Name,
			&application.Role,
			&application.Status,
			&application.HasMembership,
		); err != nil {
			return nil, fmt.Errorf("scan portal application: %w", err)
		}
		applications = append(applications, application)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate portal applications: %w", err)
	}
	return applications, nil
}
