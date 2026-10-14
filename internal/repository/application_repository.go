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
