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

type KlinikUserRepository struct {
	pool *pgxpool.Pool
}

func NewKlinikUserRepository(pool *pgxpool.Pool) *KlinikUserRepository {
	return &KlinikUserRepository{
		pool: pool,
	}
}

func (r *KlinikUserRepository) GetActiveByEmail(
	ctx context.Context,
	email string,
) (*models.KlinikUser, error) {
	email = strings.TrimSpace(email)

	if email == "" {
		return nil, nil
	}

	row := r.pool.QueryRow(
		ctx,
		`
		SELECT
			id,
			name,
			email,
			password,
			phone,
			nip,
			role,
			is_active
		FROM public.klinikpkp_user
		WHERE LOWER(email) = LOWER($1)
		  AND is_active = TRUE
		  AND deleted_at IS NULL
		LIMIT 1
		`,
		email,
	)

	var user models.KlinikUser

	err := row.Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
		&user.Phone,
		&user.NIP,
		&user.Role,
		&user.IsActive,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("get Klinik user by email: %w", err)
	}

	return &user, nil
}
