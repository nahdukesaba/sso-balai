package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		pool: pool,
	}
}

const userColumns = `
	id,
	email,
	full_name,
	role,
	status,
	phone,
	created_at,
	updated_at,
	deleted_at
`

func scanUser(row pgx.Row) (*models.AppUser, error) {
	var user models.AppUser

	err := row.Scan(
		&user.ID,
		&user.Email,
		&user.FullName,
		&user.Role,
		&user.Status,
		&user.Phone,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *UserRepository) GetByID(
	ctx context.Context,
	id string,
) (*models.AppUser, error) {
	row := r.pool.QueryRow(
		ctx,
		`
		SELECT `+userColumns+`
		FROM public.app_users
		WHERE id = $1
		  AND deleted_at IS NULL
		`,
		id,
	)

	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("get app user by id: %w", err)
	}

	return user, nil
}

func (r *UserRepository) GetByEmailIncludingDeleted(
	ctx context.Context,
	email string,
) (*models.AppUser, error) {
	row := r.pool.QueryRow(
		ctx,
		`
		SELECT `+userColumns+`
		FROM public.app_users
		WHERE LOWER(email) = LOWER($1)
		LIMIT 1
		`,
		email,
	)

	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"get app user by email: %w",
			err,
		)
	}

	return user, nil
}

func (r *UserRepository) GetByIDIncludingDeleted(
	ctx context.Context,
	id string,
) (*models.AppUser, error) {
	row := r.pool.QueryRow(
		ctx,
		`
		SELECT `+userColumns+`
		FROM public.app_users
		WHERE id = $1
		LIMIT 1
		`,
		id,
	)

	user, err := scanUser(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf(
			"get app user by id including deleted: %w",
			err,
		)
	}

	return user, nil
}

func (r *UserRepository) CreateBootstrapUser(
	ctx context.Context,
	id string,
	email string,
	fullName string,
	role string,
) (*models.AppUser, error) {
	row := r.pool.QueryRow(
		ctx,
		`
		INSERT INTO public.app_users (
			id,
			email,
			full_name,
			role,
			status
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+userColumns,
		id,
		email,
		fullName,
		role,
		models.UserStatusApproved,
	)

	user, err := scanUser(row)
	if err != nil {
		return nil, fmt.Errorf(
			"create bootstrap app user: %w",
			err,
		)
	}

	return user, nil
}
