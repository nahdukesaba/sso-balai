package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type PegawaiRepository struct {
	pool *pgxpool.Pool
}

func NewPegawaiRepository(pool *pgxpool.Pool) *PegawaiRepository {
	return &PegawaiRepository{
		pool: pool,
	}
}

func (r *PegawaiRepository) GetByAppUserID(
	ctx context.Context,
	appUserID string,
) (*models.Pegawai, error) {
	row := r.pool.QueryRow(
		ctx,
		`
		SELECT
			id,
			app_user_id,
			nip,
			nik,
			alamat,
			gelar_depan,
			gelar_belakang,
			created_at,
			updated_at,
			deleted_at
		FROM public.app_pegawai
		WHERE app_user_id = $1
		  AND deleted_at IS NULL
		`,
		appUserID,
	)

	var pegawai models.Pegawai

	err := row.Scan(
		&pegawai.ID,
		&pegawai.AppUserID,
		&pegawai.NIP,
		&pegawai.NIK,
		&pegawai.Alamat,
		&pegawai.GelarDepan,
		&pegawai.GelarBelakang,
		&pegawai.CreatedAt,
		&pegawai.UpdatedAt,
		&pegawai.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}

		return nil, fmt.Errorf("get pegawai by app user id: %w", err)
	}

	return &pegawai, nil
}
