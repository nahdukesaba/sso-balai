package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var (
	ErrKlinikMigrationConflict = errors.New("Klinik identity migration conflict")
)

type KlinikMigrationService struct {
	credentialService *KlinikCredentialService
	adminService      *SupabaseAdminService
	userRepository    *repository.UserRepository
	pegawaiRepository *repository.PegawaiRepository
}

func NewKlinikMigrationService(
	credentialService *KlinikCredentialService,
	adminService *SupabaseAdminService,
	userRepository *repository.UserRepository,
	pegawaiRepository *repository.PegawaiRepository,
) *KlinikMigrationService {
	return &KlinikMigrationService{
		credentialService: credentialService,
		adminService:      adminService,
		userRepository:    userRepository,
		pegawaiRepository: pegawaiRepository,
	}
}

func (s *KlinikMigrationService) Migrate(
	ctx context.Context,
	email string,
	nip string,
	password string,
) (*models.SupabaseAuthUser, error) {
	klinikUser, err := s.credentialService.Verify(
		ctx,
		email,
		nip,
		password,
	)
	if err != nil {
		return nil, err
	}

	existingAuthUser, err := s.adminService.FindUserByEmail(
		ctx,
		klinikUser.Email,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"check existing Supabase user: %w",
			err,
		)
	}

	// Login ke Supabase sebelumnya sudah gagal.
	// Jika email ternyata sudah ada di Auth, jangan pernah
	// mengambil alih atau mengganti password akun tersebut.
	if existingAuthUser != nil {
		return nil, ErrKlinikMigrationConflict
	}

	existingAppUser, err := s.userRepository.GetByEmailIncludingDeleted(
		ctx,
		klinikUser.Email,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"check existing app user: %w",
			err,
		)
	}

	if existingAppUser != nil {
		return nil, ErrKlinikMigrationConflict
	}

	authUser, err := s.adminService.CreateUser(
		ctx,
		klinikUser.Email,
		password,
		klinikUser.Name,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create Supabase Klinik user: %w",
			err,
		)
	}

	if authUser == nil ||
		strings.TrimSpace(authUser.ID) == "" {
		return nil, ErrAdminUnavailable
	}

	_, err = s.userRepository.CreateMigratedUser(
		ctx,
		authUser.ID,
		klinikUser.Email,
		klinikUser.Name,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create migrated app user: %w",
			err,
		)
	}

	_, err = s.pegawaiRepository.CreateForMigratedUser(
		ctx,
		authUser.ID,
		klinikUser.NIP,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create migrated employee: %w",
			err,
		)
	}

	return authUser, nil
}
