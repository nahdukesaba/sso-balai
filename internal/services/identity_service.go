package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var ErrUserNotFound = errors.New("user not found")

type IdentityService struct {
	userRepository    *repository.UserRepository
	pegawaiRepository *repository.PegawaiRepository
}

func NewIdentityService(
	userRepository *repository.UserRepository,
	pegawaiRepository *repository.PegawaiRepository,
) *IdentityService {
	return &IdentityService{
		userRepository:    userRepository,
		pegawaiRepository: pegawaiRepository,
	}
}

func (s *IdentityService) GetByUserID(
	ctx context.Context,
	userID string,
) (*models.Identity, error) {
	user, err := s.userRepository.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user identity: %w", err)
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	pegawai, err := s.pegawaiRepository.GetByAppUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get employee identity: %w", err)
	}

	return &models.Identity{
		User:    user,
		Pegawai: pegawai,
	}, nil
}
