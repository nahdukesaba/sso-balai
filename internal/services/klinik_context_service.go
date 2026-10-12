package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var ErrKlinikAccountUnavailable = errors.New("Klinik account unavailable")

type KlinikContextService struct {
	klinikUserRepository *repository.KlinikUserRepository
}

func NewKlinikContextService(
	klinikUserRepository *repository.KlinikUserRepository,
) *KlinikContextService {
	return &KlinikContextService{
		klinikUserRepository: klinikUserRepository,
	}
}

func (s *KlinikContextService) GetByAppUserID(
	ctx context.Context,
	appUserID string,
) (*models.KlinikUser, error) {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" {
		return nil, ErrKlinikAccountUnavailable
	}

	user, err := s.klinikUserRepository.GetActiveByAppUserID(
		ctx,
		appUserID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"get Klinik context: %w",
			err,
		)
	}

	if user == nil || !user.IsActive {
		return nil, ErrKlinikAccountUnavailable
	}

	return user, nil
}
