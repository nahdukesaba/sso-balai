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

func (s *KlinikContextService) GetByEmail(
	ctx context.Context,
	email string,
) (*models.KlinikUser, error) {
	email = strings.TrimSpace(email)

	if email == "" {
		return nil, ErrKlinikAccountUnavailable
	}

	user, err := s.klinikUserRepository.GetActiveByEmail(
		ctx,
		email,
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
