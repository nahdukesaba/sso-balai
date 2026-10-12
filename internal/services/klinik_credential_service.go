package services

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

type KlinikCredentialService struct {
	klinikUserRepository *repository.KlinikUserRepository
}

func NewKlinikCredentialService(
	klinikUserRepository *repository.KlinikUserRepository,
) *KlinikCredentialService {
	return &KlinikCredentialService{
		klinikUserRepository: klinikUserRepository,
	}
}

func (s *KlinikCredentialService) Verify(
	ctx context.Context,
	email string,
	password string,
) (*models.KlinikUser, error) {
	email = strings.TrimSpace(email)

	if email == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.klinikUserRepository.GetActiveByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("get Klinik credential identity: %w", err)
	}

	if user == nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(password),
	); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}
