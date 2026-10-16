package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrCredentialNotFound = errors.New(
		"central credential not found",
	)
	ErrUnsupportedPasswordAlgorithm = errors.New(
		"unsupported password algorithm",
	)
)

const (
	centralPasswordMinLength = 8
	centralPasswordMaxLength = 128
)

type CredentialStore interface {
	GetByAppUserID(
		ctx context.Context,
		appUserID string,
	) (*models.AuthCredential, error)

	Create(
		ctx context.Context,
		appUserID string,
		passwordHash string,
		passwordAlgorithm string,
		mustChangePassword bool,
	) (*models.AuthCredential, error)

	UpdatePassword(
		ctx context.Context,
		appUserID string,
		passwordHash string,
		passwordAlgorithm string,
	) (*models.AuthCredential, error)
}

type CredentialService struct {
	store CredentialStore
}

func NewCredentialService(
	store CredentialStore,
) *CredentialService {
	return &CredentialService{
		store: store,
	}
}

func validateCentralPassword(
	password string,
) error {
	if len(password) < centralPasswordMinLength ||
		len(password) > centralPasswordMaxLength ||
		strings.TrimSpace(password) == "" {
		return ErrInvalidPassword
	}

	return nil
}

func (s *CredentialService) HashPassword(
	password string,
) (string, error) {
	if err := validateCentralPassword(password); err != nil {
		return "", err
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return "", fmt.Errorf(
			"hash central password: %w",
			err,
		)
	}

	return string(hash), nil
}

func (s *CredentialService) VerifyPassword(
	credential *models.AuthCredential,
	password string,
) error {
	if credential == nil ||
		password == "" {
		return ErrInvalidCredentials
	}

	switch credential.PasswordAlgorithm {
	case models.PasswordAlgorithmBcrypt:
		if err := bcrypt.CompareHashAndPassword(
			[]byte(credential.PasswordHash),
			[]byte(password),
		); err != nil {
			return ErrInvalidCredentials
		}

		return nil

	default:
		return ErrUnsupportedPasswordAlgorithm
	}
}

func (s *CredentialService) VerifyUserPassword(
	ctx context.Context,
	appUserID string,
	password string,
) (*models.AuthCredential, error) {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	credential, err := s.store.GetByAppUserID(
		ctx,
		appUserID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"get central credential: %w",
			err,
		)
	}

	if credential == nil {
		return nil, ErrCredentialNotFound
	}

	if err := s.VerifyPassword(
		credential,
		password,
	); err != nil {
		return nil, err
	}

	return credential, nil
}

func (s *CredentialService) CreateCredential(
	ctx context.Context,
	appUserID string,
	password string,
	mustChangePassword bool,
) (*models.AuthCredential, error) {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" {
		return nil, ErrCredentialNotFound
	}

	passwordHash, err := s.HashPassword(password)
	if err != nil {
		return nil, err
	}

	credential, err := s.store.Create(
		ctx,
		appUserID,
		passwordHash,
		models.PasswordAlgorithmBcrypt,
		mustChangePassword,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create central credential: %w",
			err,
		)
	}

	return credential, nil
}

func (s *CredentialService) ReplacePassword(
	ctx context.Context,
	appUserID string,
	newPassword string,
) (*models.AuthCredential, error) {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" {
		return nil, ErrCredentialNotFound
	}

	if err := validateCentralPassword(
		newPassword,
	); err != nil {
		return nil, err
	}

	currentCredential, err := s.store.GetByAppUserID(
		ctx,
		appUserID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"get current central credential: %w",
			err,
		)
	}

	if currentCredential == nil {
		return nil, ErrCredentialNotFound
	}

	switch currentCredential.PasswordAlgorithm {
	case models.PasswordAlgorithmBcrypt:
		if err := bcrypt.CompareHashAndPassword(
			[]byte(currentCredential.PasswordHash),
			[]byte(newPassword),
		); err == nil {
			return nil, ErrSamePassword
		}

	default:
		return nil, ErrUnsupportedPasswordAlgorithm
	}

	passwordHash, err := s.HashPassword(
		newPassword,
	)
	if err != nil {
		return nil, err
	}

	updatedCredential, err := s.store.UpdatePassword(
		ctx,
		appUserID,
		passwordHash,
		models.PasswordAlgorithmBcrypt,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"replace central credential password: %w",
			err,
		)
	}

	if updatedCredential == nil {
		return nil, ErrCredentialNotFound
	}

	return updatedCredential, nil
}
