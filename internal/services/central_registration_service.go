package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var ErrInvalidRegistrationRequest = errors.New(
	"invalid central registration request",
)

type CentralRegistrationUserStore interface {
	GetByEmailIncludingDeleted(
		ctx context.Context,
		email string,
	) (*models.AppUser, error)
}

type CentralRegistrationApplicationStore interface {
	GetByCode(
		ctx context.Context,
		code string,
	) (*models.Application, error)
}

type CentralRegistrationCredentialHasher interface {
	HashPassword(
		password string,
	) (string, error)
}

type CentralRegistrationWriter interface {
	CreateNewIdentity(
		ctx context.Context,
		email string,
		fullName string,
		phone *string,
		passwordHash string,
		passwordAlgorithm string,
		applicationID string,
	) (*models.AppUser, error)
}

type CentralRegistrationService struct {
	users        CentralRegistrationUserStore
	applications CentralRegistrationApplicationStore
	credentials  CentralRegistrationCredentialHasher
	writer       CentralRegistrationWriter
}

func NewCentralRegistrationService(
	users CentralRegistrationUserStore,
	applications CentralRegistrationApplicationStore,
	credentials CentralRegistrationCredentialHasher,
	writer CentralRegistrationWriter,
) *CentralRegistrationService {
	return &CentralRegistrationService{
		users:        users,
		applications: applications,
		credentials:  credentials,
		writer:       writer,
	}
}

func (s *CentralRegistrationService) Register(
	ctx context.Context,
	email string,
	password string,
	fullName string,
	phone string,
	applicationCode string,
) (*models.Identity, error) {
	email = strings.ToLower(
		strings.TrimSpace(email),
	)

	fullName = strings.TrimSpace(fullName)
	phone = strings.TrimSpace(phone)

	applicationCode = strings.ToLower(
		strings.TrimSpace(applicationCode),
	)

	if email == "" ||
		password == "" ||
		fullName == "" ||
		applicationCode == "" {

		return nil, ErrInvalidRegistrationRequest
	}

	existingUser, err :=
		s.users.GetByEmailIncludingDeleted(
			ctx,
			email,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"find central registration identity: %w",
			err,
		)
	}

	if existingUser != nil {
		if existingUser.DeletedAt != nil {
			return nil,
				ErrRegistrationIdentityConflict
		}

		return nil, ErrAccountAlreadyExists
	}

	application, err :=
		s.applications.GetByCode(
			ctx,
			applicationCode,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve registration application: %w",
			err,
		)
	}

	if application == nil ||
		!application.IsActive {

		return nil, ErrUnsupportedApplication
	}

	passwordHash, err :=
		s.credentials.HashPassword(password)
	if err != nil {
		return nil, err
	}

	if strings.HasPrefix(phone, "0") {
		phone = "62" + phone[1:]
	}

	var phonePtr *string

	if phone != "" {
		phonePtr = &phone
	}

	user, err := s.writer.CreateNewIdentity(
		ctx,
		email,
		fullName,
		phonePtr,
		passwordHash,
		models.PasswordAlgorithmBcrypt,
		application.ID,
	)
	if err != nil {
		switch {
		case errors.Is(
			err,
			repository.ErrCentralRegistrationConflict,
		):
			return nil, ErrAccountAlreadyExists

		case errors.Is(
			err,
			repository.ErrCentralRegistrationApplicationUnavailable,
		):
			return nil, ErrUnsupportedApplication

		default:
			return nil, fmt.Errorf(
				"create central registration identity: %w",
				err,
			)
		}
	}

	if user == nil {
		return nil, ErrAuthUnavailable
	}

	return &models.Identity{
		User:    user,
		Pegawai: nil,
	}, nil
}
