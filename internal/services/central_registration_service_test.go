package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

type fakeCentralRegistrationUsers struct {
	user *models.AppUser
}

func (f *fakeCentralRegistrationUsers) GetByEmailIncludingDeleted(
	_ context.Context,
	_ string,
) (*models.AppUser, error) {
	return f.user, nil
}

type fakeCentralRegistrationApplications struct {
	application *models.Application
}

func (f *fakeCentralRegistrationApplications) GetByCode(
	_ context.Context,
	_ string,
) (*models.Application, error) {
	return f.application, nil
}

type fakeCentralRegistrationHasher struct {
	hash string
	err  error
}

func (f *fakeCentralRegistrationHasher) HashPassword(
	_ string,
) (string, error) {
	if f.err != nil {
		return "", f.err
	}

	return f.hash, nil
}

type fakeCentralRegistrationWriter struct {
	user *models.AppUser
	err  error

	email             string
	passwordHash      string
	passwordAlgorithm string
	applicationID     string
	phone             *string
}

func (f *fakeCentralRegistrationWriter) CreateNewIdentity(
	_ context.Context,
	email string,
	fullName string,
	phone *string,
	passwordHash string,
	passwordAlgorithm string,
	applicationID string,
) (*models.AppUser, error) {
	f.email = email
	f.passwordHash = passwordHash
	f.passwordAlgorithm = passwordAlgorithm
	f.applicationID = applicationID
	f.phone = phone

	if f.err != nil {
		return nil, f.err
	}

	if f.user != nil {
		return f.user, nil
	}

	return &models.AppUser{
		ID:       "user-1",
		Email:    email,
		FullName: fullName,
		Role:     "user",
		Status:   models.UserStatusApproved,
		Phone:    phone,
	}, nil
}

func TestCentralRegistrationCreatesSelfHostedIdentity(
	t *testing.T,
) {
	writer := &fakeCentralRegistrationWriter{}

	service := NewCentralRegistrationService(
		&fakeCentralRegistrationUsers{},
		&fakeCentralRegistrationApplications{
			application: &models.Application{
				ID:       "app-silapet",
				Code:     models.ApplicationCodeSilapet,
				Name:     "SILAPET",
				IsActive: true,
			},
		},
		&fakeCentralRegistrationHasher{
			hash: "$bcrypt$hashed-password",
		},
		writer,
	)

	identity, err := service.Register(
		context.Background(),
		" User@Example.com ",
		"Password123!",
		"User Example",
		"08123456789",
		" SILAPET ",
	)
	if err != nil {
		t.Fatalf(
			"register central identity: %v",
			err,
		)
	}

	if identity == nil ||
		identity.User == nil {

		t.Fatal(
			"registration identity must not be nil",
		)
	}

	if identity.User.Email !=
		"user@example.com" {

		t.Fatalf(
			"unexpected normalized email %q",
			identity.User.Email,
		)
	}

	if writer.passwordHash ==
		"Password123!" {

		t.Fatal(
			"plaintext password must not be written",
		)
	}

	if writer.passwordHash !=
		"$bcrypt$hashed-password" {

		t.Fatalf(
			"unexpected password hash %q",
			writer.passwordHash,
		)
	}

	if writer.passwordAlgorithm !=
		models.PasswordAlgorithmBcrypt {

		t.Fatalf(
			"unexpected algorithm %q",
			writer.passwordAlgorithm,
		)
	}

	if writer.applicationID !=
		"app-silapet" {

		t.Fatalf(
			"unexpected application id %q",
			writer.applicationID,
		)
	}

	if writer.phone == nil ||
		*writer.phone != "628123456789" {

		t.Fatalf(
			"unexpected normalized phone",
		)
	}
}

func TestCentralRegistrationRejectsExistingIdentity(
	t *testing.T,
) {
	service := NewCentralRegistrationService(
		&fakeCentralRegistrationUsers{
			user: &models.AppUser{
				ID:    "existing-user",
				Email: "user@example.com",
			},
		},
		&fakeCentralRegistrationApplications{},
		&fakeCentralRegistrationHasher{},
		&fakeCentralRegistrationWriter{},
	)

	_, err := service.Register(
		context.Background(),
		"user@example.com",
		"Password123!",
		"User Example",
		"",
		"silapet",
	)

	if !errors.Is(
		err,
		ErrAccountAlreadyExists,
	) {
		t.Fatalf(
			"expected ErrAccountAlreadyExists, got %v",
			err,
		)
	}
}

func TestCentralRegistrationRejectsDeletedIdentity(
	t *testing.T,
) {
	deletedAt := time.Now().UTC()

	service := NewCentralRegistrationService(
		&fakeCentralRegistrationUsers{
			user: &models.AppUser{
				ID:        "deleted-user",
				Email:     "user@example.com",
				DeletedAt: &deletedAt,
			},
		},
		&fakeCentralRegistrationApplications{},
		&fakeCentralRegistrationHasher{},
		&fakeCentralRegistrationWriter{},
	)

	_, err := service.Register(
		context.Background(),
		"user@example.com",
		"Password123!",
		"User Example",
		"",
		"silapet",
	)

	if !errors.Is(
		err,
		ErrRegistrationIdentityConflict,
	) {
		t.Fatalf(
			"expected ErrRegistrationIdentityConflict, got %v",
			err,
		)
	}
}

func TestCentralRegistrationRejectsInactiveApplication(
	t *testing.T,
) {
	service := NewCentralRegistrationService(
		&fakeCentralRegistrationUsers{},
		&fakeCentralRegistrationApplications{
			application: &models.Application{
				ID:       "app-silapet",
				Code:     "silapet",
				IsActive: false,
			},
		},
		&fakeCentralRegistrationHasher{},
		&fakeCentralRegistrationWriter{},
	)

	_, err := service.Register(
		context.Background(),
		"user@example.com",
		"Password123!",
		"User Example",
		"",
		"silapet",
	)

	if !errors.Is(
		err,
		ErrUnsupportedApplication,
	) {
		t.Fatalf(
			"expected ErrUnsupportedApplication, got %v",
			err,
		)
	}
}

func TestCentralRegistrationMapsTransactionConflict(
	t *testing.T,
) {
	service := NewCentralRegistrationService(
		&fakeCentralRegistrationUsers{},
		&fakeCentralRegistrationApplications{
			application: &models.Application{
				ID:       "app-silapet",
				Code:     "silapet",
				IsActive: true,
			},
		},
		&fakeCentralRegistrationHasher{
			hash: "$bcrypt$hashed-password",
		},
		&fakeCentralRegistrationWriter{
			err: repository.ErrCentralRegistrationConflict,
		},
	)

	_, err := service.Register(
		context.Background(),
		"user@example.com",
		"Password123!",
		"User Example",
		"",
		"silapet",
	)

	if !errors.Is(
		err,
		ErrAccountAlreadyExists,
	) {
		t.Fatalf(
			"expected ErrAccountAlreadyExists, got %v",
			err,
		)
	}
}
