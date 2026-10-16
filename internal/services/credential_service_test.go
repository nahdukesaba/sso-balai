package services

import (
	"context"
	"errors"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeCredentialStore struct {
	credential *models.AuthCredential

	createCalls int
	updateCalls int
}

func (f *fakeCredentialStore) GetByAppUserID(
	_ context.Context,
	appUserID string,
) (*models.AuthCredential, error) {
	if f.credential == nil ||
		f.credential.AppUserID != appUserID {
		return nil, nil
	}

	return f.credential, nil
}

func (f *fakeCredentialStore) Create(
	_ context.Context,
	appUserID string,
	passwordHash string,
	passwordAlgorithm string,
	mustChangePassword bool,
) (*models.AuthCredential, error) {
	f.createCalls++

	f.credential = &models.AuthCredential{
		AppUserID:          appUserID,
		PasswordHash:       passwordHash,
		PasswordAlgorithm:  passwordAlgorithm,
		MustChangePassword: mustChangePassword,
	}

	return f.credential, nil
}

func (f *fakeCredentialStore) UpdatePassword(
	_ context.Context,
	appUserID string,
	passwordHash string,
	passwordAlgorithm string,
) (*models.AuthCredential, error) {
	f.updateCalls++

	if f.credential == nil ||
		f.credential.AppUserID != appUserID {
		return nil, nil
	}

	f.credential.PasswordHash = passwordHash
	f.credential.PasswordAlgorithm = passwordAlgorithm
	f.credential.MustChangePassword = false
	f.credential.FailedAttempts = 0
	f.credential.LockedUntil = nil

	return f.credential, nil
}

func TestCredentialServiceCreateAndVerifyPassword(
	t *testing.T,
) {
	store := &fakeCredentialStore{}

	service := NewCredentialService(store)

	credential, err := service.CreateCredential(
		context.Background(),
		"user-1",
		"Password123!",
		false,
	)
	if err != nil {
		t.Fatalf(
			"create credential: %v",
			err,
		)
	}

	if credential.PasswordHash == "Password123!" {
		t.Fatal(
			"password must not be stored as plaintext",
		)
	}

	if credential.PasswordAlgorithm !=
		models.PasswordAlgorithmBcrypt {
		t.Fatalf(
			"unexpected password algorithm %q",
			credential.PasswordAlgorithm,
		)
	}

	if store.createCalls != 1 {
		t.Fatalf(
			"expected one create call, got %d",
			store.createCalls,
		)
	}

	if err := service.VerifyPassword(
		credential,
		"Password123!",
	); err != nil {
		t.Fatalf(
			"verify correct password: %v",
			err,
		)
	}

	if err := service.VerifyPassword(
		credential,
		"WrongPassword123!",
	); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf(
			"expected ErrInvalidCredentials, got %v",
			err,
		)
	}
}

func TestCredentialServicePasswordPolicy(
	t *testing.T,
) {
	service := NewCredentialService(
		&fakeCredentialStore{},
	)

	tests := []struct {
		name     string
		password string
	}{
		{
			name:     "too short",
			password: "Short1!",
		},
		{
			name:     "blank",
			password: "        ",
		},
		{
			name: "too long",
			password: string(
				make([]byte, 129),
			),
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				_, err := service.HashPassword(
					test.password,
				)

				if !errors.Is(
					err,
					ErrInvalidPassword,
				) {
					t.Fatalf(
						"expected ErrInvalidPassword, got %v",
						err,
					)
				}
			},
		)
	}
}

func TestCredentialServiceReplacePassword(
	t *testing.T,
) {
	store := &fakeCredentialStore{}
	service := NewCredentialService(store)

	_, err := service.CreateCredential(
		context.Background(),
		"user-1",
		"Password123!",
		false,
	)
	if err != nil {
		t.Fatalf(
			"create credential: %v",
			err,
		)
	}

	_, err = service.ReplacePassword(
		context.Background(),
		"user-1",
		"Password123!",
	)
	if !errors.Is(err, ErrSamePassword) {
		t.Fatalf(
			"expected ErrSamePassword, got %v",
			err,
		)
	}

	updated, err := service.ReplacePassword(
		context.Background(),
		"user-1",
		"NewPassword456!",
	)
	if err != nil {
		t.Fatalf(
			"replace password: %v",
			err,
		)
	}

	if store.updateCalls != 1 {
		t.Fatalf(
			"expected one update call, got %d",
			store.updateCalls,
		)
	}

	if err := service.VerifyPassword(
		updated,
		"Password123!",
	); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf(
			"old password must be rejected, got %v",
			err,
		)
	}

	if err := service.VerifyPassword(
		updated,
		"NewPassword456!",
	); err != nil {
		t.Fatalf(
			"new password must be valid: %v",
			err,
		)
	}
}

func TestCredentialServiceMissingCredential(
	t *testing.T,
) {
	service := NewCredentialService(
		&fakeCredentialStore{},
	)

	_, err := service.VerifyUserPassword(
		context.Background(),
		"missing-user",
		"Password123!",
	)

	if !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf(
			"expected ErrCredentialNotFound, got %v",
			err,
		)
	}
}

func TestCredentialServiceRejectsUnsupportedAlgorithm(
	t *testing.T,
) {
	service := NewCredentialService(
		&fakeCredentialStore{},
	)

	err := service.VerifyPassword(
		&models.AuthCredential{
			AppUserID:         "user-1",
			PasswordHash:      "irrelevant",
			PasswordAlgorithm: "unknown",
		},
		"Password123!",
	)

	if !errors.Is(
		err,
		ErrUnsupportedPasswordAlgorithm,
	) {
		t.Fatalf(
			"expected ErrUnsupportedPasswordAlgorithm, got %v",
			err,
		)
	}
}
