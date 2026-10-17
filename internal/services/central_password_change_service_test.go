package services

import (
	"context"
	"errors"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeCentralPasswordCredentials struct {
	verifyCredential *models.AuthCredential
	verifyErr        error
	replaceErr       error
	createErr        error

	verifyUserID  string
	verifyPass    string
	replaceUserID string
	replacePass   string
	createUserID  string
	createPass    string
	created       bool
}

func (f *fakeCentralPasswordCredentials) VerifyUserPassword(
	ctx context.Context,
	appUserID string,
	password string,
) (*models.AuthCredential, error) {
	f.verifyUserID = appUserID
	f.verifyPass = password

	return f.verifyCredential, f.verifyErr
}

func (f *fakeCentralPasswordCredentials) ReplacePassword(
	ctx context.Context,
	appUserID string,
	newPassword string,
) (*models.AuthCredential, error) {
	f.replaceUserID = appUserID
	f.replacePass = newPassword

	if f.replaceErr != nil {
		return nil, f.replaceErr
	}

	return &models.AuthCredential{
		AppUserID: appUserID,
	}, nil
}

func (f *fakeCentralPasswordCredentials) CreateCredential(
	ctx context.Context,
	appUserID string,
	password string,
	mustChangePassword bool,
) (*models.AuthCredential, error) {
	f.createUserID = appUserID
	f.createPass = password
	f.created = true

	if f.createErr != nil {
		return nil, f.createErr
	}

	return &models.AuthCredential{
		AppUserID: appUserID,
	}, nil
}

type fakeCentralPasswordChangeSessions struct {
	revokedUser string
	err         error
}

func (f *fakeCentralPasswordChangeSessions) RevokeAllByAppUserID(
	ctx context.Context,
	appUserID string,
) error {
	f.revokedUser = appUserID

	return f.err
}

type fakeCentralPasswordLegacy struct {
	session *models.SupabaseSession
	err     error

	email       string
	password    string
	signedOut   bool
	signOutWith string
}

func (f *fakeCentralPasswordLegacy) SignInWithPassword(
	ctx context.Context,
	email string,
	password string,
) (*models.SupabaseSession, error) {
	f.email = email
	f.password = password

	return f.session, f.err
}

func (f *fakeCentralPasswordLegacy) SignOut(
	ctx context.Context,
	accessToken string,
) error {
	f.signedOut = true
	f.signOutWith = accessToken

	return nil
}

func newTestCentralPasswordChangeService(
	credentials CentralPasswordCredentialService,
	legacy CentralPasswordLegacyVerifier,
) *CentralPasswordChangeService {
	return NewCentralPasswordChangeService(
		credentials,
		legacy,
		&fakeCentralPasswordChangeSessions{},
	)
}

func TestCentralPasswordChangeUsesCentralCredential(
	t *testing.T,
) {
	credentials := &fakeCentralPasswordCredentials{
		verifyCredential: &models.AuthCredential{
			AppUserID: "user-1",
		},
	}

	legacy := &fakeCentralPasswordLegacy{}

	service := newTestCentralPasswordChangeService(
		credentials,
		legacy,
	)

	err := service.Change(
		context.Background(),
		"user-1",
		"user@example.com",
		"old-password",
		"new-password",
	)
	if err != nil {
		t.Fatalf(
			"change central password: %v",
			err,
		)
	}

	if credentials.verifyUserID != "user-1" ||
		credentials.verifyPass != "old-password" {

		t.Fatal(
			"current central credential was not verified",
		)
	}

	if credentials.replaceUserID != "user-1" ||
		credentials.replacePass != "new-password" {

		t.Fatal(
			"central password was not replaced",
		)
	}

	if legacy.email != "" {
		t.Fatal(
			"legacy verifier must not be used when central credential exists",
		)
	}
}

func TestCentralPasswordChangeRejectsWrongPassword(
	t *testing.T,
) {
	service := newTestCentralPasswordChangeService(
		&fakeCentralPasswordCredentials{
			verifyErr: ErrInvalidCredentials,
		},
		&fakeCentralPasswordLegacy{},
	)

	err := service.Change(
		context.Background(),
		"user-1",
		"user@example.com",
		"wrong-password",
		"new-password",
	)

	if !errors.Is(
		err,
		ErrInvalidCurrentPassword,
	) {
		t.Fatalf(
			"expected invalid current password, got %v",
			err,
		)
	}
}

func TestCentralPasswordChangeMigratesLegacyCredential(
	t *testing.T,
) {
	credentials := &fakeCentralPasswordCredentials{
		verifyErr: ErrCredentialNotFound,
	}

	legacy := &fakeCentralPasswordLegacy{
		session: &models.SupabaseSession{
			AccessToken: "legacy-verification-token",
			User: models.SupabaseAuthUser{
				ID:    "user-1",
				Email: "user@example.com",
			},
		},
	}

	service := newTestCentralPasswordChangeService(
		credentials,
		legacy,
	)

	err := service.Change(
		context.Background(),
		"user-1",
		"user@example.com",
		"legacy-password",
		"new-central-password",
	)
	if err != nil {
		t.Fatalf(
			"migrate password during change: %v",
			err,
		)
	}

	if !credentials.created {
		t.Fatal(
			"central credential was not created",
		)
	}

	if credentials.createUserID != "user-1" ||
		credentials.createPass !=
			"new-central-password" {

		t.Fatal(
			"unexpected migrated central credential",
		)
	}

	if !legacy.signedOut ||
		legacy.signOutWith !=
			"legacy-verification-token" {

		t.Fatal(
			"legacy verification session was not revoked",
		)
	}
}

func TestCentralPasswordChangeRejectsLegacyIdentityMismatch(
	t *testing.T,
) {
	service := newTestCentralPasswordChangeService(
		&fakeCentralPasswordCredentials{
			verifyErr: ErrCredentialNotFound,
		},
		&fakeCentralPasswordLegacy{
			session: &models.SupabaseSession{
				User: models.SupabaseAuthUser{
					ID:    "different-user",
					Email: "user@example.com",
				},
			},
		},
	)

	err := service.Change(
		context.Background(),
		"user-1",
		"user@example.com",
		"legacy-password",
		"new-central-password",
	)

	if !errors.Is(
		err,
		ErrInvalidCurrentPassword,
	) {
		t.Fatalf(
			"expected identity mismatch rejection, got %v",
			err,
		)
	}
}

func TestCentralPasswordChangeRevokesSessions(
	t *testing.T,
) {
	credentials := &fakeCentralPasswordCredentials{
		verifyCredential: &models.AuthCredential{
			AppUserID: "user-1",
		},
	}

	sessions := &fakeCentralPasswordChangeSessions{}

	service := NewCentralPasswordChangeService(
		credentials,
		&fakeCentralPasswordLegacy{},
		sessions,
	)

	err := service.Change(
		context.Background(),
		"user-1",
		"user@example.com",
		"old-password",
		"new-password",
	)
	if err != nil {
		t.Fatalf(
			"change password: %v",
			err,
		)
	}

	if sessions.revokedUser != "user-1" {
		t.Fatalf(
			"expected all sessions for user-1 to be revoked, got %q",
			sessions.revokedUser,
		)
	}
}
