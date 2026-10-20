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

	verifyUserID  string
	verifyPass    string
	replaceUserID string
	replacePass   string
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

func TestCentralPasswordChangeUsesCentralCredential(
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
		sessions,
	)

	if err := service.Change(
		context.Background(),
		"user-1",
		"old-password",
		"new-password",
	); err != nil {
		t.Fatalf("change central password: %v", err)
	}

	if credentials.verifyUserID != "user-1" ||
		credentials.verifyPass != "old-password" {

		t.Fatal("current central credential was not verified")
	}

	if credentials.replaceUserID != "user-1" ||
		credentials.replacePass != "new-password" {

		t.Fatal("central password was not replaced")
	}

	if sessions.revokedUser != "user-1" {
		t.Fatalf(
			"expected all sessions for user-1 revoked, got %q",
			sessions.revokedUser,
		)
	}
}

func TestCentralPasswordChangeRequiresCurrentPassword(
	t *testing.T,
) {
	credentials := &fakeCentralPasswordCredentials{
		verifyErr: ErrInvalidCredentials,
	}

	sessions := &fakeCentralPasswordChangeSessions{}

	service := NewCentralPasswordChangeService(
		credentials,
		sessions,
	)

	err := service.Change(
		context.Background(),
		"user-1",
		"wrong-password",
		"new-password",
	)

	if !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("expected invalid current password, got %v", err)
	}

	err = service.Change(
		context.Background(),
		"user-1",
		"",
		"new-password",
	)

	if !errors.Is(err, ErrInvalidCurrentPassword) {
		t.Fatalf("empty current password must fail, got %v", err)
	}

	if credentials.replacePass != "" || sessions.revokedUser != "" {
		t.Fatal("nothing may change when the current password is wrong")
	}
}

func TestCentralPasswordChangeWithoutCredentialRequiresSetup(
	t *testing.T,
) {
	credentials := &fakeCentralPasswordCredentials{
		verifyErr: ErrCredentialNotFound,
	}

	sessions := &fakeCentralPasswordChangeSessions{}

	service := NewCentralPasswordChangeService(
		credentials,
		sessions,
	)

	err := service.Change(
		context.Background(),
		"user-1",
		"legacy-password",
		"new-central-password",
	)

	if !errors.Is(err, ErrPasswordSetupRequired) {
		t.Fatalf("expected ErrPasswordSetupRequired, got %v", err)
	}

	if credentials.replacePass != "" {
		t.Fatal("no credential may be created via change-password")
	}
}
