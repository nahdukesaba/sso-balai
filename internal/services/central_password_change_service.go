package services

import (
	"context"
	"errors"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type CentralPasswordCredentialService interface {
	VerifyUserPassword(
		ctx context.Context,
		appUserID string,
		password string,
	) (*models.AuthCredential, error)

	ReplacePassword(
		ctx context.Context,
		appUserID string,
		newPassword string,
	) (*models.AuthCredential, error)
}

type CentralPasswordChangeSessionRevoker interface {
	RevokeAllByAppUserID(
		ctx context.Context,
		appUserID string,
	) error
}

// CentralPasswordChangeService changes a password for an authenticated
// identity. The current password is verified against auth_credentials only.
// All central sessions (including the caller's) are revoked afterwards, so
// the client must log in again with the new password.
type CentralPasswordChangeService struct {
	credentials CentralPasswordCredentialService
	sessions    CentralPasswordChangeSessionRevoker
}

func NewCentralPasswordChangeService(
	credentials CentralPasswordCredentialService,
	sessions CentralPasswordChangeSessionRevoker,
) *CentralPasswordChangeService {
	return &CentralPasswordChangeService{
		credentials: credentials,
		sessions:    sessions,
	}
}

func (s *CentralPasswordChangeService) Change(
	ctx context.Context,
	appUserID string,
	oldPassword string,
	newPassword string,
) error {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" || oldPassword == "" {
		return ErrInvalidCurrentPassword
	}

	if err := validateCentralPassword(newPassword); err != nil {
		return err
	}

	if s.credentials == nil ||
		s.sessions == nil {

		return ErrAuthUnavailable
	}

	_, err := s.credentials.VerifyUserPassword(
		ctx,
		appUserID,
		oldPassword,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidCredentials):
			return ErrInvalidCurrentPassword

		case errors.Is(err, ErrCredentialNotFound):
			return ErrPasswordSetupRequired

		default:
			return err
		}
	}

	if _, err := s.credentials.ReplacePassword(
		ctx,
		appUserID,
		newPassword,
	); err != nil {
		return err
	}

	return s.sessions.RevokeAllByAppUserID(
		ctx,
		appUserID,
	)
}
