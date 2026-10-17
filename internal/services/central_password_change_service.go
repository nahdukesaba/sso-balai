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

	CreateCredential(
		ctx context.Context,
		appUserID string,
		password string,
		mustChangePassword bool,
	) (*models.AuthCredential, error)
}

type CentralPasswordLegacyVerifier interface {
	SignInWithPassword(
		ctx context.Context,
		email string,
		password string,
	) (*models.SupabaseSession, error)

	SignOut(
		ctx context.Context,
		accessToken string,
	) error
}

type CentralPasswordChangeService struct {
	credentials CentralPasswordCredentialService
	legacy      CentralPasswordLegacyVerifier
}

func NewCentralPasswordChangeService(
	credentials CentralPasswordCredentialService,
	legacy CentralPasswordLegacyVerifier,
) *CentralPasswordChangeService {
	return &CentralPasswordChangeService{
		credentials: credentials,
		legacy:      legacy,
	}
}

func (s *CentralPasswordChangeService) Change(
	ctx context.Context,
	appUserID string,
	email string,
	oldPassword string,
	newPassword string,
) error {
	appUserID = strings.TrimSpace(appUserID)
	email = strings.ToLower(strings.TrimSpace(email))

	if appUserID == "" || email == "" || oldPassword == "" {
		return ErrInvalidCurrentPassword
	}

	if err := validateCentralPassword(newPassword); err != nil {
		return err
	}

	if s.credentials == nil {
		return ErrAuthUnavailable
	}

	_, err := s.credentials.VerifyUserPassword(
		ctx,
		appUserID,
		oldPassword,
	)

	switch {
	case err == nil:
		_, err = s.credentials.ReplacePassword(
			ctx,
			appUserID,
			newPassword,
		)

		return err

	case errors.Is(err, ErrInvalidCredentials):
		return ErrInvalidCurrentPassword

	case !errors.Is(err, ErrCredentialNotFound):
		return err
	}

	// Transitional legacy bridge:
	//
	// Users that existed before self-hosted credentials were introduced
	// do not yet have an auth_credentials row. Supabase is used only to
	// prove knowledge of the legacy password. The new password is stored
	// exclusively in Central SSO.
	if s.legacy == nil {
		return ErrAuthUnavailable
	}

	legacySession, err := s.legacy.SignInWithPassword(
		ctx,
		email,
		oldPassword,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return ErrInvalidCurrentPassword
		}

		return err
	}

	if legacySession == nil ||
		strings.TrimSpace(legacySession.User.ID) == "" {

		return ErrAuthUnavailable
	}

	if strings.TrimSpace(legacySession.AccessToken) != "" {
		defer func() {
			_ = s.legacy.SignOut(
				context.Background(),
				legacySession.AccessToken,
			)
		}()
	}

	if strings.TrimSpace(legacySession.User.ID) != appUserID ||
		!strings.EqualFold(
			strings.TrimSpace(legacySession.User.Email),
			email,
		) {

		return ErrInvalidCurrentPassword
	}

	if oldPassword == newPassword {
		return ErrSamePassword
	}

	_, err = s.credentials.CreateCredential(
		ctx,
		appUserID,
		newPassword,
		false,
	)

	return err
}
