package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type CentralLoginUserStore interface {
	GetByEmailIncludingDeleted(
		ctx context.Context,
		email string,
	) (*models.AppUser, error)
}

type CentralLoginCredentialService interface {
	VerifyUserPassword(
		ctx context.Context,
		appUserID string,
		password string,
	) (*models.AuthCredential, error)

	CreateCredential(
		ctx context.Context,
		appUserID string,
		password string,
		mustChangePassword bool,
	) (*models.AuthCredential, error)
}

type CentralLoginApplicationResolver interface {
	GetByAppUserID(
		ctx context.Context,
		appUserID string,
		applicationCode string,
	) (*models.ApplicationContext, error)
}

type CentralLoginSessionService interface {
	Create(
		ctx context.Context,
		appUserID string,
		applicationID string,
		applicationCode string,
		role string,
	) (
		*models.AuthTokenSet,
		*models.AuthSession,
		error,
	)
}

type LegacyCredentialVerifier interface {
	SignInWithPassword(
		ctx context.Context,
		email string,
		password string,
	) (*models.SupabaseSession, error)
}

type CentralLoginService struct {
	users            CentralLoginUserStore
	credentials      CentralLoginCredentialService
	applications     CentralLoginApplicationResolver
	sessions         CentralLoginSessionService
	identityService  *IdentityService
	legacyCredential LegacyCredentialVerifier
}

func NewCentralLoginService(
	users CentralLoginUserStore,
	credentials CentralLoginCredentialService,
	applications CentralLoginApplicationResolver,
	sessions CentralLoginSessionService,
	identityService *IdentityService,
	legacyCredential LegacyCredentialVerifier,
) *CentralLoginService {
	return &CentralLoginService{
		users:            users,
		credentials:      credentials,
		applications:     applications,
		sessions:         sessions,
		identityService:  identityService,
		legacyCredential: legacyCredential,
	}
}

func (s *CentralLoginService) Login(
	ctx context.Context,
	email string,
	password string,
	application string,
) (*models.LoginResult, error) {
	email = strings.TrimSpace(email)
	application = strings.ToLower(
		strings.TrimSpace(application),
	)

	if email == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	if application == "" {
		return nil, ErrUnsupportedApplication
	}

	user, err := s.users.GetByEmailIncludingDeleted(
		ctx,
		email,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve central login identity: %w",
			err,
		)
	}

	if user == nil ||
		user.DeletedAt != nil ||
		!strings.EqualFold(user.Email, email) {

		return nil, ErrInvalidCredentials
	}

	err = s.ensureCentralCredential(
		ctx,
		user,
		password,
	)
	if err != nil {
		return nil, err
	}

	appContext, err := s.applications.GetByAppUserID(
		ctx,
		user.ID,
		application,
	)
	if err != nil {
		switch {
		case errors.Is(
			err,
			ErrApplicationUnavailable,
		):
			return nil, ErrUnsupportedApplication

		case errors.Is(
			err,
			ErrApplicationMembershipUnavailable,
		):
			return nil, ErrAccountUnavailable

		default:
			return nil, fmt.Errorf(
				"resolve central login application: %w",
				err,
			)
		}
	}

	if appContext == nil ||
		strings.TrimSpace(appContext.ApplicationID) == "" {

		return nil, ErrAccountUnavailable
	}

	if err := membershipLoginStatusError(
		appContext.Status,
	); err != nil {
		return nil, err
	}

	if strings.TrimSpace(appContext.Role) == "" {
		return nil, ErrAccountUnavailable
	}

	identity, err := s.identityService.GetByUserID(
		ctx,
		user.ID,
	)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrAccountUnavailable
		}

		return nil, fmt.Errorf(
			"load central login identity: %w",
			err,
		)
	}

	tokenSet, _, err := s.sessions.Create(
		ctx,
		user.ID,
		appContext.ApplicationID,
		appContext.Application,
		appContext.Role,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create central login session: %w",
			err,
		)
	}

	if tokenSet == nil {
		return nil, ErrAuthUnavailable
	}

	session := &models.SupabaseSession{
		AccessToken:  tokenSet.AccessToken,
		TokenType:    tokenSet.TokenType,
		ExpiresIn:    tokenSet.ExpiresIn,
		ExpiresAt:    tokenSet.ExpiresAt,
		RefreshToken: tokenSet.RefreshToken,
		User: models.SupabaseAuthUser{
			ID:    user.ID,
			Email: user.Email,
		},
	}

	return &models.LoginResult{
		Session:  session,
		Identity: identity,
	}, nil
}

func (s *CentralLoginService) ensureCentralCredential(
	ctx context.Context,
	user *models.AppUser,
	password string,
) error {
	_, err := s.credentials.VerifyUserPassword(
		ctx,
		user.ID,
		password,
	)

	if err == nil {
		return nil
	}

	if !errors.Is(
		err,
		ErrCredentialNotFound,
	) {
		return err
	}

	if s.legacyCredential == nil {
		return ErrInvalidCredentials
	}

	legacySession, legacyErr :=
		s.legacyCredential.SignInWithPassword(
			ctx,
			user.Email,
			password,
		)

	if legacyErr != nil {
		return legacyErr
	}

	if legacySession == nil ||
		legacySession.User.ID != user.ID ||
		!strings.EqualFold(
			legacySession.User.Email,
			user.Email,
		) {

		return ErrInvalidCredentials
	}

	_, createErr := s.credentials.CreateCredential(
		ctx,
		user.ID,
		password,
		false,
	)

	if createErr == nil {
		return nil
	}

	// Concurrent first login may have created the central
	// credential after our first lookup. Verify again before
	// surfacing the create error.
	_, verifyErr := s.credentials.VerifyUserPassword(
		ctx,
		user.ID,
		password,
	)

	if verifyErr == nil {
		return nil
	}

	return fmt.Errorf(
		"migrate central credential: %w",
		createErr,
	)
}

func membershipLoginStatusError(
	status string,
) error {
	switch status {
	case models.MembershipStatusApproved:
		return nil

	case models.MembershipStatusPending:
		return ErrAccountPending

	case models.MembershipStatusRejected:
		return ErrAccountRejected

	case models.MembershipStatusDisabled:
		return ErrAccountDisabled

	default:
		return ErrAccountUnavailable
	}
}
