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

type CentralLoginIdentityLoader interface {
	GetByUserID(
		ctx context.Context,
		userID string,
	) (*models.Identity, error)
}

// CentralLoginService authenticates a central identity against
// auth_credentials only, then derives application authorization from
// app_memberships. It never creates memberships.
type CentralLoginService struct {
	users        CentralLoginUserStore
	credentials  CentralLoginCredentialService
	applications CentralLoginApplicationResolver
	sessions     CentralLoginSessionService
	identities   CentralLoginIdentityLoader
}

func NewCentralLoginService(
	users CentralLoginUserStore,
	credentials CentralLoginCredentialService,
	applications CentralLoginApplicationResolver,
	sessions CentralLoginSessionService,
	identities CentralLoginIdentityLoader,
) *CentralLoginService {
	return &CentralLoginService{
		users:        users,
		credentials:  credentials,
		applications: applications,
		sessions:     sessions,
		identities:   identities,
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

	// 1. find central identity
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

	// 2. verify central credential
	_, err = s.credentials.VerifyUserPassword(
		ctx,
		user.ID,
		password,
	)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return nil, ErrPasswordSetupRequired
		}

		return nil, err
	}

	// 3-4. resolve application and membership
	appContext, err := s.applications.GetByAppUserID(
		ctx,
		user.ID,
		application,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrApplicationUnavailable):
			return nil, ErrUnsupportedApplication

		case errors.Is(err, ErrApplicationMembershipUnavailable):
			return nil, ErrApplicationAccessUnavailable

		default:
			return nil, fmt.Errorf(
				"resolve central login application: %w",
				err,
			)
		}
	}

	if appContext == nil ||
		strings.TrimSpace(appContext.ApplicationID) == "" {

		return nil, ErrApplicationAccessUnavailable
	}

	// 5. enforce membership status
	if err := membershipLoginStatusError(
		appContext.Status,
	); err != nil {
		return nil, err
	}

	if strings.TrimSpace(appContext.Role) == "" {
		return nil, ErrAccountUnavailable
	}

	identity, err := s.identities.GetByUserID(
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

	// 6-7. create session and issue tokens; role comes from membership.
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
