package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type SupabaseAuthentication interface {
	SignInWithPassword(
		ctx context.Context,
		email string,
		password string,
	) (*models.SupabaseSession, error)

	RefreshSession(
		ctx context.Context,
		refreshToken string,
	) (*models.SupabaseSession, error)

	VerifyAccessToken(
		ctx context.Context,
		accessToken string,
	) (*models.SupabaseAuthUser, error)

	SignOut(
		ctx context.Context,
		accessToken string,
	) error

	UpdatePassword(
		ctx context.Context,
		accessToken string,
		password string,
	) error
}

type SupabaseAuthUserStore interface {
	GetByAuthUserID(
		ctx context.Context,
		authUserID string,
	) (*models.AppUser, error)
}

type SupabaseAuthApplicationResolver interface {
	GetByAppUserID(
		ctx context.Context,
		appUserID string,
		applicationCode string,
	) (*models.ApplicationContext, error)
}

type SupabaseAuthIdentityLoader interface {
	GetByUserID(
		ctx context.Context,
		userID string,
	) (*models.Identity, error)
}

type ActiveAuthenticationService interface {
	Login(
		ctx context.Context,
		email string,
		password string,
		application string,
	) (*models.LoginResult, error)

	Refresh(
		ctx context.Context,
		refreshToken string,
	) (*models.LoginResult, error)

	AuthenticateAccessToken(
		ctx context.Context,
		accessToken string,
	) (*models.Identity, error)

	Logout(
		ctx context.Context,
		accessToken string,
	) error

	ChangePassword(
		ctx context.Context,
		appUserID string,
		email string,
		oldPassword string,
		newPassword string,
	) error
}

// SupabaseCentralAuthService owns the active authentication path. Supabase
// issues and verifies sessions, while Central SSO resolves the internal user
// and application authorization through auth_user_id and app_memberships.
type SupabaseCentralAuthService struct {
	auth         SupabaseAuthentication
	users        SupabaseAuthUserStore
	applications SupabaseAuthApplicationResolver
	identities   SupabaseAuthIdentityLoader
}

func NewSupabaseCentralAuthService(
	auth SupabaseAuthentication,
	users SupabaseAuthUserStore,
	applications SupabaseAuthApplicationResolver,
	identities SupabaseAuthIdentityLoader,
) *SupabaseCentralAuthService {
	return &SupabaseCentralAuthService{
		auth:         auth,
		users:        users,
		applications: applications,
		identities:   identities,
	}
}

func (s *SupabaseCentralAuthService) Login(
	ctx context.Context,
	email string,
	password string,
	application string,
) (*models.LoginResult, error) {
	email = strings.TrimSpace(email)
	application = strings.ToLower(strings.TrimSpace(application))

	if email == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	if application == "" {
		return nil, ErrUnsupportedApplication
	}

	if !s.available() || s.applications == nil {
		return nil, ErrAuthUnavailable
	}

	session, err := s.auth.SignInWithPassword(ctx, email, password)
	if err != nil {
		return nil, err
	}

	if session == nil ||
		strings.TrimSpace(session.AccessToken) == "" ||
		strings.TrimSpace(session.User.ID) == "" {

		return nil, ErrAuthUnavailable
	}

	user, err := s.resolveUser(ctx, session.User.ID)
	if err != nil {
		s.signOutQuietly(session.AccessToken)
		return nil, err
	}

	appContext, err := s.applications.GetByAppUserID(
		ctx,
		user.ID,
		application,
	)
	if err != nil {
		s.signOutQuietly(session.AccessToken)

		switch {
		case errors.Is(err, ErrApplicationUnavailable):
			return nil, ErrUnsupportedApplication

		case errors.Is(err, ErrApplicationMembershipUnavailable):
			return nil, ErrAccountUnavailable

		default:
			return nil, fmt.Errorf(
				"resolve Supabase login application: %w",
				err,
			)
		}
	}

	if appContext == nil ||
		strings.TrimSpace(appContext.ApplicationID) == "" ||
		strings.TrimSpace(appContext.Role) == "" {

		s.signOutQuietly(session.AccessToken)
		return nil, ErrAccountUnavailable
	}

	if err := membershipLoginStatusError(appContext.Status); err != nil {
		s.signOutQuietly(session.AccessToken)
		return nil, err
	}

	identity, err := s.loadIdentity(ctx, user.ID)
	if err != nil {
		s.signOutQuietly(session.AccessToken)
		return nil, err
	}

	return &models.LoginResult{
		Session:  session,
		Identity: identity,
	}, nil
}

func (s *SupabaseCentralAuthService) Refresh(
	ctx context.Context,
	refreshToken string,
) (*models.LoginResult, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	if !s.available() {
		return nil, ErrAuthUnavailable
	}

	session, err := s.auth.RefreshSession(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	if session == nil || strings.TrimSpace(session.User.ID) == "" {
		return nil, ErrAuthUnavailable
	}

	user, err := s.resolveUser(ctx, session.User.ID)
	if err != nil {
		s.signOutQuietly(session.AccessToken)
		return nil, err
	}

	identity, err := s.loadIdentity(ctx, user.ID)
	if err != nil {
		s.signOutQuietly(session.AccessToken)
		return nil, err
	}

	return &models.LoginResult{
		Session:  session,
		Identity: identity,
	}, nil
}

func (s *SupabaseCentralAuthService) AuthenticateAccessToken(
	ctx context.Context,
	accessToken string,
) (*models.Identity, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, ErrInvalidToken
	}

	if !s.available() {
		return nil, ErrAuthUnavailable
	}

	authUser, err := s.auth.VerifyAccessToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	if authUser == nil || strings.TrimSpace(authUser.ID) == "" {
		return nil, ErrInvalidToken
	}

	user, err := s.resolveUser(ctx, authUser.ID)
	if err != nil {
		return nil, err
	}

	return s.loadIdentity(ctx, user.ID)
}

func (s *SupabaseCentralAuthService) Logout(
	ctx context.Context,
	accessToken string,
) error {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return ErrInvalidToken
	}

	if s.auth == nil {
		return ErrAuthUnavailable
	}

	return s.auth.SignOut(ctx, accessToken)
}

func (s *SupabaseCentralAuthService) ChangePassword(
	ctx context.Context,
	appUserID string,
	email string,
	oldPassword string,
	newPassword string,
) error {
	appUserID = strings.TrimSpace(appUserID)
	email = strings.TrimSpace(email)

	if appUserID == "" || email == "" || oldPassword == "" {
		return ErrInvalidCurrentPassword
	}

	if err := validateCentralPassword(newPassword); err != nil {
		return err
	}

	if oldPassword == newPassword {
		return ErrSamePassword
	}

	if !s.available() {
		return ErrAuthUnavailable
	}

	session, err := s.auth.SignInWithPassword(ctx, email, oldPassword)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return ErrInvalidCurrentPassword
		}

		return err
	}

	if session == nil ||
		strings.TrimSpace(session.AccessToken) == "" ||
		strings.TrimSpace(session.User.ID) == "" {

		return ErrAuthUnavailable
	}

	defer s.signOutQuietly(session.AccessToken)

	user, err := s.resolveUser(ctx, session.User.ID)
	if err != nil {
		if errors.Is(err, ErrAccountUnavailable) {
			return ErrInvalidCurrentPassword
		}

		return err
	}

	if user.ID != appUserID {
		return ErrInvalidCurrentPassword
	}

	return s.auth.UpdatePassword(
		ctx,
		session.AccessToken,
		newPassword,
	)
}

func (s *SupabaseCentralAuthService) available() bool {
	return s.auth != nil && s.users != nil && s.identities != nil
}

func (s *SupabaseCentralAuthService) resolveUser(
	ctx context.Context,
	authUserID string,
) (*models.AppUser, error) {
	authUserID = strings.TrimSpace(authUserID)
	if authUserID == "" {
		return nil, ErrAccountUnavailable
	}

	user, err := s.users.GetByAuthUserID(ctx, authUserID)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve app user by Supabase auth user id: %w",
			err,
		)
	}

	if user == nil || user.DeletedAt != nil ||
		user.AuthUserID == nil ||
		strings.TrimSpace(*user.AuthUserID) != authUserID {

		return nil, ErrAccountUnavailable
	}

	return user, nil
}

func (s *SupabaseCentralAuthService) loadIdentity(
	ctx context.Context,
	appUserID string,
) (*models.Identity, error) {
	identity, err := s.identities.GetByUserID(ctx, appUserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrAccountUnavailable
		}

		return nil, fmt.Errorf("load central identity: %w", err)
	}

	if identity == nil || identity.User == nil {
		return nil, ErrAccountUnavailable
	}

	return identity, nil
}

func (s *SupabaseCentralAuthService) signOutQuietly(accessToken string) {
	if s.auth == nil || strings.TrimSpace(accessToken) == "" {
		return
	}

	_ = s.auth.SignOut(context.Background(), accessToken)
}
