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

	GetByEmailIncludingDeleted(
		ctx context.Context,
		email string,
	) (*models.AppUser, error)

	GetByIDIncludingDeleted(
		ctx context.Context,
		appUserID string,
	) (*models.AppUser, error)

	LinkAuthUserIDIfUnset(
		ctx context.Context,
		appUserID string,
		authUserID string,
	) (bool, error)
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

type LegacyPasswordVerifier interface {
	VerifyUserPassword(
		ctx context.Context,
		appUserID string,
		password string,
	) (*models.AuthCredential, error)
}

type LegacyMigrationAdmin interface {
	FindUserByEmail(
		ctx context.Context,
		email string,
	) (*models.SupabaseAuthUser, error)

	CreateUser(
		ctx context.Context,
		email string,
		password string,
		fullName string,
	) (*models.SupabaseAuthUser, error)

	DeleteUser(
		ctx context.Context,
		userID string,
	) error
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
	credentials  LegacyPasswordVerifier
	admin        LegacyMigrationAdmin
}

func NewSupabaseCentralAuthService(
	auth SupabaseAuthentication,
	users SupabaseAuthUserStore,
	applications SupabaseAuthApplicationResolver,
	identities SupabaseAuthIdentityLoader,
	credentials LegacyPasswordVerifier,
	admin LegacyMigrationAdmin,
) *SupabaseCentralAuthService {
	return &SupabaseCentralAuthService{
		auth:         auth,
		users:        users,
		applications: applications,
		identities:   identities,
		credentials:  credentials,
		admin:        admin,
	}
}

func (s *SupabaseCentralAuthService) Login(
	ctx context.Context,
	email string,
	password string,
	application string,
) (*models.LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
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

	user, err := s.users.GetByEmailIncludingDeleted(ctx, email)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve login identity by email: %w",
			err,
		)
	}

	if user == nil || !strings.EqualFold(
		strings.TrimSpace(user.Email),
		email,
	) {
		return nil, ErrInvalidCredentials
	}

	if user.DeletedAt != nil {
		return nil, ErrAccountUnavailable
	}

	// A mapped user always authenticates directly through Supabase. Never
	// fall back to the retained legacy credential after mapping exists.
	if user.AuthUserID != nil {
		return s.signInAndComplete(
			ctx,
			email,
			password,
			application,
		)
	}

	return s.migrateLegacyAndSignIn(
		ctx,
		user,
		password,
		application,
	)
}

func (s *SupabaseCentralAuthService) signInAndComplete(
	ctx context.Context,
	email string,
	password string,
	application string,
) (*models.LoginResult, error) {
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

func (s *SupabaseCentralAuthService) migrateLegacyAndSignIn(
	ctx context.Context,
	user *models.AppUser,
	password string,
	application string,
) (*models.LoginResult, error) {
	if s.credentials == nil || s.admin == nil {
		return nil, ErrAuthUnavailable
	}

	if err := legacyUserStatusError(user.Status); err != nil {
		return nil, err
	}

	appContext, err := s.resolveLoginApplication(
		ctx,
		user.ID,
		application,
	)
	if err != nil {
		return nil, err
	}

	if err := membershipLoginStatusError(appContext.Status); err != nil {
		return nil, err
	}

	_, err = s.credentials.VerifyUserPassword(
		ctx,
		user.ID,
		password,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) ||
			errors.Is(err, ErrCredentialNotFound) {

			return nil, ErrInvalidCredentials
		}

		return nil, fmt.Errorf("verify legacy credential: %w", err)
	}

	authUserID, err := s.ensureLegacyAuthIdentity(
		ctx,
		user,
		password,
	)
	if err != nil {
		return nil, err
	}

	// Resolve the committed mapping before signing in. This also prevents a
	// concurrent request from substituting a different auth identity.
	currentUser, err := s.users.GetByIDIncludingDeleted(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve migrated login identity: %w",
			err,
		)
	}

	if !isLinkedToAuthUser(currentUser, authUserID) {
		return nil, ErrAuthUnavailable
	}

	return s.signInAndComplete(
		ctx,
		user.Email,
		password,
		application,
	)
}

func (s *SupabaseCentralAuthService) resolveLoginApplication(
	ctx context.Context,
	appUserID string,
	application string,
) (*models.ApplicationContext, error) {
	appContext, err := s.applications.GetByAppUserID(
		ctx,
		appUserID,
		application,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrApplicationUnavailable):
			return nil, ErrUnsupportedApplication

		case errors.Is(err, ErrApplicationMembershipUnavailable):
			return nil, ErrAccountUnavailable

		default:
			return nil, fmt.Errorf(
				"resolve login application: %w",
				err,
			)
		}
	}

	if appContext == nil ||
		strings.TrimSpace(appContext.ApplicationID) == "" ||
		strings.TrimSpace(appContext.Role) == "" {

		return nil, ErrAccountUnavailable
	}

	return appContext, nil
}

func (s *SupabaseCentralAuthService) ensureLegacyAuthIdentity(
	ctx context.Context,
	user *models.AppUser,
	password string,
) (string, error) {
	authUser, err := s.admin.FindUserByEmail(ctx, user.Email)
	if err != nil {
		return "", fmt.Errorf(
			"%w: find legacy migration auth user: %v",
			ErrAuthUnavailable,
			err,
		)
	}

	createdByRequest := false
	if authUser == nil {
		authUser, err = s.admin.CreateUser(
			ctx,
			user.Email,
			password,
			user.FullName,
		)
		if err != nil {
			// A concurrent request may have created the same unique email after
			// the initial lookup. Resolve it before treating create as failed.
			authUser, _ = s.admin.FindUserByEmail(ctx, user.Email)
			if authUser == nil {
				return "", fmt.Errorf(
					"%w: create legacy migration auth user: %v",
					ErrAuthUnavailable,
					err,
				)
			}
		} else {
			createdByRequest = true
		}
	}

	if authUser == nil || strings.TrimSpace(authUser.ID) == "" {
		return "", ErrAuthUnavailable
	}

	authUserID := strings.TrimSpace(authUser.ID)
	if !createdByRequest {
		if err := s.verifyExistingMigrationIdentity(
			ctx,
			user.Email,
			password,
			authUserID,
		); err != nil {

			return "", err
		}
	}

	linked, linkErr := s.users.LinkAuthUserIDIfUnset(
		ctx,
		user.ID,
		authUserID,
	)
	if linked && linkErr == nil {
		return authUserID, nil
	}

	currentUser, resolveErr := s.users.GetByIDIncludingDeleted(
		ctx,
		user.ID,
	)
	if resolveErr == nil && isLinkedToAuthUser(currentUser, authUserID) {
		return authUserID, nil
	}

	if createdByRequest {
		if deleteErr := s.admin.DeleteUser(
			context.Background(),
			authUserID,
		); deleteErr != nil {

			return "", fmt.Errorf(
				"%w: legacy migration compensation failed: %v",
				ErrAuthUnavailable,
				deleteErr,
			)
		}
	}

	if linkErr != nil {
		return "", fmt.Errorf(
			"%w: link legacy auth identity: %v",
			ErrAuthUnavailable,
			linkErr,
		)
	}

	if resolveErr != nil {
		return "", fmt.Errorf(
			"%w: resolve concurrent legacy mapping: %v",
			ErrAuthUnavailable,
			resolveErr,
		)
	}

	return "", ErrAuthUnavailable
}

func (s *SupabaseCentralAuthService) verifyExistingMigrationIdentity(
	ctx context.Context,
	email string,
	password string,
	expectedAuthUserID string,
) error {
	session, err := s.auth.SignInWithPassword(ctx, email, password)
	if err != nil {
		return fmt.Errorf(
			"%w: existing Supabase identity does not match legacy credential",
			ErrAuthUnavailable,
		)
	}

	if session == nil ||
		strings.TrimSpace(session.AccessToken) == "" ||
		strings.TrimSpace(session.User.ID) != expectedAuthUserID {

		return ErrAuthUnavailable
	}

	s.signOutQuietly(session.AccessToken)

	return nil
}

func legacyUserStatusError(status string) error {
	switch status {
	case models.UserStatusApproved:
		return nil

	case models.UserStatusPending:
		return ErrAccountPending

	case models.UserStatusRejected:
		return ErrAccountRejected

	default:
		return ErrAccountUnavailable
	}
}

func isLinkedToAuthUser(
	user *models.AppUser,
	authUserID string,
) bool {
	return user != nil &&
		user.DeletedAt == nil &&
		user.AuthUserID != nil &&
		strings.TrimSpace(*user.AuthUserID) ==
			strings.TrimSpace(authUserID)
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
