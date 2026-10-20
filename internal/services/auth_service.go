package services

import (
	"context"
	"errors"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid access token")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrSamePassword       = errors.New("new password must be different from old password")
	ErrAuthRateLimited    = errors.New("too many authentication attempts")
	ErrAuthUnavailable    = errors.New("authentication service unavailable")

	ErrAccountPending               = errors.New("account is pending approval")
	ErrAccountRejected              = errors.New("account is rejected")
	ErrAccountDisabled              = errors.New("account is disabled")
	ErrAccountUnavailable           = errors.New("account is unavailable")
	ErrApplicationAccessUnavailable = errors.New("application access is unavailable")
	ErrAccountAlreadyExists         = errors.New("central account already exists")
	ErrRegistrationIdentityConflict = errors.New("central identity conflict")
	ErrInvalidRecoveryRequest       = errors.New("invalid password recovery request")
	ErrInvalidCurrentPassword       = errors.New("invalid current password")
	ErrUnsupportedApplication       = errors.New("unsupported application")

	// ErrPasswordSetupRequired means the central identity exists but has no
	// auth_credentials row yet (legacy identity). The user must complete the
	// forgot-password / password-setup flow.
	ErrPasswordSetupRequired = errors.New("password setup required")

	// ErrResetTokenExpired means a recovery token existed and was unused,
	// but its TTL elapsed.
	ErrResetTokenExpired = errors.New("password reset token expired")
)

// AuthService is the facade over the self-hosted Central SSO services.
// It has no dependency on Supabase Auth.
type AuthService struct {
	identityService                *IdentityService
	applicationContextService      *ApplicationContextService
	centralLoginService            *CentralLoginService
	centralRegistrationService     *CentralRegistrationService
	centralSessionService          *SessionService
	centralPasswordChangeService   *CentralPasswordChangeService
	centralPasswordRecoveryService *CentralPasswordRecoveryService
	applicationEnrollmentService   *ApplicationEnrollmentService
}

func NewAuthService(
	identityService *IdentityService,
	applicationContextService *ApplicationContextService,
) *AuthService {
	return &AuthService{
		identityService:           identityService,
		applicationContextService: applicationContextService,
	}
}

func (s *AuthService) SetCentralLoginService(
	service *CentralLoginService,
) {
	s.centralLoginService = service
}

func (s *AuthService) SetCentralRegistrationService(
	service *CentralRegistrationService,
) {
	s.centralRegistrationService = service
}

func (s *AuthService) SetCentralSessionService(
	service *SessionService,
) {
	s.centralSessionService = service
}

func (s *AuthService) SetCentralPasswordChangeService(
	service *CentralPasswordChangeService,
) {
	s.centralPasswordChangeService = service
}

func (s *AuthService) SetCentralPasswordRecoveryService(
	service *CentralPasswordRecoveryService,
) {
	s.centralPasswordRecoveryService = service
}

func (s *AuthService) SetApplicationEnrollmentService(
	service *ApplicationEnrollmentService,
) {
	s.applicationEnrollmentService = service
}

// RegisterCentralIdentity creates a central self-hosted identity
// together with its initial application membership.
//
// It deliberately does not create any application membership. SILAPET,
// Klinik PKP, Arsiparis, and future applications own their own authorization.
func (s *AuthService) RegisterCentralIdentity(
	ctx context.Context,
	email string,
	password string,
	fullName string,
	phone string,
	application string,
) (*models.Identity, error) {
	if s.centralRegistrationService == nil {
		return nil, ErrAuthUnavailable
	}

	return s.centralRegistrationService.Register(
		ctx,
		email,
		password,
		fullName,
		phone,
		application,
	)
}

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
	application string,
) (*models.LoginResult, error) {
	if s.centralLoginService == nil {
		return nil, ErrAuthUnavailable
	}

	return s.centralLoginService.Login(
		ctx,
		email,
		password,
		application,
	)
}

func (s *AuthService) RequestPasswordRecovery(
	ctx context.Context,
	email string,
) error {
	if s.centralPasswordRecoveryService == nil {
		return ErrAuthUnavailable
	}

	return s.centralPasswordRecoveryService.Request(
		ctx,
		email,
	)
}

// ChangePassword changes the authenticated user's central credential.
//
// Authorization has already been established by RequireAuth. Password
// verification and the resulting credential update are owned by Central SSO.
func (s *AuthService) ChangePassword(
	ctx context.Context,
	appUserID string,
	oldPassword string,
	newPassword string,
) error {
	if s.centralPasswordChangeService == nil {
		return ErrAuthUnavailable
	}

	return s.centralPasswordChangeService.Change(
		ctx,
		appUserID,
		oldPassword,
		newPassword,
	)
}

func (s *AuthService) ResetPassword(
	ctx context.Context,
	token string,
	password string,
) error {
	if s.centralPasswordRecoveryService == nil {
		return ErrAuthUnavailable
	}

	return s.centralPasswordRecoveryService.Reset(
		ctx,
		token,
		password,
	)
}

func (s *AuthService) EnrollApplication(
	ctx context.Context,
	accessToken string,
	applicationCode string,
) (string, error) {
	accessToken = strings.TrimSpace(
		accessToken,
	)

	if accessToken == "" {
		return "", ErrInvalidToken
	}

	if s.applicationEnrollmentService == nil {
		return "", ErrAuthUnavailable
	}

	identity, err :=
		s.AuthenticateAccessToken(
			ctx,
			accessToken,
		)
	if err != nil {
		return "", err
	}

	if identity == nil ||
		strings.TrimSpace(
			identity.User.ID,
		) == "" {

		return "", ErrInvalidToken
	}

	return s.applicationEnrollmentService.Request(
		ctx,
		identity.User.ID,
		applicationCode,
	)
}

func (s *AuthService) Refresh(
	ctx context.Context,
	refreshToken string,
) (*models.LoginResult, error) {
	refreshToken = strings.TrimSpace(
		refreshToken,
	)

	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	applicationCode, isCentral :=
		centralRefreshTokenApplication(
			refreshToken,
		)

	// Supabase refresh tokens are no longer an SSO session authority.
	if !isCentral {
		return nil, ErrInvalidToken
	}

	if s.centralSessionService == nil ||
		s.applicationContextService == nil {

		return nil, ErrAuthUnavailable
	}

	centralSession, err :=
		s.centralSessionService.ResolveRefreshToken(
			ctx,
			refreshToken,
		)
	if err != nil {
		if errors.Is(
			err,
			ErrInvalidRefreshToken,
		) {
			return nil, ErrInvalidToken
		}

		return nil, err
	}

	appContext, err :=
		s.applicationContextService.GetByAppUserID(
			ctx,
			centralSession.AppUserID,
			applicationCode,
		)
	if err != nil {
		if errors.Is(
			err,
			ErrApplicationMembershipUnavailable,
		) {
			return nil, ErrAccountUnavailable
		}

		return nil, err
	}

	if appContext == nil {
		return nil, ErrAccountUnavailable
	}

	if err := membershipLoginStatusError(
		appContext.Status,
	); err != nil {
		return nil, err
	}

	tokenSet, _, err :=
		s.centralSessionService.Rotate(
			ctx,
			centralSession,
			refreshToken,
			applicationCode,
			appContext.Role,
		)
	if err != nil {
		if errors.Is(
			err,
			ErrInvalidRefreshToken,
		) {
			return nil, ErrInvalidToken
		}

		return nil, err
	}

	identity, err :=
		s.loadCentralIdentity(
			ctx,
			centralSession.AppUserID,
		)
	if err != nil {
		return nil, err
	}

	return &models.LoginResult{
		Session: &models.SupabaseSession{
			AccessToken:  tokenSet.AccessToken,
			RefreshToken: tokenSet.RefreshToken,
			TokenType:    tokenSet.TokenType,
			ExpiresIn:    tokenSet.ExpiresIn,
			ExpiresAt:    tokenSet.ExpiresAt,
			User: models.SupabaseAuthUser{
				ID:    identity.User.ID,
				Email: identity.User.Email,
			},
		},
		Identity: identity,
	}, nil
}

func (s *AuthService) Logout(
	ctx context.Context,
	accessToken string,
) error {
	accessToken = strings.TrimSpace(
		accessToken,
	)

	if accessToken == "" {
		return ErrInvalidToken
	}

	if s.centralSessionService == nil {
		return ErrAuthUnavailable
	}

	err := s.centralSessionService.RevokeAccessToken(
		ctx,
		accessToken,
	)
	if err != nil {
		if errors.Is(
			err,
			ErrInvalidAccessToken,
		) {
			return ErrInvalidToken
		}

		return err
	}

	return nil
}

func (s *AuthService) AuthenticateAccessToken(
	ctx context.Context,
	accessToken string,
) (*models.Identity, error) {
	accessToken = strings.TrimSpace(
		accessToken,
	)

	if accessToken == "" {
		return nil, ErrInvalidToken
	}

	if s.centralSessionService == nil ||
		s.applicationContextService == nil {

		return nil, ErrAuthUnavailable
	}

	claims, centralSession, err :=
		s.centralSessionService.ValidateAccessToken(
			ctx,
			accessToken,
		)
	if err != nil {
		if errors.Is(
			err,
			ErrInvalidAccessToken,
		) {
			return nil, ErrInvalidToken
		}

		return nil, err
	}

	if claims == nil ||
		centralSession == nil {

		return nil, ErrInvalidToken
	}

	appContext, err :=
		s.applicationContextService.GetByAppUserID(
			ctx,
			centralSession.AppUserID,
			claims.Application(),
		)
	if err != nil {
		if errors.Is(
			err,
			ErrApplicationMembershipUnavailable,
		) {
			return nil, ErrAccountUnavailable
		}

		return nil, err
	}

	if appContext == nil {
		return nil, ErrAccountUnavailable
	}

	if err := membershipLoginStatusError(
		appContext.Status,
	); err != nil {
		return nil, err
	}

	// Authorization changes must take effect immediately.
	// A stale role requires the client to authenticate/refresh again.
	if strings.TrimSpace(
		appContext.Role,
	) != strings.TrimSpace(
		claims.Role,
	) {
		return nil, ErrInvalidToken
	}

	return s.loadCentralIdentity(
		ctx,
		centralSession.AppUserID,
	)
}

// loadCentralIdentity validates only the availability of the central
// identity. Application-specific authorization is resolved separately
// through app_memberships.
func (s *AuthService) loadCentralIdentity(
	ctx context.Context,
	userID string,
) (*models.Identity, error) {
	identity, err := s.identityService.GetByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrAccountUnavailable
		}

		return nil, err
	}

	if identity == nil || identity.User == nil {
		return nil, ErrAccountUnavailable
	}

	return identity, nil
}
