package services

import (
	"context"
	"errors"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var (
	ErrAccountPending               = errors.New("account is pending approval")
	ErrAccountRejected              = errors.New("account is rejected")
	ErrAccountDisabled              = errors.New("account is disabled")
	ErrAccountUnavailable           = errors.New("account is unavailable")
	ErrAccountAlreadyExists         = errors.New("central account already exists")
	ErrRegistrationIdentityConflict = errors.New("central identity conflict")
	ErrInvalidRegistrationRequest   = errors.New("invalid central registration request")
	ErrInvalidRecoveryRequest       = errors.New("invalid password recovery request")
	ErrInvalidCurrentPassword       = errors.New("invalid current password")
	ErrUnsupportedApplication       = errors.New("unsupported application")
)

func membershipLoginStatusError(status string) error {
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

type AuthService struct {
	supabaseAuthService          *SupabaseAuthService
	adminService                 *SupabaseAdminService
	identityService              *IdentityService
	userRepository               *repository.UserRepository
	klinikContextService         *KlinikContextService
	applicationContextService    *ApplicationContextService
	klinikMigrationService       *KlinikMigrationService
	applicationEnrollmentService *ApplicationEnrollmentService
	requestAccessService         RequestAccessEnrollment
	activeAuthenticationService  ActiveAuthenticationService
	passwordRecoveryService      PasswordRecoveryService
	registrationService          RegistrationService
	inviteAcceptanceService      InviteAcceptanceService
}

type RequestAccessEnrollment interface {
	Request(
		ctx context.Context,
		email string,
		password string,
		applicationCode string,
	) (*models.ApplicationEnrollmentResult, error)
}

func NewAuthService(
	supabaseAuthService *SupabaseAuthService,
	adminService *SupabaseAdminService,
	identityService *IdentityService,
	userRepository *repository.UserRepository,
	klinikContextService *KlinikContextService,
	applicationContextService *ApplicationContextService,
	klinikMigrationService *KlinikMigrationService,
) *AuthService {
	return &AuthService{
		supabaseAuthService:       supabaseAuthService,
		adminService:              adminService,
		identityService:           identityService,
		userRepository:            userRepository,
		klinikContextService:      klinikContextService,
		applicationContextService: applicationContextService,
		klinikMigrationService:    klinikMigrationService,
	}
}

func (s *AuthService) SetApplicationEnrollmentService(
	service *ApplicationEnrollmentService,
) {
	s.applicationEnrollmentService = service
}

func (s *AuthService) SetRequestAccessService(
	service RequestAccessEnrollment,
) {
	s.requestAccessService = service
}

func (s *AuthService) SetActiveAuthenticationService(
	service ActiveAuthenticationService,
) {
	s.activeAuthenticationService = service
}

func (s *AuthService) SetPasswordRecoveryService(
	service PasswordRecoveryService,
) {
	s.passwordRecoveryService = service
}

func (s *AuthService) SetRegistrationService(
	service RegistrationService,
) {
	s.registrationService = service
}

func (s *AuthService) SetInviteAcceptanceService(
	service InviteAcceptanceService,
) {
	s.inviteAcceptanceService = service
}

// RegisterCentralIdentity creates a Supabase Auth identity together with the
// mapped Central SSO profile and its initial application membership.
func (s *AuthService) RegisterCentralIdentity(
	ctx context.Context,
	email string,
	password string,
	fullName string,
	phone string,
	application string,
) (*models.Identity, error) {
	if s.registrationService == nil {
		return nil, ErrAuthUnavailable
	}

	return s.registrationService.Register(
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
	if s.activeAuthenticationService == nil {
		return nil, ErrAuthUnavailable
	}

	return s.activeAuthenticationService.Login(
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
	if s.passwordRecoveryService == nil {
		return ErrAuthUnavailable
	}

	return s.passwordRecoveryService.Request(
		ctx,
		email,
	)
}

// ChangePassword verifies and updates the authenticated user's Supabase
// credential. Authorization has already been established by RequireAuth.
func (s *AuthService) ChangePassword(
	ctx context.Context,
	appUserID string,
	email string,
	oldPassword string,
	newPassword string,
) error {
	if s.activeAuthenticationService == nil {
		return ErrAuthUnavailable
	}

	return s.activeAuthenticationService.ChangePassword(
		ctx,
		appUserID,
		email,
		oldPassword,
		newPassword,
	)
}

func (s *AuthService) ResetPassword(
	ctx context.Context,
	tokenHash string,
	password string,
) error {
	if s.passwordRecoveryService == nil {
		return ErrAuthUnavailable
	}

	return s.passwordRecoveryService.Reset(
		ctx,
		tokenHash,
		password,
	)
}

func (s *AuthService) AcceptInvite(
	ctx context.Context,
	accessToken string,
	password string,
) error {
	if s.inviteAcceptanceService == nil {
		return ErrAuthUnavailable
	}

	return s.inviteAcceptanceService.Accept(
		ctx,
		accessToken,
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

	result, err := s.applicationEnrollmentService.Request(
		ctx,
		identity.User.ID,
		applicationCode,
	)
	if err != nil {
		return "", err
	}
	if result == nil {
		return "", ErrAuthUnavailable
	}

	return result.Status, nil
}

func (s *AuthService) RequestAccess(
	ctx context.Context,
	email string,
	password string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	if s.requestAccessService == nil {
		return nil, ErrAuthUnavailable
	}

	result, err := s.requestAccessService.Request(
		ctx,
		email,
		password,
		applicationCode,
	)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrAuthUnavailable
	}

	return result, nil
}

func (s *AuthService) Refresh(
	ctx context.Context,
	refreshToken string,
) (*models.LoginResult, error) {
	if s.activeAuthenticationService == nil {
		return nil, ErrAuthUnavailable
	}

	return s.activeAuthenticationService.Refresh(ctx, refreshToken)
}

func (s *AuthService) Logout(
	ctx context.Context,
	accessToken string,
) error {
	if s.activeAuthenticationService == nil {
		return ErrAuthUnavailable
	}

	return s.activeAuthenticationService.Logout(ctx, accessToken)
}

func (s *AuthService) AuthenticateAccessToken(
	ctx context.Context,
	accessToken string,
) (*models.Identity, error) {
	if s.activeAuthenticationService == nil {
		return nil, ErrAuthUnavailable
	}

	return s.activeAuthenticationService.AuthenticateAccessToken(
		ctx,
		accessToken,
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
