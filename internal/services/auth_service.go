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
	ErrAccountUnavailable           = errors.New("account is unavailable")
	ErrAccountAlreadyExists         = errors.New("central account already exists")
	ErrRegistrationIdentityConflict = errors.New("central identity conflict")
	ErrInvalidRecoveryRequest       = errors.New("invalid password recovery request")
	ErrInvalidCurrentPassword       = errors.New("invalid current password")
	ErrUnsupportedApplication       = errors.New("unsupported application")
)

type AuthService struct {
	supabaseAuthService                *SupabaseAuthService
	adminService                       *SupabaseAdminService
	identityService                    *IdentityService
	userRepository                     *repository.UserRepository
	klinikContextService               *KlinikContextService
	applicationContextService          *ApplicationContextService
	klinikMigrationService             *KlinikMigrationService
	centralLoginService                *CentralLoginService
	centralRegistrationService         *CentralRegistrationService
	centralSessionService              *SessionService
	centralPasswordChangeService       *CentralPasswordChangeService
	centralPasswordRecoveryService     *CentralPasswordRecoveryService
	applicationEnrollmentService       *ApplicationEnrollmentService
	activeAuthenticationService        ActiveAuthenticationService
	klinikPasswordRecoveryRedirectURL  string
	silapetPasswordRecoveryRedirectURL string
}

func NewAuthService(
	supabaseAuthService *SupabaseAuthService,
	adminService *SupabaseAdminService,
	identityService *IdentityService,
	userRepository *repository.UserRepository,
	klinikContextService *KlinikContextService,
	applicationContextService *ApplicationContextService,
	klinikMigrationService *KlinikMigrationService,
	klinikPasswordRecoveryRedirectURL string,
	silapetPasswordRecoveryRedirectURL string,
) *AuthService {
	return &AuthService{
		supabaseAuthService:       supabaseAuthService,
		adminService:              adminService,
		identityService:           identityService,
		userRepository:            userRepository,
		klinikContextService:      klinikContextService,
		applicationContextService: applicationContextService,
		klinikMigrationService:    klinikMigrationService,
		klinikPasswordRecoveryRedirectURL: strings.TrimSpace(
			klinikPasswordRecoveryRedirectURL,
		),
		silapetPasswordRecoveryRedirectURL: strings.TrimSpace(
			silapetPasswordRecoveryRedirectURL,
		),
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

func (s *AuthService) SetActiveAuthenticationService(
	service ActiveAuthenticationService,
) {
	s.activeAuthenticationService = service
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
	if s.centralPasswordRecoveryService == nil {
		return ErrAuthUnavailable
	}

	return s.centralPasswordRecoveryService.Request(
		ctx,
		email,
	)
}

func (s *AuthService) isSilapetPasswordRecoveryEligible(
	ctx context.Context,
	email string,
) (bool, error) {
	if s.userRepository == nil ||
		s.applicationContextService == nil {

		return false, ErrAuthUnavailable
	}

	user, err := s.userRepository.GetByEmailIncludingDeleted(
		ctx,
		email,
	)
	if err != nil {
		return false, err
	}

	if user == nil || user.DeletedAt != nil {
		return false, nil
	}

	appContext, err := s.applicationContextService.GetByAppUserID(
		ctx,
		user.ID,
		models.ApplicationCodeSilapet,
	)
	if err != nil {
		if errors.Is(err, ErrApplicationUnavailable) ||
			errors.Is(err, ErrApplicationMembershipUnavailable) {

			return false, nil
		}

		return false, err
	}

	return appContext.Status == models.MembershipStatusApproved, nil
}

func (s *AuthService) isKlinikPasswordRecoveryEligible(
	ctx context.Context,
	email string,
) (bool, error) {
	if s.userRepository == nil ||
		s.klinikContextService == nil ||
		s.applicationContextService == nil {

		return false, ErrAuthUnavailable
	}

	user, err := s.userRepository.GetByEmailIncludingDeleted(ctx, email)
	if err != nil {
		return false, err
	}

	if user == nil || user.DeletedAt != nil {
		return false, nil
	}

	appContext, err := s.applicationContextService.GetByAppUserID(
		ctx,
		user.ID,
		models.ApplicationCodeKlinikPKP,
	)
	if err != nil {
		if errors.Is(err, ErrApplicationUnavailable) ||
			errors.Is(err, ErrApplicationMembershipUnavailable) {

			return false, nil
		}

		return false, err
	}

	if appContext.Status != models.MembershipStatusApproved {
		return false, nil
	}

	_, err = s.klinikContextService.GetByAppUserID(ctx, user.ID)
	if err != nil {
		if errors.Is(err, ErrKlinikAccountUnavailable) {
			return false, nil
		}

		return false, err
	}

	return true, nil
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
