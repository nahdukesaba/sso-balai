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
	application string,
) error {
	email = strings.TrimSpace(email)
	application = strings.TrimSpace(application)

	if email == "" {
		return ErrInvalidRecoveryRequest
	}

	var (
		redirectURL string
		eligible    bool
		err         error
	)

	switch application {
	case models.ApplicationCodeKlinikPKP:
		redirectURL = s.klinikPasswordRecoveryRedirectURL
		eligible, err = s.isKlinikPasswordRecoveryEligible(
			ctx,
			email,
		)

	case models.ApplicationCodeSilapet:
		redirectURL = s.silapetPasswordRecoveryRedirectURL
		eligible, err = s.isSilapetPasswordRecoveryEligible(
			ctx,
			email,
		)

	default:
		return ErrUnsupportedApplication
	}

	if err != nil {
		return err
	}

	// Keep configuration failures independent of account eligibility so the
	// public endpoint cannot disclose whether an email has app access.
	if strings.TrimSpace(redirectURL) == "" {
		return ErrAuthUnavailable
	}

	if !eligible {
		// Deliberately return success to the public handler without asking
		// Supabase to send recovery email.
		return nil
	}

	return s.supabaseAuthService.RequestPasswordRecovery(
		ctx,
		email,
		redirectURL,
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

// ChangePassword changes the password of the authenticated Akun Balai.
//
// The current password is independently verified first. The verification
// session is discarded and the caller's existing bearer token performs the
// actual password update.
func (s *AuthService) ChangePassword(
	ctx context.Context,
	accessToken string,
	email string,
	oldPassword string,
	newPassword string,
) error {
	accessToken = strings.TrimSpace(accessToken)
	email = strings.TrimSpace(email)

	if accessToken == "" {
		return ErrInvalidToken
	}

	if email == "" || oldPassword == "" {
		return ErrInvalidCurrentPassword
	}

	if len(newPassword) < 8 ||
		len(newPassword) > 128 ||
		strings.TrimSpace(newPassword) == "" {

		return ErrInvalidPassword
	}

	verificationSession, err :=
		s.supabaseAuthService.SignInWithPassword(
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

	// Password verification creates its own Supabase session. It is not
	// returned to the application, so revoke it best-effort.
	if verificationSession != nil &&
		strings.TrimSpace(verificationSession.AccessToken) != "" {

		_ = s.supabaseAuthService.SignOut(
			ctx,
			verificationSession.AccessToken,
		)
	}

	return s.supabaseAuthService.UpdatePassword(
		ctx,
		accessToken,
		newPassword,
	)
}

func (s *AuthService) ResetPassword(
	ctx context.Context,
	tokenHash string,
	password string,
) error {
	tokenHash = strings.TrimSpace(tokenHash)

	if tokenHash == "" {
		return ErrInvalidToken
	}

	if len(password) < 8 ||
		len(password) > 128 ||
		strings.TrimSpace(password) == "" {

		return ErrInvalidPassword
	}

	recoverySession, err :=
		s.supabaseAuthService.VerifyPasswordRecoveryToken(
			ctx,
			tokenHash,
		)
	if err != nil {
		return err
	}

	if recoverySession == nil ||
		strings.TrimSpace(recoverySession.AccessToken) == "" ||
		strings.TrimSpace(recoverySession.User.ID) == "" {

		return ErrInvalidToken
	}

	// A valid Supabase recovery identity must still belong to an available
	// central Akun Balai identity.
	if _, err := s.loadCentralIdentity(
		ctx,
		recoverySession.User.ID,
	); err != nil {
		if errors.Is(err, ErrAccountUnavailable) {
			return ErrInvalidToken
		}

		return err
	}

	if err := s.supabaseAuthService.UpdatePassword(
		ctx,
		recoverySession.AccessToken,
		password,
	); err != nil {
		return err
	}

	// The recovery access token never leaves Central SSO. Revoke the
	// recovery session best-effort after a successful password update.
	_ = s.supabaseAuthService.SignOut(
		ctx,
		recoverySession.AccessToken,
	)

	return nil
}

func (s *AuthService) Refresh(
	ctx context.Context,
	refreshToken string,
) (*models.LoginResult, error) {
	refreshToken = strings.TrimSpace(refreshToken)

	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	session, err := s.supabaseAuthService.RefreshSession(
		ctx,
		refreshToken,
	)
	if err != nil {
		return nil, err
	}

	identity, err := s.loadCentralIdentity(
		ctx,
		session.User.ID,
	)
	if err != nil {
		return nil, err
	}

	return &models.LoginResult{
		Session:  session,
		Identity: identity,
	}, nil
}

func (s *AuthService) Logout(
	ctx context.Context,
	accessToken string,
) error {
	accessToken = strings.TrimSpace(accessToken)

	if accessToken == "" {
		return ErrInvalidToken
	}

	return s.supabaseAuthService.SignOut(
		ctx,
		accessToken,
	)
}

func (s *AuthService) AuthenticateAccessToken(
	ctx context.Context,
	accessToken string,
) (*models.Identity, error) {
	authUser, err := s.supabaseAuthService.VerifyAccessToken(
		ctx,
		accessToken,
	)
	if err != nil {
		return nil, err
	}

	return s.loadCentralIdentity(ctx, authUser.ID)
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
