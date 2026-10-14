package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
	ErrUnsupportedApplication       = errors.New("unsupported application")
)

type AuthService struct {
	supabaseAuthService               *SupabaseAuthService
	adminService                      *SupabaseAdminService
	identityService                   *IdentityService
	userRepository                    *repository.UserRepository
	klinikContextService              *KlinikContextService
	applicationContextService         *ApplicationContextService
	klinikMigrationService            *KlinikMigrationService
	klinikPasswordRecoveryRedirectURL string
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
	}
}

// RegisterCentralIdentity creates an Akun Balai only.
//
// It deliberately does not create any application membership. SILAPET,
// Klinik PKP, Arsiparis, and future applications own their own authorization.
func (s *AuthService) RegisterCentralIdentity(
	ctx context.Context,
	email string,
	password string,
	fullName string,
	phone string,
) (*models.Identity, error) {
	email = strings.TrimSpace(email)
	fullName = strings.TrimSpace(fullName)
	phone = strings.TrimSpace(phone)

	if s.adminService == nil {
		return nil, ErrAuthUnavailable
	}

	authUser, err := s.adminService.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	appUserByEmail, err :=
		s.userRepository.GetByEmailIncludingDeleted(ctx, email)
	if err != nil {
		return nil, fmt.Errorf(
			"find central profile by email: %w",
			err,
		)
	}

	if authUser != nil {
		appUserByID, err :=
			s.userRepository.GetByIDIncludingDeleted(
				ctx,
				authUser.ID,
			)
		if err != nil {
			return nil, fmt.Errorf(
				"find central profile by auth id: %w",
				err,
			)
		}

		if appUserByID != nil &&
			appUserByID.DeletedAt == nil &&
			strings.EqualFold(appUserByID.Email, email) {

			return nil, ErrAccountAlreadyExists
		}

		return nil, ErrRegistrationIdentityConflict
	}

	// A profile without its matching Supabase Auth identity is inconsistent.
	// Public registration must never silently relink or repair it.
	if appUserByEmail != nil {
		return nil, ErrRegistrationIdentityConflict
	}

	createdAuthUser, err := s.adminService.CreateUser(
		ctx,
		email,
		password,
		fullName,
	)
	if err != nil {
		// Protect against a create race: if another request created the same
		// Auth identity first, surface the normal account-exists result.
		existing, lookupErr :=
			s.adminService.FindUserByEmail(ctx, email)

		if lookupErr == nil && existing != nil {
			return nil, ErrAccountAlreadyExists
		}

		return nil, err
	}

	if strings.HasPrefix(phone, "0") {
		phone = "62" + phone[1:]
	}

	var phonePtr *string
	if phone != "" {
		phonePtr = &phone
	}

	appUser, err := s.userRepository.CreateCentralUser(
		ctx,
		createdAuthUser.ID,
		createdAuthUser.Email,
		fullName,
		phonePtr,
	)
	if err != nil {
		// Supabase Auth and Postgres cannot participate in one transaction.
		// If profile creation fails, explicitly compensate by deleting the
		// newly-created Auth identity.
		rollbackCtx, cancel :=
			context.WithTimeout(
				context.Background(),
				5*time.Second,
			)
		defer cancel()

		rollbackErr := s.adminService.DeleteUser(
			rollbackCtx,
			createdAuthUser.ID,
		)

		if rollbackErr != nil {
			return nil, fmt.Errorf(
				"create central profile: %v; rollback auth identity: %w",
				err,
				rollbackErr,
			)
		}

		return nil, fmt.Errorf(
			"create central profile: %w",
			err,
		)
	}

	return &models.Identity{
		User:    appUser,
		Pegawai: nil,
	}, nil
}

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
) (*models.LoginResult, error) {
	email = strings.TrimSpace(email)

	session, err := s.supabaseAuthService.SignInWithPassword(
		ctx,
		email,
		password,
	)

	if err != nil {
		// Fallback Klinik hanya boleh dijalankan apabila Supabase
		// benar-benar menolak credential, bukan ketika Supabase
		// sedang unavailable atau rate-limited.
		if !errors.Is(err, ErrInvalidCredentials) {
			return nil, err
		}

		// First-login migration Klinik cukup menggunakan email dan password.
		// NIP bukan credential login dan akan diambil dari database Klinik.
		if s.klinikMigrationService == nil {
			return nil, ErrInvalidCredentials
		}

		_, migrationErr := s.klinikMigrationService.Migrate(
			ctx,
			email,
			password,
		)
		if migrationErr != nil {
			return nil, migrationErr
		}

		// Migration berhasil. Login ulang melalui Supabase supaya
		// token yang dikembalikan tetap token resmi SSO/Supabase.
		session, err = s.supabaseAuthService.SignInWithPassword(
			ctx,
			email,
			password,
		)
		if err != nil {
			return nil, err
		}
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

	var redirectURL string

	switch application {
	case "klinik_pkp":
		redirectURL = s.klinikPasswordRecoveryRedirectURL

	default:
		return ErrUnsupportedApplication
	}

	if strings.TrimSpace(redirectURL) == "" {
		return ErrAuthUnavailable
	}

	if application == "klinik_pkp" {
		eligible, err := s.isKlinikPasswordRecoveryEligible(ctx, email)
		if err != nil {
			return err
		}

		if !eligible {
			// Tetap dianggap berhasil oleh handler untuk mencegah
			// account/application enumeration, tetapi jangan kirim
			// recovery email melalui Supabase.
			return nil
		}
	}

	return s.supabaseAuthService.RequestPasswordRecovery(
		ctx,
		email,
		redirectURL,
	)
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

func (s *AuthService) ResetPassword(
	ctx context.Context,
	accessToken string,
	password string,
) error {
	accessToken = strings.TrimSpace(accessToken)

	if accessToken == "" {
		return ErrInvalidToken
	}

	if len(password) < 8 ||
		len(password) > 128 ||
		strings.TrimSpace(password) == "" {

		return ErrInvalidPassword
	}

	return s.supabaseAuthService.UpdatePassword(
		ctx,
		accessToken,
		password,
	)
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
