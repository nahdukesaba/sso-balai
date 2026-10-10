package services

import (
	"context"
	"errors"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrAccountPending     = errors.New("account is pending approval")
	ErrAccountRejected    = errors.New("account is rejected")
	ErrAccountUnavailable = errors.New("account is unavailable")
)

type AuthService struct {
	supabaseAuthService    *SupabaseAuthService
	identityService        *IdentityService
	klinikMigrationService *KlinikMigrationService
}

func NewAuthService(
	supabaseAuthService *SupabaseAuthService,
	identityService *IdentityService,
	klinikMigrationService *KlinikMigrationService,
) *AuthService {
	return &AuthService{
		supabaseAuthService:    supabaseAuthService,
		identityService:        identityService,
		klinikMigrationService: klinikMigrationService,
	}
}

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
	nip string,
) (*models.LoginResult, error) {
	email = strings.TrimSpace(email)
	nip = strings.TrimSpace(nip)

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

		// NIP bersifat opsional untuk user SSO/SILAPET existing,
		// tetapi wajib untuk first-login migration user Klinik.
		if nip == "" || s.klinikMigrationService == nil {
			return nil, ErrInvalidCredentials
		}

		_, migrationErr := s.klinikMigrationService.Migrate(
			ctx,
			email,
			nip,
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

	identity, err := s.loadApprovedIdentity(
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

	return s.loadApprovedIdentity(ctx, authUser.ID)
}

func (s *AuthService) loadApprovedIdentity(
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

	switch identity.User.Status {
	case models.UserStatusApproved:
		return identity, nil

	case models.UserStatusPending:
		return nil, ErrAccountPending

	case models.UserStatusRejected:
		return nil, ErrAccountRejected

	default:
		return nil, ErrAccountUnavailable
	}
}
