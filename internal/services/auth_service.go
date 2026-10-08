package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrAccountPending     = errors.New("account is pending approval")
	ErrAccountRejected    = errors.New("account has been rejected")
	ErrAccountUnavailable = errors.New("account is unavailable")
)

type AuthService struct {
	supabaseAuthService *SupabaseAuthService
	identityService     *IdentityService
}

func NewAuthService(
	supabaseAuthService *SupabaseAuthService,
	identityService *IdentityService,
) *AuthService {
	return &AuthService{
		supabaseAuthService: supabaseAuthService,
		identityService:     identityService,
	}
}

func (s *AuthService) Login(
	ctx context.Context,
	email string,
	password string,
) (*models.LoginResult, error) {
	session, err := s.supabaseAuthService.SignInWithPassword(
		ctx,
		email,
		password,
	)
	if err != nil {
		return nil, err
	}

	identity, err := s.identityService.GetByUserID(
		ctx,
		session.User.ID,
	)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrAccountUnavailable
		}

		return nil, fmt.Errorf("load authenticated user identity: %w", err)
	}

	switch identity.User.Status {
	case models.UserStatusApproved:
		// User is allowed to continue.

	case models.UserStatusPending:
		return nil, ErrAccountPending

	case models.UserStatusRejected:
		return nil, ErrAccountRejected

	default:
		return nil, ErrAccountUnavailable
	}

	return &models.LoginResult{
		Session:  session,
		Identity: identity,
	}, nil
}
