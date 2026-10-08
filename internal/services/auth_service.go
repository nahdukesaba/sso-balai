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

	identity, err := s.loadApprovedIdentity(ctx, session.User.ID)
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

		return nil, fmt.Errorf("load authenticated user identity: %w", err)
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
