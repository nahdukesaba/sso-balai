package services

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type SupabasePasswordRecoveryAuth interface {
	RequestPasswordRecovery(
		ctx context.Context,
		email string,
		redirectURL string,
	) error

	VerifyPasswordRecoveryToken(
		ctx context.Context,
		tokenHash string,
	) (*models.SupabaseSession, error)

	UpdatePassword(
		ctx context.Context,
		accessToken string,
		password string,
	) error
}

type PasswordRecoveryService interface {
	Request(
		ctx context.Context,
		email string,
	) error

	Reset(
		ctx context.Context,
		tokenHash string,
		password string,
	) error
}

// SupabasePasswordRecoveryService keeps Central SSO as the HTTP facade while
// delegating recovery tokens, recovery sessions, and passwords to Supabase.
type SupabasePasswordRecoveryService struct {
	auth        SupabasePasswordRecoveryAuth
	redirectURL string
}

func NewSupabasePasswordRecoveryService(
	auth SupabasePasswordRecoveryAuth,
	redirectURL string,
) (*SupabasePasswordRecoveryService, error) {
	redirectURL = strings.TrimSpace(redirectURL)
	if auth == nil {
		return nil, errors.New("Supabase password recovery auth is required")
	}

	parsedURL, err := url.ParseRequestURI(redirectURL)
	if err != nil || parsedURL.Host == "" ||
		(parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {

		return nil, errors.New(
			"PASSWORD_RECOVERY_REDIRECT_URL must be an absolute HTTP(S) URL",
		)
	}

	return &SupabasePasswordRecoveryService{
		auth:        auth,
		redirectURL: redirectURL,
	}, nil
}

func (s *SupabasePasswordRecoveryService) Request(
	ctx context.Context,
	email string,
) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ErrInvalidRecoveryRequest
	}

	if s == nil || s.auth == nil || s.redirectURL == "" {
		return ErrAuthUnavailable
	}

	return s.auth.RequestPasswordRecovery(
		ctx,
		email,
		s.redirectURL,
	)
}

func (s *SupabasePasswordRecoveryService) Reset(
	ctx context.Context,
	tokenHash string,
	password string,
) error {
	tokenHash = strings.TrimSpace(tokenHash)
	if tokenHash == "" {
		return ErrInvalidToken
	}

	if s == nil || s.auth == nil {
		return ErrAuthUnavailable
	}

	session, err := s.auth.VerifyPasswordRecoveryToken(ctx, tokenHash)
	if err != nil {
		return err
	}

	if session == nil || strings.TrimSpace(session.AccessToken) == "" {
		return ErrInvalidToken
	}

	return s.auth.UpdatePassword(
		ctx,
		session.AccessToken,
		password,
	)
}
