package services

import (
	"context"
	"errors"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type BrowserSSOMagicLinkAdmin interface {
	GenerateMagicLinkToken(context.Context, string) (string, error)
}

type BrowserSSOMagicLinkAuth interface {
	VerifyMagicLinkToken(context.Context, string) (*models.SupabaseSession, error)
}

type SupabaseBrowserSSOSessionIssuer struct {
	admin BrowserSSOMagicLinkAdmin
	auth  BrowserSSOMagicLinkAuth
}

func NewSupabaseBrowserSSOSessionIssuer(
	admin BrowserSSOMagicLinkAdmin,
	auth BrowserSSOMagicLinkAuth,
) (*SupabaseBrowserSSOSessionIssuer, error) {
	if admin == nil || auth == nil {
		return nil, errors.New("browser SSO session issuer dependencies are required")
	}
	return &SupabaseBrowserSSOSessionIssuer{admin: admin, auth: auth}, nil
}

func (s *SupabaseBrowserSSOSessionIssuer) IssueSession(
	ctx context.Context,
	email string,
) (*models.SupabaseSession, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, ErrInvalidCredentials
	}
	tokenHash, err := s.admin.GenerateMagicLinkToken(ctx, email)
	if err != nil {
		return nil, err
	}
	session, err := s.auth.VerifyMagicLinkToken(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if session == nil || session.AccessToken == "" || session.RefreshToken == "" ||
		session.User.ID == "" || !strings.EqualFold(strings.TrimSpace(session.User.Email), email) {
		return nil, ErrAuthUnavailable
	}
	return session, nil
}
