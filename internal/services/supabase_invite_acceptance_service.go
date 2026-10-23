package services

import (
	"context"
	"errors"
	"strings"
)

type SupabaseInviteAcceptanceAuth interface {
	UpdatePassword(
		ctx context.Context,
		accessToken string,
		password string,
	) error
}

type InviteAcceptanceService interface {
	Accept(
		ctx context.Context,
		accessToken string,
		password string,
	) error
}

// SupabaseInviteAcceptanceService uses the authenticated invitation session
// to set the user's initial Supabase password. It never persists credentials
// in Central SSO.
type SupabaseInviteAcceptanceService struct {
	auth SupabaseInviteAcceptanceAuth
}

func NewSupabaseInviteAcceptanceService(
	auth SupabaseInviteAcceptanceAuth,
) (*SupabaseInviteAcceptanceService, error) {
	if auth == nil {
		return nil, errors.New("Supabase invite acceptance auth is required")
	}

	return &SupabaseInviteAcceptanceService{auth: auth}, nil
}

func (s *SupabaseInviteAcceptanceService) Accept(
	ctx context.Context,
	accessToken string,
	password string,
) error {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return ErrInvalidToken
	}

	if err := validateCentralPassword(password); err != nil {
		return err
	}

	if s == nil || s.auth == nil {
		return ErrAuthUnavailable
	}

	return s.auth.UpdatePassword(ctx, accessToken, password)
}
