package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

const (
	passwordRecoveryTokenBytes = 32
	passwordRecoveryTokenTTL   = 30 * time.Minute
)

type CentralPasswordResetStore interface {
	FindActiveUserByEmail(
		ctx context.Context,
		email string,
	) (
		appUserID string,
		normalizedEmail string,
		found bool,
		err error,
	)

	InvalidateUnusedByUser(
		ctx context.Context,
		appUserID string,
	) error

	Create(
		ctx context.Context,
		appUserID string,
		tokenHash string,
		expiresAt time.Time,
	) error

	InvalidateHash(
		ctx context.Context,
		tokenHash string,
	) error

	ConsumeValidByHash(
		ctx context.Context,
		tokenHash string,
	) (string, error)

	RestoreClaimedHash(
		ctx context.Context,
		tokenHash string,
	) error
}

type CentralPasswordRecoveryCredentials interface {
	ReplacePassword(
		ctx context.Context,
		appUserID string,
		newPassword string,
	) (*models.AuthCredential, error)

	CreateCredential(
		ctx context.Context,
		appUserID string,
		password string,
		mustChangePassword bool,
	) (*models.AuthCredential, error)
}

type CentralPasswordRecoverySessionRevoker interface {
	RevokeAllByAppUserID(
		ctx context.Context,
		appUserID string,
	) error
}

type CentralPasswordRecoveryService struct {
	tokens    CentralPasswordResetStore
	creds     CentralPasswordRecoveryCredentials
	sessions  CentralPasswordRecoverySessionRevoker
	mailer    PasswordRecoveryMailer
	publicURL string
}

func NewCentralPasswordRecoveryService(
	tokens CentralPasswordResetStore,
	creds CentralPasswordRecoveryCredentials,
	sessions CentralPasswordRecoverySessionRevoker,
	mailer PasswordRecoveryMailer,
	publicURL string,
) (*CentralPasswordRecoveryService, error) {
	publicURL = strings.TrimRight(
		strings.TrimSpace(publicURL),
		"/",
	)

	if tokens == nil ||
		creds == nil ||
		sessions == nil ||
		mailer == nil ||
		publicURL == "" {

		return nil, errors.New(
			"central password recovery dependencies are required",
		)
	}

	parsed, err := url.Parse(publicURL)
	if err != nil ||
		parsed.Scheme == "" ||
		parsed.Host == "" {

		return nil, errors.New(
			"SSO_PUBLIC_URL must be a valid absolute URL",
		)
	}

	return &CentralPasswordRecoveryService{
		tokens:    tokens,
		creds:     creds,
		sessions:  sessions,
		mailer:    mailer,
		publicURL: publicURL,
	}, nil
}

func generatePasswordRecoveryToken() (
	raw string,
	hash string,
	err error,
) {
	buffer := make(
		[]byte,
		passwordRecoveryTokenBytes,
	)

	if _, err := rand.Read(buffer); err != nil {
		return "", "", fmt.Errorf(
			"generate password recovery token: %w",
			err,
		)
	}

	raw = base64.RawURLEncoding.EncodeToString(
		buffer,
	)

	digest := sha256.Sum256(
		[]byte(raw),
	)

	hash = hex.EncodeToString(
		digest[:],
	)

	return raw, hash, nil
}

func hashPasswordRecoveryToken(
	raw string,
) string {
	digest := sha256.Sum256(
		[]byte(strings.TrimSpace(raw)),
	)

	return hex.EncodeToString(
		digest[:],
	)
}

func (s *CentralPasswordRecoveryService) Request(
	ctx context.Context,
	email string,
) error {
	email = strings.ToLower(
		strings.TrimSpace(email),
	)

	if email == "" {
		return ErrInvalidRecoveryRequest
	}

	appUserID, normalizedEmail, found, err :=
		s.tokens.FindActiveUserByEmail(
			ctx,
			email,
		)
	if err != nil {
		return err
	}

	// Enumeration protection:
	// nonexistent/deleted identities receive the same public response.
	if !found {
		return nil
	}

	if err := s.tokens.InvalidateUnusedByUser(
		ctx,
		appUserID,
	); err != nil {
		return err
	}

	rawToken, tokenHash, err :=
		generatePasswordRecoveryToken()
	if err != nil {
		return err
	}

	if err := s.tokens.Create(
		ctx,
		appUserID,
		tokenHash,
		time.Now().Add(
			passwordRecoveryTokenTTL,
		),
	); err != nil {
		return err
	}

	resetURL :=
		s.publicURL +
			"/reset-password?token=" +
			url.QueryEscape(rawToken)

	if err := s.mailer.SendPasswordReset(
		ctx,
		normalizedEmail,
		resetURL,
	); err != nil {
		// Never disclose account existence through a different
		// HTTP response. Burn the undelivered token and log only
		// the transport error, never the email or raw token.
		_ = s.tokens.InvalidateHash(
			context.Background(),
			tokenHash,
		)

		log.Printf(
			"central password recovery delivery failed: %v",
			err,
		)

		return nil
	}

	return nil
}

func (s *CentralPasswordRecoveryService) Reset(
	ctx context.Context,
	rawToken string,
	newPassword string,
) error {
	rawToken = strings.TrimSpace(rawToken)

	if rawToken == "" {
		return ErrInvalidToken
	}

	if err := validateCentralPassword(
		newPassword,
	); err != nil {
		return err
	}

	tokenHash := hashPasswordRecoveryToken(
		rawToken,
	)

	// Claim the token atomically first so the same recovery token cannot
	// be used concurrently. If the reset cannot be completed, restore the
	// claim while the token is still within its TTL.
	appUserID, err :=
		s.tokens.ConsumeValidByHash(
			ctx,
			tokenHash,
		)
	if err != nil {
		if errors.Is(
			err,
			repository.ErrPasswordResetTokenExpired,
		) {
			return ErrResetTokenExpired
		}

		if errors.Is(
			err,
			repository.ErrPasswordResetTokenNotFound,
		) {
			return ErrInvalidToken
		}

		return err
	}

	restoreToken := true

	defer func() {
		if restoreToken {
			_ = s.tokens.RestoreClaimedHash(
				context.Background(),
				tokenHash,
			)
		}
	}()

	// Revoke existing self-hosted sessions before changing the password.
	// If credential persistence fails afterwards, the token is restored
	// and the user can safely retry; revoked sessions remain revoked.
	if err := s.sessions.RevokeAllByAppUserID(
		ctx,
		appUserID,
	); err != nil {
		return err
	}

	_, err = s.creds.ReplacePassword(
		ctx,
		appUserID,
		newPassword,
	)

	if errors.Is(err, ErrCredentialNotFound) {
		_, err = s.creds.CreateCredential(
			ctx,
			appUserID,
			newPassword,
			false,
		)
	}

	if err != nil {
		return err
	}

	// Success: leave used_at populated permanently.
	restoreToken = false

	return nil
}
