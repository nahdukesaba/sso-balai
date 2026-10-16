package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrInvalidRefreshToken = errors.New(
		"invalid refresh token",
	)

	ErrSessionUnavailable = errors.New(
		"auth session unavailable",
	)
)

const refreshTokenByteLength = 32

type SessionStore interface {
	Create(
		ctx context.Context,
		appUserID string,
		applicationID string,
		refreshTokenHash string,
		expiresAt time.Time,
	) (*models.AuthSession, error)

	GetByID(
		ctx context.Context,
		id string,
	) (*models.AuthSession, error)

	GetByRefreshTokenHash(
		ctx context.Context,
		refreshTokenHash string,
	) (*models.AuthSession, error)

	RotateRefreshToken(
		ctx context.Context,
		sessionID string,
		currentRefreshTokenHash string,
		newRefreshTokenHash string,
		expiresAt time.Time,
	) (*models.AuthSession, error)

	RevokeByID(
		ctx context.Context,
		sessionID string,
	) error
}

type SessionService struct {
	store           SessionStore
	accessTokens    *AccessTokenService
	refreshTokenTTL time.Duration
}

func NewSessionService(
	store SessionStore,
	accessTokens *AccessTokenService,
	refreshTokenTTL time.Duration,
) (*SessionService, error) {
	if store == nil ||
		accessTokens == nil ||
		refreshTokenTTL <= 0 {

		return nil, errors.New(
			"valid session store, access token service, and refresh ttl are required",
		)
	}

	return &SessionService{
		store:           store,
		accessTokens:    accessTokens,
		refreshTokenTTL: refreshTokenTTL,
	}, nil
}

func generateRefreshToken() (string, error) {
	raw := make(
		[]byte,
		refreshTokenByteLength,
	)

	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf(
			"generate refresh token: %w",
			err,
		)
	}

	return base64.RawURLEncoding.EncodeToString(
		raw,
	), nil
}

func hashRefreshToken(
	rawToken string,
) string {
	sum := sha256.Sum256(
		[]byte(rawToken),
	)

	return hex.EncodeToString(sum[:])
}

func (s *SessionService) Create(
	ctx context.Context,
	appUserID string,
	applicationID string,
	applicationCode string,
	role string,
) (
	*models.AuthTokenSet,
	*models.AuthSession,
	error,
) {
	appUserID = strings.TrimSpace(appUserID)
	applicationID = strings.TrimSpace(applicationID)
	applicationCode = strings.ToLower(
		strings.TrimSpace(applicationCode),
	)
	role = strings.TrimSpace(role)

	if appUserID == "" ||
		applicationID == "" ||
		applicationCode == "" ||
		role == "" {

		return nil, nil, ErrSessionUnavailable
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, nil, err
	}

	refreshTokenHash := hashRefreshToken(
		refreshToken,
	)

	refreshExpiresAt := time.Now().
		UTC().
		Add(s.refreshTokenTTL)

	session, err := s.store.Create(
		ctx,
		appUserID,
		applicationID,
		refreshTokenHash,
		refreshExpiresAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"create central auth session: %w",
			err,
		)
	}

	if session == nil {
		return nil, nil, ErrSessionUnavailable
	}

	accessToken, accessExpiresAt, err :=
		s.accessTokens.Issue(
			appUserID,
			session.ID,
			applicationCode,
			role,
		)
	if err != nil {
		_ = s.store.RevokeByID(
			ctx,
			session.ID,
		)

		return nil, nil, err
	}

	tokenSet := &models.AuthTokenSet{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "bearer",
		ExpiresIn: int(
			s.accessTokens.TTL().Seconds(),
		),
		ExpiresAt: accessExpiresAt.Unix(),
		SessionID: session.ID,
	}

	return tokenSet, session, nil
}

func (s *SessionService) ResolveRefreshToken(
	ctx context.Context,
	rawRefreshToken string,
) (*models.AuthSession, error) {
	rawRefreshToken = strings.TrimSpace(
		rawRefreshToken,
	)

	if rawRefreshToken == "" {
		return nil, ErrInvalidRefreshToken
	}

	session, err := s.store.GetByRefreshTokenHash(
		ctx,
		hashRefreshToken(rawRefreshToken),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve central refresh token: %w",
			err,
		)
	}

	if session == nil ||
		session.RevokedAt != nil ||
		!session.ExpiresAt.After(time.Now().UTC()) {

		return nil, ErrInvalidRefreshToken
	}

	return session, nil
}

func (s *SessionService) Rotate(
	ctx context.Context,
	session *models.AuthSession,
	currentRawRefreshToken string,
	applicationCode string,
	role string,
) (
	*models.AuthTokenSet,
	*models.AuthSession,
	error,
) {
	if session == nil {
		return nil, nil, ErrInvalidRefreshToken
	}

	currentRawRefreshToken = strings.TrimSpace(
		currentRawRefreshToken,
	)

	if currentRawRefreshToken == "" {
		return nil, nil, ErrInvalidRefreshToken
	}

	currentHash := hashRefreshToken(
		currentRawRefreshToken,
	)

	if currentHash != session.RefreshTokenHash {
		return nil, nil, ErrInvalidRefreshToken
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, nil, err
	}

	newHash := hashRefreshToken(
		newRefreshToken,
	)

	newRefreshExpiry := time.Now().
		UTC().
		Add(s.refreshTokenTTL)

	updatedSession, err :=
		s.store.RotateRefreshToken(
			ctx,
			session.ID,
			currentHash,
			newHash,
			newRefreshExpiry,
		)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"rotate central refresh token: %w",
			err,
		)
	}

	if updatedSession == nil {
		return nil, nil, ErrInvalidRefreshToken
	}

	accessToken, accessExpiresAt, err :=
		s.accessTokens.Issue(
			updatedSession.AppUserID,
			updatedSession.ID,
			applicationCode,
			role,
		)
	if err != nil {
		return nil, nil, err
	}

	return &models.AuthTokenSet{
			AccessToken:  accessToken,
			RefreshToken: newRefreshToken,
			TokenType:    "bearer",
			ExpiresIn: int(
				s.accessTokens.TTL().Seconds(),
			),
			ExpiresAt: accessExpiresAt.Unix(),
			SessionID: updatedSession.ID,
		},
		updatedSession,
		nil
}

func (s *SessionService) ValidateAccessToken(
	ctx context.Context,
	rawAccessToken string,
) (
	*AccessTokenClaims,
	*models.AuthSession,
	error,
) {
	claims, err := s.accessTokens.Parse(
		rawAccessToken,
	)
	if err != nil {
		return nil, nil, err
	}

	session, err := s.store.GetByID(
		ctx,
		claims.SessionID,
	)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"resolve central auth session: %w",
			err,
		)
	}

	if session == nil ||
		session.RevokedAt != nil ||
		!session.ExpiresAt.After(time.Now().UTC()) ||
		session.AppUserID != claims.Subject {

		return nil, nil, ErrInvalidAccessToken
	}

	return claims, session, nil
}

func (s *SessionService) RevokeAccessToken(
	ctx context.Context,
	rawAccessToken string,
) error {
	claims, session, err :=
		s.ValidateAccessToken(
			ctx,
			rawAccessToken,
		)
	if err != nil {
		return err
	}

	if claims == nil || session == nil {
		return ErrInvalidAccessToken
	}

	if err := s.store.RevokeByID(
		ctx,
		session.ID,
	); err != nil {
		return fmt.Errorf(
			"revoke central session: %w",
			err,
		)
	}

	return nil
}
