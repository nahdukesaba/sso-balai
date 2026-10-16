package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeSessionStore struct {
	session *models.AuthSession
}

func (f *fakeSessionStore) Create(
	_ context.Context,
	appUserID string,
	applicationID string,
	refreshTokenHash string,
	expiresAt time.Time,
) (*models.AuthSession, error) {
	f.session = &models.AuthSession{
		ID:               "session-1",
		AppUserID:        appUserID,
		ApplicationID:    applicationID,
		RefreshTokenHash: refreshTokenHash,
		ExpiresAt:        expiresAt,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	return f.session, nil
}

func (f *fakeSessionStore) GetByID(
	_ context.Context,
	id string,
) (*models.AuthSession, error) {
	if f.session == nil ||
		f.session.ID != id {
		return nil, nil
	}

	return f.session, nil
}

func (f *fakeSessionStore) GetByRefreshTokenHash(
	_ context.Context,
	refreshTokenHash string,
) (*models.AuthSession, error) {
	if f.session == nil ||
		f.session.RefreshTokenHash != refreshTokenHash {
		return nil, nil
	}

	return f.session, nil
}

func (f *fakeSessionStore) RotateRefreshToken(
	_ context.Context,
	sessionID string,
	currentRefreshTokenHash string,
	newRefreshTokenHash string,
	expiresAt time.Time,
) (*models.AuthSession, error) {
	if f.session == nil ||
		f.session.ID != sessionID ||
		f.session.RefreshTokenHash !=
			currentRefreshTokenHash ||
		f.session.RevokedAt != nil ||
		!f.session.ExpiresAt.After(
			time.Now().UTC(),
		) {

		return nil, nil
	}

	now := time.Now().UTC()

	f.session.RefreshTokenHash =
		newRefreshTokenHash

	f.session.ExpiresAt = expiresAt
	f.session.LastUsedAt = &now
	f.session.UpdatedAt = now

	return f.session, nil
}

func (f *fakeSessionStore) RevokeByID(
	_ context.Context,
	sessionID string,
) error {
	if f.session == nil ||
		f.session.ID != sessionID {
		return nil
	}

	now := time.Now().UTC()

	f.session.RevokedAt = &now
	f.session.UpdatedAt = now

	return nil
}

func newTestSessionService(
	t *testing.T,
	store SessionStore,
) *SessionService {
	t.Helper()

	accessTokens, err := NewAccessTokenService(
		testAccessTokenSecret,
		"sso-balai-test",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf(
			"create access token service: %v",
			err,
		)
	}

	service, err := NewSessionService(
		store,
		accessTokens,
		7*24*time.Hour,
	)
	if err != nil {
		t.Fatalf(
			"create session service: %v",
			err,
		)
	}

	return service
}

func TestSessionServiceCreate(
	t *testing.T,
) {
	store := &fakeSessionStore{}

	service := newTestSessionService(
		t,
		store,
	)

	tokenSet, session, err := service.Create(
		context.Background(),
		"user-1",
		"application-1",
		"silapet",
		"user",
	)
	if err != nil {
		t.Fatalf(
			"create session: %v",
			err,
		)
	}

	if tokenSet.AccessToken == "" {
		t.Fatal(
			"access token must not be empty",
		)
	}

	if tokenSet.RefreshToken == "" {
		t.Fatal(
			"refresh token must not be empty",
		)
	}

	if tokenSet.RefreshToken ==
		session.RefreshTokenHash {

		t.Fatal(
			"database must not store raw refresh token",
		)
	}

	expectedHash := hashRefreshToken(
		tokenSet.RefreshToken,
	)

	if expectedHash !=
		session.RefreshTokenHash {

		t.Fatal(
			"stored refresh token hash does not match",
		)
	}
}

func TestSessionServiceRotateRejectsReplay(
	t *testing.T,
) {
	store := &fakeSessionStore{}

	service := newTestSessionService(
		t,
		store,
	)

	tokenSet, session, err := service.Create(
		context.Background(),
		"user-1",
		"application-1",
		"silapet",
		"user",
	)
	if err != nil {
		t.Fatalf(
			"create session: %v",
			err,
		)
	}

	oldRefreshToken := tokenSet.RefreshToken

	rotated, updatedSession, err :=
		service.Rotate(
			context.Background(),
			session,
			oldRefreshToken,
			"silapet",
			"user",
		)
	if err != nil {
		t.Fatalf(
			"rotate refresh token: %v",
			err,
		)
	}

	if rotated.RefreshToken ==
		oldRefreshToken {

		t.Fatal(
			"refresh token must rotate",
		)
	}

	_, _, err = service.Rotate(
		context.Background(),
		updatedSession,
		oldRefreshToken,
		"silapet",
		"user",
	)

	if !errors.Is(
		err,
		ErrInvalidRefreshToken,
	) {
		t.Fatalf(
			"expected replay rejection, got %v",
			err,
		)
	}
}

func TestSessionServiceValidateAndRevokeAccessToken(
	t *testing.T,
) {
	store := &fakeSessionStore{}

	service := newTestSessionService(
		t,
		store,
	)

	tokenSet, _, err := service.Create(
		context.Background(),
		"user-1",
		"application-1",
		"klinik_pkp",
		"admin",
	)
	if err != nil {
		t.Fatalf(
			"create session: %v",
			err,
		)
	}

	claims, session, err :=
		service.ValidateAccessToken(
			context.Background(),
			tokenSet.AccessToken,
		)
	if err != nil {
		t.Fatalf(
			"validate access token: %v",
			err,
		)
	}

	if claims.Application() != "klinik_pkp" {
		t.Fatalf(
			"unexpected application %q",
			claims.Application(),
		)
	}

	if claims.Role != "admin" {
		t.Fatalf(
			"unexpected role %q",
			claims.Role,
		)
	}

	if session.ID != tokenSet.SessionID {
		t.Fatalf(
			"unexpected session id %q",
			session.ID,
		)
	}

	if err := service.RevokeAccessToken(
		context.Background(),
		tokenSet.AccessToken,
	); err != nil {
		t.Fatalf(
			"revoke access token: %v",
			err,
		)
	}

	_, _, err = service.ValidateAccessToken(
		context.Background(),
		tokenSet.AccessToken,
	)

	if !errors.Is(
		err,
		ErrInvalidAccessToken,
	) {
		t.Fatalf(
			"expected revoked token rejection, got %v",
			err,
		)
	}
}
