package services

import (
	"errors"
	"testing"
	"time"
)

const testAccessTokenSecret = "this-is-a-test-secret-with-at-least-32-characters"

func TestAccessTokenServiceIssueAndParse(
	t *testing.T,
) {
	service, err := NewAccessTokenService(
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

	token, expiresAt, err := service.Issue(
		"user-1",
		"session-1",
		"silapet",
		"user",
	)
	if err != nil {
		t.Fatalf(
			"issue access token: %v",
			err,
		)
	}

	if token == "" {
		t.Fatal("access token must not be empty")
	}

	if !expiresAt.After(time.Now()) {
		t.Fatal(
			"access token expiry must be in the future",
		)
	}

	claims, err := service.Parse(token)
	if err != nil {
		t.Fatalf(
			"parse access token: %v",
			err,
		)
	}

	if claims.Subject != "user-1" {
		t.Fatalf(
			"unexpected subject %q",
			claims.Subject,
		)
	}

	if claims.SessionID != "session-1" {
		t.Fatalf(
			"unexpected session id %q",
			claims.SessionID,
		)
	}

	if claims.Application() != "silapet" {
		t.Fatalf(
			"unexpected application %q",
			claims.Application(),
		)
	}

	if claims.Role != "user" {
		t.Fatalf(
			"unexpected role %q",
			claims.Role,
		)
	}
}

func TestAccessTokenServiceRejectsTamperedToken(
	t *testing.T,
) {
	service, err := NewAccessTokenService(
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

	token, _, err := service.Issue(
		"user-1",
		"session-1",
		"silapet",
		"user",
	)
	if err != nil {
		t.Fatalf(
			"issue access token: %v",
			err,
		)
	}

	token += "tampered"

	_, err = service.Parse(token)

	if !errors.Is(
		err,
		ErrInvalidAccessToken,
	) {
		t.Fatalf(
			"expected ErrInvalidAccessToken, got %v",
			err,
		)
	}
}

func TestAccessTokenServiceRejectsShortSecret(
	t *testing.T,
) {
	_, err := NewAccessTokenService(
		"short",
		"sso-balai-test",
		15*time.Minute,
	)

	if !errors.Is(
		err,
		ErrInvalidTokenConfiguration,
	) {
		t.Fatalf(
			"expected ErrInvalidTokenConfiguration, got %v",
			err,
		)
	}
}
