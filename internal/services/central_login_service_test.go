package services

import (
	"context"
	"errors"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeCentralLoginUsers struct {
	user *models.AppUser
}

func (f *fakeCentralLoginUsers) GetByEmailIncludingDeleted(
	_ context.Context,
	_ string,
) (*models.AppUser, error) {
	return f.user, nil
}

type fakeCentralLoginCredentials struct {
	hasCredential bool
	password      string
	createCalls   int
}

func (f *fakeCentralLoginCredentials) VerifyUserPassword(
	_ context.Context,
	appUserID string,
	password string,
) (*models.AuthCredential, error) {
	if !f.hasCredential {
		return nil, ErrCredentialNotFound
	}

	if password != f.password {
		return nil, ErrInvalidCredentials
	}

	return &models.AuthCredential{
		AppUserID:         appUserID,
		PasswordAlgorithm: models.PasswordAlgorithmBcrypt,
	}, nil
}

func (f *fakeCentralLoginCredentials) CreateCredential(
	_ context.Context,
	appUserID string,
	password string,
	_ bool,
) (*models.AuthCredential, error) {
	f.createCalls++
	f.hasCredential = true
	f.password = password

	return &models.AuthCredential{
		AppUserID:         appUserID,
		PasswordAlgorithm: models.PasswordAlgorithmBcrypt,
	}, nil
}

type fakeCentralLoginApplications struct {
	context *models.ApplicationContext
	err     error
}

func (f *fakeCentralLoginApplications) GetByAppUserID(
	_ context.Context,
	_ string,
	_ string,
) (*models.ApplicationContext, error) {
	return f.context, f.err
}

type fakeCentralLoginSessions struct {
	createCalls     int
	appUserID       string
	applicationID   string
	applicationCode string
	role            string
}

func (f *fakeCentralLoginSessions) Create(
	_ context.Context,
	appUserID string,
	applicationID string,
	applicationCode string,
	role string,
) (
	*models.AuthTokenSet,
	*models.AuthSession,
	error,
) {
	f.createCalls++
	f.appUserID = appUserID
	f.applicationID = applicationID
	f.applicationCode = applicationCode
	f.role = role

	return &models.AuthTokenSet{
			AccessToken:  "central-access",
			RefreshToken: "central-refresh",
			TokenType:    "bearer",
			ExpiresIn:    900,
			ExpiresAt:    9999999999,
			SessionID:    "session-1",
		},
		&models.AuthSession{
			ID:            "session-1",
			AppUserID:     appUserID,
			ApplicationID: applicationID,
		},
		nil
}

type fakeLegacyCredentialVerifier struct {
	calls   int
	session *models.SupabaseSession
	err     error
}

func (f *fakeLegacyCredentialVerifier) SignInWithPassword(
	_ context.Context,
	_ string,
	_ string,
) (*models.SupabaseSession, error) {
	f.calls++

	return f.session, f.err
}

func TestCentralLoginUsesCentralCredential(
	t *testing.T,
) {
	user := &models.AppUser{
		ID:       "user-1",
		Email:    "user@example.com",
		FullName: "User Test",
	}

	credentials := &fakeCentralLoginCredentials{
		hasCredential: true,
		password:      "Password123!",
	}

	sessions := &fakeCentralLoginSessions{}

	legacy := &fakeLegacyCredentialVerifier{}

	service := &CentralLoginService{
		users:       &fakeCentralLoginUsers{user: user},
		credentials: credentials,
		applications: &fakeCentralLoginApplications{
			context: &models.ApplicationContext{
				UserID:        user.ID,
				ApplicationID: "app-silapet",
				Application:   "silapet",
				Role:          "user",
				Status:        models.MembershipStatusApproved,
			},
		},
		sessions:         sessions,
		legacyCredential: legacy,
	}

	// Avoid database dependency in this unit test by testing
	// the composition until identity loading separately below.
	err := service.ensureCentralCredential(
		context.Background(),
		user,
		"Password123!",
	)
	if err != nil {
		t.Fatalf(
			"verify central credential: %v",
			err,
		)
	}

	if legacy.calls != 0 {
		t.Fatalf(
			"legacy verifier must not be called, got %d",
			legacy.calls,
		)
	}
}

func TestCentralLoginMigratesLegacyCredential(
	t *testing.T,
) {
	user := &models.AppUser{
		ID:    "user-1",
		Email: "user@example.com",
	}

	credentials := &fakeCentralLoginCredentials{}

	legacy := &fakeLegacyCredentialVerifier{
		session: &models.SupabaseSession{
			User: models.SupabaseAuthUser{
				ID:    user.ID,
				Email: user.Email,
			},
		},
	}

	service := &CentralLoginService{
		credentials:      credentials,
		legacyCredential: legacy,
	}

	err := service.ensureCentralCredential(
		context.Background(),
		user,
		"Password123!",
	)
	if err != nil {
		t.Fatalf(
			"migrate legacy credential: %v",
			err,
		)
	}

	if legacy.calls != 1 {
		t.Fatalf(
			"expected one legacy verification, got %d",
			legacy.calls,
		)
	}

	if credentials.createCalls != 1 {
		t.Fatalf(
			"expected one central credential create, got %d",
			credentials.createCalls,
		)
	}

	err = service.ensureCentralCredential(
		context.Background(),
		user,
		"Password123!",
	)
	if err != nil {
		t.Fatalf(
			"verify migrated credential: %v",
			err,
		)
	}

	if legacy.calls != 1 {
		t.Fatal(
			"legacy verifier must not be used after migration",
		)
	}
}

func TestCentralLoginRejectsLegacyIdentityMismatch(
	t *testing.T,
) {
	user := &models.AppUser{
		ID:    "user-1",
		Email: "user@example.com",
	}

	service := &CentralLoginService{
		credentials: &fakeCentralLoginCredentials{},
		legacyCredential: &fakeLegacyCredentialVerifier{
			session: &models.SupabaseSession{
				User: models.SupabaseAuthUser{
					ID:    "different-user",
					Email: user.Email,
				},
			},
		},
	}

	err := service.ensureCentralCredential(
		context.Background(),
		user,
		"Password123!",
	)

	if !errors.Is(
		err,
		ErrInvalidCredentials,
	) {
		t.Fatalf(
			"expected ErrInvalidCredentials, got %v",
			err,
		)
	}
}

func TestCentralLoginRejectsWrongCentralPassword(
	t *testing.T,
) {
	user := &models.AppUser{
		ID:    "user-1",
		Email: "user@example.com",
	}

	legacy := &fakeLegacyCredentialVerifier{}

	service := &CentralLoginService{
		credentials: &fakeCentralLoginCredentials{
			hasCredential: true,
			password:      "CorrectPassword123!",
		},
		legacyCredential: legacy,
	}

	err := service.ensureCentralCredential(
		context.Background(),
		user,
		"WrongPassword123!",
	)

	if !errors.Is(
		err,
		ErrInvalidCredentials,
	) {
		t.Fatalf(
			"expected ErrInvalidCredentials, got %v",
			err,
		)
	}

	if legacy.calls != 0 {
		t.Fatal(
			"wrong central password must not fall back to legacy auth",
		)
	}
}

func TestCentralLoginMembershipStatus(
	t *testing.T,
) {
	tests := []struct {
		name   string
		status string
		err    error
	}{
		{
			name:   "pending",
			status: models.MembershipStatusPending,
			err:    ErrAccountPending,
		},
		{
			name:   "rejected",
			status: models.MembershipStatusRejected,
			err:    ErrAccountRejected,
		},
		{
			name:   "disabled",
			status: models.MembershipStatusDisabled,
			err:    ErrAccountUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(
			test.name,
			func(t *testing.T) {
				statusErr := membershipLoginStatusError(
					test.status,
				)

				if !errors.Is(
					statusErr,
					test.err,
				) {
					t.Fatalf(
						"expected %v, got %v",
						test.err,
						statusErr,
					)
				}
			},
		)
	}
}
