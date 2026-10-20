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
	verifyCalls   int
}

func (f *fakeCentralLoginCredentials) VerifyUserPassword(
	_ context.Context,
	appUserID string,
	password string,
) (*models.AuthCredential, error) {
	f.verifyCalls++

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

type fakeApplicationLookup struct {
	applications map[string]*models.Application
}

func (f *fakeApplicationLookup) GetByCode(
	_ context.Context,
	code string,
) (*models.Application, error) {
	return f.applications[code], nil
}

// fakeMembershipLookup is read-only on purpose: there is no way for the
// login path to create a membership through it.
type fakeMembershipLookup struct {
	// key: appUserID + "|" + applicationID
	memberships map[string]*models.AppMembership
	lookups     int
}

func (f *fakeMembershipLookup) GetByAppUserAndApplicationID(
	_ context.Context,
	appUserID string,
	applicationID string,
) (*models.AppMembership, error) {
	f.lookups++

	return f.memberships[appUserID+"|"+applicationID], nil
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

type fakeCentralLoginIdentities struct{}

func (f *fakeCentralLoginIdentities) GetByUserID(
	_ context.Context,
	userID string,
) (*models.Identity, error) {
	return &models.Identity{
		User: &models.AppUser{
			ID:    userID,
			Email: "user@example.com",
		},
	}, nil
}

type loginHarness struct {
	service     *CentralLoginService
	credentials *fakeCentralLoginCredentials
	sessions    *fakeCentralLoginSessions
	memberships *fakeMembershipLookup
}

func newLoginHarness(
	hasCredential bool,
	memberships map[string]*models.AppMembership,
) *loginHarness {
	user := &models.AppUser{
		ID:       "user-1",
		Email:    "user@example.com",
		FullName: "User Test",
	}

	credentials := &fakeCentralLoginCredentials{
		hasCredential: hasCredential,
		password:      "Password123!",
	}

	sessions := &fakeCentralLoginSessions{}

	membershipLookup := &fakeMembershipLookup{
		memberships: memberships,
	}

	applicationContext := NewApplicationContextService(
		&fakeApplicationLookup{
			applications: map[string]*models.Application{
				"silapet": {
					ID:       "app-silapet",
					Code:     "silapet",
					Name:     "SILAPET",
					IsActive: true,
				},
				"klinik_pkp": {
					ID:       "app-klinik",
					Code:     "klinik_pkp",
					Name:     "Klinik PKP",
					IsActive: true,
				},
				"arsiparis": {
					ID:       "app-arsip",
					Code:     "arsiparis",
					Name:     "Arsiparis",
					IsActive: true,
				},
			},
		},
		membershipLookup,
	)

	return &loginHarness{
		service: NewCentralLoginService(
			&fakeCentralLoginUsers{user: user},
			credentials,
			applicationContext,
			sessions,
			&fakeCentralLoginIdentities{},
		),
		credentials: credentials,
		sessions:    sessions,
		memberships: membershipLookup,
	}
}

func membership(
	applicationID string,
	role string,
	status string,
) *models.AppMembership {
	return &models.AppMembership{
		AppUserID:     "user-1",
		ApplicationID: applicationID,
		Role:          role,
		Status:        status,
	}
}

func multiAppMemberships() map[string]*models.AppMembership {
	return map[string]*models.AppMembership{
		"user-1|app-silapet": membership(
			"app-silapet",
			"user",
			models.MembershipStatusApproved,
		),
		"user-1|app-klinik": membership(
			"app-klinik",
			"admin",
			models.MembershipStatusApproved,
		),
	}
}

func TestCentralLoginReturnsAppSpecificAuthorization(
	t *testing.T,
) {
	harness := newLoginHarness(true, multiAppMemberships())

	tests := []struct {
		application string
		wantRole    string
		wantAppID   string
	}{
		{"silapet", "user", "app-silapet"},
		{"klinik_pkp", "admin", "app-klinik"},
	}

	for _, test := range tests {
		t.Run(test.application, func(t *testing.T) {
			result, err := harness.service.Login(
				context.Background(),
				"user@example.com",
				"Password123!",
				test.application,
			)
			if err != nil {
				t.Fatalf("login: %v", err)
			}

			if result.Session.AccessToken == "" {
				t.Fatal("expected access token")
			}

			if harness.sessions.role != test.wantRole {
				t.Fatalf(
					"expected role %q, got %q",
					test.wantRole,
					harness.sessions.role,
				)
			}

			if harness.sessions.applicationID != test.wantAppID ||
				harness.sessions.applicationCode != test.application {

				t.Fatalf(
					"unexpected session scope %q/%q",
					harness.sessions.applicationID,
					harness.sessions.applicationCode,
				)
			}
		})
	}
}

func TestCentralLoginWithoutMembershipDoesNotCreateOne(
	t *testing.T,
) {
	memberships := multiAppMemberships()
	before := len(memberships)

	harness := newLoginHarness(true, memberships)

	_, err := harness.service.Login(
		context.Background(),
		"user@example.com",
		"Password123!",
		"arsiparis",
	)

	if !errors.Is(err, ErrApplicationAccessUnavailable) {
		t.Fatalf(
			"expected ErrApplicationAccessUnavailable, got %v",
			err,
		)
	}

	if len(memberships) != before {
		t.Fatal("login must never create a membership")
	}

	if harness.sessions.createCalls != 0 {
		t.Fatal("no session may be created without membership")
	}
}

func TestCentralLoginMembershipStatuses(
	t *testing.T,
) {
	tests := []struct {
		status string
		err    error
	}{
		{models.MembershipStatusPending, ErrAccountPending},
		{models.MembershipStatusRejected, ErrAccountRejected},
		{models.MembershipStatusDisabled, ErrAccountDisabled},
		{"something-else", ErrAccountUnavailable},
	}

	for _, test := range tests {
		t.Run(test.status, func(t *testing.T) {
			harness := newLoginHarness(
				true,
				map[string]*models.AppMembership{
					"user-1|app-silapet": membership(
						"app-silapet",
						"user",
						test.status,
					),
				},
			)

			_, err := harness.service.Login(
				context.Background(),
				"user@example.com",
				"Password123!",
				"silapet",
			)

			if !errors.Is(err, test.err) {
				t.Fatalf("expected %v, got %v", test.err, err)
			}

			if harness.sessions.createCalls != 0 {
				t.Fatal("no session for non-approved membership")
			}
		})
	}
}

func TestCentralLoginRejectsWrongPassword(
	t *testing.T,
) {
	harness := newLoginHarness(true, multiAppMemberships())

	_, err := harness.service.Login(
		context.Background(),
		"user@example.com",
		"WrongPassword123!",
		"silapet",
	)

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestCentralLoginUnknownEmailIsInvalidCredentials(
	t *testing.T,
) {
	service := NewCentralLoginService(
		&fakeCentralLoginUsers{},
		&fakeCentralLoginCredentials{},
		nil,
		&fakeCentralLoginSessions{},
		&fakeCentralLoginIdentities{},
	)

	_, err := service.Login(
		context.Background(),
		"nobody@example.com",
		"Password123!",
		"silapet",
	)

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestCentralLoginIdentityWithoutCredentialRequiresPasswordSetup(
	t *testing.T,
) {
	harness := newLoginHarness(false, multiAppMemberships())

	_, err := harness.service.Login(
		context.Background(),
		"user@example.com",
		"AnyPassword123!",
		"silapet",
	)

	if !errors.Is(err, ErrPasswordSetupRequired) {
		t.Fatalf("expected ErrPasswordSetupRequired, got %v", err)
	}

	if harness.sessions.createCalls != 0 {
		t.Fatal("no session without credential")
	}
}

func TestApplicationContextResolvesRoleAndStatusFromMemberships(
	t *testing.T,
) {
	harness := newLoginHarness(true, multiAppMemberships())

	service := harness.service.applications

	klinik, err := service.GetByAppUserID(
		context.Background(),
		"user-1",
		"klinik_pkp",
	)
	if err != nil {
		t.Fatal(err)
	}

	if klinik.Role != "admin" ||
		klinik.Status != models.MembershipStatusApproved {

		t.Fatalf("unexpected klinik context %+v", klinik)
	}

	silapet, err := service.GetByAppUserID(
		context.Background(),
		"user-1",
		"silapet",
	)
	if err != nil {
		t.Fatal(err)
	}

	if silapet.Role != "user" {
		t.Fatalf("unexpected silapet role %q", silapet.Role)
	}

	_, err = service.GetByAppUserID(
		context.Background(),
		"user-1",
		"arsiparis",
	)

	if !errors.Is(err, ErrApplicationMembershipUnavailable) {
		t.Fatalf(
			"expected ErrApplicationMembershipUnavailable, got %v",
			err,
		)
	}
}
