package services

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeSupabaseAuthentication struct {
	signInSession  *models.SupabaseSession
	signInErr      error
	refreshSession *models.SupabaseSession
	refreshErr     error
	verifiedUser   *models.SupabaseAuthUser
	verifyErr      error
	signOutErr     error
	updateErr      error

	signInCalls     int
	refreshCalls    int
	verifyCalls     int
	signOutCalls    int
	updateCalls     int
	signInEmail     string
	signInPassword  string
	refreshToken    string
	verifiedToken   string
	signOutToken    string
	updateToken     string
	updatedPassword string
}

func (f *fakeSupabaseAuthentication) SignInWithPassword(
	_ context.Context,
	email string,
	password string,
) (*models.SupabaseSession, error) {
	f.signInCalls++
	f.signInEmail = email
	f.signInPassword = password

	return f.signInSession, f.signInErr
}

func (f *fakeSupabaseAuthentication) RefreshSession(
	_ context.Context,
	refreshToken string,
) (*models.SupabaseSession, error) {
	f.refreshCalls++
	f.refreshToken = refreshToken

	return f.refreshSession, f.refreshErr
}

func (f *fakeSupabaseAuthentication) VerifyAccessToken(
	_ context.Context,
	accessToken string,
) (*models.SupabaseAuthUser, error) {
	f.verifyCalls++
	f.verifiedToken = accessToken

	return f.verifiedUser, f.verifyErr
}

func (f *fakeSupabaseAuthentication) SignOut(
	_ context.Context,
	accessToken string,
) error {
	f.signOutCalls++
	f.signOutToken = accessToken

	return f.signOutErr
}

func (f *fakeSupabaseAuthentication) UpdatePassword(
	_ context.Context,
	accessToken string,
	password string,
) error {
	f.updateCalls++
	f.updateToken = accessToken
	f.updatedPassword = password

	return f.updateErr
}

type fakeSupabaseAuthUsers struct {
	user               *models.AppUser
	err                error
	emailErr           error
	idErr              error
	linkErr            error
	forceLinkConflict  bool
	conflictAuthUserID string
	authUserID         string
	linkedAuthUserID   string
	lookupCalls        int
	emailLookupCalls   int
	idLookupCalls      int
	linkCalls          int
}

func (f *fakeSupabaseAuthUsers) GetByAuthUserID(
	_ context.Context,
	authUserID string,
) (*models.AppUser, error) {
	f.lookupCalls++
	f.authUserID = authUserID

	return f.user, f.err
}

func (f *fakeSupabaseAuthUsers) GetByEmailIncludingDeleted(
	_ context.Context,
	_ string,
) (*models.AppUser, error) {
	f.emailLookupCalls++

	return f.user, f.emailErr
}

func (f *fakeSupabaseAuthUsers) GetByIDIncludingDeleted(
	_ context.Context,
	_ string,
) (*models.AppUser, error) {
	f.idLookupCalls++

	return f.user, f.idErr
}

func (f *fakeSupabaseAuthUsers) LinkAuthUserIDIfUnset(
	_ context.Context,
	_ string,
	authUserID string,
) (bool, error) {
	f.linkCalls++
	f.linkedAuthUserID = authUserID

	if f.linkErr != nil {
		return false, f.linkErr
	}

	if f.forceLinkConflict ||
		f.user == nil ||
		f.user.AuthUserID != nil {
		if f.forceLinkConflict &&
			f.user != nil &&
			f.conflictAuthUserID != "" {

			f.user.AuthUserID = &f.conflictAuthUserID
		}

		return false, nil
	}

	f.user.AuthUserID = &f.linkedAuthUserID

	return true, nil
}

type fakeSupabaseAuthApplications struct {
	context         *models.ApplicationContext
	err             error
	appUserID       string
	applicationCode string
	lookupCalls     int
}

type fakeSupabaseLoginEnrollments struct {
	result          *models.ApplicationEnrollmentResult
	err             error
	calls           int
	appUserID       string
	applicationCode string
}

func (f *fakeSupabaseLoginEnrollments) Request(
	_ context.Context,
	appUserID string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	f.calls++
	f.appUserID = appUserID
	f.applicationCode = applicationCode
	return f.result, f.err
}

func (f *fakeSupabaseAuthApplications) GetByAppUserID(
	_ context.Context,
	appUserID string,
	applicationCode string,
) (*models.ApplicationContext, error) {
	f.lookupCalls++
	f.appUserID = appUserID
	f.applicationCode = applicationCode

	return f.context, f.err
}

type fakeSupabaseAuthIdentities struct {
	identity  *models.Identity
	err       error
	userID    string
	loadCalls int
}

func (f *fakeSupabaseAuthIdentities) GetByUserID(
	_ context.Context,
	userID string,
) (*models.Identity, error) {
	f.loadCalls++
	f.userID = userID

	return f.identity, f.err
}

func mappedSupabaseUser() (*models.AppUser, *models.Identity) {
	authUserID := "auth-user-1"
	user := &models.AppUser{
		ID:         "app-user-1",
		AuthUserID: &authUserID,
		Email:      "user@example.com",
		FullName:   "User Test",
	}

	return user, &models.Identity{User: user}
}

func newSupabaseAuthFacade(
	auth SupabaseAuthentication,
	users SupabaseAuthUserStore,
	applications SupabaseAuthApplicationResolver,
	identities SupabaseAuthIdentityLoader,
) *AuthService {
	return newSupabaseAuthFacadeWithEnrollment(
		auth,
		users,
		applications,
		nil,
		identities,
	)
}

func newSupabaseAuthFacadeWithEnrollment(
	auth SupabaseAuthentication,
	users SupabaseAuthUserStore,
	applications SupabaseAuthApplicationResolver,
	enrollments RequestAccessEnrollmentService,
	identities SupabaseAuthIdentityLoader,
) *AuthService {
	active := NewSupabaseCentralAuthService(
		auth,
		users,
		applications,
		enrollments,
		identities,
	)

	return &AuthService{
		activeAuthenticationService: active,
	}
}

func TestSupabaseLoginSuccess(t *testing.T) {
	user, identity := mappedSupabaseUser()
	auth := &fakeSupabaseAuthentication{
		signInSession: &models.SupabaseSession{
			AccessToken:  "supabase-access",
			RefreshToken: "supabase-refresh",
			TokenType:    "bearer",
			ExpiresIn:    3600,
			ExpiresAt:    123456789,
			User: models.SupabaseAuthUser{
				ID:    *user.AuthUserID,
				Email: user.Email,
			},
		},
	}
	users := &fakeSupabaseAuthUsers{user: user}
	applications := &fakeSupabaseAuthApplications{
		context: &models.ApplicationContext{
			UserID:        user.ID,
			ApplicationID: "application-1",
			Application:   models.ApplicationCodeSilapet,
			Role:          "admin",
			Status:        models.MembershipStatusApproved,
		},
	}
	identities := &fakeSupabaseAuthIdentities{identity: identity}
	service := newSupabaseAuthFacade(
		auth,
		users,
		applications,
		identities,
	)

	result, err := service.Login(
		context.Background(),
		" user@example.com ",
		"Password123!",
		" SILAPET ",
	)
	if err != nil {
		t.Fatalf("login returned error: %v", err)
	}

	if result == nil || result.Session != auth.signInSession {
		t.Fatal("login did not return the original Supabase session")
	}

	if result.Identity == nil || result.Identity.User.ID != user.ID {
		t.Fatal("login did not return the internal app_users identity")
	}

	if users.authUserID != *user.AuthUserID {
		t.Fatalf("resolved auth user id %q", users.authUserID)
	}

	if applications.appUserID != user.ID ||
		applications.applicationCode != models.ApplicationCodeSilapet {

		t.Fatalf(
			"resolved membership with app user %q and application %q",
			applications.appUserID,
			applications.applicationCode,
		)
	}
}

func TestMappedLoginFailureReturnsError(t *testing.T) {
	user, identity := mappedSupabaseUser()
	auth := &fakeSupabaseAuthentication{
		signInErr: ErrInvalidCredentials,
	}
	service := newSupabaseAuthFacade(
		auth,
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{},
		&fakeSupabaseAuthIdentities{identity: identity},
	)

	_, err := service.Login(
		context.Background(),
		user.Email,
		"WrongPassword!",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
}

func TestSupabaseLoginRejectsUnknownAuthUserID(t *testing.T) {
	knownAuthUserID := "known-auth-user"
	user := &models.AppUser{
		ID:         "app-user-1",
		AuthUserID: &knownAuthUserID,
		Email:      "user@example.com",
	}
	auth := &fakeSupabaseAuthentication{
		signInSession: &models.SupabaseSession{
			AccessToken: "supabase-access",
			User: models.SupabaseAuthUser{
				ID: "unknown-auth-user",
			},
		},
	}
	enrollments := &fakeSupabaseLoginEnrollments{}
	service := newSupabaseAuthFacadeWithEnrollment(
		auth,
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{},
		enrollments,
		&fakeSupabaseAuthIdentities{},
	)

	_, err := service.Login(
		context.Background(),
		"user@example.com",
		"Password123!",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrAccountUnavailable) {
		t.Fatalf("expected account unavailable, got %v", err)
	}

	if auth.signOutCalls != 1 || auth.signOutToken != "supabase-access" {
		t.Fatal("unmapped Supabase session was not signed out")
	}
	if enrollments.calls != 0 {
		t.Fatal("unknown auth user created an application membership")
	}
}

func TestSupabaseLoginMembershipStatus(t *testing.T) {
	tests := []struct {
		name        string
		status      string
		expectedErr error
	}{
		{
			name:        "pending",
			status:      models.MembershipStatusPending,
			expectedErr: ErrAccountPending,
		},
		{
			name:        "rejected",
			status:      models.MembershipStatusRejected,
			expectedErr: ErrAccountRejected,
		},
		{
			name:        "disabled",
			status:      models.MembershipStatusDisabled,
			expectedErr: ErrAccountDisabled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user, identity := mappedSupabaseUser()
			auth := &fakeSupabaseAuthentication{
				signInSession: &models.SupabaseSession{
					AccessToken: "supabase-access",
					User: models.SupabaseAuthUser{
						ID: *user.AuthUserID,
					},
				},
			}
			service := newSupabaseAuthFacade(
				auth,
				&fakeSupabaseAuthUsers{user: user},
				&fakeSupabaseAuthApplications{
					context: &models.ApplicationContext{
						ApplicationID: "application-1",
						Role:          "user",
						Status:        test.status,
					},
				},
				&fakeSupabaseAuthIdentities{identity: identity},
			)

			_, err := service.Login(
				context.Background(),
				user.Email,
				"Password123!",
				models.ApplicationCodeSilapet,
			)
			if !errors.Is(err, test.expectedErr) {
				t.Fatalf("expected %v, got %v", test.expectedErr, err)
			}

			if auth.signOutCalls != 1 {
				t.Fatal("denied Supabase session was not signed out")
			}
		})
	}
}

func TestSupabaseLoginAutoEnrollsMissingMembershipAsPending(t *testing.T) {
	tests := []struct {
		name    string
		outcome models.ApplicationEnrollmentOutcome
	}{
		{
			name:    "first login creates membership",
			outcome: models.ApplicationEnrollmentCreated,
		},
		{
			name:    "soft deleted membership reopens",
			outcome: models.ApplicationEnrollmentReopened,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user, identity := mappedSupabaseUser()
			auth := &fakeSupabaseAuthentication{
				signInSession: &models.SupabaseSession{
					AccessToken:  "temporary-access",
					RefreshToken: "temporary-refresh",
					User: models.SupabaseAuthUser{
						ID: *user.AuthUserID,
					},
				},
			}
			enrollments := &fakeSupabaseLoginEnrollments{
				result: &models.ApplicationEnrollmentResult{
					Application: models.ApplicationCodeSilapet,
					Status:      models.MembershipStatusPending,
					Outcome:     test.outcome,
				},
			}
			service := newSupabaseAuthFacadeWithEnrollment(
				auth,
				&fakeSupabaseAuthUsers{user: user},
				&fakeSupabaseAuthApplications{
					err: ErrApplicationMembershipUnavailable,
				},
				enrollments,
				&fakeSupabaseAuthIdentities{identity: identity},
			)

			result, err := service.Login(
				context.Background(),
				user.Email,
				"Password123!",
				models.ApplicationCodeSilapet,
			)
			if !errors.Is(err, ErrAccountPending) || result != nil {
				t.Fatalf("expected pending without a session, result=%#v err=%v", result, err)
			}
			if enrollments.calls != 1 || enrollments.appUserID != user.ID ||
				enrollments.applicationCode != models.ApplicationCodeSilapet {

				t.Fatal("missing membership was not delegated to the enrollment state machine")
			}
			if auth.signOutCalls != 1 || auth.signOutToken != "temporary-access" {
				t.Fatal("temporary Supabase session was not locally cleaned up")
			}
		})
	}
}

func TestSupabaseLoginExistingPendingDoesNotEnrollAgain(t *testing.T) {
	user, identity := mappedSupabaseUser()
	auth := &fakeSupabaseAuthentication{
		signInSession: &models.SupabaseSession{
			AccessToken: "temporary-access",
			User:        models.SupabaseAuthUser{ID: *user.AuthUserID},
		},
	}
	enrollments := &fakeSupabaseLoginEnrollments{}
	service := newSupabaseAuthFacadeWithEnrollment(
		auth,
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{
			context: &models.ApplicationContext{
				ApplicationID: "application-1",
				Role:          "user",
				Status:        models.MembershipStatusPending,
			},
		},
		enrollments,
		&fakeSupabaseAuthIdentities{identity: identity},
	)

	result, err := service.Login(
		context.Background(),
		user.Email,
		"Password123!",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrAccountPending) || result != nil {
		t.Fatalf("expected existing pending result, result=%#v err=%v", result, err)
	}
	if enrollments.calls != 0 || auth.signOutCalls != 1 {
		t.Fatal("existing pending membership was duplicated or session was not cleaned")
	}
}

func TestSupabaseLoginInvalidCredentialsNeverAutoEnroll(t *testing.T) {
	user, identity := mappedSupabaseUser()
	enrollments := &fakeSupabaseLoginEnrollments{}
	service := newSupabaseAuthFacadeWithEnrollment(
		&fakeSupabaseAuthentication{signInErr: ErrInvalidCredentials},
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{err: ErrApplicationMembershipUnavailable},
		enrollments,
		&fakeSupabaseAuthIdentities{identity: identity},
	)

	result, err := service.Login(
		context.Background(),
		user.Email,
		"wrong-password",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrInvalidCredentials) || result != nil {
		t.Fatalf("expected invalid credentials, result=%#v err=%v", result, err)
	}
	if enrollments.calls != 0 {
		t.Fatal("invalid credentials created an application membership")
	}
}

func TestSupabaseConcurrentFirstLoginKeepsOneLogicalMembership(t *testing.T) {
	user, identity := mappedSupabaseUser()
	store := &concurrentEnrollmentStore{}
	service := newSupabaseAuthFacadeWithEnrollment(
		&fakeSupabaseAuthentication{
			signInSession: &models.SupabaseSession{
				AccessToken: "temporary-access",
				User:        models.SupabaseAuthUser{ID: *user.AuthUserID},
			},
		},
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{err: ErrApplicationMembershipUnavailable},
		store,
		&fakeSupabaseAuthIdentities{identity: identity},
	)

	const workers = 12
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := service.Login(
				context.Background(),
				user.Email,
				"Password123!",
				models.ApplicationCodeSilapet,
			)
			if result != nil || !errors.Is(err, ErrAccountPending) {
				errorsByWorker <- errors.New("concurrent login did not return pending without session")
				return
			}
			errorsByWorker <- nil
		}()
	}
	wait.Wait()
	close(errorsByWorker)

	for err := range errorsByWorker {
		if err != nil {
			t.Fatal(err)
		}
	}
	if store.created != 1 {
		t.Fatalf("expected one logical membership creation, got %d", store.created)
	}
}

func TestSupabaseRefresh(t *testing.T) {
	user, identity := mappedSupabaseUser()
	auth := &fakeSupabaseAuthentication{
		refreshSession: &models.SupabaseSession{
			AccessToken:  "refreshed-access",
			RefreshToken: "rotated-refresh",
			User: models.SupabaseAuthUser{
				ID: *user.AuthUserID,
			},
		},
	}
	service := newSupabaseAuthFacade(
		auth,
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{},
		&fakeSupabaseAuthIdentities{identity: identity},
	)

	result, err := service.Refresh(context.Background(), "supabase-refresh")
	if err != nil {
		t.Fatalf("refresh returned error: %v", err)
	}

	if auth.refreshCalls != 1 || auth.refreshToken != "supabase-refresh" {
		t.Fatal("refresh was not delegated to Supabase")
	}

	if result.Session != auth.refreshSession ||
		result.Identity.User.ID != user.ID {

		t.Fatal("refresh did not return Supabase tokens and internal identity")
	}
}

func TestSupabaseAccessTokenAuthentication(t *testing.T) {
	user, identity := mappedSupabaseUser()
	auth := &fakeSupabaseAuthentication{
		verifiedUser: &models.SupabaseAuthUser{
			ID:    *user.AuthUserID,
			Email: user.Email,
		},
	}
	service := newSupabaseAuthFacade(
		auth,
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{},
		&fakeSupabaseAuthIdentities{identity: identity},
	)

	result, err := service.AuthenticateAccessToken(
		context.Background(),
		"supabase-access",
	)
	if err != nil {
		t.Fatalf("authentication returned error: %v", err)
	}

	if auth.verifyCalls != 1 || auth.verifiedToken != "supabase-access" {
		t.Fatal("access token was not verified through Supabase")
	}

	if result == nil || result.User.ID != user.ID {
		t.Fatal("authentication did not return internal identity")
	}
}

func TestSupabaseLogout(t *testing.T) {
	auth := &fakeSupabaseAuthentication{}
	service := newSupabaseAuthFacade(
		auth,
		&fakeSupabaseAuthUsers{},
		&fakeSupabaseAuthApplications{},
		&fakeSupabaseAuthIdentities{},
	)

	err := service.Logout(context.Background(), "supabase-access")
	if err != nil {
		t.Fatalf("logout returned error: %v", err)
	}

	if auth.signOutCalls != 1 || auth.signOutToken != "supabase-access" {
		t.Fatal("logout was not delegated to Supabase")
	}
}

func TestSupabaseChangePassword(t *testing.T) {
	user, identity := mappedSupabaseUser()
	auth := &fakeSupabaseAuthentication{
		signInSession: &models.SupabaseSession{
			AccessToken: "password-session-access",
			User: models.SupabaseAuthUser{
				ID:    *user.AuthUserID,
				Email: user.Email,
			},
		},
	}
	service := newSupabaseAuthFacade(
		auth,
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{},
		&fakeSupabaseAuthIdentities{identity: identity},
	)

	err := service.ChangePassword(
		context.Background(),
		user.ID,
		user.Email,
		"OldPassword123!",
		"NewPassword123!",
	)
	if err != nil {
		t.Fatalf("change password returned error: %v", err)
	}

	if auth.signInCalls != 1 ||
		auth.signInPassword != "OldPassword123!" {

		t.Fatal("old password was not verified through Supabase")
	}

	if auth.updateCalls != 1 ||
		auth.updateToken != "password-session-access" ||
		auth.updatedPassword != "NewPassword123!" {

		t.Fatal("password was not updated with the verified Supabase session")
	}

	if auth.signOutCalls != 1 ||
		auth.signOutToken != "password-session-access" {

		t.Fatal("temporary password verification session was not signed out")
	}
}

func legacySupabaseUser() (*models.AppUser, *models.Identity) {
	user := &models.AppUser{
		ID:       "legacy-app-user-1",
		Email:    "legacy@example.com",
		FullName: "Legacy User",
		Status:   models.UserStatusApproved,
	}

	return user, &models.Identity{User: user}
}

func TestUnmappedUserLoginRejectsWithAccountUnavailable(t *testing.T) {
	user, identity := legacySupabaseUser()
	auth := &fakeSupabaseAuthentication{}
	service := newSupabaseAuthFacade(
		auth,
		&fakeSupabaseAuthUsers{user: user},
		&fakeSupabaseAuthApplications{},
		&fakeSupabaseAuthIdentities{identity: identity},
	)

	_, err := service.Login(
		context.Background(),
		user.Email,
		"Password123!",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrAccountUnavailable) {
		t.Fatalf("expected ErrAccountUnavailable, got %v", err)
	}
}


