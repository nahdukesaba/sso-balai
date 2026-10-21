package services

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeRequestAccessUsers struct {
	mu    sync.Mutex
	user  *models.AppUser
	err   error
	email string
	calls int
}

func (f *fakeRequestAccessUsers) GetByEmailIncludingDeleted(
	_ context.Context,
	email string,
) (*models.AppUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.email = email
	return f.user, f.err
}

type fakeRequestAccessAuth struct {
	mu          sync.Mutex
	session     *models.SupabaseSession
	signInErr   error
	signOutErr  error
	signInCalls int
	signOuts    []string
	email       string
	password    string
}

func (f *fakeRequestAccessAuth) SignInWithPassword(
	_ context.Context,
	email string,
	password string,
) (*models.SupabaseSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signInCalls++
	f.email = email
	f.password = password
	return f.session, f.signInErr
}

func (f *fakeRequestAccessAuth) SignOut(
	_ context.Context,
	accessToken string,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signOuts = append(f.signOuts, accessToken)
	return f.signOutErr
}

type fakeRequestAccessEnrollments struct {
	mu          sync.Mutex
	result      *models.ApplicationEnrollmentResult
	err         error
	calls       int
	userID      string
	application string
}

func (f *fakeRequestAccessEnrollments) Request(
	_ context.Context,
	appUserID string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.userID = appUserID
	f.application = applicationCode
	return f.result, f.err
}

func mappedRequestAccessUser() *models.AppUser {
	authUserID := "auth-user-id"
	return &models.AppUser{
		ID:         "app-user-id",
		AuthUserID: &authUserID,
		Email:      "employee@example.com",
	}
}

func requestAccessSession(authUserID string) *models.SupabaseSession {
	return &models.SupabaseSession{
		AccessToken: "temporary-access-token",
		User: models.SupabaseAuthUser{
			ID: authUserID,
		},
	}
}

func pendingEnrollment(
	outcome models.ApplicationEnrollmentOutcome,
) *models.ApplicationEnrollmentResult {
	return &models.ApplicationEnrollmentResult{
		Application: "silapet",
		Status:      models.MembershipStatusPending,
		Outcome:     outcome,
	}
}

func TestCentralRequestAccessCreatesPendingWithoutTargetMembership(t *testing.T) {
	users := &fakeRequestAccessUsers{user: mappedRequestAccessUser()}
	auth := &fakeRequestAccessAuth{
		session: requestAccessSession("auth-user-id"),
	}
	enrollments := &fakeRequestAccessEnrollments{
		result: pendingEnrollment(models.ApplicationEnrollmentCreated),
	}
	service := NewCentralRequestAccessService(auth, users, enrollments)

	result, err := service.Request(
		context.Background(),
		" Employee@Example.com ",
		"correct-password",
		" SILAPET ",
	)
	if err != nil {
		t.Fatalf("request access: %v", err)
	}

	if result.Status != models.MembershipStatusPending ||
		result.Outcome != models.ApplicationEnrollmentCreated {
		t.Fatalf("unexpected enrollment result: %#v", result)
	}
	if users.email != "employee@example.com" ||
		auth.email != "employee@example.com" ||
		auth.password != "correct-password" {
		t.Fatal("identity credentials were not normalized/delegated")
	}
	if enrollments.userID != "app-user-id" ||
		enrollments.application != "silapet" {
		t.Fatal("enrollment did not use mapped app user and target application")
	}
	if len(auth.signOuts) != 1 ||
		auth.signOuts[0] != "temporary-access-token" {
		t.Fatal("temporary Supabase session was not cleaned up after success")
	}
}

func TestCentralRequestAccessRejectsWrongPasswordWithoutMembership(t *testing.T) {
	auth := &fakeRequestAccessAuth{signInErr: ErrInvalidCredentials}
	enrollments := &fakeRequestAccessEnrollments{}
	service := NewCentralRequestAccessService(
		auth,
		&fakeRequestAccessUsers{user: mappedRequestAccessUser()},
		enrollments,
	)

	_, err := service.Request(
		context.Background(),
		"employee@example.com",
		"wrong-password",
		"silapet",
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if enrollments.calls != 0 || len(auth.signOuts) != 0 {
		t.Fatal("wrong password must not create membership or clean a missing session")
	}
}

func TestCentralRequestAccessUnknownAndLegacyUsersAreSafe(t *testing.T) {
	tests := []struct {
		name string
		user *models.AppUser
	}{
		{name: "unknown user"},
		{
			name: "unmapped legacy user",
			user: &models.AppUser{
				ID:    "legacy-user-id",
				Email: "employee@example.com",
			},
		},
		{
			name: "deleted mapped user",
			user: func() *models.AppUser {
				user := mappedRequestAccessUser()
				deletedAt := time.Now()
				user.DeletedAt = &deletedAt
				return user
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &fakeRequestAccessAuth{}
			enrollments := &fakeRequestAccessEnrollments{}
			service := NewCentralRequestAccessService(
				auth,
				&fakeRequestAccessUsers{user: test.user},
				enrollments,
			)

			_, err := service.Request(
				context.Background(),
				"employee@example.com",
				"password",
				"silapet",
			)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("expected generic credential error, got %v", err)
			}
			if auth.signInCalls != 0 || enrollments.calls != 0 {
				t.Fatal("unavailable identity must not authenticate or enroll")
			}
		})
	}
}

func TestCentralRequestAccessRejectsAuthUserMappingMismatch(t *testing.T) {
	auth := &fakeRequestAccessAuth{
		session: requestAccessSession("different-auth-user-id"),
	}
	enrollments := &fakeRequestAccessEnrollments{}
	service := NewCentralRequestAccessService(
		auth,
		&fakeRequestAccessUsers{user: mappedRequestAccessUser()},
		enrollments,
	)

	_, err := service.Request(
		context.Background(),
		"employee@example.com",
		"password",
		"silapet",
	)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected mapping mismatch rejection, got %v", err)
	}
	if enrollments.calls != 0 || len(auth.signOuts) != 1 {
		t.Fatal("mapping mismatch must not enroll and must clean the session")
	}
}

func TestCentralRequestAccessApplicationUnavailable(t *testing.T) {
	for _, name := range []string{"missing application", "inactive application"} {
		t.Run(name, func(t *testing.T) {
			auth := &fakeRequestAccessAuth{
				session: requestAccessSession("auth-user-id"),
			}
			service := NewCentralRequestAccessService(
				auth,
				&fakeRequestAccessUsers{user: mappedRequestAccessUser()},
				&fakeRequestAccessEnrollments{
					err: ErrApplicationEnrollmentUnavailable,
				},
			)

			_, err := service.Request(
				context.Background(),
				"employee@example.com",
				"password",
				"unavailable-app",
			)
			if !errors.Is(err, ErrApplicationEnrollmentUnavailable) {
				t.Fatalf("expected unavailable application, got %v", err)
			}
			if len(auth.signOuts) != 1 {
				t.Fatal("application failure must clean the temporary session")
			}
		})
	}
}

func TestCentralRequestAccessMembershipStateMachine(t *testing.T) {
	tests := []struct {
		name        string
		result      *models.ApplicationEnrollmentResult
		enrollErr   error
		expectedErr error
	}{
		{
			name:   "existing pending is idempotent",
			result: pendingEnrollment(models.ApplicationEnrollmentAlreadyPending),
		},
		{
			name: "existing approved is not replaced",
			result: &models.ApplicationEnrollmentResult{
				Application: "silapet",
				Status:      models.MembershipStatusApproved,
				Outcome:     models.ApplicationEnrollmentAlreadyApproved,
			},
			expectedErr: ErrApplicationAccessAlreadyGranted,
		},
		{
			name:        "existing rejected stays blocked",
			enrollErr:   ErrApplicationEnrollmentBlocked,
			expectedErr: ErrApplicationEnrollmentBlocked,
		},
		{
			name:   "soft deleted membership is reopened",
			result: pendingEnrollment(models.ApplicationEnrollmentReopened),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &fakeRequestAccessAuth{
				session: requestAccessSession("auth-user-id"),
			}
			service := NewCentralRequestAccessService(
				auth,
				&fakeRequestAccessUsers{user: mappedRequestAccessUser()},
				&fakeRequestAccessEnrollments{
					result: test.result,
					err:    test.enrollErr,
				},
			)

			result, err := service.Request(
				context.Background(),
				"employee@example.com",
				"password",
				"silapet",
			)
			if test.expectedErr != nil {
				if !errors.Is(err, test.expectedErr) {
					t.Fatalf("expected %v, got %v", test.expectedErr, err)
				}
			} else if err != nil || result == nil {
				t.Fatalf("expected success, result=%#v err=%v", result, err)
			}
			if len(auth.signOuts) != 1 {
				t.Fatal("every authenticated state transition must clean the session")
			}
		})
	}
}

func TestCentralRequestAccessCleanupFailureDoesNotRollbackMembership(t *testing.T) {
	auth := &fakeRequestAccessAuth{
		session:    requestAccessSession("auth-user-id"),
		signOutErr: ErrAuthUnavailable,
	}
	service := NewCentralRequestAccessService(
		auth,
		&fakeRequestAccessUsers{user: mappedRequestAccessUser()},
		&fakeRequestAccessEnrollments{
			result: pendingEnrollment(models.ApplicationEnrollmentCreated),
		},
	)

	result, err := service.Request(
		context.Background(),
		"employee@example.com",
		"password",
		"silapet",
	)
	if err != nil || result == nil {
		t.Fatalf("cleanup failure changed membership result: %#v, %v", result, err)
	}
	if len(auth.signOuts) != 1 {
		t.Fatal("cleanup was not attempted")
	}
}

type concurrentEnrollmentStore struct {
	mu      sync.Mutex
	exists  bool
	created int
}

func (s *concurrentEnrollmentStore) Request(
	_ context.Context,
	_ string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	outcome := models.ApplicationEnrollmentAlreadyPending
	if !s.exists {
		s.exists = true
		s.created++
		outcome = models.ApplicationEnrollmentCreated
	}
	return &models.ApplicationEnrollmentResult{
		Application: applicationCode,
		Status:      models.MembershipStatusPending,
		Outcome:     outcome,
	}, nil
}

func TestCentralRequestAccessConcurrentRequestsKeepOneLogicalMembership(t *testing.T) {
	store := &concurrentEnrollmentStore{}
	service := NewCentralRequestAccessService(
		&fakeRequestAccessAuth{
			session: requestAccessSession("auth-user-id"),
		},
		&fakeRequestAccessUsers{user: mappedRequestAccessUser()},
		store,
	)

	const workers = 16
	errorsByWorker := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := service.Request(
				context.Background(),
				"employee@example.com",
				"password",
				"silapet",
			)
			errorsByWorker <- err
		}()
	}
	wait.Wait()
	close(errorsByWorker)

	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent request failed: %v", err)
		}
	}
	if store.created != 1 {
		t.Fatalf("expected one logical membership creation, got %d", store.created)
	}
}
