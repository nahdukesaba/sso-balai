package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

type fakeSupabaseRegistrationUsers struct {
	results []*models.AppUser
	errs    []error
	calls   int
}

func (f *fakeSupabaseRegistrationUsers) GetByEmailIncludingDeleted(
	_ context.Context,
	_ string,
) (*models.AppUser, error) {
	index := f.calls
	f.calls++

	var user *models.AppUser
	if index < len(f.results) {
		user = f.results[index]
	}

	var err error
	if index < len(f.errs) {
		err = f.errs[index]
	}

	return user, err
}

type fakeSupabaseRegistrationApplications struct {
	application *models.Application
	err         error
	calls       int
	code        string
}

func (f *fakeSupabaseRegistrationApplications) GetByCode(
	_ context.Context,
	code string,
) (*models.Application, error) {
	f.calls++
	f.code = code

	return f.application, f.err
}

type fakeSupabaseRegistrationAdmin struct {
	findResults []*models.SupabaseAuthUser
	findErrors  []error
	createdUser *models.SupabaseAuthUser
	createErr   error
	deleteErr   error

	findCalls       int
	createCalls     int
	deleteCalls     int
	createdEmail    string
	createdPassword string
	createdFullName string
	deletedUserID   string
}

func (f *fakeSupabaseRegistrationAdmin) FindUserByEmail(
	_ context.Context,
	_ string,
) (*models.SupabaseAuthUser, error) {
	index := f.findCalls
	f.findCalls++

	var user *models.SupabaseAuthUser
	if index < len(f.findResults) {
		user = f.findResults[index]
	}

	var err error
	if index < len(f.findErrors) {
		err = f.findErrors[index]
	}

	return user, err
}

func (f *fakeSupabaseRegistrationAdmin) CreateUser(
	_ context.Context,
	email string,
	password string,
	fullName string,
) (*models.SupabaseAuthUser, error) {
	f.createCalls++
	f.createdEmail = email
	f.createdPassword = password
	f.createdFullName = fullName

	return f.createdUser, f.createErr
}

func (f *fakeSupabaseRegistrationAdmin) DeleteUser(
	_ context.Context,
	userID string,
) error {
	f.deleteCalls++
	f.deletedUserID = userID

	return f.deleteErr
}

type fakeSupabaseRegistrationWriter struct {
	user *models.AppUser
	err  error

	calls            int
	authUserID       string
	email            string
	phone            *string
	userRole         string
	userStatus       string
	applicationID    string
	membershipRole   string
	membershipStatus string
}

func (f *fakeSupabaseRegistrationWriter) CreateNewSupabaseIdentity(
	_ context.Context,
	authUserID string,
	email string,
	fullName string,
	phone *string,
	userRole string,
	userStatus string,
	applicationID string,
	membershipRole string,
	membershipStatus string,
) (*models.AppUser, error) {
	f.calls++
	f.authUserID = authUserID
	f.email = email
	f.phone = phone
	f.userRole = userRole
	f.userStatus = userStatus
	f.applicationID = applicationID
	f.membershipRole = membershipRole
	f.membershipStatus = membershipStatus

	if f.err != nil {
		return nil, f.err
	}

	if f.user != nil {
		return f.user, nil
	}

	return &models.AppUser{
		ID:         "internal-app-user-id",
		AuthUserID: &f.authUserID,
		Email:      email,
		FullName:   fullName,
		Role:       userRole,
		Status:     userStatus,
		Phone:      phone,
	}, nil
}

func activeRegistrationApplication() *fakeSupabaseRegistrationApplications {
	return &fakeSupabaseRegistrationApplications{
		application: &models.Application{
			ID:       "silapet-application-id",
			Code:     models.ApplicationCodeSilapet,
			Name:     "SILAPET",
			IsActive: true,
		},
	}
}

func TestSupabaseRegistrationCreatesMappedIdentity(t *testing.T) {
	admin := &fakeSupabaseRegistrationAdmin{
		findResults: []*models.SupabaseAuthUser{nil},
		createdUser: &models.SupabaseAuthUser{
			ID:    "supabase-auth-user-id",
			Email: "employee@example.com",
		},
	}
	writer := &fakeSupabaseRegistrationWriter{}
	service := NewSupabaseRegistrationService(
		&fakeSupabaseRegistrationUsers{results: []*models.AppUser{nil}},
		activeRegistrationApplication(),
		admin,
		writer,
	)

	identity, err := service.Register(
		context.Background(),
		" Employee@Example.com ",
		"RegistrationPassword123!",
		" Employee Example ",
		"08123456789",
		" SILAPET ",
	)
	if err != nil {
		t.Fatalf("register Supabase identity: %v", err)
	}

	if admin.createCalls != 1 ||
		admin.createdPassword != "RegistrationPassword123!" {

		t.Fatal("registration password was not sent unchanged to Supabase")
	}

	if writer.calls != 1 ||
		writer.authUserID != "supabase-auth-user-id" {

		t.Fatal("Supabase identity was not linked to the local profile")
	}

	if identity == nil || identity.User == nil ||
		identity.User.ID != "internal-app-user-id" ||
		identity.User.ID == writer.authUserID {

		t.Fatal("response did not preserve the internal app_users ID")
	}

	if identity.User.AuthUserID == nil ||
		*identity.User.AuthUserID != writer.authUserID {

		t.Fatal("returned profile does not contain the Supabase mapping")
	}

	if writer.applicationID != "silapet-application-id" ||
		writer.userRole != "user" ||
		writer.userStatus != models.UserStatusApproved ||
		writer.membershipRole != "user" ||
		writer.membershipStatus != models.MembershipStatusPending {

		t.Fatal("registration application, role, or status policy changed")
	}

	if writer.phone == nil || *writer.phone != "628123456789" {
		t.Fatal("phone normalization changed")
	}
}

func TestSupabaseRegistrationRejectsExistingProfiles(t *testing.T) {
	deletedAt := time.Now().UTC()
	tests := []struct {
		name        string
		user        *models.AppUser
		expectedErr error
	}{
		{
			name: "legacy unmapped",
			user: &models.AppUser{
				ID:     "legacy-app-user-id",
				Email:  "employee@example.com",
				Status: models.UserStatusApproved,
			},
			expectedErr: ErrAccountAlreadyExists,
		},
		{
			name: "mapped",
			user: func() *models.AppUser {
				authUserID := "mapped-auth-user-id"
				return &models.AppUser{
					ID:         "mapped-app-user-id",
					AuthUserID: &authUserID,
					Email:      "employee@example.com",
				}
			}(),
			expectedErr: ErrAccountAlreadyExists,
		},
		{
			name: "pending",
			user: &models.AppUser{
				ID:     "pending-app-user-id",
				Email:  "employee@example.com",
				Status: models.UserStatusPending,
			},
			expectedErr: ErrAccountAlreadyExists,
		},
		{
			name: "rejected",
			user: &models.AppUser{
				ID:     "rejected-app-user-id",
				Email:  "employee@example.com",
				Status: models.UserStatusRejected,
			},
			expectedErr: ErrAccountAlreadyExists,
		},
		{
			name: "deleted",
			user: &models.AppUser{
				ID:        "deleted-app-user-id",
				Email:     "employee@example.com",
				DeletedAt: &deletedAt,
			},
			expectedErr: ErrRegistrationIdentityConflict,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admin := &fakeSupabaseRegistrationAdmin{}
			writer := &fakeSupabaseRegistrationWriter{}
			service := NewSupabaseRegistrationService(
				&fakeSupabaseRegistrationUsers{
					results: []*models.AppUser{test.user},
				},
				activeRegistrationApplication(),
				admin,
				writer,
			)

			_, err := service.Register(
				context.Background(),
				"employee@example.com",
				"RegistrationPassword123!",
				"Employee Example",
				"",
				models.ApplicationCodeSilapet,
			)
			if !errors.Is(err, test.expectedErr) {
				t.Fatalf("expected %v, got %v", test.expectedErr, err)
			}

			if admin.createCalls != 0 || writer.calls != 0 {
				t.Fatal("existing profile caused registration writes")
			}
		})
	}
}

func TestSupabaseRegistrationRejectsInactiveApplication(t *testing.T) {
	admin := &fakeSupabaseRegistrationAdmin{}
	writer := &fakeSupabaseRegistrationWriter{}
	service := NewSupabaseRegistrationService(
		&fakeSupabaseRegistrationUsers{},
		&fakeSupabaseRegistrationApplications{
			application: &models.Application{
				ID:       "inactive-application-id",
				Code:     models.ApplicationCodeSilapet,
				IsActive: false,
			},
		},
		admin,
		writer,
	)

	_, err := service.Register(
		context.Background(),
		"employee@example.com",
		"RegistrationPassword123!",
		"Employee Example",
		"",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrUnsupportedApplication) {
		t.Fatalf("expected unsupported application, got %v", err)
	}

	if admin.createCalls != 0 || writer.calls != 0 {
		t.Fatal("inactive application caused registration writes")
	}
}

func TestSupabaseRegistrationRejectsUnmappedAuthIdentity(t *testing.T) {
	admin := &fakeSupabaseRegistrationAdmin{
		findResults: []*models.SupabaseAuthUser{
			{
				ID:    "existing-auth-user-id",
				Email: "employee@example.com",
			},
		},
	}
	writer := &fakeSupabaseRegistrationWriter{}
	service := NewSupabaseRegistrationService(
		&fakeSupabaseRegistrationUsers{results: []*models.AppUser{nil}},
		activeRegistrationApplication(),
		admin,
		writer,
	)

	_, err := service.Register(
		context.Background(),
		"employee@example.com",
		"RegistrationPassword123!",
		"Employee Example",
		"",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrRegistrationIdentityConflict) {
		t.Fatalf("expected identity conflict, got %v", err)
	}

	if admin.createCalls != 0 || writer.calls != 0 {
		t.Fatal("ambiguous Supabase identity caused registration writes")
	}
}

func TestSupabaseRegistrationCreateFailureDoesNotCreateProfile(t *testing.T) {
	admin := &fakeSupabaseRegistrationAdmin{
		findResults: []*models.SupabaseAuthUser{nil, nil},
		createErr:   errors.New("Supabase create failed"),
	}
	writer := &fakeSupabaseRegistrationWriter{}
	service := NewSupabaseRegistrationService(
		&fakeSupabaseRegistrationUsers{results: []*models.AppUser{nil}},
		activeRegistrationApplication(),
		admin,
		writer,
	)

	_, err := service.Register(
		context.Background(),
		"employee@example.com",
		"RegistrationPassword123!",
		"Employee Example",
		"",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrAuthUnavailable) {
		t.Fatalf("expected auth unavailable, got %v", err)
	}

	if writer.calls != 0 {
		t.Fatal("Supabase create failure created a local profile")
	}
}

func TestSupabaseRegistrationDatabaseFailuresAreCompensated(t *testing.T) {
	tests := []struct {
		name      string
		writerErr error
	}{
		{
			name:      "profile creation",
			writerErr: errors.New("profile insert failed"),
		},
		{
			name: "membership creation",
			writerErr: repository.
				ErrCentralRegistrationApplicationUnavailable,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admin := &fakeSupabaseRegistrationAdmin{
				findResults: []*models.SupabaseAuthUser{nil},
				createdUser: &models.SupabaseAuthUser{
					ID:    "created-auth-user-id",
					Email: "employee@example.com",
				},
			}
			writer := &fakeSupabaseRegistrationWriter{err: test.writerErr}
			service := NewSupabaseRegistrationService(
				&fakeSupabaseRegistrationUsers{
					results: []*models.AppUser{nil},
				},
				activeRegistrationApplication(),
				admin,
				writer,
			)

			_, err := service.Register(
				context.Background(),
				"employee@example.com",
				"RegistrationPassword123!",
				"Employee Example",
				"",
				models.ApplicationCodeSilapet,
			)
			if err == nil {
				t.Fatal("expected registration failure")
			}

			if admin.deleteCalls != 1 ||
				admin.deletedUserID != "created-auth-user-id" {

				t.Fatal("database failure did not delete created auth identity")
			}
		})
	}
}

func TestSupabaseRegistrationConcurrentDuplicateDoesNotOverwrite(t *testing.T) {
	concurrentAuthUserID := "concurrent-auth-user-id"
	concurrentProfile := &models.AppUser{
		ID:         "concurrent-app-user-id",
		AuthUserID: &concurrentAuthUserID,
		Email:      "employee@example.com",
	}
	users := &fakeSupabaseRegistrationUsers{
		results: []*models.AppUser{nil, concurrentProfile},
	}
	admin := &fakeSupabaseRegistrationAdmin{
		findResults: []*models.SupabaseAuthUser{
			nil,
			{
				ID:    concurrentAuthUserID,
				Email: concurrentProfile.Email,
			},
		},
		createErr: errors.New("duplicate auth email"),
	}
	writer := &fakeSupabaseRegistrationWriter{}
	service := NewSupabaseRegistrationService(
		users,
		activeRegistrationApplication(),
		admin,
		writer,
	)

	_, err := service.Register(
		context.Background(),
		concurrentProfile.Email,
		"RegistrationPassword123!",
		"Employee Example",
		"",
		models.ApplicationCodeSilapet,
	)
	if !errors.Is(err, ErrAccountAlreadyExists) {
		t.Fatalf("expected account already exists, got %v", err)
	}

	if writer.calls != 0 || admin.deleteCalls != 0 ||
		*concurrentProfile.AuthUserID != concurrentAuthUserID {

		t.Fatal("concurrent registration overwrote or deleted existing mapping")
	}
}

func TestSupabaseRegistrationHasNoLegacyCredentialDependency(t *testing.T) {
	service := NewSupabaseRegistrationService(
		&fakeSupabaseRegistrationUsers{},
		activeRegistrationApplication(),
		&fakeSupabaseRegistrationAdmin{},
		&fakeSupabaseRegistrationWriter{},
	)

	if service == nil {
		t.Fatal("expected registration service")
	}

	// The constructor and writer contract intentionally expose no credential
	// repository, password hash, or auth_credentials operation.
}
