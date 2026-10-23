package services

import (
	"context"
	"errors"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

type fakeKlinikAdminAuthorizer struct {
	result *models.ApplicationContext
	err    error
	code   string
	userID string
}

func (f *fakeKlinikAdminAuthorizer) GetByAppUserID(_ context.Context, userID, code string) (*models.ApplicationContext, error) {
	f.userID, f.code = userID, code
	return f.result, f.err
}

type fakeKlinikProvisioningAdmin struct {
	found                               *models.SupabaseAuthUser
	findErr                             error
	invited                             *models.SupabaseAuthUser
	inviteErr                           error
	findCalls, inviteCalls, deleteCalls int
	deletedID                           string
}

func (f *fakeKlinikProvisioningAdmin) FindUserByEmail(context.Context, string) (*models.SupabaseAuthUser, error) {
	f.findCalls++
	return f.found, f.findErr
}
func (f *fakeKlinikProvisioningAdmin) InviteUser(context.Context, string, string) (*models.SupabaseAuthUser, error) {
	f.inviteCalls++
	return f.invited, f.inviteErr
}
func (f *fakeKlinikProvisioningAdmin) DeleteUser(_ context.Context, id string) error {
	f.deleteCalls++
	f.deletedID = id
	return nil
}

type fakeKlinikProvisioningWriter struct {
	result                      *models.KlinikAdminUser
	err                         error
	calls                       int
	authID, email, role, status string
}

func (f *fakeKlinikProvisioningWriter) Provision(_ context.Context, authID, email, fullName string, phone, nip, nik, alamat, gelarDepan, gelarBelakang *string, role, status string) (*models.KlinikAdminUser, error) {
	f.calls++
	f.authID, f.email, f.role, f.status = authID, email, role, status
	return f.result, f.err
}

func approvedKlinikAdminAuthorizer() *fakeKlinikAdminAuthorizer {
	return &fakeKlinikAdminAuthorizer{result: &models.ApplicationContext{Application: models.ApplicationCodeKlinikPKP, Role: "admin", Status: models.MembershipStatusApproved}}
}
func validKlinikProvisioningInput() KlinikAdminProvisioningInput {
	return KlinikAdminProvisioningInput{Email: " User@Example.com ", FullName: " User Example ", NIP: "198001012010011001", Role: "user", Status: models.MembershipStatusPending}
}

func TestKlinikAdminProvisioningReusesExistingSupabaseIdentity(t *testing.T) {
	authorizer := approvedKlinikAdminAuthorizer()
	admin := &fakeKlinikProvisioningAdmin{found: &models.SupabaseAuthUser{ID: "existing-auth", Email: "user@example.com"}}
	writer := &fakeKlinikProvisioningWriter{result: &models.KlinikAdminUser{AppUserID: "app-user", Email: "user@example.com"}}
	result, err := NewKlinikAdminUserService(authorizer, admin, writer).Provision(context.Background(), "actor", validKlinikProvisioningInput())
	if err != nil || result == nil || writer.authID != "existing-auth" || admin.inviteCalls != 0 {
		t.Fatalf("existing identity not reused: result=%#v err=%v", result, err)
	}
	if authorizer.code != models.ApplicationCodeKlinikPKP || writer.email != "user@example.com" || writer.role != "user" || writer.status != models.MembershipStatusPending {
		t.Fatal("Klinik scope or normalized payload changed")
	}
}

func TestKlinikAdminProvisioningInvitesNewIdentityWithoutPassword(t *testing.T) {
	admin := &fakeKlinikProvisioningAdmin{invited: &models.SupabaseAuthUser{ID: "invited-auth", Email: "user@example.com"}}
	writer := &fakeKlinikProvisioningWriter{result: &models.KlinikAdminUser{AppUserID: "app-user"}}
	_, err := NewKlinikAdminUserService(approvedKlinikAdminAuthorizer(), admin, writer).Provision(context.Background(), "actor", validKlinikProvisioningInput())
	if err != nil || admin.inviteCalls != 1 || writer.authID != "invited-auth" {
		t.Fatalf("new identity was not invited: %v", err)
	}
	// The admin interface deliberately exposes InviteUser(email, fullName), not
	// CreateUser(password), so no plaintext credential can enter this flow.
}

func TestKlinikAdminProvisioningRejectsUnauthorizedCaller(t *testing.T) {
	for _, applicationContext := range []*models.ApplicationContext{
		nil,
		{Role: "user", Status: models.MembershipStatusApproved},
		{Role: "admin", Status: models.MembershipStatusPending},
	} {
		admin := &fakeKlinikProvisioningAdmin{}
		writer := &fakeKlinikProvisioningWriter{}
		_, err := NewKlinikAdminUserService(&fakeKlinikAdminAuthorizer{result: applicationContext}, admin, writer).Provision(context.Background(), "actor", validKlinikProvisioningInput())
		if !errors.Is(err, ErrKlinikAdminForbidden) || admin.findCalls != 0 || writer.calls != 0 {
			t.Fatalf("unauthorized provisioning reached dependencies: %v", err)
		}
	}
}

func TestKlinikAdminProvisioningValidatesRoleAndStatus(t *testing.T) {
	for _, mutation := range []func(*KlinikAdminProvisioningInput){func(i *KlinikAdminProvisioningInput) { i.Role = "superadmin" }, func(i *KlinikAdminProvisioningInput) { i.Status = "active" }} {
		input := validKlinikProvisioningInput()
		mutation(&input)
		admin := &fakeKlinikProvisioningAdmin{}
		writer := &fakeKlinikProvisioningWriter{}
		_, err := NewKlinikAdminUserService(approvedKlinikAdminAuthorizer(), admin, writer).Provision(context.Background(), "actor", input)
		if !errors.Is(err, ErrInvalidKlinikProvisioningRequest) || admin.findCalls != 0 || writer.calls != 0 {
			t.Fatalf("invalid role/status was accepted: %v", err)
		}
	}
}

func TestKlinikAdminProvisioningCompensatesNewAuthIdentity(t *testing.T) {
	admin := &fakeKlinikProvisioningAdmin{invited: &models.SupabaseAuthUser{ID: "new-auth"}}
	writer := &fakeKlinikProvisioningWriter{err: repository.ErrKlinikProvisioningConflict}
	_, err := NewKlinikAdminUserService(approvedKlinikAdminAuthorizer(), admin, writer).Provision(context.Background(), "actor", validKlinikProvisioningInput())
	if !errors.Is(err, repository.ErrKlinikProvisioningConflict) || admin.deleteCalls != 1 || admin.deletedID != "new-auth" {
		t.Fatalf("new auth identity was not compensated: %v", err)
	}
}

func TestKlinikAdminProvisioningReusesConcurrentInvite(t *testing.T) {
	admin := &fakeKlinikProvisioningAdmin{inviteErr: errors.New("duplicate email")}
	findCalls := 0
	writer := &fakeKlinikProvisioningWriter{result: &models.KlinikAdminUser{AppUserID: "app-user"}}
	wrappedAdmin := &concurrentInviteAdmin{base: admin, calls: &findCalls}
	_, err := NewKlinikAdminUserService(approvedKlinikAdminAuthorizer(), wrappedAdmin, writer).Provision(context.Background(), "actor", validKlinikProvisioningInput())
	if err != nil || writer.authID != "concurrent-auth" || admin.deleteCalls != 0 {
		t.Fatalf("concurrent invite was not reused safely: %v", err)
	}
}

type concurrentInviteAdmin struct {
	base  *fakeKlinikProvisioningAdmin
	calls *int
}

func (a *concurrentInviteAdmin) FindUserByEmail(context.Context, string) (*models.SupabaseAuthUser, error) {
	*a.calls = *a.calls + 1
	if *a.calls == 1 {
		return nil, nil
	}
	return &models.SupabaseAuthUser{ID: "concurrent-auth", Email: "user@example.com"}, nil
}
func (a *concurrentInviteAdmin) InviteUser(ctx context.Context, email, name string) (*models.SupabaseAuthUser, error) {
	return a.base.InviteUser(ctx, email, name)
}
func (a *concurrentInviteAdmin) DeleteUser(ctx context.Context, id string) error {
	return a.base.DeleteUser(ctx, id)
}
