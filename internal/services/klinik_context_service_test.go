package services

import (
	"context"
	"errors"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeKlinikIdentityStore struct {
	identity *models.KlinikIdentity
	err      error
}

func (f *fakeKlinikIdentityStore) GetByAppUserID(
	context.Context,
	string,
) (*models.KlinikIdentity, error) {
	return f.identity, f.err
}

func canonicalKlinikIdentity() *models.KlinikIdentity {
	phone := "08123456789"
	nip := "198001012010011001"
	return &models.KlinikIdentity{
		AppUserID:       "app-user-1",
		AuthUserID:      "auth-user-1",
		Email:           "pegawai@example.com",
		FullName:        "Pegawai Klinik",
		Phone:           &phone,
		NIP:             &nip,
		ApplicationCode: models.ApplicationCodeKlinikPKP,
		Role:            "admin",
		Status:          models.MembershipStatusApproved,
	}
}

func TestKlinikContextServiceReturnsCanonicalIdentityWithoutLocalUser(t *testing.T) {
	want := canonicalKlinikIdentity()
	service := NewKlinikContextService(&fakeKlinikIdentityStore{identity: want})

	got, err := service.GetByAppUserID(context.Background(), want.AppUserID)
	if err != nil {
		t.Fatalf("get canonical Klinik identity: %v", err)
	}
	if got != want {
		t.Fatalf("expected canonical identity pointer, got %#v", got)
	}
	if got.NIP == nil || *got.NIP != "198001012010011001" {
		t.Fatalf("expected NIP from canonical app_pegawai projection, got %#v", got.NIP)
	}
}

func TestKlinikContextServiceAcceptsKlinikRoles(t *testing.T) {
	for _, role := range []string{"admin", "user", " ADMIN ", "USER"} {
		t.Run(role, func(t *testing.T) {
			identity := canonicalKlinikIdentity()
			identity.Role = role
			service := NewKlinikContextService(&fakeKlinikIdentityStore{identity: identity})

			got, err := service.GetByAppUserID(context.Background(), identity.AppUserID)
			if err != nil {
				t.Fatalf("expected accepted role %q, got %v", role, err)
			}
			if got.Role != normalizeKlinikRole(role) {
				t.Fatalf("expected normalized role %q, got %q", normalizeKlinikRole(role), got.Role)
			}
		})
	}
}

func TestKlinikContextServiceRejectsUnavailableCanonicalIdentity(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*models.KlinikIdentity)
		nilID  bool
	}{
		{name: "missing identity", nilID: true},
		{name: "different app user", mutate: func(identity *models.KlinikIdentity) { identity.AppUserID = "other-user" }},
		{name: "missing auth user", mutate: func(identity *models.KlinikIdentity) { identity.AuthUserID = "" }},
		{name: "other application", mutate: func(identity *models.KlinikIdentity) { identity.ApplicationCode = "silapet" }},
		{name: "pending membership", mutate: func(identity *models.KlinikIdentity) { identity.Status = models.MembershipStatusPending }},
		{name: "rejected membership", mutate: func(identity *models.KlinikIdentity) { identity.Status = models.MembershipStatusRejected }},
		{name: "disabled membership", mutate: func(identity *models.KlinikIdentity) { identity.Status = "disabled" }},
		{name: "invalid role", mutate: func(identity *models.KlinikIdentity) { identity.Role = "operator" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := canonicalKlinikIdentity()
			if test.nilID {
				identity = nil
			} else if test.mutate != nil {
				test.mutate(identity)
			}
			service := NewKlinikContextService(&fakeKlinikIdentityStore{identity: identity})

			_, err := service.GetByAppUserID(context.Background(), "app-user-1")
			if !errors.Is(err, ErrKlinikAccountUnavailable) {
				t.Fatalf("expected Klinik account unavailable, got %v", err)
			}
		})
	}
}

func TestKlinikContextServicePropagatesRepositoryError(t *testing.T) {
	want := errors.New("database unavailable")
	service := NewKlinikContextService(&fakeKlinikIdentityStore{err: want})

	_, err := service.GetByAppUserID(context.Background(), "app-user-1")
	if !errors.Is(err, want) {
		t.Fatalf("expected repository error, got %v", err)
	}
}

func normalizeKlinikRole(role string) string {
	if role == " ADMIN " || role == "admin" {
		return "admin"
	}
	return "user"
}
