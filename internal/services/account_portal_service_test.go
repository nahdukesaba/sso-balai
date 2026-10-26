package services

import (
	"context"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type fakeAccountPortalApplications struct {
	applications []models.PortalApplicationAccess
}

func (f *fakeAccountPortalApplications) ListForPortalUser(
	context.Context,
	string,
) ([]models.PortalApplicationAccess, error) {
	return f.applications, nil
}

func TestAccountPortalLaunchRequiresApprovedMembershipAndServerURL(t *testing.T) {
	browser, store, _, _, _, _ := newBrowserSSOTestService(t)
	store.session = &models.BrowserSSOSession{
		TokenHash: hashOpaqueToken("portal-cookie"), AuthUserID: "auth-user-id", AppUserID: "app-user-id",
	}
	applications := &fakeAccountPortalApplications{applications: []models.PortalApplicationAccess{
		{Code: "silapet", Name: "Browser supplied label", Role: "user", Status: models.MembershipStatusPending, HasMembership: true},
	}}
	portal, err := NewAccountPortalService(
		browser, applications, "http://silapet.test:8081/api/auth/sso/start", "http://klinik-pkp.test:3000/api/auth/sso/start",
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := portal.View(context.Background(), "portal-cookie", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Applications) != 1 || view.Applications[0].Launchable ||
		view.Applications[0].LaunchURL != "" || view.Applications[0].StatusLabel != "Menunggu Persetujuan" ||
		view.Applications[0].Description != "Portal layanan peminjaman fasilitas sarana, prasarana, serta kendaraan operasional resmi BP3KP Sumatera II" {
		t.Fatalf("pending membership became launchable: %#v", view.Applications)
	}

	applications.applications[0].Status = models.MembershipStatusApproved
	view, err = portal.View(context.Background(), "portal-cookie", "")
	if err != nil {
		t.Fatal(err)
	}
	card := view.Applications[0]
	if !card.Launchable || card.LaunchURL != "/portal/launch?app=silapet" || card.Name != "SILAPET" {
		t.Fatalf("approved application did not use server metadata: %#v", card)
	}
	launchTarget, err := portal.Launch(context.Background(), "portal-cookie", "silapet")
	if err != nil || launchTarget != "http://silapet.test:8081/api/auth/sso/start" {
		t.Fatalf("unexpected launch target: target=%q err=%v", launchTarget, err)
	}
}

func TestAccountPortalRejectsUnsafeLaunchConfiguration(t *testing.T) {
	browser, _, _, _, _, _ := newBrowserSSOTestService(t)
	for _, launchURL := range []string{"", "/relative", "javascript:alert(1)", "https://user@example.com/"} {
		if _, err := NewAccountPortalService(
			browser, &fakeAccountPortalApplications{}, launchURL, "http://localhost:3000/",
		); err == nil {
			t.Fatalf("unsafe launch URL accepted: %q", launchURL)
		}
	}
	for _, launchURL := range []string{"", "/relative", "javascript:alert(1)", "https://user@example.com/"} {
		if _, err := NewAccountPortalService(
			browser, &fakeAccountPortalApplications{}, "http://localhost:8081/", launchURL,
		); err == nil {
			t.Fatalf("unsafe Klinik launch URL accepted: %q", launchURL)
		}
	}
}

func TestAccountPortalKlinikMetadataAndApplicationSpecificAccess(t *testing.T) {
	browser, store, _, _, _, _ := newBrowserSSOTestService(t)
	store.session = &models.BrowserSSOSession{
		TokenHash: hashOpaqueToken("portal-cookie"), AuthUserID: "auth-user-id", AppUserID: "app-user-id",
	}
	applications := &fakeAccountPortalApplications{applications: []models.PortalApplicationAccess{
		{
			Code: models.ApplicationCodeKlinikPKP, Name: "Untrusted name", Role: "admin",
			Status: models.MembershipStatusApproved, HasMembership: true,
		},
	}}
	portal, err := NewAccountPortalService(
		browser, applications, "http://silapet.test:8081/api/auth/sso/start", "http://klinik-pkp.test:3000/api/auth/sso/start",
	)
	if err != nil {
		t.Fatal(err)
	}

	view, err := portal.View(context.Background(), "portal-cookie", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Applications) != 1 {
		t.Fatalf("unexpected applications: %#v", view.Applications)
	}
	card := view.Applications[0]
	if card.Name != "Klinik PKP" || card.Description != "Portal layanan informasi, konsultasi, dan pendampingan teknis perumahan serta permukiman BP3KP Sumatera II" ||
		card.RoleLabel != "Admin" || card.StatusLabel != "Akses Aktif" || !card.Launchable ||
		card.LaunchURL != "/portal/launch?app=klinik_pkp" {
		t.Fatalf("unexpected Klinik card: %#v", card)
	}
	launchTarget, err := portal.Launch(context.Background(), "portal-cookie", "klinik_pkp")
	if err != nil || launchTarget != "http://klinik-pkp.test:3000/api/auth/sso/start" {
		t.Fatalf("unexpected Klinik launch target: target=%q err=%v", launchTarget, err)
	}

	applications.applications[0].Role = "user"
	applications.applications[0].Status = models.MembershipStatusPending
	view, err = portal.View(context.Background(), "portal-cookie", "")
	if err != nil {
		t.Fatal(err)
	}
	card = view.Applications[0]
	if card.RoleLabel != "Pengguna" || card.StatusLabel != "Menunggu Persetujuan" ||
		card.Launchable || card.LaunchURL != "" {
		t.Fatalf("pending Klinik card became launchable: %#v", card)
	}
}

func TestPortalStatusLabelsMatchPortalCopy(t *testing.T) {
	tests := []struct {
		name          string
		status        string
		hasMembership bool
		want          string
	}{
		{name: "no membership", status: models.MembershipStatusApproved, want: "Belum Memiliki Akses"},
		{name: "approved", status: models.MembershipStatusApproved, hasMembership: true, want: "Akses Aktif"},
		{name: "pending", status: models.MembershipStatusPending, hasMembership: true, want: "Menunggu Persetujuan"},
		{name: "rejected", status: models.MembershipStatusRejected, hasMembership: true, want: "Akses Ditolak"},
		{name: "disabled", status: models.MembershipStatusDisabled, hasMembership: true, want: "Akses Dinonaktifkan"},
		{name: "unknown", status: "unknown", hasMembership: true, want: "Akses Tidak Tersedia"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := portalStatusLabel(test.status, test.hasMembership); got != test.want {
				t.Fatalf("unexpected portal status label: got %q want %q", got, test.want)
			}
		})
	}
}
