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
		view.Applications[0].LaunchURL != "" || view.Applications[0].StatusLabel != "Menunggu persetujuan" {
		t.Fatalf("pending membership became launchable: %#v", view.Applications)
	}

	applications.applications[0].Status = models.MembershipStatusApproved
	view, err = portal.View(context.Background(), "portal-cookie", "")
	if err != nil {
		t.Fatal(err)
	}
	card := view.Applications[0]
	if !card.Launchable || card.LaunchURL != "http://silapet.test:8081/api/auth/sso/start" || card.Name != "SILAPET" {
		t.Fatalf("approved application did not use server metadata: %#v", card)
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
	if card.Name != "Klinik PKP" || card.Description != "Portal layanan informasi, konsultasi, dan pendampingan teknis BP3KP Sumatera II untuk sektor perumahan dan kawasan permukiman." ||
		card.RoleLabel != "Admin" || card.StatusLabel != "Akses aktif" || !card.Launchable ||
		card.LaunchURL != "http://klinik-pkp.test:3000/api/auth/sso/start" {
		t.Fatalf("unexpected Klinik card: %#v", card)
	}

	applications.applications[0].Role = "user"
	applications.applications[0].Status = models.MembershipStatusPending
	view, err = portal.View(context.Background(), "portal-cookie", "")
	if err != nil {
		t.Fatal(err)
	}
	card = view.Applications[0]
	if card.RoleLabel != "Pengguna" || card.StatusLabel != "Menunggu persetujuan" ||
		card.Launchable || card.LaunchURL != "" {
		t.Fatalf("pending Klinik card became launchable: %#v", card)
	}
}
