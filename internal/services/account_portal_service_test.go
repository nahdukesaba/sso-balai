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
	portal, err := NewAccountPortalService(browser, applications, "http://localhost:8081/")
	if err != nil {
		t.Fatal(err)
	}
	view, err := portal.View(context.Background(), "portal-cookie")
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Applications) != 1 || view.Applications[0].Launchable ||
		view.Applications[0].LaunchURL != "" || view.Applications[0].StatusLabel != "Menunggu persetujuan" {
		t.Fatalf("pending membership became launchable: %#v", view.Applications)
	}

	applications.applications[0].Status = models.MembershipStatusApproved
	view, err = portal.View(context.Background(), "portal-cookie")
	if err != nil {
		t.Fatal(err)
	}
	card := view.Applications[0]
	if !card.Launchable || card.LaunchURL != "http://localhost:8081/" || card.Name != "SILAPET" {
		t.Fatalf("approved application did not use server metadata: %#v", card)
	}
}

func TestAccountPortalRejectsUnsafeLaunchConfiguration(t *testing.T) {
	browser, _, _, _, _, _ := newBrowserSSOTestService(t)
	for _, launchURL := range []string{"", "/relative", "javascript:alert(1)", "https://user@example.com/"} {
		if _, err := NewAccountPortalService(browser, &fakeAccountPortalApplications{}, launchURL); err == nil {
			t.Fatalf("unsafe launch URL accepted: %q", launchURL)
		}
	}
}
