package services

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

type AccountPortalApplicationStore interface {
	ListForPortalUser(context.Context, string) ([]models.PortalApplicationAccess, error)
}

type accountPortalApplicationMetadata struct {
	Name        string
	Description string
	LaunchURL   string
}

type AccountPortalService struct {
	browser      *BrowserSSOService
	applications AccountPortalApplicationStore
	metadata     map[string]accountPortalApplicationMetadata
}

func NewAccountPortalService(
	browser *BrowserSSOService,
	applications AccountPortalApplicationStore,
	silapetLaunchURL string,
	klinikLaunchURL string,
) (*AccountPortalService, error) {
	if browser == nil || applications == nil {
		return nil, errors.New("account portal dependencies are required")
	}
	silapetLaunchURL = strings.TrimSpace(silapetLaunchURL)
	if !validPortalLaunchURL(silapetLaunchURL) {
		return nil, errors.New("PORTAL_SILAPET_LAUNCH_URL must be an absolute HTTP(S) URL")
	}
	klinikLaunchURL = strings.TrimSpace(klinikLaunchURL)
	if !validPortalLaunchURL(klinikLaunchURL) {
		return nil, errors.New("PORTAL_KLINIK_LAUNCH_URL must be an absolute HTTP(S) URL")
	}
	return &AccountPortalService{
		browser:      browser,
		applications: applications,
		metadata: map[string]accountPortalApplicationMetadata{
			models.ApplicationCodeSilapet: {
				Name:        "SILAPET",
				Description: "Layanan peminjaman fasilitas dan kendaraan Balai.",
				LaunchURL:   silapetLaunchURL,
			},
			models.ApplicationCodeKlinikPKP: {
				Name:        "Klinik PKP",
				Description: "Portal layanan informasi, konsultasi, dan pendampingan teknis BP3KP Sumatera II untuk sektor perumahan dan kawasan permukiman.",
				LaunchURL:   klinikLaunchURL,
			},
		},
	}, nil
}

func validPortalLaunchURL(value string) bool {
	if strings.ContainsAny(value, "*#") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}

func (s *AccountPortalService) View(
	ctx context.Context,
	browserToken string,
) (*models.AccountPortalView, error) {
	identity, err := s.browser.ResolveBrowserIdentity(ctx, browserToken)
	if err != nil {
		return nil, err
	}
	view := &models.AccountPortalView{Identity: identity}
	if identity == nil || identity.User == nil {
		return view, nil
	}

	accesses, err := s.applications.ListForPortalUser(ctx, identity.User.ID)
	if err != nil {
		return nil, err
	}
	view.Applications = make([]models.PortalApplicationCard, 0, len(accesses))
	for _, access := range accesses {
		metadata := s.metadata[strings.ToLower(strings.TrimSpace(access.Code))]
		name := strings.TrimSpace(metadata.Name)
		if name == "" {
			name = strings.TrimSpace(access.Name)
		}
		statusLabel := portalStatusLabel(access.Status, access.HasMembership)
		roleLabel := portalRoleLabel(access.Role, access.HasMembership)
		launchable := access.HasMembership && access.Status == models.MembershipStatusApproved &&
			validPortalLaunchURL(metadata.LaunchURL)
		launchURL := ""
		if launchable {
			launchURL = metadata.LaunchURL
		}
		view.Applications = append(view.Applications, models.PortalApplicationCard{
			Code:        access.Code,
			Name:        name,
			Description: metadata.Description,
			StatusLabel: statusLabel,
			RoleLabel:   roleLabel,
			LaunchURL:   launchURL,
			Launchable:  launchable,
		})
	}
	return view, nil
}

func (s *AccountPortalService) Login(
	ctx context.Context,
	email string,
	password string,
) (string, time.Time, error) {
	return s.browser.Login(ctx, email, password)
}

func portalStatusLabel(status string, hasMembership bool) string {
	if !hasMembership {
		return "Belum memiliki akses"
	}
	switch status {
	case models.MembershipStatusApproved:
		return "Akses aktif"
	case models.MembershipStatusPending:
		return "Menunggu persetujuan"
	case models.MembershipStatusRejected:
		return "Akses ditolak"
	case models.MembershipStatusDisabled:
		return "Akses dinonaktifkan"
	default:
		return "Status akses tidak tersedia"
	}
}

func portalRoleLabel(role string, hasMembership bool) string {
	if !hasMembership {
		return ""
	}
	switch role {
	case "admin":
		return "Admin"
	case "user":
		return "Pengguna"
	default:
		return ""
	}
}
