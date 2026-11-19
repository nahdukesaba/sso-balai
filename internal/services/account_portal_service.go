package services

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
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
	mu           sync.RWMutex
	metadata     map[string]accountPortalApplicationMetadata
}

func NewAccountPortalService(
	browser *BrowserSSOService,
	applications AccountPortalApplicationStore,
	silapetLaunchURL string,
	klinikLaunchURL string,
	arsiparisLaunchURL ...string,
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
	var resolvedArsiparisLaunchURL string
	if len(arsiparisLaunchURL) > 0 {
		resolvedArsiparisLaunchURL = strings.TrimSpace(arsiparisLaunchURL[0])
		if !validPortalLaunchURL(resolvedArsiparisLaunchURL) {
			return nil, errors.New("PORTAL_ARSIPARIS_LAUNCH_URL must be an absolute HTTP(S) URL")
		}
	}
	metadata := map[string]accountPortalApplicationMetadata{
		models.ApplicationCodeSilapet: {
			Name:        "SILAPET",
			Description: "Portal layanan peminjaman fasilitas sarana, prasarana, serta kendaraan operasional resmi BP3KP Sumatera II",
			LaunchURL:   silapetLaunchURL,
		},
		models.ApplicationCodeKlinikPKP: {
			Name:        "Klinik PKP",
			Description: "Portal layanan informasi, konsultasi, dan pendampingan teknis perumahan serta permukiman BP3KP Sumatera II",
			LaunchURL:   klinikLaunchURL,
		},
		models.ApplicationCodeArsiparis: {
			Name:        "Arsiparis",
			Description: "Portal layanan pengelolaan arsip kegiatan, laporan, dan bukti dukung resmi BP3KP Sumatera II",
			LaunchURL:   resolvedArsiparisLaunchURL,
		},
	}
	return &AccountPortalService{
		browser:      browser,
		applications: applications,
		metadata:     metadata,
	}, nil
}


func (s *AccountPortalService) getMetadata(code string) (accountPortalApplicationMetadata, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	meta, ok := s.metadata[strings.ToLower(strings.TrimSpace(code))]
	return meta, ok
}

func (s *AccountPortalService) RemoveApplication(code string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.metadata, strings.ToLower(strings.TrimSpace(code)))
}

func (s *AccountPortalService) RegisterApplication(code, name, description, launchURL string) error {
	if s == nil {
		return errors.New("account portal service is required")
	}
	code = strings.ToLower(strings.TrimSpace(code))
	launchURL = strings.TrimSpace(launchURL)
	if code == "" || !validPortalLaunchURL(launchURL) {
		return errors.New("valid application code and launch URL are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metadata[code] = accountPortalApplicationMetadata{
		Name:        strings.TrimSpace(name),
		Description: strings.TrimSpace(description),
		LaunchURL:   launchURL,
	}
	return nil
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
	pendingRequest string,
) (*models.AccountPortalView, error) {
	identity, err := s.browser.ResolveBrowserIdentity(ctx, browserToken)
	if err != nil {
		return nil, err
	}
	view := &models.AccountPortalView{Identity: identity}
	if strings.TrimSpace(pendingRequest) != "" {
		applicationCode, pendingErr := s.browser.PendingAuthorization(pendingRequest)
		if pendingErr != nil {
			return nil, pendingErr
		}
		metadata, _ := s.getMetadata(applicationCode)
		name := strings.TrimSpace(metadata.Name)
		if name == "" {
			name = applicationCode
		}
		view.PendingAuthorization = &models.PortalPendingAuthorization{
			ApplicationName: name,
			Request:         pendingRequest,
			LoginURL:        "/account/login?request=" + url.QueryEscape(pendingRequest),
			ContinueURL:     "/authorize/continue?request=" + url.QueryEscape(pendingRequest),
		}
	}
	if identity == nil || identity.User == nil {
		return view, nil
	}

	accesses, err := s.applications.ListForPortalUser(ctx, identity.User.ID)
	if err != nil {
		return nil, err
	}
	view.Applications = make([]models.PortalApplicationCard, 0, len(accesses))
	for _, access := range accesses {
		metadata, ok := s.getMetadata(access.Code)
		if !ok {
			continue
		}
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
			launchURL = "/portal/launch?app=" + url.QueryEscape(access.Code)
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

func (s *AccountPortalService) Launch(
	ctx context.Context,
	browserToken string,
	applicationCode string,
) (string, error) {
	identity, err := s.browser.ResolveBrowserIdentity(ctx, browserToken)
	if err != nil {
		return "", err
	}
	if identity == nil || identity.User == nil {
		return "", ErrAccountUnavailable
	}
	appCode := strings.ToLower(strings.TrimSpace(applicationCode))
	accesses, err := s.applications.ListForPortalUser(ctx, identity.User.ID)
	if err != nil {
		return "", err
	}
	var targetAccess *models.PortalApplicationAccess
	for i := range accesses {
		if strings.EqualFold(accesses[i].Code, appCode) {
			targetAccess = &accesses[i]
			break
		}
	}
	if targetAccess == nil || !targetAccess.HasMembership || targetAccess.Status != models.MembershipStatusApproved {
		return "", ErrAccountUnavailable
	}
	metadata, ok := s.getMetadata(appCode)
	if !ok || !validPortalLaunchURL(metadata.LaunchURL) {
		return "", ErrAccountUnavailable
	}
	return metadata.LaunchURL, nil
}

func (s *AccountPortalService) ConfiguredLaunchURL(applicationCode string) string {
	appCode := strings.ToLower(strings.TrimSpace(applicationCode))
	meta, _ := s.getMetadata(appCode)
	return meta.LaunchURL
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
		return "Belum Memiliki Akses"
	}
	switch status {
	case models.MembershipStatusApproved:
		return "Akses Aktif"
	case models.MembershipStatusPending:
		return "Menunggu Persetujuan"
	case models.MembershipStatusRejected:
		return "Akses Ditolak"
	case models.MembershipStatusDisabled:
		return "Akses Dinonaktifkan"
	default:
		return "Akses Tidak Tersedia"
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
