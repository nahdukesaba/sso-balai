package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/repository"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

const ssoAdminCSRFCookie = "balai_sso_admin_csrf"

func (h *BrowserSSOHandler) SetAdminRepository(repo *repository.SSOAdminRepository) {
	if h != nil {
		h.adminRepo = repo
	}
}

func (h *BrowserSSOHandler) SetAdminAuthService(auth *services.SupabaseAdminService) {
	if h != nil {
		h.adminAuth = auth
	}
}

func (h *BrowserSSOHandler) requireSSOAdmin(c *fiber.Ctx) (string, string, bool) {
	if h == nil || h.service == nil || h.adminRepo == nil {
		_ = browserSSOError(c, fiber.StatusServiceUnavailable, "admin_unavailable", "Admin SSO tidak tersedia.")
		return "", "", false
	}
	token := strings.TrimSpace(c.Cookies(browserSSOSessionCookie))
	if token == "" {
		_ = c.Redirect("/account/login", fiber.StatusSeeOther)
		return "", "", false
	}
	identity, err := h.service.ResolveBrowserIdentity(c.UserContext(), token)
	if err != nil || identity == nil || identity.User == nil {
		_ = c.Redirect("/account/login", fiber.StatusSeeOther)
		return "", "", false
	}
	isAdmin, err := h.adminRepo.IsSSOAdmin(c.UserContext(), identity.User.ID)
	if err != nil || !isAdmin {
		_ = browserSSOError(c, fiber.StatusForbidden, "forbidden", "Akses khusus Admin Pusat SSO.")
		return "", "", false
	}
	return identity.User.ID, identity.User.FullName, true
}

func (h *BrowserSSOHandler) AdminSSOPage(c *fiber.Ctx) error {
	_, adminName, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}

	csrf, err := services.RandomBrowserSSOToken(32)
	if err != nil {
		return browserSSOError(c, fiber.StatusInternalServerError, "admin_unavailable", "Gagal menyiapkan sesi admin.")
	}
	h.setCookie(c, ssoAdminCSRFCookie, csrf, 1800, time.Time{})

	apps, err := h.adminRepo.ListApplications(c.UserContext())
	if err != nil {
		return browserSSOError(c, fiber.StatusInternalServerError, "admin_unavailable", "Gagal memuat daftar aplikasi.")
	}
	search := strings.TrimSpace(c.Query("q"))
	filter := strings.ToLower(strings.TrimSpace(c.Query("filter")))
	if filter != "deleted" && filter != "all" {
		filter = "active"
	}
	users, err := h.adminRepo.ListUsers(c.UserContext(), search, filter)
	if err != nil {
		return browserSSOError(c, fiber.StatusInternalServerError, "admin_unavailable", "Gagal memuat daftar pengguna.")
	}

	type appRow struct {
		repository.SSOAdminApplication
		RedirectURIsCSV           string
		PostLogoutRedirectURIsCSV string
	}
	appRows := make([]appRow, 0, len(apps))
	for _, a := range apps {
		appRows = append(appRows, appRow{
			SSOAdminApplication:       a,
			RedirectURIsCSV:           strings.Join(a.RedirectURIs, ", "),
			PostLogoutRedirectURIsCSV: strings.Join(a.PostLogoutRedirectURIs, ", "),
		})
	}

	setAccountPortalPageHeaders(c)
	var out strings.Builder
	err = ssoAdminTemplate.Execute(&out, struct {
		AdminName string
		CSRF      string
		Tab       string
		Search    string
		Filter    string
		Message   string
		Error     string
		Apps      []appRow
		Users     []repository.SSOAdminUser
	}{
		AdminName: adminName,
		CSRF:      csrf,
		Tab:       normalizeAdminTab(c.Query("tab")),
		Search:    search,
		Filter:    filter,
		Message:   strings.TrimSpace(c.Query("msg")),
		Error:     strings.TrimSpace(c.Query("err")),
		Apps:      appRows,
		Users:     users,
	})
	if err != nil {
		return err
	}
	return c.SendString(out.String())
}

func (h *BrowserSSOHandler) AdminSSOSaveApp(c *fiber.Ctx) error {
	_, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=apps&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	code := strings.ToLower(strings.TrimSpace(c.FormValue("code")))
	name := strings.TrimSpace(c.FormValue("name"))
	clientID := strings.TrimSpace(c.FormValue("client_id"))
	policy := strings.ToUpper(strings.TrimSpace(c.FormValue("access_policy")))
	launchURL := strings.TrimSpace(c.FormValue("launch_url"))
	description := strings.TrimSpace(c.FormValue("description"))
	isActive := c.FormValue("is_active") == "on" || c.FormValue("is_active") == "true"
	redirectURIs := splitTrimmedCSV(c.FormValue("redirect_uris"))
	postLogoutURIs := splitTrimmedCSV(c.FormValue("post_logout_redirect_uris"))
	if len(postLogoutURIs) == 0 && launchURL != "" {
		postLogoutURIs = []string{launchURL}
	}

	if code == "" || name == "" || clientID == "" || launchURL == "" || len(redirectURIs) == 0 {
		return c.Redirect("/admin/sso?tab=apps&err="+url.QueryEscape("Code, Nama, Client ID, Launch URL, dan Redirect URIs wajib diisi."), fiber.StatusSeeOther)
	}

	app := repository.SSOAdminApplication{
		Code:                   code,
		Name:                   name,
		IsActive:               isActive,
		ClientID:               clientID,
		AccessPolicy:           policy,
		RedirectURIs:           redirectURIs,
		PostLogoutRedirectURIs: postLogoutURIs,
		LaunchURL:              launchURL,
		Description:            description,
	}

	if err := h.adminRepo.UpsertApplication(c.UserContext(), app); err != nil {
		return c.Redirect("/admin/sso?tab=apps&err="+url.QueryEscape("Gagal menyimpan aplikasi: "+err.Error()), fiber.StatusSeeOther)
	}

	// Live-sync into BrowserSSOService & AccountPortalService without restart.
	if isActive {
		secretBytes := make([]byte, 24)
		_, _ = rand.Read(secretBytes)
		if err := h.service.UpsertClient(services.BrowserSSOClient{
			ClientID:               clientID,
			ApplicationCode:        code,
			AccessPolicy:           policy,
			IntrospectionSecret:    hex.EncodeToString(secretBytes),
			RedirectURIs:           redirectURIs,
			PostLogoutRedirectURIs: postLogoutURIs,
		}); err != nil {
			return c.Redirect("/admin/sso?tab=apps&err="+url.QueryEscape("Tersimpan di DB, tetapi URL tidak valid: "+err.Error()), fiber.StatusSeeOther)
		}
		if h.portalService != nil {
			_ = h.portalService.RegisterApplication(code, name, description, launchURL)
		}
	} else {
		h.service.RemoveClient(clientID)
		if h.portalService != nil {
			h.portalService.RemoveApplication(code)
		}
	}

	return c.Redirect("/admin/sso?tab=apps&msg="+url.QueryEscape("Aplikasi "+name+" berhasil disimpan dan langsung aktif."), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) AdminSSOSaveMembership(c *fiber.Ctx) error {
	_, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	userID := strings.TrimSpace(c.FormValue("app_user_id"))
	appID := strings.TrimSpace(c.FormValue("application_id"))
	role := strings.TrimSpace(c.FormValue("role"))
	status := strings.TrimSpace(c.FormValue("status"))
	search := strings.TrimSpace(c.FormValue("q"))

	if userID == "" || appID == "" {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Pengguna dan aplikasi wajib dipilih."), fiber.StatusSeeOther)
	}
	if err := h.adminRepo.UpsertMembership(c.UserContext(), userID, appID, role, status); err != nil {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("Gagal memperbarui akses pengguna."), fiber.StatusSeeOther)
	}
	return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&msg="+url.QueryEscape("Akses & role pengguna berhasil diperbarui."), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) AdminSSOToggleSuperAdmin(c *fiber.Ctx) error {
	currentUserID, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	targetID := strings.TrimSpace(c.FormValue("app_user_id"))
	isAdmin := c.FormValue("is_sso_admin") == "true"
	search := strings.TrimSpace(c.FormValue("q"))
	if targetID == "" {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Pengguna tidak valid."), fiber.StatusSeeOther)
	}
	if targetID == currentUserID && !isAdmin {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("Tidak dapat mencabut hak Admin Pusat dari akun sendiri."), fiber.StatusSeeOther)
	}
	if err := h.adminRepo.SetSSOAdmin(c.UserContext(), targetID, isAdmin); err != nil {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("Gagal mengubah status Admin Pusat."), fiber.StatusSeeOther)
	}
	return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&msg="+url.QueryEscape("Status Admin Pusat SSO berhasil diperbarui."), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) provisionAuthAndAppUser(
	c *fiber.Ctx,
	email string,
	fullName string,
	phone string,
	password string,
	isSSOAdmin bool,
) (string, error) {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	if cleanEmail == "" || !strings.Contains(cleanEmail, "@") {
		return "", fmt.Errorf("email tidak valid")
	}
	if strings.TrimSpace(fullName) == "" {
		return "", fmt.Errorf("nama lengkap wajib diisi")
	}

	var authUserID string
	if h.adminAuth != nil {
		existing, _ := h.adminAuth.FindUserByEmail(c.UserContext(), cleanEmail)
		if existing != nil && existing.ID != "" {
			authUserID = existing.ID
			if password != "" {
				_ = h.adminAuth.UpdateUser(c.UserContext(), authUserID, fullName, password)
			}
		} else if password != "" {
			created, err := h.adminAuth.CreateUser(c.UserContext(), cleanEmail, password, fullName)
			if err != nil {
				return "", err
			}
			authUserID = created.ID
		} else {
			invited, err := h.adminAuth.InviteUser(c.UserContext(), cleanEmail, fullName)
			if err != nil {
				return "", err
			}
			authUserID = invited.ID
		}
	}

	return h.adminRepo.UpsertUser(c.UserContext(), cleanEmail, fullName, phone, authUserID, isSSOAdmin)
}

func (h *BrowserSSOHandler) AdminSSOCreateUser(c *fiber.Ctx) error {
	_, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	email := strings.ToLower(strings.TrimSpace(c.FormValue("email")))
	fullName := strings.TrimSpace(c.FormValue("full_name"))
	phone := strings.TrimSpace(c.FormValue("phone"))
	password := c.FormValue("password")
	isSSOAdmin := c.FormValue("is_sso_admin") == "on" || c.FormValue("is_sso_admin") == "true"

	if password != "" && len(password) < 8 {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Password minimal 8 karakter (atau kosongkan untuk kirim undangan email)."), fiber.StatusSeeOther)
	}

	appUserID, err := h.provisionAuthAndAppUser(c, email, fullName, phone, password, isSSOAdmin)
	if err != nil {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Gagal membuat user: "+err.Error()), fiber.StatusSeeOther)
	}

	initialRole := strings.TrimSpace(c.FormValue("initial_role"))
	if form, formErr := c.MultipartForm(); formErr == nil && form != nil {
		for _, appID := range form.Value["app_ids"] {
			_ = h.adminRepo.UpsertMembership(c.UserContext(), appUserID, appID, initialRole, "approved")
		}
	} else if args := c.Context().PostArgs().PeekMulti("app_ids"); len(args) > 0 {
		for _, raw := range args {
			_ = h.adminRepo.UpsertMembership(c.UserContext(), appUserID, string(raw), initialRole, "approved")
		}
	}

	return c.Redirect("/admin/sso?tab=users&msg="+url.QueryEscape("User "+email+" berhasil ditambahkan."), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) AdminSSOUpdateUser(c *fiber.Ctx) error {
	_, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	userID := strings.TrimSpace(c.FormValue("app_user_id"))
	fullName := strings.TrimSpace(c.FormValue("full_name"))
	phone := strings.TrimSpace(c.FormValue("phone"))
	newPassword := c.FormValue("new_password")
	search := strings.TrimSpace(c.FormValue("q"))
	filter := strings.TrimSpace(c.FormValue("filter"))

	if userID == "" || fullName == "" {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&filter="+url.QueryEscape(filter)+"&err="+url.QueryEscape("Nama lengkap wajib diisi."), fiber.StatusSeeOther)
	}
	if newPassword != "" && len(newPassword) < 8 {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&filter="+url.QueryEscape(filter)+"&err="+url.QueryEscape("Password baru minimal 8 karakter."), fiber.StatusSeeOther)
	}

	user, err := h.adminRepo.GetUserByID(c.UserContext(), userID)
	if err != nil {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("User tidak ditemukan."), fiber.StatusSeeOther)
	}
	if err := h.adminRepo.UpdateUserProfile(c.UserContext(), userID, fullName, phone); err != nil {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("Gagal memperbarui profil user."), fiber.StatusSeeOther)
	}
	if h.adminAuth != nil && user.AuthUserID != "" {
		if err := h.adminAuth.UpdateUser(c.UserContext(), user.AuthUserID, fullName, newPassword); err != nil {
			return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("Profil tersimpan, tetapi gagal update password/auth: "+err.Error()), fiber.StatusSeeOther)
		}
	}

	return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&filter="+url.QueryEscape(filter)+"&msg="+url.QueryEscape("Data user "+user.Email+" berhasil diperbarui."), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) AdminSSODeleteUser(c *fiber.Ctx) error {
	currentUserID, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	targetID := strings.TrimSpace(c.FormValue("app_user_id"))
	search := strings.TrimSpace(c.FormValue("q"))
	if targetID == "" || targetID == currentUserID {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("Tidak dapat menghapus akun sendiri."), fiber.StatusSeeOther)
	}
	if err := h.adminRepo.SoftDeleteUser(c.UserContext(), targetID); err != nil {
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("Gagal menghapus user."), fiber.StatusSeeOther)
	}
	return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&msg="+url.QueryEscape("User berhasil dinonaktifkan (soft delete)."), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) AdminSSORestoreUser(c *fiber.Ctx) error {
	_, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	targetID := strings.TrimSpace(c.FormValue("app_user_id"))
	search := strings.TrimSpace(c.FormValue("q"))
	if targetID == "" {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("User tidak valid."), fiber.StatusSeeOther)
	}
	if err := h.adminRepo.RestoreUser(c.UserContext(), targetID); err != nil {
		return c.Redirect("/admin/sso?tab=users&filter=deleted&q="+url.QueryEscape(search)+"&err="+url.QueryEscape("Gagal memulihkan user."), fiber.StatusSeeOther)
	}
	return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&msg="+url.QueryEscape("User berhasil dipulihkan."), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) AdminSSOBulkImportUsers(c *fiber.Ctx) error {
	_, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	rawText := strings.TrimSpace(c.FormValue("csv_text"))
	if fileHeader, err := c.FormFile("csv_file"); err == nil && fileHeader != nil && fileHeader.Size > 0 {
		f, openErr := fileHeader.Open()
		if openErr == nil {
			defer f.Close()
			if data, readErr := io.ReadAll(io.LimitReader(f, 2<<20)); readErr == nil {
				if trimmed := strings.TrimSpace(string(data)); trimmed != "" {
					rawText = trimmed
				}
			}
		}
	}

	if rawText == "" {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Masukkan data CSV atau pilih file .csv terlebih dahulu."), fiber.StatusSeeOther)
	}

	rawText = strings.TrimPrefix(rawText, "\ufeff")
	comma := ','
	if strings.Contains(strings.SplitN(rawText, "\n", 2)[0], ";") && !strings.Contains(strings.SplitN(rawText, "\n", 2)[0], ",") {
		comma = ';'
	}
	reader := csv.NewReader(bytes.NewBufferString(rawText))
	reader.Comma = comma
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Format CSV tidak valid: "+err.Error()), fiber.StatusSeeOther)
	}

	targetAppID := strings.TrimSpace(c.FormValue("application_id"))
	targetRole := strings.TrimSpace(c.FormValue("role"))
	targetStatus := strings.TrimSpace(c.FormValue("status"))

	var okCount, failCount int
	for idx, row := range records {
		if len(row) < 2 {
			continue
		}
		email := strings.TrimSpace(row[0])
		fullName := strings.TrimSpace(row[1])
		if idx == 0 && (strings.EqualFold(email, "email") || strings.Contains(strings.ToLower(fullName), "nama")) {
			continue
		}
		phone := ""
		password := ""
		if len(row) >= 3 {
			phone = strings.TrimSpace(row[2])
		}
		if len(row) >= 4 {
			password = strings.TrimSpace(row[3])
		}
		uid, err := h.provisionAuthAndAppUser(c, email, fullName, phone, password, false)
		if err != nil {
			failCount++
			continue
		}
		if targetAppID != "" {
			_ = h.adminRepo.UpsertMembership(c.UserContext(), uid, targetAppID, targetRole, targetStatus)
		}
		okCount++
	}

	msg := fmt.Sprintf("Bulk import selesai: %d user berhasil diproses, %d gagal.", okCount, failCount)
	return c.Redirect("/admin/sso?tab=users&msg="+url.QueryEscape(msg), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) AdminSSOBulkAction(c *fiber.Ctx) error {
	currentUserID, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	if !verifyAdminCSRF(c) {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Sesi form kedaluwarsa, silakan coba lagi."), fiber.StatusSeeOther)
	}

	var userIDs []string
	for _, raw := range c.Context().PostArgs().PeekMulti("user_ids") {
		if id := strings.TrimSpace(string(raw)); id != "" {
			userIDs = append(userIDs, id)
		}
	}
	if len(userIDs) == 0 {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Centang minimal 1 pengguna terlebih dahulu."), fiber.StatusSeeOther)
	}

	action := strings.TrimSpace(c.FormValue("bulk_action"))
	search := strings.TrimSpace(c.FormValue("q"))
	filter := strings.TrimSpace(c.FormValue("filter"))

	if action == "delete" {
		affected, err := h.adminRepo.BulkSoftDeleteUsers(c.UserContext(), userIDs, currentUserID)
		if err != nil {
			return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Gagal menghapus massal user."), fiber.StatusSeeOther)
		}
		msg := fmt.Sprintf("%d user berhasil dihapus (soft delete).", affected)
		return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&filter="+url.QueryEscape(filter)+"&msg="+url.QueryEscape(msg), fiber.StatusSeeOther)
	}

	appID := strings.TrimSpace(c.FormValue("application_id"))
	role := strings.TrimSpace(c.FormValue("role"))
	status := strings.TrimSpace(c.FormValue("status"))
	if appID == "" {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Pilih aplikasi tujuan untuk bulk update akses."), fiber.StatusSeeOther)
	}
	affected, err := h.adminRepo.BulkUpsertMemberships(c.UserContext(), userIDs, appID, role, status)
	if err != nil {
		return c.Redirect("/admin/sso?tab=users&err="+url.QueryEscape("Gagal memperbarui akses massal."), fiber.StatusSeeOther)
	}
	msg := fmt.Sprintf("Akses massal berhasil diperbarui untuk %d user.", affected)
	return c.Redirect("/admin/sso?tab=users&q="+url.QueryEscape(search)+"&filter="+url.QueryEscape(filter)+"&msg="+url.QueryEscape(msg), fiber.StatusSeeOther)
}

func verifyAdminCSRF(c *fiber.Ctx) bool {
	csrf := strings.TrimSpace(c.FormValue("csrf"))
	cookieCSRF := strings.TrimSpace(c.Cookies(ssoAdminCSRFCookie))
	return csrf != "" && cookieCSRF != "" && subtle.ConstantTimeCompare([]byte(csrf), []byte(cookieCSRF)) == 1
}

func normalizeAdminTab(raw string) string {
	if strings.EqualFold(strings.TrimSpace(raw), "users") {
		return "users"
	}
	return "apps"
}

func splitTrimmedCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

const ssoAdminStyles = accountPortalStyles + `
.tabs{display:inline-flex;gap:.35rem;padding:.3rem;border:1px solid var(--line);border-radius:.75rem;background:#fff;margin-bottom:1.5rem}
.tab{padding:.5rem 1rem;border-radius:.55rem;text-decoration:none;font-size:.86rem;font-weight:600;color:var(--muted)}
.tab.active{background:var(--accent);color:#fff}
.alert{padding:.8rem 1rem;border-radius:.75rem;margin-bottom:1.25rem;font-size:.88rem;font-weight:600}
.alert.ok{background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46}
.alert.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b}
.panel-box{padding:1.5rem;border:1px solid var(--line);border-radius:1rem;background:#fff;box-shadow:var(--shadow);margin-bottom:1.5rem}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:.85rem 1rem}
.form-grid .full{grid-column:1/-1}
.form-grid label{margin-top:0}
select,textarea{width:100%;margin-top:.35rem;padding:.65rem .8rem;border:1px solid #cbd5e1;border-radius:.55rem;font:inherit;font-size:.9rem;background:#fff}
.check-row{display:flex;align-items:center;gap:.5rem;margin-top:.5rem;font-size:.88rem;font-weight:600}
.check-row input{width:auto;margin:0}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.86rem}
th,td{padding:.75rem .65rem;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:.74rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.pill{display:inline-flex;align-items:center;padding:.18rem .55rem;border-radius:999px;font-size:.72rem;font-weight:700}
.pill.approved{background:#ecfdf5;color:#047857}
.pill.pending{background:#fffbeb;color:#b45309}
.pill.rejected,.pill.disabled{background:#fef2f2;color:#b91c1c}
.pill.admin{background:#e0f2fe;color:#0369a1}
.inline-form{display:flex;flex-wrap:wrap;gap:.45rem;align-items:center}
.inline-form select{width:auto;margin-top:0;padding:.35rem .55rem;font-size:.78rem}
.mem-list{display:flex;flex-direction:column;gap:.45rem}
.mem-row{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.5rem;padding:.4rem .6rem;border-radius:.5rem;background:#f8fafc;border:1px solid var(--line)}
.search-bar{display:flex;flex-wrap:wrap;gap:.6rem;margin-bottom:1rem;align-items:center}
.search-bar input{margin-top:0;max-width:20rem}
.search-bar select{width:auto;margin-top:0;padding:.6rem .75rem}
.bulk-bar{display:flex;flex-wrap:wrap;gap:.55rem;align-items:center;padding:.8rem 1rem;margin-bottom:1rem;border:1px solid #bae6fd;border-radius:.75rem;background:#f0f9ff}
.bulk-bar select{width:auto;margin-top:0;padding:.45rem .65rem;font-size:.82rem}
.drawer{border:1px solid var(--line);border-radius:.85rem;background:#fff;margin-bottom:1rem;overflow:hidden}
.drawer summary{padding:.9rem 1.25rem;font-weight:700;font-size:.92rem;cursor:pointer;background:#f8fafc;list-style:none;display:flex;align-items:center;justify-content:space-between}
.drawer summary::-webkit-details-marker{display:none}
.drawer-body{padding:1.25rem;border-top:1px solid var(--line)}
.app-checks{display:flex;flex-wrap:wrap;gap:.6rem 1rem;margin-top:.35rem}
.btn-danger{background:#dc2626;color:#fff}
.btn-danger:hover{background:#b91c1c}
.user-actions{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.45rem}
.edit-box{margin-top:.55rem;padding:.65rem;border:1px solid var(--line);border-radius:.6rem;background:#f8fafc}
.edit-box input{margin-top:.25rem;padding:.45rem .6rem;font-size:.82rem}
.edit-box label{margin-top:.45rem;font-size:.76rem}
`

var ssoAdminTemplate = template.Must(template.New("sso-admin").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Pusat SSO - BP3KP Sumatera II</title>` + accountPortalFavicon + `<style>` + ssoAdminStyles + `</style></head><body>` + accountPortalBrandHeader + `<div class="user-nav"><a class="button secondary sm" href="/">Portal Aplikasi</a><span class="user-chip"><span class="avatar" aria-hidden="true">A</span>{{.AdminName}}</span><a class="button secondary sm" href="/logout?portal=1&immediate=1">Keluar</a></div></div></header><main>
<div class="section-head" style="margin-bottom:1rem"><div><h1>Admin Pusat SSO</h1><p class="lead">Kelola daftar website terhubung, role pengguna, dan persetujuan akses tanpa restart server.</p></div></div>
<nav class="tabs" aria-label="Menu Admin SSO">
  <a class="tab {{if eq .Tab "apps"}}active{{end}}" href="/admin/sso?tab=apps">Aplikasi &amp; Client SSO</a>
  <a class="tab {{if eq .Tab "users"}}active{{end}}" href="/admin/sso?tab=users">Pengguna, Role &amp; Approval</a>
</nav>
{{if .Message}}<div class="alert ok" role="status">{{.Message}}</div>{{end}}
{{if .Error}}<div class="alert err" role="alert">{{.Error}}</div>{{end}}

{{if eq .Tab "apps"}}
<section class="panel-box">
  <h2>Tambah / Perbarui Aplikasi SSO</h2>
  <p class="muted" style="margin-bottom:1rem">Isi <strong>Code</strong> yang sama jika ingin memperbarui aplikasi yang sudah ada. Perubahan langsung aktif tanpa restart.</p>
  <form method="post" action="/admin/sso/apps">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <div class="form-grid">
      <div><label for="app-code">Code (unik, huruf kecil)</label><input id="app-code" name="code" placeholder="mis. arsip" required></div>
      <div><label for="app-name">Nama Aplikasi</label><input id="app-name" name="name" placeholder="mis. Arsip Digital" required></div>
      <div><label for="app-client-id">Client ID</label><input id="app-client-id" name="client_id" placeholder="mis. arsip-web" required></div>
      <div><label for="app-policy">Kebijakan Akses</label><select id="app-policy" name="access_policy"><option value="AUTO_USER">AUTO_USER (otomatis/approval)</option><option value="RESTRICTED">RESTRICTED (khusus yang disetujui)</option></select></div>
      <div class="full"><label for="app-launch">Launch URL (URL utama web)</label><input id="app-launch" name="launch_url" type="url" placeholder="https://arsip.bp3kpsumatera2.com/" required></div>
      <div class="full"><label for="app-redirects">Redirect URIs (pisahkan dengan koma)</label><input id="app-redirects" name="redirect_uris" placeholder="https://arsip.bp3kpsumatera2.com/auth/sso/callback, http://localhost:8080/auth/sso/callback" required></div>
      <div class="full"><label for="app-logout">Post-Logout Redirect URIs (opsional, pisahkan koma)</label><input id="app-logout" name="post_logout_redirect_uris" placeholder="https://arsip.bp3kpsumatera2.com/"></div>
      <div class="full"><label for="app-desc">Deskripsi Singkat</label><input id="app-desc" name="description" placeholder="Portal pengelolaan arsip resmi BP3KP Sumatera II"></div>
      <div class="full"><label class="check-row"><input type="checkbox" name="is_active" checked> Aplikasi Aktif di SSO</label></div>
    </div>
    <button class="button" type="submit" style="margin-top:1.1rem">Simpan &amp; Aktifkan Aplikasi</button>
  </form>
</section>

<section class="panel-box">
  <h2 style="margin-bottom:1rem">Daftar Aplikasi Terdaftar ({{len .Apps}})</h2>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Aplikasi</th><th>Port (FE/BE)</th><th>Client ID</th><th>Kebijakan</th><th>Redirect URIs</th><th>Status</th></tr></thead>
      <tbody>
        {{range .Apps}}
        <tr>
          <td><strong>{{.Name}}</strong><div class="muted" style="font-size:.78rem">{{.Code}} · {{.LaunchURL}}</div></td>
          <td>
            <div style="display:flex;gap:.3rem;flex-wrap:wrap">
              {{if .Port}}<span class="pill" style="font-size:.72rem">FE: {{.Port}}</span>{{end}}
              {{if .BackendPort}}<span class="pill" style="font-size:.72rem">BE: {{.BackendPort}}</span>{{end}}
              {{if and (not .Port) (not .BackendPort)}}<span class="muted" style="font-size:.75rem">-</span>{{end}}
            </div>
          </td>
          <td><code>{{.ClientID}}</code></td>
          <td><span class="pill admin">{{.AccessPolicy}}</span></td>
          <td style="max-width:22rem;word-break:break-all;font-size:.78rem">{{.RedirectURIsCSV}}</td>
          <td>{{if .IsActive}}<span class="pill approved">Aktif</span>{{else}}<span class="pill disabled">Nonaktif</span>{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</section>
{{else}}
<details class="drawer">
  <summary>+ Tambah User Baru (Create Pegawai)</summary>
  <div class="drawer-body">
    <form method="post" action="/admin/sso/users/create" class="form-grid">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <div><label for="cu-email">Email Pegawai</label><input id="cu-email" name="email" type="email" placeholder="nama@bp3kpsumatera2.com" required></div>
      <div><label for="cu-name">Nama Lengkap</label><input id="cu-name" name="full_name" placeholder="Nama lengkap pegawai" required></div>
      <div><label for="cu-phone">No. HP (opsional)</label><input id="cu-phone" name="phone" placeholder="0812..."></div>
      <div><label for="cu-pass">Password (min 8 karakter, kosong = kirim invite)</label><input id="cu-pass" name="password" type="password" minlength="8" placeholder="Kosongkan untuk kirim email undangan"></div>
      <div><label for="cu-role">Role Awal</label><select id="cu-role" name="initial_role"><option value="user">Pengguna (user)</option><option value="admin">Admin (admin)</option></select></div>
      <div style="display:flex;align-items:flex-end"><label class="check-row"><input type="checkbox" name="is_sso_admin"> Jadikan Admin Pusat SSO</label></div>
      <div class="full">
        <label>Beri Akses Awal ke Aplikasi</label>
        <div class="app-checks">
          {{range .Apps}}<label class="check-row"><input type="checkbox" name="app_ids" value="{{.ID}}"> {{.Name}}</label>{{end}}
        </div>
      </div>
      <div class="full"><button class="button" type="submit">Simpan User Baru</button></div>
    </form>
  </div>
</details>

<details class="drawer">
  <summary>Bulk Import User (Upload CSV / Paste Massal)</summary>
  <div class="drawer-body">
    <p class="muted" style="margin-bottom:.85rem">Format per baris: <code>email,nama_lengkap,no_hp,password</code> (kolom <code>no_hp</code> dan <code>password</code> opsional; jika password kosong maka otomatis kirim undangan email).</p>
    <form method="post" action="/admin/sso/users/bulk-import" enctype="multipart/form-data" class="form-grid">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <div class="full"><label for="bi-file">Upload File .csv (opsional)</label><input id="bi-file" name="csv_file" type="file" accept=".csv,text/csv"></div>
      <div class="full"><label for="bi-text">Atau Paste Data CSV di Sini</label><textarea id="bi-text" name="csv_text" rows="4" placeholder="budi@bp3kpsumatera2.com,Budi Santoso,08123456789,Password123!&#10;sari@bp3kpsumatera2.com,Sari Dewi,08129876543,"></textarea></div>
      <div>
        <label for="bi-app">Otomatis Beri Akses Aplikasi (opsional)</label>
        <select id="bi-app" name="application_id"><option value="">-- Tidak assign aplikasi --</option>{{range .Apps}}<option value="{{.ID}}">{{.Name}} ({{.Code}})</option>{{end}}</select>
      </div>
      <div><label for="bi-role">Role</label><select id="bi-role" name="role"><option value="user">user</option><option value="admin">admin</option></select></div>
      <div><label for="bi-status">Status Approval</label><select id="bi-status" name="status"><option value="approved">approved</option><option value="pending">pending</option></select></div>
      <div class="full"><button class="button" type="submit">Jalankan Bulk Import</button></div>
    </form>
  </div>
</details>

<section class="panel-box">
  <h2>Atur Akses Pengguna ke Aplikasi</h2>
  <p class="muted" style="margin-bottom:1rem">Pilih pengguna dan aplikasi untuk mengatur role (<code>user</code> / <code>admin</code>) dan approval (<code>approved</code> / <code>pending</code> / <code>rejected</code> / <code>disabled</code>).</p>
  <form method="post" action="/admin/sso/memberships" class="form-grid">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="q" value="{{.Search}}">
    <div>
      <label for="m-user">Pengguna</label>
      <select id="m-user" name="app_user_id" required>
        {{range .Users}}{{if not .IsDeleted}}<option value="{{.ID}}">{{.FullName}} ({{.Email}})</option>{{end}}{{end}}
      </select>
    </div>
    <div>
      <label for="m-app">Aplikasi</label>
      <select id="m-app" name="application_id" required>
        {{range .Apps}}<option value="{{.ID}}">{{.Name}} ({{.Code}})</option>{{end}}
      </select>
    </div>
    <div>
      <label for="m-role">Role</label>
      <select id="m-role" name="role"><option value="user">Pengguna (user)</option><option value="admin">Admin (admin)</option></select>
    </div>
    <div>
      <label for="m-status">Status Approval</label>
      <select id="m-status" name="status"><option value="approved">Disetujui (approved)</option><option value="pending">Menunggu (pending)</option><option value="rejected">Ditolak (rejected)</option><option value="disabled">Dinonaktifkan (disabled)</option></select>
    </div>
    <div class="full"><button class="button" type="submit">Simpan Akses &amp; Role</button></div>
  </form>
</section>

<section class="panel-box">
  <h2 style="margin-bottom:.75rem">Daftar Pengguna, CRUD &amp; Aksi Massal ({{len .Users}})</h2>
  <form method="get" action="/admin/sso" class="search-bar">
    <input type="hidden" name="tab" value="users">
    <input name="q" value="{{.Search}}" placeholder="Cari nama atau email pegawai...">
    <select name="filter" aria-label="Filter Status User">
      <option value="active" {{if eq .Filter "active"}}selected{{end}}>User Aktif</option>
      <option value="deleted" {{if eq .Filter "deleted"}}selected{{end}}>User Terhapus</option>
      <option value="all" {{if eq .Filter "all"}}selected{{end}}>Semua User</option>
    </select>
    <button class="button secondary" type="submit">Filter</button>
  </form>

  <form id="bulk-form" method="post" action="/admin/sso/users/bulk-action" class="bulk-bar">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="q" value="{{.Search}}">
    <input type="hidden" name="filter" value="{{.Filter}}">
    <strong style="font-size:.82rem">Aksi Massal (centang user di tabel):</strong>
    <select name="bulk_action" aria-label="Jenis Aksi Massal">
      <option value="membership">Update Akses Aplikasi</option>
      <option value="delete">Hapus User Terpilih (Soft Delete)</option>
    </select>
    <select name="application_id" aria-label="Aplikasi Target">
      <option value="">-- Pilih Aplikasi --</option>
      {{range .Apps}}<option value="{{.ID}}">{{.Name}}</option>{{end}}
    </select>
    <select name="role" aria-label="Role Target">
      <option value="user">user</option>
      <option value="admin">admin</option>
    </select>
    <select name="status" aria-label="Status Target">
      <option value="approved">approved</option>
      <option value="pending">pending</option>
      <option value="rejected">rejected</option>
      <option value="disabled">disabled</option>
    </select>
    <button class="button sm" type="submit">Terapkan ke Terpilih</button>
  </form>

  <div class="table-wrap">
    <table>
      <thead><tr><th style="width:2.2rem">Pilih</th><th>Pegawai &amp; Kelola</th><th>Admin Pusat</th><th>Akses Aplikasi (Role &amp; Approval)</th></tr></thead>
      <tbody>
        {{range .Users}}
        {{$uid := .ID}}
        <tr>
          <td>
            {{if not .IsDeleted}}
            <input type="checkbox" form="bulk-form" name="user_ids" value="{{$uid}}" aria-label="Pilih {{.FullName}}">
            {{end}}
          </td>
          <td>
            <strong>{{.FullName}}</strong>
            {{if .IsDeleted}}<span class="pill disabled">Terhapus</span>{{end}}
            <div class="muted" style="font-size:.78rem">{{.Email}}{{if .Phone}} · {{.Phone}}{{end}}</div>
            <div class="user-actions">
              {{if .IsDeleted}}
              <form method="post" action="/admin/sso/users/restore" class="inline-form">
                <input type="hidden" name="csrf" value="{{$.CSRF}}">
                <input type="hidden" name="app_user_id" value="{{$uid}}">
                <input type="hidden" name="q" value="{{$.Search}}">
                <button class="button secondary sm" type="submit">Pulihkan</button>
              </form>
              {{else}}
              <details>
                <summary class="button secondary sm" style="display:inline-flex">Edit / Reset Password</summary>
                <form method="post" action="/admin/sso/users/update" class="edit-box">
                  <input type="hidden" name="csrf" value="{{$.CSRF}}">
                  <input type="hidden" name="app_user_id" value="{{$uid}}">
                  <input type="hidden" name="q" value="{{$.Search}}">
                  <input type="hidden" name="filter" value="{{$.Filter}}">
                  <label>Nama Lengkap</label>
                  <input name="full_name" value="{{.FullName}}" required>
                  <label>No. HP</label>
                  <input name="phone" value="{{.Phone}}">
                  <label>Password Baru (opsional, min 8 char)</label>
                  <input name="new_password" type="password" minlength="8" placeholder="Kosongkan jika tidak ganti">
                  <button class="button sm" type="submit" style="margin-top:.6rem">Simpan Perubahan</button>
                </form>
              </details>
              <form method="post" action="/admin/sso/users/delete" class="inline-form">
                <input type="hidden" name="csrf" value="{{$.CSRF}}">
                <input type="hidden" name="app_user_id" value="{{$uid}}">
                <input type="hidden" name="q" value="{{$.Search}}">
                <button class="button btn-danger sm" type="submit">Hapus</button>
              </form>
              {{end}}
            </div>
          </td>
          <td>
            {{if not .IsDeleted}}
            <form method="post" action="/admin/sso/users/superadmin" class="inline-form">
              <input type="hidden" name="csrf" value="{{$.CSRF}}">
              <input type="hidden" name="app_user_id" value="{{$uid}}">
              <input type="hidden" name="q" value="{{$.Search}}">
              {{if .IsSSOAdmin}}
                <input type="hidden" name="is_sso_admin" value="false">
                <span class="pill admin">Admin Pusat</span>
                <button class="button secondary sm" type="submit">Cabut</button>
              {{else}}
                <input type="hidden" name="is_sso_admin" value="true">
                <button class="button secondary sm" type="submit">Jadikan Admin Pusat</button>
              {{end}}
            </form>
            {{end}}
          </td>
          <td>
            <div class="mem-list">
              {{range .Memberships}}
              <form method="post" action="/admin/sso/memberships" class="mem-row">
                <input type="hidden" name="csrf" value="{{$.CSRF}}">
                <input type="hidden" name="app_user_id" value="{{$uid}}">
                <input type="hidden" name="application_id" value="{{.ApplicationID}}">
                <input type="hidden" name="q" value="{{$.Search}}">
                <span><strong>{{.ApplicationName}}</strong> <span class="pill {{.Status}}">{{.Status}}</span> <span class="pill admin">{{.Role}}</span></span>
                <span class="inline-form">
                  <select name="role" aria-label="Role">
                    <option value="user" {{if eq .Role "user"}}selected{{end}}>user</option>
                    <option value="admin" {{if eq .Role "admin"}}selected{{end}}>admin</option>
                  </select>
                  <select name="status" aria-label="Status">
                    <option value="approved" {{if eq .Status "approved"}}selected{{end}}>approved</option>
                    <option value="pending" {{if eq .Status "pending"}}selected{{end}}>pending</option>
                    <option value="rejected" {{if eq .Status "rejected"}}selected{{end}}>rejected</option>
                    <option value="disabled" {{if eq .Status "disabled"}}selected{{end}}>disabled</option>
                  </select>
                  <button class="button sm" type="submit">Update</button>
                </span>
              </form>
              {{else}}
              <span class="muted" style="font-size:.8rem">Belum ada akses aplikasi.</span>
              {{end}}
            </div>
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</section>
{{end}}
</main></body></html>`))
