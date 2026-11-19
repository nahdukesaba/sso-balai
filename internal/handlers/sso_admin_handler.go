package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
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
	users, err := h.adminRepo.ListUsers(c.UserContext(), search)
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
		Message   string
		Error     string
		Apps      []appRow
		Users     []repository.SSOAdminUser
	}{
		AdminName: adminName,
		CSRF:      csrf,
		Tab:       normalizeAdminTab(c.Query("tab")),
		Search:    search,
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
.search-bar{display:flex;gap:.6rem;margin-bottom:1rem;max-width:28rem}
.search-bar input{margin-top:0}
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
<section class="panel-box">
  <h2>Atur Akses Pengguna ke Aplikasi</h2>
  <p class="muted" style="margin-bottom:1rem">Pilih pengguna dan aplikasi untuk mengatur role (<code>user</code> / <code>admin</code>) dan approval (<code>approved</code> / <code>pending</code> / <code>rejected</code> / <code>disabled</code>).</p>
  <form method="post" action="/admin/sso/memberships" class="form-grid">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="q" value="{{.Search}}">
    <div>
      <label for="m-user">Pengguna</label>
      <select id="m-user" name="app_user_id" required>
        {{range .Users}}<option value="{{.ID}}">{{.FullName}} ({{.Email}})</option>{{end}}
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
  <h2 style="margin-bottom:.75rem">Daftar Pengguna &amp; Hak Akses ({{len .Users}})</h2>
  <form method="get" action="/admin/sso" class="search-bar">
    <input type="hidden" name="tab" value="users">
    <input name="q" value="{{.Search}}" placeholder="Cari nama atau email pegawai...">
    <button class="button secondary" type="submit">Cari</button>
  </form>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Pegawai</th><th>Admin Pusat</th><th>Akses Aplikasi (Role &amp; Approval)</th></tr></thead>
      <tbody>
        {{range .Users}}
        {{$uid := .ID}}
        <tr>
          <td><strong>{{.FullName}}</strong><div class="muted" style="font-size:.78rem">{{.Email}}</div></td>
          <td>
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
