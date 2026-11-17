package handlers

import (
	"crypto/subtle"
	"errors"
	"html/template"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

const (
	accountRegisterCSRF = "balai_portal_register_csrf"
	accessAdminCSRF     = "balai_admin_csrf"
)

// SetRegistrationService enables self-service signup at /account/register.
func (h *BrowserSSOHandler) SetRegistrationService(service services.RegistrationService) {
	if h != nil {
		h.registration = service
	}
}

// SetMembershipAdminService enables the access approval page at /admin.
func (h *BrowserSSOHandler) SetMembershipAdminService(service *services.MembershipAdminService) {
	if h != nil {
		h.admin = service
	}
}

// signupURL links the login form to signup when the requesting app accepts it.
func (h *BrowserSSOHandler) signupURL(pendingRequest string) string {
	if pendingRequest == "" || h.registration == nil {
		return ""
	}
	if _, err := h.service.SignupApplication(pendingRequest); err != nil {
		return ""
	}
	return "/account/register?request=" + url.QueryEscape(pendingRequest)
}

type registerForm struct {
	CSRF     string
	Request  string
	AppName  string
	Message  string
	FullName string
	Email    string
	Phone    string
	LoginURL string
}

func (h *BrowserSSOHandler) RegisterPage(c *fiber.Ctx) error {
	if h == nil || h.portalService == nil || h.service == nil || h.registration == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	pendingRequest := strings.TrimSpace(c.Query("request"))
	formAction, appName, err := h.registerContext(c, pendingRequest)
	if err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "signup_unavailable", "Pendaftaran tidak tersedia untuk aplikasi ini.")
	}
	if identity, _ := h.service.ResolveBrowserIdentity(c.UserContext(), c.Cookies(browserSSOSessionCookie)); identity != nil {
		return c.Redirect(afterLoginURL(pendingRequest), fiber.StatusSeeOther)
	}
	csrf, err := services.RandomBrowserSSOToken(32)
	if err != nil {
		return browserSSOError(c, fiber.StatusInternalServerError, "portal_unavailable", "Account portal is unavailable.")
	}
	h.setCookie(c, accountRegisterCSRF, csrf, 1800, time.Time{})
	return renderRegister(c, formAction, registerForm{CSRF: csrf, Request: pendingRequest, AppName: appName,
		LoginURL: "/account/login?request=" + url.QueryEscape(pendingRequest)})
}

func (h *BrowserSSOHandler) RegisterSubmit(c *fiber.Ctx) error {
	if h == nil || h.portalService == nil || h.service == nil || h.registration == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	csrf := strings.TrimSpace(c.FormValue("csrf"))
	cookieCSRF := strings.TrimSpace(c.Cookies(accountRegisterCSRF))
	if csrf == "" || cookieCSRF == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookieCSRF)) != 1 {
		return browserSSOError(c, fiber.StatusForbidden, "invalid_csrf", "Formulir kedaluwarsa. Silakan ulangi.")
	}
	pendingRequest := strings.TrimSpace(c.FormValue("request"))
	formAction, appName, err := h.registerContext(c, pendingRequest)
	if err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "signup_unavailable", "Pendaftaran tidak tersedia untuk aplikasi ini.")
	}
	appCode, _ := h.service.SignupApplication(pendingRequest)
	form := registerForm{
		CSRF: csrf, Request: pendingRequest, AppName: appName,
		FullName: strings.TrimSpace(c.FormValue("full_name")),
		Email:    strings.ToLower(strings.TrimSpace(c.FormValue("email"))),
		Phone:    strings.TrimSpace(c.FormValue("phone")),
		LoginURL: "/account/login?request=" + url.QueryEscape(pendingRequest),
	}
	password := c.FormValue("password")
	parsedEmail, emailErr := mail.ParseAddress(form.Email)
	switch {
	case form.FullName == "" || form.Email == "" || password == "":
		form.Message = "Nama, email, dan password wajib diisi."
	case emailErr != nil || !strings.EqualFold(parsedEmail.Address, form.Email):
		form.Message = "Format email tidak valid."
	case len(password) < 8 || len(password) > 128:
		form.Message = "Password harus 8 sampai 128 karakter."
	case password != c.FormValue("password_confirm"):
		form.Message = "Konfirmasi password tidak sama."
	}
	if form.Message != "" {
		return renderRegister(c, formAction, form)
	}

	_, err = h.registration.Register(c.UserContext(), form.Email, password, form.FullName, form.Phone, appCode)
	switch {
	case err == nil:
	case errors.Is(err, services.ErrAccountAlreadyExists), errors.Is(err, services.ErrRegistrationIdentityConflict):
		form.Message = "Email sudah terdaftar. Silakan masuk dengan Akun Balai Anda."
		return renderRegister(c, formAction, form)
	case errors.Is(err, services.ErrInvalidPassword), errors.Is(err, services.ErrInvalidRegistrationRequest):
		form.Message = "Data pendaftaran tidak valid."
		return renderRegister(c, formAction, form)
	default:
		form.Message = "Pendaftaran sedang tidak dapat diproses. Coba lagi nanti."
		return renderRegister(c, formAction, form)
	}

	h.clearCookie(c, accountRegisterCSRF)
	rawToken, expiresAt, err := h.portalService.Login(c.UserContext(), form.Email, password)
	if err != nil {
		// The account exists; the user can still sign in manually.
		return c.Redirect(form.LoginURL, fiber.StatusSeeOther)
	}
	h.setSessionCookie(c, rawToken, expiresAt)
	// Authorization returns status=pending to the app until an admin approves.
	return c.Redirect(afterLoginURL(pendingRequest), fiber.StatusSeeOther)
}

// registerContext validates that signup is allowed for the pending request and
// returns the CSP form-action and application name for the page.
func (h *BrowserSSOHandler) registerContext(c *fiber.Ctx, pendingRequest string) (string, string, error) {
	if pendingRequest == "" {
		return "", "", services.ErrSignupNotAllowed
	}
	if _, err := h.service.SignupApplication(pendingRequest); err != nil {
		return "", "", err
	}
	formAction, err := h.loginFormAction(pendingRequest)
	if err != nil {
		return "", "", err
	}
	view, err := h.portalService.View(c.UserContext(), "", pendingRequest)
	if err != nil {
		return "", "", err
	}
	return formAction, pendingAppName(view), nil
}

func renderRegister(c *fiber.Ctx, formAction string, form registerForm) error {
	setBrowserSSOPageHeaders(c, formAction)
	var output strings.Builder
	if err := accountRegisterTemplate.Execute(&output, form); err != nil {
		return err
	}
	return c.SendString(output.String())
}

// accessActor resolves the signed-in admin page user; nil means not signed in.
func (h *BrowserSSOHandler) accessActor(c *fiber.Ctx) (*models.AppUser, error) {
	identity, err := h.service.ResolveBrowserIdentity(c.UserContext(), c.Cookies(browserSSOSessionCookie))
	if err != nil || identity == nil {
		return nil, err
	}
	return identity.User, nil
}

func (h *BrowserSSOHandler) AdminPage(c *fiber.Ctx) error {
	if h == nil || h.service == nil || h.admin == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "admin_unavailable", "Admin page is unavailable.")
	}
	actor, err := h.accessActor(c)
	if err != nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "admin_unavailable", "Admin page is unavailable.")
	}
	if actor == nil {
		return c.Redirect("/account/login", fiber.StatusSeeOther)
	}
	canManage, err := h.admin.CanManage(c.UserContext(), actor.ID)
	if err != nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "admin_unavailable", "Admin page is unavailable.")
	}
	if !canManage {
		c.Status(fiber.StatusForbidden)
		return h.renderLogoutState(c, "Akses ditolak", "Akun Anda bukan admin aplikasi mana pun.", "/", "Kembali ke portal")
	}
	memberships, err := h.admin.List(c.UserContext(), actor.ID)
	if err != nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "admin_unavailable", "Admin page is unavailable.")
	}
	csrf, err := services.RandomBrowserSSOToken(32)
	if err != nil {
		return browserSSOError(c, fiber.StatusInternalServerError, "admin_unavailable", "Admin page is unavailable.")
	}
	h.setCookie(c, accessAdminCSRF, csrf, 3600, time.Time{})
	setBrowserSSOPageHeaders(c, "'self'")
	var output strings.Builder
	if err := accessAdminTemplate.Execute(&output, struct {
		CSRF        string
		ActorID     string
		Memberships []models.ManagedMembership
		Message     string
	}{csrf, actor.ID, memberships, adminMessages[c.Query("msg")]}); err != nil {
		return err
	}
	return c.SendString(output.String())
}

var adminMessages = map[string]string{
	"saved":     "Perubahan akses disimpan.",
	"forbidden": "Anda tidak dapat mengubah akses tersebut.",
	"invalid":   "Perubahan tidak valid.",
	"error":     "Perubahan gagal disimpan. Coba lagi.",
}

func (h *BrowserSSOHandler) AdminUpdate(c *fiber.Ctx) error {
	if h == nil || h.service == nil || h.admin == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "admin_unavailable", "Admin page is unavailable.")
	}
	csrf := strings.TrimSpace(c.FormValue("csrf"))
	cookieCSRF := strings.TrimSpace(c.Cookies(accessAdminCSRF))
	if csrf == "" || cookieCSRF == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookieCSRF)) != 1 {
		return browserSSOError(c, fiber.StatusForbidden, "invalid_csrf", "Formulir kedaluwarsa. Muat ulang halaman.")
	}
	actor, err := h.accessActor(c)
	if err != nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "admin_unavailable", "Admin page is unavailable.")
	}
	if actor == nil {
		return c.Redirect("/account/login", fiber.StatusSeeOther)
	}
	err = h.admin.Update(c.UserContext(), actor.ID, c.FormValue("membership_id"), c.FormValue("role"), c.FormValue("status"))
	message := "saved"
	switch {
	case errors.Is(err, services.ErrMembershipChangeForbidden):
		message = "forbidden"
	case errors.Is(err, services.ErrMembershipChangeInvalid):
		message = "invalid"
	case err != nil:
		message = "error"
	}
	return c.Redirect("/admin?msg="+message, fiber.StatusSeeOther)
}

var accountRegisterTemplate = template.Must(template.New("account-register").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Daftar - Akun Balai Pegawai</title><style>` + accountPortalStyles + `</style></head><body><main><header class="brand"><div class="brand-mark" aria-hidden="true">BP3KP</div><div><div class="brand-name">BP3KP Sumatera II</div><div class="brand-unit">Akun Balai Pegawai</div></div></header><section class="panel" style="max-width:30rem;margin:0 auto"><h1>Daftar</h1>{{if .AppName}}<p class="status">Akses ke {{.AppName}}</p>{{end}}<p class="lead">Buat Akun Balai. Akses aplikasi aktif setelah disetujui admin.</p>{{if .Message}}<p class="error" role="alert">{{.Message}}</p>{{end}}<form method="post" action="/account/register"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="request" value="{{.Request}}"><label for="full_name">Nama Lengkap</label><input id="full_name" name="full_name" autocomplete="name" value="{{.FullName}}" required><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" value="{{.Email}}" required><label for="phone">Nomor HP (opsional)</label><input id="phone" name="phone" type="tel" autocomplete="tel" value="{{.Phone}}"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="8" maxlength="128" required><label for="password_confirm">Ulangi Password</label><input id="password_confirm" name="password_confirm" type="password" autocomplete="new-password" minlength="8" maxlength="128" required><button class="button" type="submit" style="width:100%;margin-top:1.25rem">Daftar</button></form><p><a class="footer-link" href="{{.LoginURL}}">Sudah punya akun? Masuk</a></p></section></main></body></html>`))

var accessAdminTemplate = template.Must(template.New("access-admin").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kelola Akses - Akun Balai Pegawai</title><style>` + accountPortalStyles + `table{width:100%;border-collapse:collapse;margin-top:1rem}th,td{padding:.6rem;border-bottom:1px solid #d9e3e9;text-align:left;vertical-align:top}th{font-size:.85rem;color:#526574}.row-form{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center}.row-form select{padding:.45rem;border:1px solid #b9c8d2;border-radius:.4rem;font:inherit}.row-form .button{min-height:2.2rem;padding:.4rem .7rem}.table-wrap{overflow-x:auto}.ok{color:#075985;font-weight:700}</style></head><body><main><header class="brand"><div class="brand-mark" aria-hidden="true">BP3KP</div><div><div class="brand-name">BP3KP Sumatera II</div><div class="brand-unit">Akun Balai Pegawai</div></div></header><section class="panel"><div class="identity"><h1>Kelola Akses</h1><a class="button secondary" href="/">Kembali ke portal</a></div><p class="muted">Permintaan yang menunggu persetujuan tampil paling atas.</p>{{if .Message}}<p class="ok" role="status">{{.Message}}</p>{{end}}<div class="table-wrap"><table><thead><tr><th scope="col">Aplikasi</th><th scope="col">Pengguna</th><th scope="col">Status</th><th scope="col">Aksi</th></tr></thead><tbody>{{range .Memberships}}<tr><td>{{.ApplicationName}}</td><td>{{.FullName}}<br><span class="muted">{{.Email}}</span></td><td>{{.StatusLabel}}</td><td>{{if eq .AppUserID $.ActorID}}<span class="muted">Akun Anda</span>{{else}}<form class="row-form" method="post" action="/admin/memberships"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="membership_id" value="{{.ID}}"><label class="muted" for="role-{{.ID}}" style="margin:0;font-weight:400">Role</label><select id="role-{{.ID}}" name="role"><option value="user"{{if eq .Role "user"}} selected{{end}}>Pengguna</option><option value="admin"{{if eq .Role "admin"}} selected{{end}}>Admin</option></select><button class="button" name="status" value="approved" type="submit">{{if eq .Status "approved"}}Simpan{{else}}Setujui{{end}}</button>{{if eq .Status "pending"}}<button class="button secondary" name="status" value="rejected" type="submit">Tolak</button>{{end}}{{if eq .Status "approved"}}<button class="button secondary" name="status" value="disabled" type="submit">Nonaktifkan</button>{{end}}</form>{{end}}</td></tr>{{else}}<tr><td colspan="4" class="muted">Belum ada pengguna.</td></tr>{{end}}</tbody></table></div></section></main></body></html>`))
