package handlers

import (
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

//go:embed logo-pkp.png
var accountPortalLogoPNG []byte

var accountPortalLogoDataURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(accountPortalLogoPNG)

func (h *BrowserSSOHandler) PortalHome(c *fiber.Ctx) error {
	if h == nil || h.portalService == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	pendingRequest := strings.TrimSpace(c.Query("request"))
	view, err := h.portalService.View(
		c.UserContext(), c.Cookies(browserSSOSessionCookie), pendingRequest,
	)
	if err != nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	setAccountPortalPageHeaders(c)
	if view.Identity == nil || view.Identity.User == nil {
		return renderAccountPortalLoggedOut(c, view)
	}
	if h.adminRepo != nil {
		if isAdmin, err := h.adminRepo.IsSSOAdmin(c.UserContext(), view.Identity.User.ID); err == nil {
			view.IsSSOAdmin = isAdmin
		}
	}
	return renderAccountPortalLoggedIn(c, view)
}

func (h *BrowserSSOHandler) PortalLaunch(c *fiber.Ctx) error {
	if h == nil || h.portalService == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	browserToken := c.Cookies(browserSSOSessionCookie)
	if strings.TrimSpace(browserToken) == "" {
		return c.Redirect("/account/login", fiber.StatusSeeOther)
	}
	appCode := strings.TrimSpace(c.Query("app"))
	if appCode == "" {
		appCode = strings.TrimSpace(c.Params("app"))
	}
	if appCode == "" {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_application", "Target application is required.")
	}
	launchURL, err := h.portalService.Launch(c.UserContext(), browserToken, appCode)
	if err != nil {
		return browserSSOError(c, fiber.StatusForbidden, "launch_denied", "Aplikasi tidak tersedia untuk akun ini.")
	}
	h.setCookie(c, portalLaunchCookie, strings.ToLower(appCode), 120, time.Time{})
	return c.Redirect(launchURL, fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) PortalLoginPage(c *fiber.Ctx) error {
	if h == nil || h.portalService == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	pendingRequest := strings.TrimSpace(c.Query("request"))
	view, err := h.portalService.View(
		c.UserContext(), c.Cookies(browserSSOSessionCookie), pendingRequest,
	)
	if err != nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	if view.Identity != nil && view.Identity.User != nil {
		return c.Redirect(portalURL(pendingRequest), fiber.StatusSeeOther)
	}
	csrf, err := services.RandomBrowserSSOToken(32)
	if err != nil {
		return browserSSOError(c, fiber.StatusInternalServerError, "portal_unavailable", "Account portal is unavailable.")
	}
	h.setCookie(c, accountPortalLoginCSRF, csrf, 3600, time.Time{})
	return h.renderAccountPortalLogin(c, csrf, pendingRequest, "")
}

func (h *BrowserSSOHandler) PortalLoginSubmit(c *fiber.Ctx) error {
	if h == nil || h.portalService == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	csrf := strings.TrimSpace(c.FormValue("csrf"))
	pendingRequest := strings.TrimSpace(c.FormValue("request"))
	cookieCSRF := strings.TrimSpace(c.Cookies(accountPortalLoginCSRF))
	if csrf == "" || cookieCSRF == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookieCSRF)) != 1 {
		if view, viewErr := h.portalService.View(c.UserContext(), c.Cookies(browserSSOSessionCookie), pendingRequest); viewErr == nil &&
			view != nil && view.Identity != nil && view.Identity.User != nil {
			return c.Redirect(portalURL(pendingRequest), fiber.StatusSeeOther)
		}
		if newCSRF, csrfErr := services.RandomBrowserSSOToken(32); csrfErr == nil {
			h.setCookie(c, accountPortalLoginCSRF, newCSRF, 3600, time.Time{})
			c.Status(fiber.StatusForbidden)
			return h.renderAccountPortalLogin(c, newCSRF, pendingRequest, "Sesi formulir login kedaluwarsa. Silakan coba masuk kembali.")
		}
		return browserSSOError(c, fiber.StatusForbidden, "invalid_csrf", "The login form expired. Try again.")
	}
	rawToken, expiresAt, err := h.portalService.Login(
		c.UserContext(),
		strings.TrimSpace(c.FormValue("email")),
		c.FormValue("password"),
	)
	if err != nil {
		return h.renderAccountPortalLogin(c, csrf, pendingRequest, "Email atau password tidak valid.")
	}
	h.setSessionCookie(c, rawToken, expiresAt)
	h.clearCookie(c, accountPortalLoginCSRF)
	return c.Redirect(portalURL(pendingRequest), fiber.StatusSeeOther)
}

func portalURL(pendingRequest string) string {
	if strings.TrimSpace(pendingRequest) == "" {
		return "/"
	}
	return "/authorize/continue?request=" + url.QueryEscape(pendingRequest)
}

func renderAccountPortalLoggedOut(c *fiber.Ctx, view *models.AccountPortalView) error {
	var output strings.Builder
	if err := accountPortalLoggedOutTemplate.Execute(&output, view); err != nil {
		return err
	}
	return c.SendString(output.String())
}

func renderAccountPortalLoggedIn(c *fiber.Ctx, view *models.AccountPortalView) error {
	var output strings.Builder
	if err := accountPortalLoggedInTemplate.Execute(&output, view); err != nil {
		return err
	}
	return c.SendString(output.String())
}

func (h *BrowserSSOHandler) renderAccountPortalLogin(c *fiber.Ctx, csrf string, request string, message string) error {
	setAccountPortalPageHeaders(c)
	if h != nil && h.service != nil && strings.TrimSpace(request) != "" {
		if authReq, err := h.service.OpenAuthorizeRequest(request); err == nil {
			if origin, originErr := browserSSORedirectOrigin(authReq.RedirectURI); originErr == nil && origin != "" {
				c.Set("Content-Security-Policy", fmt.Sprintf(
					"default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; form-action 'self' %s; base-uri 'none'; frame-ancestors 'none'",
					origin,
				))
			}
		}
	}
	var output strings.Builder
	if err := accountPortalLoginTemplate.Execute(&output, struct {
		CSRF    string
		Request string
		Message string
	}{csrf, request, message}); err != nil {
		return err
	}
	return c.SendString(output.String())
}

func setAccountPortalPageHeaders(c *fiber.Ctx) {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	c.Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	c.Type("html", "utf-8")
}

const accountPortalStyles = `:root{--bg:#f8fafc;--surface:#ffffff;--ink:#0f172a;--muted:#475569;--line:#e2e8f0;--accent:#0b5d78;--accent-hover:#08475c;--accent-soft:#e0f2fe;--khaki:#c9b478;--shadow:0 1px 2px rgba(15,23,42,.04),0 10px 28px -8px rgba(15,23,42,.08);font-family:system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif;color:var(--ink);background:var(--bg)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:radial-gradient(60rem 36rem at 12% -8%,#dbeafe66,transparent 60%),radial-gradient(50rem 32rem at 92% 0%,#fef3c755,transparent 55%),#f8fafc;color:var(--ink)}
.topbar{position:sticky;top:0;z-index:10;background:rgba(255,255,255,.88);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.topbar-inner{width:min(72rem,calc(100% - 2rem));margin:0 auto;height:4rem;display:flex;align-items:center;justify-content:space-between;gap:1rem}
.brand{display:flex;align-items:center;gap:.75rem;text-decoration:none;color:inherit}
.brand-mark{display:grid;place-items:center;width:2.4rem;height:2.4rem;border-radius:.65rem;background:linear-gradient(135deg,#0b333d,#0f5c6e);color:#fff;font-size:.66rem;font-weight:800;letter-spacing:.06em;box-shadow:0 2px 6px rgba(11,51,61,.25)}
.brand-logo{width:2.5rem;height:2.5rem;object-fit:contain;display:block;flex-shrink:0}
.brand-name{font-weight:700;font-size:.95rem;line-height:1.2}
.brand-unit{color:var(--muted);font-size:.76rem}
.user-nav{display:flex;align-items:center;gap:.65rem}
.user-chip{display:inline-flex;align-items:center;gap:.5rem;padding:.35rem .75rem .35rem .4rem;border:1px solid var(--line);border-radius:999px;background:#fff;font-size:.82rem;font-weight:600;color:var(--ink)}
.avatar{display:grid;place-items:center;width:1.65rem;height:1.65rem;border-radius:999px;background:var(--accent-soft);color:var(--accent)}
main{width:min(72rem,calc(100% - 2rem));margin:0 auto;padding:2.25rem 0 4rem}
.auth-wrap{min-height:calc(100vh - 4rem);display:grid;place-items:center;padding:2rem 1rem}
.auth-card{width:min(27rem,100%);padding:2.25rem 2rem;border:1px solid var(--line);border-radius:1.25rem;background:var(--surface);box-shadow:var(--shadow)}
.auth-head{text-align:center;margin-bottom:1.5rem}
.auth-head .brand-mark{width:3rem;height:3rem;margin:0 auto 1rem;font-size:.74rem}
.auth-head .brand-logo{width:3.75rem;height:3.75rem;margin:0 auto 1rem}
.auth-head h1{margin-top:.35rem}
.auth-card .status{margin:0 auto .5rem;display:table}
h1,h2,h3{margin:0;letter-spacing:-.025em}
h1{font-size:clamp(1.65rem,3.5vw,2.2rem);font-weight:750;line-height:1.2}
h2{font-size:1.08rem;font-weight:700}
.lead,.muted{color:var(--muted);line-height:1.6;font-size:.92rem;margin:.4rem 0 0}
.hero{text-align:center;padding:1.25rem 0 2rem}
.hero-badge{display:inline-flex;align-items:center;gap:.45rem;padding:.3rem .8rem;border-radius:999px;border:1px solid #cbd5e1;background:#fff;font-size:.76rem;font-weight:600;color:var(--accent);margin-bottom:.85rem}
.hero h1{font-size:clamp(1.75rem,4vw,2.5rem)}
.pending-box{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:1rem;padding:1.1rem 1.35rem;margin-bottom:2rem;border:1px solid #bae6fd;border-radius:1rem;background:linear-gradient(135deg,#f0f9ff,#ffffff);box-shadow:var(--shadow)}
.section-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem}
.section-head h2{font-size:1.05rem;font-weight:700;color:var(--ink)}
.section-hint{font-size:.82rem;color:var(--muted)}
.apps{display:grid;grid-template-columns:repeat(auto-fit,minmax(17.5rem,1fr));gap:1.15rem}
.card{display:flex;flex-direction:column;padding:1.4rem;border:1px solid var(--line);border-radius:1rem;background:var(--surface);box-shadow:0 1px 3px rgba(15,23,42,.04);transition:transform .18s ease,box-shadow .18s ease,border-color .18s ease}
.card:hover{transform:translateY(-2px);border-color:#94a3b8;box-shadow:var(--shadow)}
.card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:.75rem;margin-bottom:1rem}
.app-tile{display:grid;place-items:center;width:2.75rem;height:2.75rem;border-radius:.75rem;background:linear-gradient(135deg,#e0f2fe,#f0f9ff);color:var(--accent);border:1px solid #bae6fd}
.card-meta{display:flex;flex-direction:column;align-items:flex-end;gap:.25rem}
.card h2{font-size:1.1rem;margin-bottom:.35rem}
.card .muted{font-size:.86rem;margin:0 0 1rem;flex:1}
.status{display:inline-flex;align-items:center;gap:.38rem;margin:0;padding:.22rem .65rem;border-radius:999px;font-size:.74rem;font-weight:700;line-height:1.2;border:1px solid #a7f3d0;background:#ecfdf5;color:#047857}
.status-dot{width:.45rem;height:.45rem;border-radius:50%;background:currentColor;flex-shrink:0}
.status.status-active,.status.status-approved{background:#ecfdf5;color:#047857;border-color:#a7f3d0}
.status.status-active .status-dot,.status.status-approved .status-dot{background:#10b981;box-shadow:0 0 0 2px #d1fae5}
.status.status-pending{background:#fffbeb;color:#b45309;border-color:#fde68a}
.status.status-pending .status-dot{background:#f59e0b;box-shadow:0 0 0 2px #fef3c7}
.status.status-rejected{background:#fef2f2;color:#b91c1c;border-color:#fecaca}
.status.status-rejected .status-dot{background:#ef4444;box-shadow:0 0 0 2px #fee2e2}
.status.status-disabled{background:#f1f5f9;color:#475569;border-color:#cbd5e1}
.status.status-disabled .status-dot{background:#94a3b8;box-shadow:0 0 0 2px #e2e8f0}
.status.status-none{background:#f8fafc;color:#64748b;border-color:#e2e8f0}
.status.status-none .status-dot{background:#94a3b8;box-shadow:0 0 0 2px #f1f5f9}
.role{margin:0;color:var(--muted);font-size:.76rem;font-weight:600}
.no-launch-hint{display:flex;align-items:center;justify-content:center;min-height:2.6rem;margin-top:.35rem;padding:.5rem .85rem;border-radius:.6rem;background:#f8fafc;border:1px dashed #cbd5e1;text-align:center}
.no-launch-text{font-size:.8rem;font-weight:600;color:var(--muted)}
.icon-badge{display:grid;place-items:center;width:3.25rem;height:3.25rem;border-radius:1rem;margin:0 auto 1.25rem;box-shadow:0 4px 12px -2px rgba(15,23,42,.08)}
.icon-badge.danger{background:#fef2f2;border:1px solid #fecaca;color:#dc2626}
.icon-badge.warning{background:#fffbeb;border:1px solid #fde68a;color:#d97706}
.icon-badge.success{background:#ecfdf5;border:1px solid #a7f3d0;color:#059669}
.icon-badge.info{background:#f0f9ff;border:1px solid #bae6fd;color:#0284c7}
.button{display:inline-flex;align-items:center;justify-content:center;gap:.45rem;min-height:2.6rem;padding:.6rem 1.05rem;border:0;border-radius:.6rem;background:var(--accent);color:#fff;font:inherit;font-size:.88rem;font-weight:600;text-decoration:none;cursor:pointer;transition:background .15s ease,transform .15s ease}
.button:hover{background:var(--accent-hover)}
.button.secondary{border:1px solid #cbd5e1;background:#fff;color:var(--ink)}
.button.secondary:hover{background:#f1f5f9;border-color:#94a3b8}
.button.danger{background:#dc2626;color:#fff}
.button.danger:hover{background:#b91c1c}
form[action="/logout"] button{display:inline-flex;align-items:center;justify-content:center;gap:.45rem;width:100%;min-height:2.6rem;padding:.6rem 1.05rem;border:0;border-radius:.6rem;background:var(--danger,#dc2626);color:#fff;font:inherit;font-size:.88rem;font-weight:600;text-decoration:none;cursor:pointer;transition:background .15s ease,transform .15s ease}
form[action="/logout"] button:hover{background:var(--danger-hover,#b91c1c)}
.button.sm{min-height:2.1rem;padding:.4rem .85rem;font-size:.8rem}
.card .button{width:100%;margin-top:.35rem}
.actions{display:flex;flex-wrap:wrap;gap:.65rem;margin-top:1.5rem}
.actions .button{flex:1;min-width:8rem}
.notice-box{padding:.9rem 1rem;border-radius:.75rem;background:#fffbeb;border:1px solid #fde68a;color:#92400e;font-size:.82rem;line-height:1.5;margin-top:1.25rem;text-align:left}
.notice-box strong{display:block;margin-bottom:.2rem;color:#78350f}
label{display:block;margin-top:1rem;font-size:.84rem;font-weight:600;color:var(--ink)}
input{width:100%;margin-top:.35rem;padding:.68rem .85rem;border:1px solid #cbd5e1;border-radius:.55rem;font:inherit;font-size:.92rem;background:#fff;transition:border-color .15s ease,box-shadow .15s ease}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px #0b5d7822}
.error{padding:.65rem .85rem;border-radius:.55rem;background:#fef2f2;border:1px solid #fecaca;color:#b42318;font-size:.85rem;font-weight:500;margin:0 0 .5rem}
.form-foot{display:flex;justify-content:space-between;align-items:center;margin-top:1rem;font-size:.84rem}
.footer-link{color:var(--accent);font-weight:600;text-decoration:none}
.footer-link:hover{text-decoration:underline}
.portal-foot{margin-top:3rem;text-align:center;font-size:.78rem;color:#64748b}
@media(max-width:640px){.user-chip{display:none}.auth-card{padding:1.75rem 1.35rem}.actions .button{width:100%;flex:none}}`

var accountPortalBrandHeader = `<header class="topbar"><div class="topbar-inner"><div class="brand"><img class="brand-logo" src="` + accountPortalLogoDataURI + `" alt="" aria-hidden="true"><div><div class="brand-name">BP3KP Sumatera II</div><div class="brand-unit">Akun Balai Pegawai</div></div></div>`

var accountPortalFavicon = `<link rel="icon" type="image/png" href="` + accountPortalLogoDataURI + `">`

var accountPortalLoggedOutTemplate = template.Must(template.New("account-portal-logged-out").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Akun Balai Pegawai - BP3KP Sumatera II</title>` + accountPortalFavicon + `<style>` + accountPortalStyles + `</style></head><body>` + accountPortalBrandHeader + `</div></header><div class="auth-wrap"><section class="auth-card"><div class="auth-head"><img class="brand-logo" src="` + accountPortalLogoDataURI + `" alt="" aria-hidden="true"><p class="muted">Portal Layanan Internal Balai PK3P Sumatera II</p><h1>Akun Balai Pegawai</h1><p class="lead">Satu akun terpadu untuk mengakses seluruh aplikasi internal BP3KP Sumatera II.</p></div>{{if .PendingAuthorization}}<p class="status">{{.PendingAuthorization.ApplicationName}}</p>{{end}}<div class="actions"><a class="button" href="{{if .PendingAuthorization}}{{.PendingAuthorization.LoginURL}}{{else}}/account/login{{end}}">Masuk</a><a class="button secondary" href="/forgot-password">Lupa Password</a></div></section></div></body></html>`))

var accountPortalLoggedInTemplate = template.Must(template.New("account-portal").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Akun Balai Pegawai - BP3KP Sumatera II</title>` + accountPortalFavicon + `<style>` + accountPortalStyles + `</style></head><body>` + accountPortalBrandHeader + `<div class="user-nav">{{if .IsSSOAdmin}}<a class="button sm" href="/admin/sso">Kelola SSO</a>{{end}}<span class="user-chip"><span class="avatar" aria-hidden="true"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg></span>{{.Identity.User.FullName}}</span><a class="button secondary sm" href="/logout?portal=1">Keluar</a></div></div></header><main><section class="hero"><div class="hero-badge">Single Sign-On · BP3KP Sumatera II</div><h1>Halo, {{.Identity.User.FullName}}</h1><p class="lead">Pilih aplikasi layanan internal yang ingin Anda buka.</p></section>{{if .PendingAuthorization}}<div class="pending-box"><div><strong>Otorisasi Aplikasi Siap</strong><p class="muted" style="margin:.2rem 0 0">Lanjutkan masuk ke {{.PendingAuthorization.ApplicationName}} menggunakan sesi akun Anda.</p></div><a class="button" href="{{.PendingAuthorization.ContinueURL}}">Lanjut ke {{.PendingAuthorization.ApplicationName}}</a></div>{{end}}<div class="section-head"><h2>Aplikasi Anda</h2><span class="section-hint">Terhubung dengan Akun Balai</span></div><div class="apps">{{range .Applications}}<article class="card"><div class="card-top"><div class="app-tile" aria-hidden="true"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></svg></div><div class="card-meta"><p class="status {{.StatusClass}}"><span class="status-dot" aria-hidden="true"></span>{{.StatusLabel}}</p>{{if .RoleLabel}}<p class="role">{{.RoleLabel}}</p>{{end}}</div></div><h2>{{.Name}}</h2>{{if .Description}}<p class="muted">{{.Description}}</p>{{end}}{{if .Launchable}}<a class="button" href="{{.LaunchURL}}">Buka Aplikasi</a>{{else}}<div class="no-launch-hint"><span class="no-launch-text">{{if eq .StatusClass "status-pending"}}Menunggu Persetujuan Admin{{else if eq .StatusClass "status-rejected"}}Permohonan Akses Ditolak{{else if eq .StatusClass "status-disabled"}}Akses Dinonaktifkan{{else}}Belum Memiliki Akses{{end}}</span></div>{{end}}</article>{{else}}<p class="muted">Tidak Ada Aplikasi Yang Tersedia</p>{{end}}</div><footer class="portal-foot">Kementerian Perumahan dan Kawasan Permukiman · BP3KP Sumatera II</footer></main></body></html>`))

var accountPortalLoginTemplate = template.Must(template.New("account-portal-login").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Masuk - Akun Balai Pegawai</title>` + accountPortalFavicon + `<style>` + accountPortalStyles + `</style></head><body>` + accountPortalBrandHeader + `</div></header><div class="auth-wrap"><section class="auth-card"><div class="auth-head"><img class="brand-logo" src="` + accountPortalLogoDataURI + `" alt="" aria-hidden="true"><h1>Masuk</h1><p class="lead">Gunakan Email & Password Akun Balai Anda</p></div>{{if .Message}}<p class="error" role="alert">{{.Message}}</p>{{end}}<form method="post" action="/account/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="request" value="{{.Request}}"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" placeholder="nama@bp3kpsumatera2.com" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" placeholder="Masukkan password" required><button class="button" type="submit" style="width:100%;margin-top:1.35rem">Masuk</button></form><div class="form-foot"><a class="footer-link" href="/forgot-password">Lupa Password?</a></div></section></div></body></html>`))
