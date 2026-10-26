package handlers

import (
	"crypto/subtle"
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

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
	h.setCookie(c, accountPortalLoginCSRF, csrf, 600, time.Time{})
	return renderAccountPortalLogin(c, csrf, pendingRequest, "")
}

func (h *BrowserSSOHandler) PortalLoginSubmit(c *fiber.Ctx) error {
	if h == nil || h.portalService == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "portal_unavailable", "Account portal is unavailable.")
	}
	csrf := strings.TrimSpace(c.FormValue("csrf"))
	pendingRequest := strings.TrimSpace(c.FormValue("request"))
	cookieCSRF := strings.TrimSpace(c.Cookies(accountPortalLoginCSRF))
	if csrf == "" || cookieCSRF == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookieCSRF)) != 1 {
		return browserSSOError(c, fiber.StatusForbidden, "invalid_csrf", "The login form expired. Try again.")
	}
	rawToken, expiresAt, err := h.portalService.Login(
		c.UserContext(),
		strings.TrimSpace(c.FormValue("email")),
		c.FormValue("password"),
	)
	if err != nil {
		return renderAccountPortalLogin(c, csrf, pendingRequest, "Email atau password tidak valid.")
	}
	h.setSessionCookie(c, rawToken, expiresAt)
	h.clearCookie(c, accountPortalLoginCSRF)
	return c.Redirect(portalURL(pendingRequest), fiber.StatusSeeOther)
}

func portalURL(pendingRequest string) string {
	if strings.TrimSpace(pendingRequest) == "" {
		return "/"
	}
	return "/?request=" + url.QueryEscape(pendingRequest)
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

func renderAccountPortalLogin(c *fiber.Ctx, csrf string, request string, message string) error {
	setAccountPortalPageHeaders(c)
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
	c.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	c.Type("html", "utf-8")
}

const accountPortalStyles = `:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#17212b;background:#eef3f7}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(145deg,#eef5f8,#f8fafc 55%,#e7eff3)}main{width:min(70rem,calc(100% - 2rem));margin:0 auto;padding:3rem 0 4rem}.brand{display:flex;align-items:center;gap:.9rem;margin-bottom:2.5rem}.brand-mark{display:grid;place-items:center;width:3.25rem;height:3.25rem;border-radius:.8rem;background:#075985;color:#fff;font-size:.78rem;font-weight:800;letter-spacing:.08em}.brand-name{font-weight:750}.brand-unit{color:#526574;font-size:.9rem}.panel{padding:clamp(1.5rem,4vw,3rem);border:1px solid #d9e3e9;border-radius:1.15rem;background:#fffffff2;box-shadow:0 1.25rem 3rem #29455714}h1,h2{margin-top:0}h1{font-size:clamp(2rem,6vw,3.5rem);letter-spacing:-.04em}h2{font-size:1.25rem}.lead,.muted{color:#526574;line-height:1.65}.actions{display:flex;flex-wrap:wrap;gap:.75rem;margin-top:1.5rem}.button{display:inline-flex;align-items:center;justify-content:center;min-height:2.8rem;padding:.7rem 1.05rem;border:0;border-radius:.55rem;background:#075985;color:#fff;font:inherit;font-weight:700;text-decoration:none;cursor:pointer}.button.secondary{border:1px solid #c7d5df;background:#fff;color:#173142}.identity{display:flex;justify-content:space-between;gap:1rem;align-items:flex-start}.apps{display:grid;grid-template-columns:repeat(auto-fit,minmax(15rem,1fr));gap:1rem;margin-top:1rem}.card{display:flex;flex-direction:column;min-height:14rem;padding:1.25rem;border:1px solid #d9e3e9;border-radius:.85rem;background:#fff}.card p{margin:.35rem 0}.card .button{margin-top:auto}.status{font-weight:750;color:#075985}.role{color:#526574;font-size:.92rem}.spacer{margin-top:2.5rem}label{display:block;margin-top:1rem;font-weight:700}input{width:100%;margin-top:.4rem;padding:.75rem;border:1px solid #b9c8d2;border-radius:.5rem;font:inherit}.error{color:#b42318}.footer-link{color:#075985}@media(max-width:640px){main{padding-top:1.25rem}.identity{display:block}.actions .button{width:100%}}`

var accountPortalLoggedOutTemplate = template.Must(template.New("account-portal-logged-out").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Akun Balai Pegawai - BP3KP Sumatera II</title><style>` + accountPortalStyles + `</style></head><body><main><header class="brand"><div class="brand-mark" aria-hidden="true">BP3KP</div><div><div class="brand-name">BP3KP Sumatera II</div><div class="brand-unit">Akun Balai Pegawai</div></div></header><section class="panel"><p class="muted">Portal Layanan Internal Balai PK3P Sumatera II</p><h1>Akun Balai Pegawai</h1>{{if .PendingAuthorization}}<p class="status">{{.PendingAuthorization.ApplicationName}}</p>{{end}}<div class="actions"><a class="button" href="{{if .PendingAuthorization}}{{.PendingAuthorization.LoginURL}}{{else}}/account/login{{end}}">Masuk</a><a class="button secondary" href="/forgot-password">Lupa Password</a></div></section></main></body></html>`))

var accountPortalLoggedInTemplate = template.Must(template.New("account-portal").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Akun Balai Pegawai - BP3KP Sumatera II</title><style>` + accountPortalStyles + `</style></head><body><main><header class="brand"><div class="brand-mark" aria-hidden="true">BP3KP</div><div><div class="brand-name">BP3KP Sumatera II</div><div class="brand-unit">Akun Balai Pegawai</div></div></header><section class="panel"><div class="identity"><div><h1>Halo, {{.Identity.User.FullName}}</h1></div><a class="button secondary" href="/logout?portal=1">Keluar</a></div>{{if .PendingAuthorization}}<div class="spacer"><a class="button" href="{{.PendingAuthorization.ContinueURL}}">Lanjut ke {{.PendingAuthorization.ApplicationName}}</a></div>{{end}}<div class="spacer"><h2>Aplikasi Anda</h2><div class="apps">{{range .Applications}}<article class="card"><h2>{{.Name}}</h2>{{if .Description}}<p class="muted">{{.Description}}</p>{{end}}<p class="status">{{.StatusLabel}}</p>{{if .RoleLabel}}<p class="role">{{.RoleLabel}}</p>{{end}}{{if .Launchable}}<a class="button" href="{{.LaunchURL}}">Buka Aplikasi</a>{{end}}</article>{{else}}<p class="muted">Tidak Ada Aplikasi Yang Tersedia</p>{{end}}</div></div></section></main></body></html>`))

var accountPortalLoginTemplate = template.Must(template.New("account-portal-login").Parse(`<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Masuk - Akun Balai Pegawai</title><style>` + accountPortalStyles + `</style></head><body><main><header class="brand"><div class="brand-mark" aria-hidden="true">BP3KP</div><div><div class="brand-name">BP3KP Sumatera II</div><div class="brand-unit">Akun Balai Pegawai</div></div></header><section class="panel" style="max-width:30rem;margin:0 auto"><h1>Masuk</h1><p class="lead">Gunakan Email & Password Akun Balai Anda</p>{{if .Message}}<p class="error" role="alert">{{.Message}}</p>{{end}}<form method="post" action="/account/login"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="request" value="{{.Request}}"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button class="button" type="submit" style="width:100%;margin-top:1.25rem">Masuk</button></form><p><a class="footer-link" href="/forgot-password">Lupa Password?</a></p></section></main></body></html>`))
