package handlers

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

const (
	browserSSOSessionCookie = "balai_sso_session"
	browserSSOCSRFCookie    = "balai_sso_csrf"
	browserSSOLogoutCSRF    = "balai_sso_logout_csrf"
	accountPortalLoginCSRF  = "balai_portal_login_csrf"
	portalLaunchCookie      = "balai_portal_launch"
)

type BrowserSSOHandler struct {
	service        *services.BrowserSSOService
	portalService  *services.AccountPortalService
	adminRepo      *repository.SSOAdminRepository
	cookieSecure   bool
	cookieSameSite string
	sessionTTL     time.Duration
}

func (h *BrowserSSOHandler) SetAccountPortalService(service *services.AccountPortalService) {
	if h != nil {
		h.portalService = service
	}
}

func NewBrowserSSOHandler(
	service *services.BrowserSSOService,
	cookieSecure bool,
	cookieSameSite string,
	sessionTTL time.Duration,
) *BrowserSSOHandler {
	return &BrowserSSOHandler{
		service: service, cookieSecure: cookieSecure,
		cookieSameSite: normalizeSameSite(cookieSameSite), sessionTTL: sessionTTL,
	}
}

func normalizeSameSite(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return fiber.CookieSameSiteStrictMode
	case "none":
		return fiber.CookieSameSiteNoneMode
	default:
		return fiber.CookieSameSiteLaxMode
	}
}

func (h *BrowserSSOHandler) Authorize(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Browser SSO is not configured.")
	}
	request, sealed, err := h.authorizeRequest(c)
	if err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_authorize_request", "Invalid SSO authorization request.")
	}

	h.clearCookie(c, portalLaunchCookie)
	browserToken := c.Cookies(browserSSOSessionCookie)
	if strings.TrimSpace(browserToken) != "" {
		result, authErr := h.service.Authorize(c.UserContext(), request, browserToken)
		if authErr == nil && !result.LoginRequired {
			redirect, parseErr := url.Parse(result.RedirectURI)
			if parseErr == nil {
				query := redirect.Query()
				query.Set("state", result.State)
				if result.Code != "" {
					query.Set("code", result.Code)
				} else {
					query.Set("status", result.Status)
				}
				redirect.RawQuery = query.Encode()
				return c.Redirect(redirect.String(), fiber.StatusFound)
			}
		}
	}

	return c.Redirect("/?request="+url.QueryEscape(sealed), fiber.StatusFound)
}

func (h *BrowserSSOHandler) ContinueAuthorize(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Browser SSO is not configured.")
	}
	request, sealed, err := h.authorizeRequest(c)
	if err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_authorize_request", "Invalid SSO authorization request.")
	}
	result, err := h.service.Authorize(c.UserContext(), request, c.Cookies(browserSSOSessionCookie))
	if err != nil {
		return browserSSOError(c, fiber.StatusUnauthorized, "authorization_failed", "SSO authorization could not be completed.")
	}
	if result.LoginRequired {
		return c.Redirect("/?request="+url.QueryEscape(sealed), fiber.StatusFound)
	}
	redirect, err := url.Parse(result.RedirectURI)
	if err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_redirect_uri", "Invalid SSO redirect URI.")
	}
	query := redirect.Query()
	query.Set("state", result.State)
	if result.Code != "" {
		query.Set("code", result.Code)
	} else {
		query.Set("status", result.Status)
	}
	redirect.RawQuery = query.Encode()
	return c.Redirect(redirect.String(), fiber.StatusFound)
}

func (h *BrowserSSOHandler) authorizeRequest(c *fiber.Ctx) (models.BrowserSSOAuthorizeRequest, string, error) {
	sealed := strings.TrimSpace(c.Query("request"))
	if sealed != "" {
		request, err := h.service.OpenAuthorizeRequest(sealed)
		return request, sealed, err
	}
	request := models.BrowserSSOAuthorizeRequest{
		ClientID: c.Query("client_id"), RedirectURI: c.Query("redirect_uri"),
		ResponseType: c.Query("response_type"), State: c.Query("state"),
		CodeChallenge:       c.Query("code_challenge"),
		CodeChallengeMethod: c.Query("code_challenge_method"),
	}
	sealed, err := h.service.SealAuthorizeRequest(request)
	return request, sealed, err
}

func (h *BrowserSSOHandler) LoginPage(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Browser SSO is not configured.")
	}
	request := strings.TrimSpace(c.Query("request"))
	authorizeRequest, err := h.service.OpenAuthorizeRequest(request)
	if err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_authorize_request", "Invalid SSO authorization request.")
	}
	if _, err := browserSSORedirectOrigin(authorizeRequest.RedirectURI); err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_authorize_request", "Invalid SSO authorization request.")
	}
	csrf, err := services.RandomBrowserSSOToken(32)
	if err != nil {
		return browserSSOError(c, fiber.StatusInternalServerError, "sso_unavailable", "Browser SSO is unavailable.")
	}
	h.setCSRFCookie(c, csrf)
	return h.renderLogin(c, request, authorizeRequest.RedirectURI, csrf, "")
}

func (h *BrowserSSOHandler) LoginSubmit(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Browser SSO is not configured.")
	}
	request := strings.TrimSpace(c.FormValue("request"))
	csrf := strings.TrimSpace(c.FormValue("csrf"))
	cookieCSRF := strings.TrimSpace(c.Cookies(browserSSOCSRFCookie))
	if csrf == "" || cookieCSRF == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookieCSRF)) != 1 {
		return browserSSOError(c, fiber.StatusForbidden, "invalid_csrf", "The login form expired. Start SSO again.")
	}
	authorizeRequest, err := h.service.OpenAuthorizeRequest(request)
	if err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_authorize_request", "Invalid SSO authorization request.")
	}
	if _, err := browserSSORedirectOrigin(authorizeRequest.RedirectURI); err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_authorize_request", "Invalid SSO authorization request.")
	}
	rawToken, expiresAt, err := h.service.Login(
		c.UserContext(), c.FormValue("email"), c.FormValue("password"),
	)
	if err != nil {
		return h.renderLogin(c, request, authorizeRequest.RedirectURI, csrf, "Email atau password tidak valid.")
	}
	h.setSessionCookie(c, rawToken, expiresAt)
	h.clearCookie(c, browserSSOCSRFCookie)
	return c.Redirect("/authorize/continue?request="+url.QueryEscape(request), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) LogoutPage(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Logout is unavailable.")
	}
	clientID := strings.TrimSpace(c.Query("client_id"))
	redirectURI := strings.TrimSpace(c.Query("post_logout_redirect_uri"))
	cancelReturn := strings.TrimSpace(c.Query("cancel_return"))
	if cancelReturn == "" {
		cancelReturn = strings.TrimSpace(c.Query("return_to"))
	}
	portalReturn := c.Query("portal") == "1"
	if err := h.service.ValidatePostLogoutRedirect(clientID, redirectURI); err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_logout_request", "Invalid logout request.")
	}
	var validatedCancel string
	if cancelReturn != "" && clientID != "" && redirectURI != "" {
		if valid, err := h.service.ValidateCancelReturn(clientID, redirectURI, cancelReturn); err == nil && valid != "" {
			validatedCancel = valid
		}
	}
	active, err := h.service.HasActiveBrowserSession(
		c.UserContext(),
		c.Cookies(browserSSOSessionCookie),
	)
	if err != nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Logout is unavailable.")
	}
	if !active {
		if redirectURI != "" {
			return c.Redirect(redirectURI, fiber.StatusSeeOther)
		}
		if portalReturn {
			return c.Redirect("/", fiber.StatusSeeOther)
		}
		return h.renderLogoutState(
			c,
			"Anda sudah keluar",
			"Tidak ada sesi akun aktif pada browser ini.",
			"",
			"",
		)
	}
	if c.Query("immediate") == "1" || c.Query("confirm") == "1" {
		_ = h.service.RevokeBrowserSession(
			c.UserContext(),
			c.Cookies(browserSSOSessionCookie),
		)
		h.clearCookie(c, browserSSOSessionCookie)
		h.clearCookie(c, browserSSOLogoutCSRF)
		if redirectURI != "" {
			return c.Redirect(redirectURI, fiber.StatusSeeOther)
		}
		if portalReturn {
			return c.Redirect("/", fiber.StatusSeeOther)
		}
		return h.renderLogoutComplete(c)
	}
	if clientID == "" && redirectURI == "" && c.QueryBool("cancelled", false) {
		return h.renderLogoutState(
			c,
			"Logout dibatalkan",
			"Sesi akun Anda tetap aktif.",
			"/logout",
			"Kembali",
		)
	}
	csrf, err := services.RandomBrowserSSOToken(32)
	if err != nil {
		return browserSSOError(c, fiber.StatusInternalServerError, "sso_unavailable", "Logout is unavailable.")
	}
	h.setCookie(c, browserSSOLogoutCSRF, csrf, 600, time.Time{})
	return h.renderLogout(c, csrf, clientID, redirectURI, portalReturn, validatedCancel)
}

func (h *BrowserSSOHandler) LogoutSubmit(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Logout is unavailable.")
	}
	csrf := strings.TrimSpace(c.FormValue("csrf"))
	cookieCSRF := strings.TrimSpace(c.Cookies(browserSSOLogoutCSRF))
	if csrf == "" || cookieCSRF == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(cookieCSRF)) != 1 {
		return browserSSOError(c, fiber.StatusForbidden, "invalid_csrf", "The logout form expired. Try again.")
	}
	clientID := strings.TrimSpace(c.FormValue("client_id"))
	redirectURI := strings.TrimSpace(c.FormValue("post_logout_redirect_uri"))
	portalReturn := c.FormValue("portal") == "1"
	if err := h.service.ValidatePostLogoutRedirect(clientID, redirectURI); err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_logout_request", "Invalid logout request.")
	}
	err := h.service.RevokeBrowserSession(
		c.UserContext(),
		c.Cookies(browserSSOSessionCookie),
	)
	h.clearCookie(c, browserSSOSessionCookie)
	h.clearCookie(c, browserSSOLogoutCSRF)
	if err != nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Logout could not be completed.")
	}
	if redirectURI != "" {
		return c.Redirect(redirectURI, fiber.StatusSeeOther)
	}
	if portalReturn {
		return c.Redirect("/", fiber.StatusSeeOther)
	}
	return h.renderLogoutComplete(c)
}

type browserSSOExchangeRequest struct {
	Code         string `json:"code"`
	ClientID     string `json:"clientId"`
	RedirectURI  string `json:"redirectUri"`
	CodeVerifier string `json:"codeVerifier"`
}

func (h *BrowserSSOHandler) Exchange(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Browser SSO is not configured.")
	}
	var request browserSSOExchangeRequest
	if err := c.BodyParser(&request); err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_request", "Invalid exchange request.")
	}
	result, err := h.service.Exchange(
		c.UserContext(), strings.TrimSpace(request.Code), strings.TrimSpace(request.ClientID),
		strings.TrimSpace(request.RedirectURI), strings.TrimSpace(request.CodeVerifier),
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidAuthorizationCode),
			errors.Is(err, services.ErrInvalidPKCEVerifier),
			errors.Is(err, services.ErrInvalidBrowserSession):
			return browserSSOError(c, fiber.StatusUnauthorized, "invalid_authorization_code", "Authorization code is invalid or expired.")
		default:
			return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "SSO exchange could not be completed.")
		}
	}
	var apps []models.PortalApplicationCard
	if h.portalService != nil && result.Identity != nil && result.Identity.User != nil {
		apps = h.portalService.UserApplications(c.UserContext(), result.Identity.User.ID)
	}
	return c.JSON(fiber.Map{
		"accessToken":  result.Session.AccessToken,
		"refreshToken": result.Session.RefreshToken,
		"tokenType":    result.Session.TokenType,
		"expiresIn":    result.Session.ExpiresIn,
		"expiresAt":    result.Session.ExpiresAt,
		"sid":          result.SSOSessionID,
		"user":         result.Identity.User,
		"applications": apps,
	})
}

func (h *BrowserSSOHandler) Session(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"authenticated": false})
	}
	browserToken := c.Cookies(browserSSOSessionCookie)
	if strings.TrimSpace(browserToken) == "" {
		return c.JSON(fiber.Map{"authenticated": false})
	}
	identity, err := h.service.ResolveBrowserIdentity(c.UserContext(), browserToken)
	if err != nil || identity == nil || identity.User == nil {
		return c.JSON(fiber.Map{"authenticated": false})
	}
	var apps []models.PortalApplicationCard
	if h.portalService != nil {
		apps = h.portalService.UserApplications(c.UserContext(), identity.User.ID)
	}
	return c.JSON(fiber.Map{
		"authenticated": true,
		"user":          identity.User,
		"applications":  apps,
	})
}

type browserSSOIntrospectionRequest struct {
	ClientID  string `json:"clientId"`
	SID       string `json:"sid"`
	AppUserID string `json:"appUserId"`
}

func (h *BrowserSSOHandler) Introspect(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Browser SSO is not configured.")
	}
	var request browserSSOIntrospectionRequest
	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"active": false})
	}
	authorization := strings.Fields(strings.TrimSpace(c.Get(fiber.HeaderAuthorization)))
	if len(authorization) != 2 || !strings.EqualFold(authorization[0], "Bearer") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"active": false})
	}
	active, err := h.service.Introspect(
		c.UserContext(),
		request.ClientID,
		authorization[1],
		request.SID,
		request.AppUserID,
	)
	if errors.Is(err, services.ErrInvalidBrowserSession) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"active": false})
	}
	if err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"active": false})
	}
	return c.JSON(fiber.Map{"active": active})
}

func (h *BrowserSSOHandler) renderLogin(
	c *fiber.Ctx,
	request string,
	redirectURI string,
	csrf string,
	message string,
) error {
	redirectOrigin, err := browserSSORedirectOrigin(redirectURI)
	if err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_authorize_request", "Invalid SSO authorization request.")
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	c.Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; form-action 'self' %s; base-uri 'none'; frame-ancestors 'none'",
		redirectOrigin,
	))
	c.Type("html", "utf-8")
	var output strings.Builder
	if err := browserSSOLoginTemplate.Execute(&output, struct {
		Request string
		CSRF    string
		Message string
	}{request, csrf, message}); err != nil {
		return err
	}
	return c.SendString(output.String())
}

func (h *BrowserSSOHandler) renderLogout(
	c *fiber.Ctx,
	csrf string,
	clientID string,
	redirectURI string,
	portalReturn bool,
	validatedCancel ...string,
) error {
	formAction := "'self'"
	if redirectURI != "" {
		redirectOrigin, err := browserSSORedirectOrigin(redirectURI)
		if err != nil {
			return browserSSOError(c, fiber.StatusBadRequest, "invalid_logout_request", "Invalid logout request.")
		}
		formAction += " " + redirectOrigin
	}
	setBrowserSSOPageHeaders(c, formAction)
	var output strings.Builder
	// The same registered app entry handles either decision by validating its
	// preserved session: Cancel keeps the SID active; Confirm revokes it.
	// Central does not choose role routes or delete application cookies.
	cancelURL := firstNonEmptyString(redirectURI, "/logout?cancelled=1")
	if len(validatedCancel) > 0 && validatedCancel[0] != "" {
		cancelURL = validatedCancel[0]
	}
	portal := ""
	if portalReturn {
		cancelURL = "/"
		portal = "1"
	}
	if err := browserSSOLogoutTemplate.Execute(&output, struct {
		CSRF        string
		ClientID    string
		RedirectURI string
		CancelURL   string
		Portal      string
	}{csrf, clientID, redirectURI, cancelURL, portal}); err != nil {
		return err
	}
	return c.SendString(output.String())
}

func (h *BrowserSSOHandler) renderLogoutComplete(c *fiber.Ctx) error {
	setBrowserSSOPageHeaders(c, "'self'")
	return c.SendString(browserSSOLogoutCompletePage)
}

func (h *BrowserSSOHandler) renderLogoutState(
	c *fiber.Ctx,
	title string,
	message string,
	actionURL string,
	actionLabel string,
) error {
	setBrowserSSOPageHeaders(c, "'self'")
	var output strings.Builder
	if err := browserSSOLogoutStateTemplate.Execute(&output, struct {
		Title       string
		Message     string
		ActionURL   string
		ActionLabel string
	}{title, message, actionURL, actionLabel}); err != nil {
		return err
	}
	return c.SendString(output.String())
}

func setBrowserSSOPageHeaders(c *fiber.Ctx, formAction string) {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	c.Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; form-action %s; base-uri 'none'; frame-ancestors 'none'",
		formAction,
	))
	c.Type("html", "utf-8")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func browserSSORedirectOrigin(redirectURI string) (string, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(redirectURI))
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "http" && scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return "", errors.New("browser SSO redirect URI has no valid HTTP origin")
	}
	return (&url.URL{Scheme: scheme, Host: parsed.Host}).String(), nil
}

func (h *BrowserSSOHandler) setSessionCookie(c *fiber.Ctx, value string, expires time.Time) {
	c.Cookie(&fiber.Cookie{Name: browserSSOSessionCookie, Value: value, Path: "/", HTTPOnly: true,
		Secure: h.cookieSecure, SameSite: h.cookieSameSite, Expires: expires,
		MaxAge: int(time.Until(expires).Seconds())})
}

func (h *BrowserSSOHandler) setCSRFCookie(c *fiber.Ctx, value string) {
	h.setCookie(c, browserSSOCSRFCookie, value, 600, time.Time{})
}

func (h *BrowserSSOHandler) setCookie(c *fiber.Ctx, name, value string, maxAge int, expires time.Time) {
	c.Cookie(&fiber.Cookie{Name: name, Value: value, Path: "/", HTTPOnly: true,
		Secure: h.cookieSecure, SameSite: h.cookieSameSite, MaxAge: maxAge, Expires: expires})
}

func (h *BrowserSSOHandler) clearCookie(c *fiber.Ctx, name string) {
	c.Cookie(&fiber.Cookie{Name: name, Value: "", Path: "/", HTTPOnly: true,
		Secure: h.cookieSecure, SameSite: h.cookieSameSite, MaxAge: -1, Expires: time.Unix(1, 0)})
}

func browserSSOError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"error": code, "message": message})
}

var browserSSOLoginTemplate = template.Must(template.New("browser-sso-login").Parse(`<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Masuk SSO Balai</title>` + accountPortalFavicon + `<style>` + accountPortalStyles + `</style></head>
<body>` + accountPortalBrandHeader + `</div></header><div class="auth-wrap"><main class="auth-card"><div class="auth-head"><img class="brand-logo" src="` + accountPortalLogoDataURI + `" alt="" aria-hidden="true"><h1>Masuk dengan SSO Balai</h1><p class="lead">Gunakan akun Balai Anda untuk melanjutkan.</p></div>{{if .Message}}<p class="error" role="alert">{{.Message}}</p>{{end}}<form method="post" action="/login"><input type="hidden" name="request" value="{{.Request}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" placeholder="nama@bp3kpsumatera2.com" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" placeholder="Masukkan password" required><button class="button" type="submit" style="width:100%;margin-top:1.35rem">Masuk</button></form></main></div><footer class="portal-foot" style="margin-top:1rem;margin-bottom:2rem">Kementerian Perumahan dan Kawasan Permukiman · BP3KP Sumatera II</footer></body></html>`))

var browserSSOLogoutTemplate = template.Must(template.New("browser-sso-logout").Parse(`<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Konfirmasi Keluar Akun Balai Pegawai</title>` + accountPortalFavicon + `<style>` + accountPortalStyles + `</style></head>
<body>` + accountPortalBrandHeader + `</div></header><div class="auth-wrap"><main class="auth-card" style="text-align:center"><div class="icon-badge danger" aria-hidden="true"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg></div><h1>Keluar dari Akun Balai?</h1><p class="lead" style="margin-top:.6rem">Anda akan keluar dari semua aplikasi yang menggunakan sesi Akun Balai Pegawai!</p><div class="notice-box"><strong>Perhatian</strong>Sesi masuk pada seluruh aplikasi internal Balai (SILAPET, Klinik PKP, Arsiparis, Sijabu, Kompu) yang terhubung pada peramban ini akan diakhiri.</div><div class="actions" style="margin-top:1.5rem"><form method="post" action="/logout" style="width:100%;margin:0"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="client_id" value="{{.ClientID}}"><input type="hidden" name="post_logout_redirect_uri" value="{{.RedirectURI}}"><input type="hidden" name="portal" value="{{.Portal}}"><button type="submit">Keluar</button></form><a class="button secondary" href="{{.CancelURL}}">Batal</a></div></main></div><footer class="portal-foot" style="margin-top:1rem;margin-bottom:2rem">Kementerian Perumahan dan Kawasan Permukiman · BP3KP Sumatera II</footer></body></html>`))

var browserSSOLogoutStateTemplate = template.Must(template.New("browser-sso-logout-state").Parse(`<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>` + accountPortalFavicon + `<style>` + accountPortalStyles + `</style></head>
<body>` + accountPortalBrandHeader + `</div></header><div class="auth-wrap"><main class="auth-card" style="text-align:center"><div class="icon-badge info" aria-hidden="true"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg></div><h1>{{.Title}}</h1><p class="lead" style="margin-top:.6rem">{{.Message}}</p>{{if .ActionURL}}<div class="actions" style="margin-top:1.5rem"><a class="button" href="{{.ActionURL}}">{{.ActionLabel}}</a></div>{{end}}</main></div><footer class="portal-foot" style="margin-top:1rem;margin-bottom:2rem">Kementerian Perumahan dan Kawasan Permukiman · BP3KP Sumatera II</footer></body></html>`))

var browserSSOLogoutCompletePage = `<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Anda telah keluar</title>` + accountPortalFavicon + `<style>` + accountPortalStyles + `</style></head><body>` + accountPortalBrandHeader + `</div></header><div class="auth-wrap"><main class="auth-card" style="text-align:center"><div class="icon-badge success" aria-hidden="true"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div><h1>Anda telah keluar</h1><p class="lead" style="margin-top:.6rem">Sesi akun pada browser ini telah berakhir.</p><div class="actions" style="margin-top:1.5rem"><a class="button" href="/account/login">Masuk Kembali</a></div></main></div><footer class="portal-foot" style="margin-top:1rem;margin-bottom:2rem">Kementerian Perumahan dan Kawasan Permukiman · BP3KP Sumatera II</footer></body></html>`
