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
	"github.com/nahdukesaba/sso-balai/internal/services"
)

const (
	browserSSOSessionCookie = "balai_sso_session"
	browserSSOCSRFCookie    = "balai_sso_csrf"
	browserSSOLogoutCSRF    = "balai_sso_logout_csrf"
	accountPortalLoginCSRF  = "balai_portal_login_csrf"
)

type BrowserSSOHandler struct {
	service        *services.BrowserSSOService
	portalService  *services.AccountPortalService
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
	result, err := h.service.Authorize(c.UserContext(), request, c.Cookies(browserSSOSessionCookie))
	if err != nil {
		return browserSSOError(c, fiber.StatusUnauthorized, "authorization_failed", "SSO authorization could not be completed.")
	}
	if result.LoginRequired {
		return c.Redirect("/login?request="+url.QueryEscape(sealed), fiber.StatusFound)
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
	return c.Redirect("/authorize?request="+url.QueryEscape(request), fiber.StatusSeeOther)
}

func (h *BrowserSSOHandler) LogoutPage(c *fiber.Ctx) error {
	if h == nil || h.service == nil {
		return browserSSOError(c, fiber.StatusServiceUnavailable, "sso_unavailable", "Logout is unavailable.")
	}
	clientID := strings.TrimSpace(c.Query("client_id"))
	redirectURI := strings.TrimSpace(c.Query("post_logout_redirect_uri"))
	portalReturn := c.Query("portal") == "1"
	if err := h.service.ValidatePostLogoutRedirect(clientID, redirectURI); err != nil {
		return browserSSOError(c, fiber.StatusBadRequest, "invalid_logout_request", "Invalid logout request.")
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
	return h.renderLogout(c, csrf, clientID, redirectURI, portalReturn)
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
	return c.JSON(fiber.Map{
		"accessToken":  result.Session.AccessToken,
		"refreshToken": result.Session.RefreshToken,
		"tokenType":    result.Session.TokenType,
		"expiresIn":    result.Session.ExpiresIn,
		"expiresAt":    result.Session.ExpiresAt,
		"user":         result.Identity.User,
	})
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
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' %s; base-uri 'none'; frame-ancestors 'none'",
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
	cancelURL := firstNonEmptyString(redirectURI, "/logout?cancelled=1")
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
		"default-src 'none'; style-src 'unsafe-inline'; form-action %s; base-uri 'none'; frame-ancestors 'none'",
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
<title>Masuk SSO Balai</title><style>:root{font-family:system-ui,sans-serif;color:#17212b}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f8}main{width:min(28rem,calc(100% - 2rem));padding:2rem;border-radius:.75rem;background:#fff;box-shadow:0 .5rem 2rem #1f29371a}h1{margin-top:0}label{display:block;margin-top:1rem;font-weight:600}input,button{box-sizing:border-box;width:100%;margin-top:.4rem;padding:.75rem;font:inherit}button{margin-top:1.25rem;border:0;border-radius:.4rem;background:#075985;color:#fff;cursor:pointer}.error{color:#b91c1c}</style></head>
<body><main><h1>Masuk dengan SSO Balai</h1><p>Gunakan akun Balai Anda untuk melanjutkan.</p>{{if .Message}}<p class="error" role="alert">{{.Message}}</p>{{end}}<form method="post" action="/login"><input type="hidden" name="request" value="{{.Request}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Masuk</button></form></main></body></html>`))

var browserSSOLogoutTemplate = template.Must(template.New("browser-sso-logout").Parse(`<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Keluar dari akun</title><style>:root{font-family:system-ui,sans-serif;color:#17212b}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f8}main{width:min(28rem,calc(100% - 2rem));padding:2rem;border-radius:.75rem;background:#fff;box-shadow:0 .5rem 2rem #1f29371a}h1{margin-top:0}form{margin-top:1.5rem}button,a{box-sizing:border-box;display:block;width:100%;padding:.75rem;border-radius:.4rem;text-align:center;font:inherit;text-decoration:none}button{border:0;background:#075985;color:#fff;cursor:pointer}a{margin-top:.75rem;border:1px solid #cbd5e1;color:#17212b}</style></head>
<body><main><h1>Keluar dari akun</h1><p>Anda akan keluar dari akun pada browser ini.</p><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="client_id" value="{{.ClientID}}"><input type="hidden" name="post_logout_redirect_uri" value="{{.RedirectURI}}"><input type="hidden" name="portal" value="{{.Portal}}"><button type="submit">Keluar</button></form><a href="{{.CancelURL}}">Batal</a></main></body></html>`))

var browserSSOLogoutStateTemplate = template.Must(template.New("browser-sso-logout-state").Parse(`<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title><style>:root{font-family:system-ui,sans-serif;color:#17212b}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f8}main{width:min(28rem,calc(100% - 2rem));padding:2rem;border-radius:.75rem;background:#fff;box-shadow:0 .5rem 2rem #1f29371a}h1{margin-top:0}a{box-sizing:border-box;display:block;width:100%;margin-top:1rem;padding:.75rem;border:1px solid #cbd5e1;border-radius:.4rem;color:#17212b;text-align:center;text-decoration:none}</style></head>
<body><main><h1>{{.Title}}</h1><p>{{.Message}}</p>{{if .ActionURL}}<a href="{{.ActionURL}}">{{.ActionLabel}}</a>{{end}}</main></body></html>`))

const browserSSOLogoutCompletePage = `<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Anda telah keluar</title><style>:root{font-family:system-ui,sans-serif;color:#17212b}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f6f8}main{width:min(28rem,calc(100% - 2rem));padding:2rem;border-radius:.75rem;background:#fff;box-shadow:0 .5rem 2rem #1f29371a}</style></head><body><main><h1>Anda telah keluar</h1><p>Sesi akun pada browser ini telah berakhir.</p></main></body></html>`
