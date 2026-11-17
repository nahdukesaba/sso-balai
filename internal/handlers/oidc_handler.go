package handlers

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/services"
)

type OIDCHandler struct {
	provider *services.OIDCProvider
}

func NewOIDCHandler(provider *services.OIDCProvider) *OIDCHandler {
	return &OIDCHandler{provider: provider}
}

func (h *OIDCHandler) Discovery(c *fiber.Ctx) error {
	c.Set(fiber.HeaderAccessControlAllowOrigin, "*")
	return c.JSON(h.provider.Discovery())
}

func (h *OIDCHandler) JWKS(c *fiber.Ctx) error {
	c.Set(fiber.HeaderAccessControlAllowOrigin, "*")
	return c.JSON(h.provider.JWKS())
}

// Token implements the authorization_code grant (RFC 6749 section 4.1.3) with
// client_secret_basic or client_secret_post authentication and PKCE.
func (h *OIDCHandler) Token(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set(fiber.HeaderPragma, "no-cache")
	if c.FormValue("grant_type") != "authorization_code" {
		return oauthError(c, fiber.StatusBadRequest, "unsupported_grant_type")
	}
	clientID, clientSecret, basic, ok := clientCredentials(c)
	if !ok {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request")
	}
	response, err := h.provider.Token(
		c.UserContext(), c.FormValue("code"), clientID, clientSecret,
		c.FormValue("redirect_uri"), c.FormValue("code_verifier"),
	)
	switch {
	case err == nil:
		return c.JSON(response)
	case errors.Is(err, services.ErrInvalidClient):
		if basic {
			c.Set(fiber.HeaderWWWAuthenticate, `Basic realm="sso-balai"`)
		}
		return oauthError(c, fiber.StatusUnauthorized, "invalid_client")
	case errors.Is(err, services.ErrInvalidAuthorizationCode),
		errors.Is(err, services.ErrInvalidPKCEVerifier),
		errors.Is(err, services.ErrInvalidBrowserSession),
		errors.Is(err, services.ErrAccountUnavailable):
		return oauthError(c, fiber.StatusBadRequest, "invalid_grant")
	default:
		return oauthError(c, fiber.StatusServiceUnavailable, "temporarily_unavailable")
	}
}

// clientCredentials reads HTTP Basic (form-urlencoded per RFC 6749 section
// 2.3.1) or client_id/client_secret form fields; using both is rejected.
func clientCredentials(c *fiber.Ctx) (clientID, secret string, basic, ok bool) {
	header := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
	formSecret := c.FormValue("client_secret")
	if header == "" {
		return c.FormValue("client_id"), formSecret, false, true
	}
	scheme, encoded, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") || formSecret != "" {
		return "", "", true, false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return "", "", true, false
	}
	rawID, rawSecret, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", true, false
	}
	if clientID, err = url.QueryUnescape(rawID); err != nil {
		return "", "", true, false
	}
	if secret, err = url.QueryUnescape(rawSecret); err != nil {
		return "", "", true, false
	}
	if formID := c.FormValue("client_id"); formID != "" && formID != clientID {
		return "", "", true, false
	}
	return clientID, secret, true, true
}

func (h *OIDCHandler) UserInfo(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	scheme, token, found := strings.Cut(strings.TrimSpace(c.Get(fiber.HeaderAuthorization)), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="sso-balai"`)
		return c.SendStatus(fiber.StatusUnauthorized)
	}
	info, err := h.provider.UserInfo(c.UserContext(), strings.TrimSpace(token))
	if errors.Is(err, services.ErrInvalidAccessToken) {
		c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="sso-balai", error="invalid_token"`)
		return c.SendStatus(fiber.StatusUnauthorized)
	}
	if err != nil {
		return oauthError(c, fiber.StatusServiceUnavailable, "temporarily_unavailable")
	}
	return c.JSON(info)
}

func oauthError(c *fiber.Ctx, status int, code string) error {
	return c.Status(status).JSON(fiber.Map{"error": code})
}
