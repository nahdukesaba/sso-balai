package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/nahdukesaba/sso-balai/internal/handlers"
	"github.com/nahdukesaba/sso-balai/internal/middleware"
)

// RegisterOIDC exposes the standard OpenID Connect endpoints.
func RegisterOIDC(app *fiber.App, handler *handlers.OIDCHandler) {
	app.Get("/.well-known/openid-configuration", handler.Discovery)
	app.Get("/.well-known/jwks.json", handler.JWKS)
	app.Post("/oauth/token", handler.Token)
	app.Get("/oauth/userinfo", handler.UserInfo)
	app.Post("/oauth/userinfo", handler.UserInfo)
}

func RegisterKlinikAdminUsers(app *fiber.App, handler *handlers.KlinikAdminUserHandler, auth *middleware.AuthMiddleware) {
	app.Post("/api/v1/admin/klinik/users", auth.RequireAuth, handler.Provision)
}
