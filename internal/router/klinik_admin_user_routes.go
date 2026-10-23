package router

import (
	"github.com/gofiber/fiber/v2"
	"github.com/nahdukesaba/sso-balai/internal/handlers"
	"github.com/nahdukesaba/sso-balai/internal/middleware"
)

func RegisterKlinikAdminUsers(app *fiber.App, handler *handlers.KlinikAdminUserHandler, auth *middleware.AuthMiddleware) {
	app.Post("/api/v1/admin/klinik/users", auth.RequireAuth, handler.Provision)
}
