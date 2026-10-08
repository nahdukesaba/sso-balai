package router

import (
	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/handlers"
	"github.com/nahdukesaba/sso-balai/internal/middleware"
)

func Register(
	app *fiber.App,
	authHandler *handlers.AuthHandler,
	authMiddleware *middleware.AuthMiddleware,
) {
	api := app.Group("/api/v1")

	auth := api.Group("/auth")

	auth.Post("/login", authHandler.Login)
	auth.Get("/me", authMiddleware.RequireAuth, authHandler.Me)
}
