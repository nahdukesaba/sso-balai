package router

import (
	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/handlers"
)

func Register(
	app *fiber.App,
	authHandler *handlers.AuthHandler,
) {
	api := app.Group("/api/v1")

	auth := api.Group("/auth")
	auth.Post("/login", authHandler.Login)
}
