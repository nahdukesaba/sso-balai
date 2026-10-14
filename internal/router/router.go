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
	auth.Post("/register", authHandler.Register)
	auth.Post("/forgot-password", authHandler.ForgotPassword)
	auth.Post("/reset-password", authHandler.ResetPassword)
	auth.Post("/refresh", authHandler.Refresh)
	auth.Post("/logout", authHandler.Logout)
	auth.Put("/password", authMiddleware.RequireAuth, authHandler.ChangePassword)
	auth.Get("/me", authMiddleware.RequireAuth, authHandler.Me)
	auth.Get("/application-context", authMiddleware.RequireAuth, authHandler.ApplicationContext)
	auth.Get("/klinik-context", authMiddleware.RequireAuth, authHandler.KlinikContext)
}
