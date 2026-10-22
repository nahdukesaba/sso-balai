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
	browserSSOHandlers ...*handlers.BrowserSSOHandler,
) {
	app.Get("/reset-password", authHandler.ResetPasswordPage)

	if len(browserSSOHandlers) > 0 && browserSSOHandlers[0] != nil {
		browserSSOHandler := browserSSOHandlers[0]
		app.Get("/authorize", browserSSOHandler.Authorize)
		app.Get("/login", browserSSOHandler.LoginPage)
		app.Post("/login", browserSSOHandler.LoginSubmit)
		app.Get("/logout", browserSSOHandler.LogoutPage)
		app.Post("/logout", browserSSOHandler.LogoutSubmit)
		app.Post("/api/v1/auth/sso/exchange", browserSSOHandler.Exchange)
	}

	api := app.Group("/api/v1")

	auth := api.Group("/auth")

	auth.Post("/login", authHandler.Login)
	auth.Post("/register", authHandler.Register)
	auth.Post("/forgot-password", authHandler.ForgotPassword)
	auth.Post("/reset-password", authHandler.ResetPassword)
	auth.Post("/request-access", authHandler.RequestAccess)
	auth.Post("/refresh", authHandler.Refresh)
	auth.Post("/logout", authHandler.Logout)
	auth.Put("/password", authMiddleware.RequireAuth, authHandler.ChangePassword)
	auth.Post(
		"/applications/enroll",
		authMiddleware.RequireAuth,
		authHandler.EnrollApplication,
	)
	auth.Get("/me", authMiddleware.RequireAuth, authHandler.Me)
	auth.Get("/application-context", authMiddleware.RequireAuth, authHandler.ApplicationContext)
	auth.Get("/klinik-context", authMiddleware.RequireAuth, authHandler.KlinikContext)
}
