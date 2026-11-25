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
	app.Get("/forgot-password", authHandler.ForgotPasswordPage)
	app.Get("/accept-invite", authHandler.AcceptInvitePage)

	if len(browserSSOHandlers) > 0 && browserSSOHandlers[0] != nil {
		browserSSOHandler := browserSSOHandlers[0]
		app.Get("/", browserSSOHandler.PortalHome)
		app.Get("/portal/launch", browserSSOHandler.PortalLaunch)
		app.Get("/portal/launch/:app", browserSSOHandler.PortalLaunch)
		app.Get("/account/login", browserSSOHandler.PortalLoginPage)
		app.Post("/account/login", browserSSOHandler.PortalLoginSubmit)
		app.Get("/authorize", browserSSOHandler.Authorize)
		app.Get("/authorize/continue", browserSSOHandler.ContinueAuthorize)
		app.Get("/login", browserSSOHandler.LoginPage)
		app.Post("/login", browserSSOHandler.LoginSubmit)
		app.Get("/logout", browserSSOHandler.LogoutPage)
		app.Post("/logout", browserSSOHandler.LogoutSubmit)
		app.Post("/api/v1/auth/sso/exchange", browserSSOHandler.Exchange)
		app.Post("/api/v1/auth/sso/introspect", browserSSOHandler.Introspect)
		app.Get("/api/v1/auth/sso/session", browserSSOHandler.Session)
		app.Get("/api/v1/auth/apps", browserSSOHandler.PublicApps)
		app.Options("/api/v1/auth/apps", browserSSOHandler.PublicApps)
		app.Get("/api/v1/public/apps", browserSSOHandler.PublicApps)
		app.Options("/api/v1/public/apps", browserSSOHandler.PublicApps)
		app.Get("/widget/default-logo.png", browserSSOHandler.DefaultLogoPNG)
		app.Get("/widget/app-switcher.js", browserSSOHandler.AppSwitcherWidgetJS)
		app.Get("/admin/sso", browserSSOHandler.AdminSSOPage)
		app.Get("/admin/sso/docs.md", browserSSOHandler.AdminSSODownloadDocsMD)
		app.Post("/admin/sso/apps", browserSSOHandler.AdminSSOSaveApp)
		app.Post("/admin/sso/apps/delete", browserSSOHandler.AdminSSODeleteApp)
		app.Post("/admin/sso/memberships", browserSSOHandler.AdminSSOSaveMembership)
		app.Post("/admin/sso/users/superadmin", browserSSOHandler.AdminSSOToggleSuperAdmin)
		app.Post("/admin/sso/users/create", browserSSOHandler.AdminSSOCreateUser)
		app.Post("/admin/sso/users/update", browserSSOHandler.AdminSSOUpdateUser)
		app.Post("/admin/sso/users/delete", browserSSOHandler.AdminSSODeleteUser)
		app.Post("/admin/sso/users/restore", browserSSOHandler.AdminSSORestoreUser)
		app.Get("/admin/sso/users/template.xlsx", browserSSOHandler.AdminSSODownloadUserTemplateXLSX)
		app.Post("/admin/sso/users/bulk-import", browserSSOHandler.AdminSSOBulkImportUsers)
		app.Post("/admin/sso/users/bulk-action", browserSSOHandler.AdminSSOBulkAction)
	}

	api := app.Group("/api/v1")

	auth := api.Group("/auth")

	auth.Post("/login", authHandler.Login)
	auth.Post("/register", authHandler.Register)
	auth.Post("/forgot-password", authHandler.ForgotPassword)
	auth.Post("/reset-password", authHandler.ResetPassword)
	auth.Post("/accept-invite", authHandler.AcceptInvite)
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
