package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/nahdukesaba/sso-balai/internal/handlers"
	"github.com/nahdukesaba/sso-balai/internal/middleware"
	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/services"
)

type routeRequestAccessService struct{}

func (routeRequestAccessService) Request(
	_ context.Context,
	_ string,
	_ string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	return &models.ApplicationEnrollmentResult{
		Application: applicationCode,
		Status:      models.MembershipStatusPending,
		Outcome:     models.ApplicationEnrollmentCreated,
	}, nil
}

func TestRequestAccessRouteIsPublic(t *testing.T) {
	authService := &services.AuthService{}
	authService.SetRequestAccessService(routeRequestAccessService{})
	handler := handlers.NewAuthHandler(authService, nil, nil)
	authMiddleware := middleware.NewAuthMiddleware(authService)
	app := fiber.New()
	Register(app, handler, authMiddleware)

	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/auth/request-access",
		strings.NewReader(`{
			"email":"employee@example.com",
			"password":"password",
			"application":"silapet"
		}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	if err != nil {
		t.Fatalf("perform public request-access request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected public endpoint status 200, got %d", response.StatusCode)
	}
}
