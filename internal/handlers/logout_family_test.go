package handlers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/nahdukesaba/sso-balai/internal/models"
)

func TestBothAppsCancelKeepsFamilyAndConfirmRevokesFamily(t *testing.T) {
	for _, origin := range []struct{ client, target string }{
		{"klinik-pkp-web", "http://klinik-pkp.test:3000/login"},
		{"silapet-web", "http://silapet.test:8080/login"},
	} {
		t.Run(origin.client, func(t *testing.T) {
			const sid = "11111111-1111-4111-8111-111111111111"
			handler, store := newHandlerBrowserSSOTestSetup(t, &models.BrowserSSOSession{
				ID: sid, AuthUserID: "auth-user", AppUserID: "app-user", ExpiresAt: time.Now().Add(time.Hour),
			}, "http://silapet.test:8080/auth/sso/callback", nil)
			app := fiber.New()
			app.Get("/logout", handler.LogoutPage)
			app.Post("/logout", handler.LogoutSubmit)
			query := url.Values{"client_id": {origin.client}, "post_logout_redirect_uri": {origin.target}}
			req := httptest.NewRequest(http.MethodGet, "/logout?"+query.Encode(), nil)
			req.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "browser-cookie"})
			page, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			defer page.Body.Close()
			body, _ := io.ReadAll(page.Body)
			if page.StatusCode != http.StatusOK || !strings.Contains(string(body), `href="`+origin.target+`">Batal`) {
				t.Fatal("Cancel did not return to the exact registered app session entry")
			}
			if store.revokeCalls != 0 || responseCookie(page, browserSSOSessionCookie) != nil {
				t.Fatal("confirmation page changed the active browser session")
			}
			checkFamily := func(wantActive bool) {
				t.Helper()
				for _, client := range []struct{ id, secret string }{
					{"silapet-web", "handler-test-introspection-secret-0001"},
					{"klinik-pkp-web", "klinik-test-introspection-secret-00001"},
				} {
					active, checkErr := handler.service.Introspect(context.Background(), client.id, client.secret, sid, "app-user")
					if checkErr != nil || active != wantActive {
						t.Fatalf("wrong family state for %s: active=%t err=%v", client.id, active, checkErr)
					}
				}
			}
			// Following Cancel is navigation to the app, with no Central mutation.
			checkFamily(true)
			csrf := responseCookie(page, browserSSOLogoutCSRF)
			if csrf == nil {
				t.Fatal("missing confirmation CSRF")
			}
			query.Set("csrf", csrf.Value)
			confirm := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(query.Encode()))
			confirm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			confirm.AddCookie(csrf)
			confirm.AddCookie(&http.Cookie{Name: browserSSOSessionCookie, Value: "browser-cookie"})
			result, err := app.Test(confirm)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Body.Close()
			if result.StatusCode != http.StatusSeeOther || result.Header.Get("Location") != origin.target || store.revokeCalls != 1 {
				t.Fatal("Confirm did not revoke and return to the registered app")
			}
			checkFamily(false)
			if !store.unrelatedActive {
				t.Fatal("Confirm revoked an unrelated session")
			}
			for _, cookie := range result.Cookies() {
				if cookie.Domain != "" || (cookie.Name != browserSSOSessionCookie && cookie.Name != browserSSOLogoutCSRF) {
					t.Fatal("Central attempted cross-app cookie cleanup")
				}
			}
		})
	}
}
