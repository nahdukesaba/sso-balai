# Browser SSO Balai

Browser SSO is an optional authorization-code flow for registered Balai clients. It does not replace the existing direct email/password API.

## SILAPET client

- Client ID: `silapet-web`
- Application code: `silapet`
- Local redirect URI: `http://localhost:8081/auth/sso/callback`
- Redirect URIs use an exact configuration allowlist; arbitrary callback URLs are rejected.
- The browser client has no client secret. PKCE S256 protects the authorization code.

## Flow

1. SILAPET backend creates a random state and a PKCE challenge, stores only the state hash, and redirects the browser to `GET /authorize`.
2. Central validates the client, exact redirect URI, response type, state, and S256 challenge.
3. If the opaque `HttpOnly` Central session cookie is absent, Central displays `GET /login`. The login POST uses a double-submit CSRF token and authenticates through Supabase password login.
4. Central stores only the browser-session token hash and identity IDs. It does not store a Supabase access or refresh token in the browser-session row, and revokes the transient password-login session on a best-effort basis.
5. Approved membership receives a random, short-lived code. Missing membership is auto-enrolled as `user/pending`; pending receives `status=pending`; rejected or disabled receives `status=denied`.
6. SILAPET backend verifies and atomically consumes state, derives its server-held PKCE verifier, and exchanges the code server-to-server.
7. Central atomically consumes the authorization code only when code hash, client, redirect URI, PKCE challenge, expiry, and unused state all match.
8. Central uses the Supabase Admin `generate_link` magic-link primitive and verifies its token hash server-to-server to obtain an independent Supabase session. The returned Auth user ID must match the browser session before tokens are returned to SILAPET backend.

Only `code`, `state`, or a safe membership status is placed in the callback URL. Supabase access and refresh tokens never enter a redirect URL.

## Central account portal

When Browser SSO is enabled, Central also serves the public `GET /` **Akun Balai** portal. A logged-out visitor can use the CSRF-protected `GET/POST /account/login` form or open `GET /forgot-password`. Portal login reuses the Supabase-backed browser-session login and creates the same opaque `balai_sso_session`; it does not require membership in an application and does not alter the sealed-request contract of the existing `GET/POST /login` Browser SSO routes.

For an active Central session, the portal resolves `auth_user_id` back to the current internal identity and lists active applications from `applications`, joined to that user's `app_memberships`. Friendly membership and role labels are rendered server-side. Only an approved SILAPET membership receives a launch link. The launch destination comes from `PORTAL_SILAPET_LAUNCH_URL`, never from browser input; other applications remain visible with their database name and membership status but are not launchable until their server-controlled metadata and Browser SSO integration are configured.

Password recovery continues through the existing Supabase-owned `POST /api/v1/auth/forgot-password` flow, `PASSWORD_RECOVERY_REDIRECT_URL`, and `GET /reset-password`. Portal logout enters `GET /logout?portal=1`, preserves the existing confirmation and CSRF checks, revokes the current browser session on POST, clears its cookie, and returns safely to `/`.

## Session and logout semantics

The Central cookie is opaque, `HttpOnly`, `Path=/`, configurable `SameSite`, and `Secure=true` by default. `SameSite=None` is rejected unless `Secure=true`. Local HTTP development must explicitly set `SSO_BROWSER_COOKIE_SECURE=false`; production must retain `true`.

SILAPET logout is coordinated only when the verified SILAPET access token says
the current application session came from Browser SSO. A direct-login SILAPET
session is revoked and returns directly to SILAPET `/login`, even if an
unrelated Central browser cookie happens to exist.

For Browser SSO sessions, the application first revokes its Supabase session
and clears local state, then navigates through its backend to Central
`GET /logout`. Central shows a CSRF-protected confirmation only when the opaque
cookie resolves to an active browser session. Missing, expired, or revoked
sessions receive an already-logged-out state, or return directly to an exact
registered application URI. `POST /logout` revokes only the session identified
by the current opaque cookie. Sessions belonging to other applications are not
revoked. Registered cancel actions return to the exact configured application
login URI; direct Central cancel uses the existing `/logout?cancelled=1` state.

## Configuration

- `SSO_BROWSER_ENABLED`
- `SSO_BROWSER_SESSION_KEY` (base64-encoded 32-byte key used to seal authorization context)
- `SSO_BROWSER_COOKIE_SECURE`
- `SSO_BROWSER_COOKIE_SAME_SITE`
- `SSO_BROWSER_SESSION_TTL`
- `SSO_AUTHORIZATION_CODE_TTL`
- `SSO_SILAPET_CLIENT_ID`
- `SSO_SILAPET_APPLICATION_CODE`
- `SSO_SILAPET_REDIRECT_URIS` (comma-separated exact allowlist)
- `SSO_SILAPET_POST_LOGOUT_REDIRECT_URIS` (comma-separated exact allowlist)
- `PORTAL_SILAPET_LAUNCH_URL` (absolute server-controlled HTTP(S) URL; use `http://127.0.0.1:5173/` for the local SILAPET frontend and configure the production URL in its environment)

The feature is fail-closed and disabled by default. The local portal is available at the Central listener (for the current local stack, `http://127.0.0.1:18082/`). Apply migration `000006_create_browser_sso` only to the intended local environment before enabling it. The account portal itself adds no migration.
