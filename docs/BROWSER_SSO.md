# Browser SSO Balai

Browser SSO is an optional authorization-code flow for registered Balai clients. It does not replace the existing direct email/password API.

## Trusted client registry

Central loads an immutable, config-backed registry at startup. Every exact
`client_id` resolves to one server-owned application code and its own exact
redirect and post-logout URI allowlists. Application code is never accepted
from browser input. Unknown clients, malformed HTTP(S) URIs, duplicate client
IDs, wildcard URLs, and cross-client redirects fail closed.

### SILAPET client

- Client ID: `silapet-web`
- Application code: `silapet`
- Local redirect URI: `http://silapet.test:8080/auth/sso/callback`
- Local post-logout URI: `http://silapet.test:8080/login`
- Local portal launch URL: `http://silapet.test:8081/api/auth/sso/start`
- Redirect URIs use an exact configuration allowlist; arbitrary callback URLs are rejected.
- The browser client has no client secret. PKCE S256 protects the authorization code.

### Klinik PKP client

- Client ID: `klinik-pkp-web`
- Application code: `klinik_pkp`
- Local redirect URI: `http://klinik-pkp.test:3000/auth/sso/callback`
- Local post-logout URI: `http://klinik-pkp.test:3000/login`
- Local portal launch URL: `http://klinik-pkp.test:3000/api/auth/sso/start`

These Klinik values are for local development. Production redirect,
post-logout, and launch URLs are not finalized and must be supplied through the
production environment; they are not inferred from requests.

## Flow

1. A registered application backend creates a random state and a PKCE challenge, stores only the state hash, and redirects the browser to `GET /authorize`.
2. Central validates the client, exact redirect URI, response type, state, and S256 challenge.
3. If the opaque `HttpOnly` Central session cookie is absent, Central displays `GET /login`. The login POST uses a double-submit CSRF token and authenticates through Supabase password login.
4. Central stores only the browser-session token hash and identity IDs. It does not store a Supabase access or refresh token in the browser-session row, and revokes the transient password-login session on a best-effort basis.
5. Approved membership receives a random, short-lived code. Missing membership is auto-enrolled as `user/pending`; pending receives `status=pending`; rejected or disabled receives `status=denied`.
6. The application backend verifies and atomically consumes state, derives its server-held PKCE verifier, and exchanges the code server-to-server.
7. Central atomically consumes the authorization code only when code hash, client, redirect URI, PKCE challenge, expiry, and unused state all match.
8. Central uses the Supabase Admin `generate_link` magic-link primitive and verifies its token hash server-to-server to obtain an independent Supabase session. The returned Auth user ID must match the browser session before tokens are returned to SILAPET backend.

Only `code`, `state`, or a safe membership status is placed in the callback URL. Supabase access and refresh tokens never enter a redirect URL.

## Central account portal

When Browser SSO is enabled, Central also serves the public `GET /` **Akun Balai** portal. A logged-out visitor can use the CSRF-protected `GET/POST /account/login` form or open `GET /forgot-password`. Portal login reuses the Supabase-backed browser-session login and creates the same opaque `balai_sso_session`; it does not require membership in an application and does not alter the sealed-request contract of the existing `GET/POST /login` Browser SSO routes.

For an active Central session, the portal resolves `auth_user_id` back to the current internal identity and lists active applications from `applications`, joined to that user's `app_memberships`. Friendly membership and role labels are rendered server-side. Approved SILAPET and Klinik PKP memberships receive their own trusted launch links; pending, rejected, disabled, or missing memberships do not. Launch destinations come from `PORTAL_SILAPET_LAUNCH_URL` and `PORTAL_KLINIK_LAUNCH_URL`, never from browser input. Other applications remain visible with their database name and membership status but are not launchable until their server-controlled metadata and Browser SSO integration are configured.

Password recovery continues through the existing Supabase-owned `POST /api/v1/auth/forgot-password` flow, `PASSWORD_RECOVERY_REDIRECT_URL`, and `GET /reset-password`. Portal logout enters `GET /logout?portal=1`, preserves the existing confirmation and CSRF checks, revokes the current browser session on POST, clears its cookie, and returns safely to `/`.

## Session and logout semantics

The Central cookie is opaque, `HttpOnly`, `Path=/`, configurable `SameSite`, and `Secure=true` by default. `SameSite=None` is rejected unless `Secure=true`. Local HTTP development must explicitly set `SSO_BROWSER_COOKIE_SECURE=false`; production must retain `true`.

Both apps decide logout behavior from the verified server-owned login source.
DIRECT logout immediately clears only that app session, without revoking or
introspecting a Central SID.

For SSO sessions, initiation preserves the app cookies and upstream credentials
and navigates through the app backend to Central `GET /logout`. Central shows
a CSRF-protected confirmation for an active opaque browser session. Cancel
does not mutate that session. Only `POST /logout` revokes the current SID.
All SSO apps bound to that SID reject it on their next validation or refresh;
independent DIRECT sessions and unrelated Central SIDs remain active.

Both Confirm and Cancel return to the exact registered application `/login`.
The app revalidates its preserved session: an active SID restores the app-owned
role route; a revoked SID is rejected and the app clears its invalid cookies.
Central never deletes another host's cookies or selects an app role route.
Missing, expired, or revoked Central sessions receive an already-logged-out
state or return to the exact registered URI. Direct Central cancel uses the
existing `/logout?cancelled=1` state; portal cancel returns to `/`.

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
- `PORTAL_SILAPET_LAUNCH_URL` (app SSO start URL; `http://silapet.test:8081/api/auth/sso/start` locally)
- `SSO_KLINIK_CLIENT_ID` (`klinik-pkp-web` locally)
- `SSO_KLINIK_APPLICATION_CODE` (`klinik_pkp`)
- `SSO_KLINIK_REDIRECT_URIS` (comma-separated exact allowlist; `http://klinik-pkp.test:3000/auth/sso/callback` locally)
- `SSO_KLINIK_POST_LOGOUT_REDIRECT_URIS` (comma-separated exact allowlist; `http://klinik-pkp.test:3000/login` locally)
- `PORTAL_KLINIK_LAUNCH_URL` (app SSO start URL; `http://klinik-pkp.test:3000/api/auth/sso/start` locally)

The feature is fail-closed and disabled by default. The local portal is available at `http://sso-balai.test:18082/`. The existing stack already has the Browser SSO schema. The portal launch and logout sequencing fixes add no migration. Existing `.env` overrides must be changed manually to the launch URLs above; changing `.env.example` does not change a running service. Restart the local Central process after updating those values.
