# Browser SSO Balai

Browser SSO is an optional authorization-code flow for registered Balai clients. It does not replace the existing direct email/password API.

## Trusted client registry

Central loads an immutable registry from `public.sso_clients` (joined to
`public.applications`) at startup. Every exact `client_id` resolves to one
server-owned application code, its own exact redirect and post-logout URI
allowlists, an optional portal launch URL and description, an access policy,
and the SHA-256 hash of its introspection secret. Application code is never
accepted from browser input. Unknown clients, malformed HTTP(S) URIs, duplicate
client IDs, more than one client per application, wildcard URLs, and
cross-client redirects fail closed.

Register or update a client with `go run ./cmd/sso-client` (flags:
`-client-id`, `-app`, `-name`, `-description`, `-launch-url`,
`-redirect-uris`, `-post-logout-uris`, `-access-policy`, `-secret-env`), then
restart the API. Adding a new Balai application needs no code change. The
browser client has no client secret; PKCE S256 protects the authorization code.
The introspection secret only authenticates the app backend's
`/api/v1/auth/sso/introspect` calls.

Local development clients (see README for the registration commands):

| Client ID | App code | Redirect URI | Post-logout URI | Launch URL |
| --- | --- | --- | --- | --- |
| `silapet-web` | `silapet` | `http://silapet.test:8080/auth/sso/callback` | `http://silapet.test:8080/login` | `http://silapet.test:8081/api/auth/sso/start` |
| `klinik-pkp-web` | `klinik_pkp` | `http://klinik-pkp.test:3000/auth/sso/callback` | `http://klinik-pkp.test:3000/login` | `http://klinik-pkp.test:3000/api/auth/sso/start` |

## Flow

1. A registered application backend creates a random state and a PKCE challenge, stores only the state hash, and redirects the browser to `GET /authorize`.
2. Central validates the client, exact redirect URI, response type, state, and S256 challenge.
3. If the opaque `HttpOnly` Central session cookie is valid, Central immediately redirects back to the app with a code (or a membership status), with no extra click. Otherwise it redirects straight to the `GET /account/login?request=...` form. The login POST uses a double-submit CSRF token, authenticates through Supabase password login, then resumes at `/authorize/continue`.
4. Central stores only the browser-session token hash and identity IDs. It does not store a Supabase access or refresh token in the browser-session row, and revokes the transient password-login session on a best-effort basis.
5. Approved membership receives a random, short-lived code. Missing membership is auto-enrolled as `user/pending`; pending receives `status=pending`; rejected or disabled receives `status=denied`.
6. The application backend verifies and atomically consumes state, derives its server-held PKCE verifier, and exchanges the code server-to-server.
7. Central atomically consumes the authorization code only when code hash, client, redirect URI, PKCE challenge, expiry, and unused state all match.
8. Central uses the Supabase Admin `generate_link` magic-link primitive and verifies its token hash server-to-server to obtain an independent Supabase session. The returned Auth user ID must match the browser session before tokens are returned to SILAPET backend.

Only `code`, `state`, or a safe membership status is placed in the callback URL. Supabase access and refresh tokens never enter a redirect URL.

## Central account portal

When Browser SSO is enabled, Central also serves the public `GET /` **Akun Balai** portal. A logged-out visitor can use the CSRF-protected `GET/POST /account/login` form or open `GET /forgot-password`. Portal login reuses the Supabase-backed browser-session login and creates the same opaque `balai_sso_session`; it does not require membership in an application. It is also the login form for app-initiated SSO: with a sealed `request`, a successful login continues at `/authorize/continue` instead of the portal. Portal **Buka Aplikasi** enters the app's SSO start URL; the app's `/authorize` call then succeeds silently because the Central session is already active.

For an active Central session, the portal resolves `auth_user_id` back to the current internal identity and lists active applications from `applications`, joined to that user's `app_memberships`. Friendly membership and role labels are rendered server-side. Approved SILAPET and Klinik PKP memberships receive their own trusted launch links; pending, rejected, disabled, or missing memberships do not. Launch destinations come from `sso_clients.launch_url`, never from browser input. Applications without a registered client or launch URL remain visible with their database name and membership status but are not launchable.

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

## Signup and access approval

Central is the only place to sign in or sign up. Access policy per client:

- `AUTO_USER`: users may self-register at `GET/POST /account/register`
  (reached from the login form or with `prompt=create` on `/authorize`) and
  first logins request access. Both create a `pending` membership; the app
  receives `status=pending` until an admin approves.
- `RESTRICTED`: no self-service; access only through invitation/provisioning.

`GET /admin` lists memberships of the applications the signed-in user manages,
pending first. Central admins (`app_users.role = 'admin'`) manage every active
application; approved application admins manage only their application. The
actor's own membership is never changeable. `POST /admin/memberships` (double
submit CSRF) sets role (`user`/`admin`) and status (`approved`, `rejected`,
`disabled`); scope is re-checked in the same SQL transaction that updates the
row and appends an `app_audit_events` record (`entity_kind = 'membership'`).

Self-registered accounts are created with a confirmed email (no ownership
check); approval is the gate, so admins should verify the requester.

## OpenID Connect

When `SSO_OIDC_ISSUER` and `SSO_OIDC_SIGNING_KEY_FILE` are set, Central is a
standard OpenID Connect provider on top of the same browser session, client
registry and membership checks:

| Endpoint | Path |
| --- | --- |
| Discovery | `GET /.well-known/openid-configuration` |
| JWKS | `GET /.well-known/jwks.json` |
| Authorization | `GET /authorize` (adds `scope` and `nonce`) |
| Token | `POST /oauth/token` |
| UserInfo | `GET/POST /oauth/userinfo` |
| End session | `GET /logout` (accepts `id_token_hint` in place of `client_id`) |

- Only `response_type=code` with PKCE `S256` is accepted (OAuth 2.1). The
  token endpoint also requires client authentication (`client_secret_basic`
  or `client_secret_post`); the client secret is the client's registered
  introspection secret.
- Tokens are RS256 JWTs signed with the configured key (`kid` is a thumbprint
  of the public key) and live 15 minutes. `id_token` is returned only when
  `scope` contains `openid`; `email`/`email_verified` need `email`, and
  `name`/`preferred_username` need `profile`. `sub` is the Central app user ID,
  `sid` the Central browser session ID, `app_role` the membership role.
- Codes are redeemed once and re-check the browser session, user and approved
  membership before tokens are issued. UserInfo repeats those checks, so a
  Central logout or revoked membership is visible immediately.
- The legacy `POST /api/v1/auth/sso/exchange` and `/introspect` endpoints keep
  working for SILAPET and Klinik.
- Not implemented: refresh tokens, `prompt`/`max_age`, `state` passthrough on
  logout, and front/back-channel logout notifications.

## Configuration

- `SSO_BROWSER_ENABLED`
- `SSO_BROWSER_SESSION_KEY` (base64-encoded 32-byte key used to seal authorization context)
- `SSO_BROWSER_COOKIE_SECURE`
- `SSO_BROWSER_COOKIE_SAME_SITE`
- `SSO_BROWSER_SESSION_TTL`
- `SSO_AUTHORIZATION_CODE_TTL`
- `SSO_OIDC_ISSUER` (optional; public base URL, no trailing slash)
- `SSO_OIDC_SIGNING_KEY_FILE` (optional; path to an RSA 2048+ PEM private key)

Per-application values are rows in `public.sso_clients`, not environment
variables.

The feature is fail-closed and disabled by default. The local portal is available at `http://sso-balai.test:18082/`. The existing stack already has the Browser SSO schema. The portal launch and logout sequencing fixes add no migration. Migration `000008` adds `public.sso_clients` and `000009` adds the OIDC `nonce`/`scope` code columns; register each client before restarting with Browser SSO enabled.
