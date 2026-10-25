# Final SSO browser-flow hardening - 2026-10-25

Implementation and automated verification are complete locally. Browser canaries
against the running custom-host stack remain manual; this report does not mark
those canaries as passed. No session architecture or schema redesign was needed.

## Root causes and resulting behavior

Klinik's logout route terminated the backend session and expired application
cookies before Central displayed its decision. SILAPET's backend likewise
revoked its upstream token session and cleared its encrypted cookie; its
frontend also cleared presentation state unconditionally. Central Cancel kept
the SID active but could not restore credentials already deleted by the app.

Both apps now preserve SSO credentials at initiation. Central's existing Cancel
link performs navigation without revocation. The exact registered app `/login`
return validates the preserved session and chooses the app's role route. Only
the CSRF-protected confirmation POST revokes the Central SID. SSO apps bound to
it then reject requests/refresh on their next introspection and clear invalid
cookies. DIRECT logout remains immediate and local; DIRECT sessions do not
depend on Central introspection.

The portal rendered its configured launch URL verbatim. Public-root launch
configuration bypassed SSO start. The verified entrypoints are Klinik frontend
`/api/auth/sso/start` (which redirects through its backend) and SILAPET backend
`/api/auth/sso/start`. Defaults/examples and regression fixtures now use those
routes. Approved membership alone exposes a normal launch action; pending,
rejected, disabled, and missing memberships retain their existing restrictions.
Each app still chooses its own role destination after exchange.

## Changed files

Paths below are relative to each repository.

### Central - sso-balai

- `.env.example`: custom-host callback, logout return and SSO launch examples.
- `internal/config/config.go`: SILAPET fallback launch is its SSO start route.
- `internal/config/config_test.go`: configured launch URL assertions.
- `internal/handlers/account_portal_handler_test.go`: rendered approved/pending links.
- `internal/handlers/browser_sso_handler.go`: documents shared return semantics.
- `internal/handlers/browser_sso_handler_test.go`: custom-host logout allowlists.
- `internal/handlers/logout_family_test.go`: both origin apps, Cancel/Confirm,
  both client introspections, unrelated session and host-only cookie checks.
- `internal/services/account_portal_service_test.go`: exact SSO launch targets.
- `docs/BROWSER_SSO.md`: current topology and logout sequencing.
- `docs/FINAL_SSO_HARDENING.md`: this handoff.

### Klinik frontend - klinik-pkp

- `src/app/api/auth/logout/route.ts`: preserve signed SSO session before any
  backend logout or cookie clearing; signed refresh fallback if access expired.
- `tests/browser-sso-contract.test.mjs`: includes the new route regression suite.
- `tests/logout-lifecycle.test.mjs`: runs the actual logout handler and session
  reader with mocked external boundaries; tests SSO preservation, revocation
  rejection, DIRECT cleanup/isolation, and foreign-origin rejection.

`next.config.mjs` is a pre-existing user change and is excluded from this commit.
Klinik backend remains unchanged and was not retested for this patch.

### SILAPET backend - office-craft-api

- `internal/handlers/auth_handler.go`: SSO early return preserves credentials.
- `internal/handlers/auth_handler_sso_test.go`: source-dependent logout assertions.
- `internal/handlers/logout_lifecycle_test.go`: actual encrypted app cookie,
  middleware, logout and refresh against mock Central introspection. Verifies
  original cookie usability on Cancel and rejection after Confirm.

### SILAPET frontend - office-craft

- `src/components/layout/UserMenu.tsx`: SSO navigation returns before state cleanup.
- `src/lib/auth/logout.test.ts`: sequencing and existing login bootstrap contracts.
- `docs/10_AUTHENTICATION.md`
- `docs/18_ARCHITECTURAL_DECISIONS.md`
- `docs/39_AI_MEMORY.md`
- `docs/41_DECISION_LOG.md`

`vite.config.ts` is a pre-existing user change and is excluded from this commit.

## Automated verification

| Repository | Checks | Result |
| --- | --- | --- |
| Central | gofmt, `go test ./...`, `go build ./...` | PASS |
| SILAPET backend | gofmt, `go test ./...`, `go build ./...` | PASS |
| Klinik frontend | `npm.cmd test` (31 tests), `npm.cmd run build`, targeted ESLint | PASS |
| SILAPET frontend | `npm.cmd test` (8 tests), `npm.cmd run build`, TypeScript with `--noEmit --incremental false`, targeted ESLint | PASS |
| Changed repositories | `git diff --check` | PASS |

SILAPET targeted ESLint disables only the Prettier rule to avoid existing line
ending/formatting noise; full-repository lint was not run. SILAPET build reports
dependency/bundler warnings but exits successfully. Central build reports a
nonfatal module stat-cache write warning and exits successfully. Go build caches
use writable OS temporary directories; no cache artifact is committed.

## Manual local configuration

Set these non-secret values in Central's existing `.env`, then restart Central:

```dotenv
PORTAL_SILAPET_LAUNCH_URL=http://silapet.test:8081/api/auth/sso/start
PORTAL_KLINIK_LAUNCH_URL=http://klinik-pkp.test:3000/api/auth/sso/start
```

Keep the existing exact logout return URLs aligned (no separate Cancel URL):

```dotenv
# Central
SSO_SILAPET_POST_LOGOUT_REDIRECT_URIS=http://silapet.test:8080/login
SSO_KLINIK_POST_LOGOUT_REDIRECT_URIS=http://klinik-pkp.test:3000/login
# SILAPET backend
SSO_POST_LOGOUT_REDIRECT_URI=http://silapet.test:8080/login
# Klinik backend
SSO_POST_LOGOUT_REDIRECT_URI=http://klinik-pkp.test:3000/login
```

These are expected values, not a claim that the existing `.env` was inspected.
No `.env` was modified, and no secret value was printed or changed. Start/restart
changed applications from the patched source using the existing local workflow.

## Manual canaries still to run

1. With an active Central session, launch each approved portal card. Confirm
   SSO start, session reuse without a new credential prompt, and app-owned role
   landing (Klinik admin `/admin`, user `/`; SILAPET admin `/admin`, user `/dashboard`).
2. Check a pending card has no normal active launch action; verify rejected and
   no-access behavior still follows existing request-access policy.
3. With both apps on SSO, initiate logout from Klinik and choose Batal. Confirm
   role landing, reload and a protected request work in both apps. Repeat with
   SILAPET as the origin. Check origin app cookies were not expired at initiation.
4. Repeat from each origin with Confirm. The origin returns unauthenticated;
   the other SSO app rejects on its next request/reload/refresh.
5. Test Klinik DIRECT + SILAPET SSO, then the reverse: DIRECT logout affects
   only that app; confirmed SSO logout leaves the other app's DIRECT session usable.
6. Confirm cookies remain host-only/HttpOnly and no access token, refresh token,
   JWT, or SID appears in localStorage/sessionStorage.

No push, deployment, migration, secret change, browser credential persistence,
shared cookie domain, or unrelated user-work reversal was performed. No 10F
work was started and completed SILAPET session hardening was not redone.
