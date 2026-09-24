# Console browser authentication UI

The AuthPages module contains the local sign-in page and authenticated-session
gate for the embedded React application. The login route requests one-use
pre-auth CSRF state before enabling submission. Login and logout use same-origin
fetch requests with browser-managed cookies; the UI never reads the opaque
session cookie.

## Interface

- /login renders local username and password fields with password-manager
  autocomplete attributes and generic credential errors.
- The page POSTs to /auth/v1/login with the pre-auth CSRF token. On success it
  navigates to /, which re-reads GET /api/v1/session.
- Other application routes query the session endpoint without caching and
  render a sign-in or unavailable state unless the endpoint returns an active
  session. Seeded C1 mode bypasses this browser gate and continues to use its
  synthetic personas.
- The application shell's Sign out action POSTs /auth/v1/logout with the
  current session CSRF token.
- The production Overview, Agents, and Findings pages use the authenticated
  C2 read routes. Demo persona headers and unsupported free-text filters are
  only used in the explicitly seeded development experience.

## Configuration and failure behaviour

The page has no independent configuration. openvibes-console must be started
with paired database URL and loopback public origin settings to provide local
authentication; in C0 mode the session gate reports authentication
unavailable and does not expose the application workspace. Failed login
responses do not display account or lockout details. Password state is cleared
after each submit attempt.

## How to test

npm test covers the login route markup. npm run test:e2e -- --project
Chromium and Firefox e2e runs cover the sign-in page, accessibility tree,
pre-auth request, CSRF header and credential payload, session gate, logout
CSRF header, and authenticated shell using controlled HTTP responses.
