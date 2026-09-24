# Console authentication HTTP adapter

The C3 HTTP adapter validates a browser session against `platform_store::console_auth`
and builds the stable `GET /api/v1/session` response. It exposes no data routes;
the C2 global read models remain unavailable through this router until their
queries enforce the caller's asset-group scope.

## Interface

- `authenticated_router(pool, public_origin)` builds a router with database-
  backed authentication. `public_origin` is the canonical configured browser
  origin; `public_router()` remains the C0 fail-closed router.
- `GET /api/v1/session` accepts exactly one valid `__Host-openvibes-session`
  cookie, rejects bearer or conflicting credentials, checks session and CSRF
  digests in constant time, touches the bounded idle expiry, and resolves active
  role bindings on each request.
- `GET /auth/v1/preauth` stores a five-minute, one-use hash-only challenge and
  returns its CSRF token with separate HttpOnly pre-auth and browser-binding
  cookies. It sets no cookies if persistence fails. The in-memory secret
  wrappers clear their owned buffers when dropped.
- `POST /auth/v1/login` requires that pre-auth challenge, matching CSRF header,
  exact Origin, and a socket peer address supplied through `ConnectInfo`.
  Account and source throttles are hashed and domain-separated. Password
  verification runs in a blocking worker behind a four-slot bound, with a
  cached dummy Argon2id credential for missing, disabled, invalid, and locked
  accounts. Failures use a generic response and are audited; success creates a
  fresh opaque session and clears the one-use pre-auth cookies. Older valid
  Argon2 hashes are upgraded without changing the auth generation.
- `POST /auth/v1/logout` enforces the same Origin and synchronizer-token checks,
  revokes only the presented session, records the logout in the audit log, and
  clears the session cookie. Repeating logout remains safe.
- Missing, malformed, expired, revoked, disabled, or stale-generation sessions
  receive the same generic `401` problem. Store failures return a generic `503`.
- Session responses are `Cache-Control: no-store`. The CSRF token is derived
  from the high-entropy session secret with a domain separator; only its digest
  is persisted by the store.

## Configuration

The router constructor accepts a `platform_store::Pool` and canonical public
origin. The executable constructs it when strict config supplies both
`database_url` and `public_origin`, and requires that migrations have already
advanced the database to schema 8. Startup never runs migrations. The current
listener is loopback-only and config accepts only canonical HTTP loopback
origins. Login throttling uses trusted socket `ConnectInfo`; forwarded headers
are ignored. When auth settings are absent, the executable serves the C0
fail-closed router. `GET /api/v1/agents/summary` now requires a live human
session with `agents.read`, resolves role bindings on each request, and passes
the effective global or asset-group scope to its SQL aggregate, paginated
list, detail, and certificate queries. Agent and certificate cursors are
bounded and rejected when their filters or scope differ from the current
request. Detail responses include up to 100 certificate metadata rows; the
separate certificate route provides full cursor pagination. Finding and
latest-summary routes require `findings.read` and use the same active SQL
scope; latest-finding list/detail and history list/event routes use that scope
in SQL. Their bounded cursors are tied to the active filters and scope, and
history requires a lower time bound for partition pruning. Audit retention
reads require `audit.read`; updates require global `audit.retention.manage`,
CSRF, exact Origin, same-origin Fetch Metadata, and a version-matching
`If-Match`. Other control-plane data routes remain unavailable.

## Failure behaviour

Invalid credentials never reveal whether an account exists. Database errors
are reduced to the generic authentication-unavailable problem. Unknown persisted
role ids grant no capabilities. Asset-scoped bindings flow through the existing
RBAC resolver; endpoints must still enforce those scopes in SQL before serving
agent or finding records.

## How to test

Run `cargo test --offline -p openvibes-console` for API contract and router
checks. The PostgreSQL-backed HTTP journey covers login, account-enumeration
failure shape, session rotation, and logout:
`OPENVIBES_TEST_DATABASE_URL=… cargo test --offline -p openvibes-console
--test auth_http`. Store transaction coverage uses the same isolated test
cluster with `cargo test --offline -p platform-store --test console_auth`.
