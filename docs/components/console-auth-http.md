# Console authentication HTTP adapter

The C3 HTTP adapter validates a browser session against `platform_store::console_auth`
and builds the stable `GET /api/v1/session` response. It also exposes
permission-checked read models, enrollment-token management, and audit routes.

## Interface

- `authenticated_router(pool, public_origin)` builds a router with database-
  backed authentication. `public_origin` is the canonical configured browser
  origin; `public_router()` remains the C0 fail-closed router.
  `authenticated_router_for_hosts(pool, public_origin, hosts)` also serves
  `hosts` (`name:port`); the executable passes the server certificate's
  names in direct-TLS mode (board #71).
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
- `GET /api/v1/enrollment-tokens` returns at most 100 newest token metadata
  rows and never returns token hashes or plaintext. `POST` requires
  `tokens.create`, CSRF, and an `Idempotency-Key`; successful creation returns
  the secret once, while a same-key/same-request retry returns metadata with
  `secret_available=false`. Reusing a key for different settings returns 409.
  `GET /api/v1/enrollment-tokens/{token_id}` returns one secret-free record.
  `POST /api/v1/enrollment-tokens/{token_id}/revoke` requires `tokens.revoke`
  and audits the revocation. These responses are `Cache-Control: no-store`.
- `/api/v1/service-accounts` lists safe account metadata and creates an account
  with one global built-in role. Per-account token routes list metadata, issue
  an expiring `ovc_` bearer secret once, revoke a token, or disable the account
  (which also revokes all its tokens). Token issue requires an
  `Idempotency-Key`; a matching retry returns metadata without the original
  secret and a mismatched retry returns 409. These mutations require
  `service_accounts.manage`; reads require `service_accounts.read`.
  Service-account bearer credentials are accepted for scoped read routes, and
  are rejected when mixed with a browser cookie. The first-release adapter
  refuses bearer-authenticated mutations; those require a browser session and
  CSRF checks.
- `/api/v1/rule-sets` and per-set bundle history are global `rules.read`
  reads. Admin is the only built-in role granted `rules.read` by default;
  custom roles may receive it explicitly. Rule upload preview verifies the
  Ed25519 signature, envelope digest,
  expiry, parser limits, and currently trusted issuer against read-only public
  trust keys. Publish repeats verification, binds the confirmation token to
  the exact bytes, and stores the bundle plus its audit row atomically. The
  console never manages private signing keys or trust-key changes.
- Missing, malformed, expired, revoked, disabled, or stale-generation sessions
  receive the same generic `401` problem. Store failures return a generic `503`.
- Session responses are `Cache-Control: no-store`. The CSRF token is derived
  from the high-entropy session secret with a domain separator; only its digest
  is persisted by the store.

### Users and passwords (#85)

- `POST /api/v1/access-control/users` (`rbac.manage`, global binding, CSRF):
  username (the CLI's rule, stored lowercase), display name and a built-in
  role (a create that loses a race on the same name is 409, not 503). The
  answer (201, `no-store`) carries a generated one-time password
  (20 symbols from an unambiguous alphabet, about 99 bits), shown only
  there. 409 when the username is taken. Audited as `user.created` with
  `actor_kind = user`.
- The user then signs in with it. Until they set their own password,
  `GET /api/v1/session` says `password_must_change: true` with no
  capabilities, and every other session route answers 403
  `password_change_required`. The gate sits in `session_capabilities`, the
  one path every session route but `GET /session` and set-password takes.
- `POST /api/v1/session/password` (browser sessions, CSRF): the current
  password and a new one of at least 15 characters that differs from it.
  400 `invalid_current_password`, `weak_password` or `password_unchanged`.
  A wrong current password counts against sign-in's per-account limit (5
  in 15 minutes, shared with sign-in), then 429 `too_many_attempts`, so a
  stolen session cannot guess it faster than sign-in could.
  On success (204) the flag is cleared, the user's other sessions are
  signed out, and `auth.password.changed` is audited. The same route is the
  account menu's Change password.

## Configuration

The router constructor accepts a `platform_store::Pool` and canonical public
origin. The executable constructs it when strict config supplies both
  `database_url` and `public_origin`, and requires that migrations have already
advanced the database to schema 23. Startup never runs migrations. The current
listener is loopback-only and config accepts only canonical HTTP loopback
origins. Login throttling has a five-failure per-account limit and a higher
per-source limit; in reverse-proxy mode, the last address in `X-Forwarded-For`
is used only from an authenticated proxy peer. This supports proxies that
append their observed client address to a forwarded chain; an invalid final
address disables only the per-source bucket.
When auth settings are absent, the executable serves the C0
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
history requires a lower time bound for partition pruning. Latest-finding
triage reads and writes use the same finding scope; writes require
`findings.triage`, CSRF, exact Origin, same-origin Fetch Metadata, and a
matching ETag `If-Match`. State, assignment, note, history, and audit are
committed atomically. Audit retention
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
failure shape, session rotation, and logout (`--test users_http`: New
user, the forced change, self-service change):
`OPENVIBES_TEST_DATABASE_URL=… cargo test --offline -p openvibes-console
--test auth_http`. Store transaction coverage uses the same isolated test
cluster with `cargo test --offline -p platform-store --test console_auth`.
