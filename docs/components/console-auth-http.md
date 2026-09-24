# Console authentication HTTP adapter

The C3 HTTP adapter validates a browser session against `platform_store::console_auth`
and builds the stable `GET /api/v1/session` response. It exposes no data routes;
the C2 global read models remain unavailable through this router until their
queries enforce the caller's asset-group scope.

## Interface

- `authenticated_router(pool)` builds a router with database-backed session
  validation. `public_router()` remains the C0 fail-closed router.
- `GET /api/v1/session` accepts exactly one valid `__Host-openvibes-session`
  cookie, rejects bearer or conflicting credentials, checks session and CSRF
  digests in constant time, touches the bounded idle expiry, and resolves active
  role bindings on each request.
- Missing, malformed, expired, revoked, disabled, or stale-generation sessions
  receive the same generic `401` problem. Store failures return a generic `503`.
- Session responses are `Cache-Control: no-store`. The CSRF token is derived
  from the high-entropy session secret with a domain separator; only its digest
  is persisted by the store.

## Configuration

The caller supplies a `platform_store::Pool`; pool sizing and the PostgreSQL
connection string stay with process configuration. The router does not trust
proxy headers and does not enable any production data route.

## Failure behaviour

Invalid credentials never reveal whether an account exists. Database errors
are reduced to the generic authentication-unavailable problem. Unknown persisted
role ids grant no capabilities. Asset-scoped bindings flow through the existing
RBAC resolver; endpoints must still enforce those scopes in SQL before serving
agent or finding records.

## How to test

Run `cargo test --offline -p openvibes-console` for API contract and router
checks. Database-backed session coverage uses the isolated PostgreSQL target in
the platform-store test harness: `OPENVIBES_TEST_DATABASE_URL=… cargo test
--offline -p platform-store --test console_auth`.
