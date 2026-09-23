# openvibes-console

The human-facing OpenVIBES web application and versioned administration API.
It is a same-origin React/TypeScript application embedded in an Axum service.
The approved product and technical contracts are in
[`../specs/2026-09-23-console-product-design.md`](../specs/2026-09-23-console-product-design.md)
and
[`../specs/2026-09-23-console-technical-design.md`](../specs/2026-09-23-console-technical-design.md).

The console owns browser assets, `/api/v1`, local human authentication,
server-side sessions, RBAC enforcement, and service-account API
authentication. It does not accept agent credentials, implement agent
protocol endpoints, sign rules, operate CA private keys, edit host
configuration, or control system services. Local host administration belongs
to `openvibes-admin tui`.

## Status

The design is approved and C0 (the contract and build skeleton) is in
implementation. Production authentication and data routes remain fail-closed
until their later milestones provide the required database-backed sessions and
authorisation.

## Interfaces

The production service has two HTTP surfaces:

| Surface | Routes | Contract |
|---|---|---|
| Public HTTPS | `/`, known browser routes, `/assets/*`, `/auth/*`, `/api/v1/*` | Same-origin web UI and human/service-account API. Unknown API, auth, and asset paths are real 404 responses and never receive the SPA index. |
| Loopback health listener | `/health`, `/ready` | Liveness and dependency/schema readiness only; never exposed by the public router. |

The JSON API uses closed request validation, bounded bodies, RFC Problem
Details-style errors with stable codes and request IDs, opaque keyset cursors,
and `Cache-Control: no-store`. Mutations use idempotency keys or
ETag/`If-Match` where replay or stale edits matter. Rust DTOs generate the
checked OpenAPI snapshot, which generates the browser TypeScript client.

The first-release UI covers overview, agents, findings and analyst triage,
enrollment tokens, pre-signed rule bundles, access control and exact agent
tags, service accounts, and the audit log, retention policy, and bounded CSV
export. CA and rule-trust-key administration remain CLI-only.

## Configuration

The final service configuration is strict, bounded TOML with unknown keys and
relative key/certificate paths refused. Its approved deployment constraints
are:

- direct TLS 1.3 termination is the default and requires a server certificate
  chain and private key;
- reverse-proxy mode is explicit and requires a canonical external HTTPS
  origin plus an allow-list of trusted proxy addresses;
- forwarded headers are ignored unless the immediate peer is trusted;
- plaintext proxy upstreams may bind only to loopback or a Unix socket;
  non-loopback upstreams remain TLS protected;
- the health listener must be loopback-only;
- the production PostgreSQL connection uses the least-privilege
  `openvibes_console` role;
- session lifetimes, request limits, password hashing, export limits, and the
  private CSV spool are bounded configuration rather than browser choices.

The exact TOML keys and defaults land with the runtime configuration milestone
and this page must be updated in that same change. Development uses a
loopback-only seeded server; the `dev-seed` implementation and its conspicuous
banner are never included in the production RPM.

## Failure behaviour

- A release build fails if the generated frontend manifest, build stamp, or a
  referenced embedded asset is missing.
- Missing or invalid security configuration, a wildcard plaintext proxy bind,
  a non-loopback health listener, or an untrusted forwarded-header setup makes
  startup fail rather than weakening the trust boundary.
- `/ready` returns 503 while PostgreSQL is unreachable, its schema is older or
  newer than the supported version, or required local-auth state is not ready;
  `/health` remains a process-liveness check.
- Production auth and data routes remain unavailable until their owning
  milestones are complete. There is no permissive temporary authentication
  mode.
- API failures are bounded Problem Details responses and never expose SQL,
  credentials, tokens, certificates, IdP payloads, or authorisation detail.
- Authorisation is applied in database queries before aggregation, filtering,
  and pagination. An object outside the caller's asset scope looks absent.
- A mutation whose audit append fails rolls back. Token plaintext is shown
  once and cannot be recovered afterward.

## Build and test

The reproducible production sequence is Rust OpenAPI export, snapshot/client
drift checking, locked frontend install and checks, Vite build, embedded-asset
validation, then the Rust `embedded-ui` release build. The build never invokes
a package manager implicitly, and the eventual RPM build uses a checksummed
npm source cache with `npm ci --offline`.

As the milestone files land, run:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
cargo doc --locked --workspace --all-features --no-deps
cargo test --locked --workspace --all-features
scripts/build-console.sh
scripts/test-console-e2e.sh
```

Frontend verification includes strict type checking, linting, unit and
Testing Library tests, production asset generation, accessibility checks, and
Playwright journeys in Chromium, Firefox, and WebKit. Contract tests exercise
the complete Axum router first against deterministic seeded data and later
against PostgreSQL. Security tests cover route fall-through, cache headers,
CSP, session/CSRF handling, object scope, audit atomicity, trusted proxies,
secret redaction, and bounded CSV export.
