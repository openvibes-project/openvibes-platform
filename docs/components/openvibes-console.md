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

The design is approved and C0 is complete: a
loopback-only Axum process with separate public and health routers, an embedded
React shell, exact static-asset routing, report-only security headers, locked
frontend tooling, checked Rust-generated OpenAPI, and CI build validation.
One checked frontend contract now supplies the browser-route and public-asset
inventory to both Rust and TypeScript, and the production output carries a
SHA-256 build stamp over the exact source inputs and generated files.
The shell uses native platform interaction primitives: a Popover API help menu
with arrow-key navigation, a modal `<dialog>` with focus return, and the native
theme `<select>`. They pass the target CSP and axe checks in the real-browser
suite without adding a component dependency.
The supplied logo references are represented by reviewed, self-contained
transparent SVG paths: a compact mark and light- and dark-surface wordmarks.
The expanded shell follows the active theme while the compact shell, favicon,
and application manifest use the mark. ImageMagick deterministically renders
the committed 32, 192, and 512 pixel PNG derivatives from that SVG source.
Production authentication and data routes remain fail-closed until their
later milestones provide the required database-backed sessions and
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
checked OpenAPI snapshot, which generates the committed browser TypeScript
contract. The production build checks both snapshot and generated-client drift
before Vite runs.

`GET /api/v1/session` defines the current-human-session contract: principal,
authentication method and level, effective permission/scope pairs, CSRF value,
and idle/absolute expiry. Until C3 supplies authenticated sessions, the route
returns `503 authentication_unavailable`; it never manufactures an anonymous
or implicitly privileged session. Service-account bearer tokens cannot use
this browser-session route.

Collection DTOs use opaque cursors with a default limit of 50, maximum limit
of 100, and a 2,048-byte cursor bound. Response envelopes contain typed items,
an optional next cursor, and an RFC 3339 generation time. Concrete collection
schemas enter OpenAPI when their owning routes are implemented.

The first-release UI covers overview, agents, findings and analyst triage,
enrollment tokens, pre-signed rule bundles, access control and exact agent
tags, service accounts, and the audit log, retention policy, and bounded CSV
export. CA and rule-trust-key administration remain CLI-only.

## Configuration

### Current (C0)

`openvibes-console [--config PATH]` reads `/etc/openvibes/console.toml` by
default: strict TOML (unknown keys refused) with two keys, both loopback
only and different:

```toml
development_listen = "127.0.0.1:8443"   # the development web listener
health_listen = "127.0.0.1:18482"       # /health and /ready
```

A non-loopback address, equal addresses, or a malformed file is refused at
startup ("invalid console configuration"), and `run` refuses a listener that
is not loopback even if bound elsewhere. The e2e fixture uses 18490/18491,
clear of ingest's 18480 and distribution's 18481.

### Planned (C1 to C5)

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

**Now (C0):**

- The development listener answers only loopback `Host` names (`localhost`,
  `127.0.0.1`, `[::1]`, any port); any other `Host` gets 421, so a
  DNS-rebinding page cannot read it. Requests without `Host` pass.
- Framing is refused: `Content-Security-Policy: frame-ancestors 'none'` is
  enforced (with `X-Frame-Options: DENY`) while the full policy is still
  report-only.
- A wrong method on an API route is a 405 Problem Details response with
  `Cache-Control: no-store`, like every API error.
- An `embedded-ui` build fails if the shared route/public-asset contract,
  generated frontend manifest, SPA entry, exact public-file inventory, or a
  referenced embedded asset is missing or inconsistent. It also refuses a
  stale build stamp whose sorted input/output inventory or SHA-256 digest does
  not match the files being embedded.
- Frontend tests refuse brand SVGs with scripts, animation, embedded raster,
  external references, text/fonts, or background rectangles, and verify the
  PNG signatures, alpha channel, and declared dimensions.
**Planned (C1 to C5), not implemented yet:**

- Request limits (body size, request deadline, in-flight and connection
  caps, as in ingest) land before any non-loopback or TLS listener.
- Missing or invalid security configuration, a wildcard plaintext proxy bind,
  a non-loopback health listener, or an untrusted forwarded-header setup makes
  startup fail rather than weakening the trust boundary.
- `/ready` returns 503 while PostgreSQL is unreachable, its schema is older or
  newer than the supported version, or required local-auth state is not ready;
  `/health` remains a process-liveness check.
- Production auth and data routes remain unavailable until their owning
  milestones are complete. There is no permissive temporary authentication
  mode.
- `GET /api/v1/session` therefore returns a no-store, bounded 503 Problem
  Details response until C3; its eventual 200 schema is already versioned in
  the checked API contract.
- API failures are bounded Problem Details responses and never expose SQL,
  credentials, tokens, certificates, IdP payloads, or authorisation detail.
- Authorisation is applied in database queries before aggregation, filtering,
  and pagination. An object outside the caller's asset scope looks absent.
- A mutation whose audit append fails rolls back. Token plaintext is shown
  once and cannot be recovered afterward.

## Build and test

The reproducible production sequence renders the PNG brand derivatives with
ImageMagick, exports Rust OpenAPI, checks snapshot/client drift, performs the
locked frontend install and checks, runs Vite, generates the content-derived
build stamp, validates embedded assets, then builds the Rust `embedded-ui`
release. The Rust build script reads the checked frontend contract and verifies
the stamp but never invokes a package manager.

Run `scripts/build-console-brand-assets.sh` alone after an intentional change
to `web/public/brand/openvibes-mark.svg`. It accepts ImageMagick 7 (`magick`) or
ImageMagick 6 (`convert`); CI installs ImageMagick explicitly. The SVG files are
the reviewed sources and the generated PNG files are committed so offline
packaging has no hidden artwork input.

`scripts/build-console-npm-cache.sh OUTPUT_DIR` creates a separate
`linux-x64` cache artefact named by the SHA-256 of `package-lock.json`, plus a
checksum sidecar. It contains npm's content-addressed cache, the lock digest,
and the target platform, but no `node_modules`. The networked cache-preparation
stage is separate from packaging. `scripts/check-console-npm-cache.sh ARCHIVE`
checks the sidecar, allow-lists archive paths, refuses special files, confirms
the current lock digest and platform, then runs `npm ci --offline` and the Vite
build. CI runs both scripts. The eventual RPM build consumes the same artefact;
the first package target is Fedora Linux x86_64, so caches for other platforms
are deliberately distinct.

For the current C0 foundation, run:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -F unsafe-code
cargo doc --locked --workspace --all-features --no-deps
cargo test --locked --workspace --all-features
scripts/build-console.sh
archive=$(scripts/build-console-npm-cache.sh target/console-npm-cache)
scripts/check-console-npm-cache.sh "$archive"
scripts/test-console-e2e.sh
cargo run --locked -p openvibes-console --bin export_openapi -- \
  --check docs/api/console-v1.openapi.json
```

`export_openapi` has no `embedded-ui` dependency. With no arguments it writes
deterministic pretty JSON to stdout; `--check PATH` fails on snapshot drift.
Run `npm --prefix crates/openvibes-console/web run generate:api` after an
intentional API change; `scripts/build-console.sh` fails if the generated
browser contract does not match the snapshot.

Current frontend verification includes strict type checking, linting, unit
tests, dependency audit, production asset generation, and Rust-side embedded
asset tests. Playwright journeys run the embedded binary in Chromium, Firefox,
and WebKit and cover axe accessibility analysis, target CSP headers and browser
violations, first-paint theme persistence, keyboard entry, native menu/dialog/
combobox focus behaviour, and reserved-route fall-through. Later contract tests
exercise the complete Axum router first against deterministic seeded data and
then against PostgreSQL. Security coverage expands from the current route
fall-through, cache-header, and CSP checks to session/CSRF handling, object
scope, audit atomicity, trusted proxies, secret redaction, and bounded CSV
export.
