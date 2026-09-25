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

The design is approved. C0 and C1 are complete. C3 local authentication is
implemented through pre-auth, login, session validation/refresh, logout, and
password hash upgrade. When both `database_url` and `public_origin` are set,
the executable connects to PostgreSQL, requires schema version 16, and serves
the authenticated router. Otherwise it serves the C0 development router,
where `/api/v1/session` remains fail-closed. The authenticated router now
serves permission-checked, SQL-scoped agent summary, list, detail, and
certificate routes, plus finding summary, latest, and history reads. Access
control has a global read inventory for roles, bindings, and asset groups,
plus CSRF-protected local-user role binding changes and audited asset-group
selector management. Enrollment-token, service-account, and signed rule-bundle
read/preview/publish flows are available through the console API and UI;
private signing and trust-key management remain local CLI operations.
Global audit event search and retention-policy
reads/updates are available; `/audit` provides a filtered, cursor-paginated
activity screen without exposing event details or request source metadata.
Global `audit.export` users can download the exact visible filters as bounded
CSV; the export audit event records only filters, row count, and digest.
The first-account bootstrap and account recovery CLI is available through
`openvibes-admin user`. The embedded UI has a login form, session gate, and
sign-out action, and its production Overview, Agents, Findings, Audit, and
Access control pages use authenticated APIs. Agent detail also provides a
reason-required revoke operation; the store enforces the effective global or
asset-group scope in SQL and commits revocation with its audit row.
Enrollment-token listing, one-time secret creation with idempotent retries,
and audited revocation are available through global `tokens.read`,
`tokens.create`, and `tokens.revoke` capabilities. The token secret is stored
only as the same SHA-256 digest used by ingest, and is never repeated on a
replayed create response. The C1 seeded read slice is
implemented: a
loopback-only Axum process with separate public and health routers, an embedded
React shell, exact static-asset routing, enforced security headers, locked
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
Production data routes remain unavailable until their later milestones
provide SQL-enforced authorisation. The C1 `dev-seed` feature exposes a synthetic read-only API
only on the loopback development router; it is not part of the production
OpenAPI snapshot or package.

## Interfaces

The production service has two HTTP surfaces:

| Surface | Routes | Contract |
|---|---|---|
| Public HTTPS | `/`, known browser routes, `/assets/*`, `/auth/*`, `/api/v1/*` | Same-origin web UI and human/service-account API. Unknown API, auth, and asset paths are real 404 responses and never receive the SPA index. |
| Loopback health listener | `/health`, `/ready` | Liveness and dependency/schema readiness only; never exposed by the public router. |

The JSON API uses closed request validation, bounded bodies, RFC Problem
Details-style errors with stable codes, and opaque keyset cursors. Every public
response carries an `X-Request-ID`; structured request logs include that ID,
method, matched route template, and status without query strings or bodies.
Mutations use idempotency keys or
ETag/`If-Match` where replay or stale edits matter. Rust DTOs generate the
checked OpenAPI snapshot, which generates the committed browser TypeScript
contract. The production build checks both snapshot and generated-client drift
before Vite runs.

`GET /api/v1/session` defines the current-human-session contract: principal,
authentication method and level, effective permission/scope pairs, CSRF value,
and idle/absolute expiry. In C0 mode it returns
`503 authentication_unavailable`; the authenticated C3 router returns a
database-validated session or generic `401`. It never manufactures an
anonymous or implicitly privileged session. Service-account bearer tokens
cannot use this browser-session route.

Collection DTOs use opaque cursors with a default limit of 50, maximum limit
of 100, and a 2,048-byte cursor bound. Response envelopes contain typed items,
an optional next cursor, and an RFC 3339 generation time. Agent, certificate,
latest-finding, and finding-history response schemas are generated into OpenAPI
and the TypeScript client; the seeded API reuses those DTOs. Agent fields match
the stored schema, including optional hostname/heartbeat data and multiple
certificate records. Finding fields include confidence, evidence, scan ID,
receive time, and authenticated origin. Implemented agent and finding reads
resolve current permission scopes for each request and apply asset-group
selectors in SQL before pagination or aggregation. Access-control, audit,
enrollment, service-account, rule-set, triage, and agent-revocation operations
use authenticated, permission-checked routes with transactional audit records.

The implemented production UI covers sign-in, overview, agents, findings,
enrollment, service accounts, rule sets, access control, audit, and
latest-finding analyst triage with version-checked updates. RPM installation
and C5 deployment behavior still need integration validation. CA and
rule-trust-key administration remain CLI-only.

## Configuration

### Current

`openvibes-console [--config PATH]` reads `/etc/openvibes/console.toml` by
default: strict TOML (unknown keys refused). The health listener must be a
distinct loopback address. `transport_mode` explicitly selects `development`,
`direct_tls`, or `reverse_proxy`. Development mode is loopback-only. Direct TLS
requires both absolute `server_certificate_file` and `server_key_file` paths
and permits a non-loopback public listener. Optional `database_url` and
`public_origin` must be provided together; HTTP origins must be loopback, while
HTTPS origins are required for direct TLS and reverse proxy. For example:

```toml
development_listen = "127.0.0.1:8443"   # the development web listener
health_listen = "127.0.0.1:18482"       # /health and /ready
transport_mode = "development"
database_url = "postgresql:///openvibes?host=/run/postgresql" # optional
public_origin = "http://localhost:8443" # required with database_url
```

A non-loopback address, equal addresses, unpaired auth fields, non-loopback
origin, unpaired TLS paths, relative TLS paths, or malformed file is refused at startup ("invalid console
configuration"), and `run` refuses a listener that is not loopback even if
bound elsewhere. TLS PEM files are capped at 1 MiB, must contain a valid
certificate chain and key, and are checked before serving; handshakes are TLS
1.3 only with a 10-second deadline. Startup checks that the database is already at schema 16; it
never runs migrations. The database URL is redacted from `Debug`. Authenticated
requests must use the configured Host authority. The e2e fixture uses
18490/18491, clear of ingest's 18480 and distribution's 18481.

Reverse-proxy mode requires authenticated database configuration and a
canonical HTTPS `public_origin`. It uses either a loopback TCP listener with
1–64 unique loopback `trusted_proxy_addresses`, or a Unix socket with an
absolute `unix_socket_file` and 1–64 unique `trusted_proxy_uids`. The TCP and
Unix trust lists are mutually exclusive. Requests from other peers are
rejected. Unix sockets are created mode 0660; the proxy user must be able to
traverse the parent directory and belong to the socket's group. Forwarded
headers are ignored; the proxy must preserve the configured Host authority.
HSTS is set for both direct TLS and reverse-proxy responses.

### Development seed (C1)

Run the API with `cargo run -p openvibes-console --example seeded_server
--features dev-seed` (defaults to loopback ports 18490/18491), then run
`npm run dev` from `crates/openvibes-console/web` for the Vite UI. The Vite
server proxies API requests to the seeded API. API requests accept the
demo-only `x-openvibes-dev-persona` and `x-openvibes-dev-mode` headers; the UI
controls persist those values in local storage. The persona names use the
same built-in role resolver as C3, with a fixed demo asset-group binding for
`scoped_operator`. Data is deterministic and synthetic; the 50,000-agent mode
returns bounded pages and never loads all rows into the browser. These
temporary routes are intentionally absent from the production OpenAPI
contract until the database-backed C2/C3 routes exist.

### Planned (C2 to C5)

The remaining service configuration is strict, bounded TOML with unknown keys
and relative key/certificate paths refused. Its approved deployment constraints
are:

- direct TLS 1.3 termination is available with a configured server certificate
  chain and private key; TLS responses include HSTS;
- reverse-proxy mode is explicit and requires a canonical external HTTPS
  origin plus an allow-list of trusted proxy peers (loopback TCP addresses or
  Unix effective UIDs);
- forwarded headers are ignored; Host/Origin checks use the configured
  external origin;
- plaintext proxy upstreams may bind only to loopback or a Unix socket;
  non-loopback upstreams remain TLS protected;
- the health listener must be loopback-only;
- the production PostgreSQL connection uses the least-privilege
  `openvibes_console` role;
- session lifetimes, request limits, password hashing, export limits, and the
  private CSV spool are bounded configuration rather than browser choices.

The systemd unit creates `/run/openvibes-console` as a service-owned runtime
directory and removes it when the service stops. In Unix proxy mode, the
configured peer UIDs are checked using kernel peer credentials. Development
uses a loopback-only seeded server; the `dev-seed` implementation and its
conspicuous banner are never included in the production RPM.

The offline RPM build script validates the caller-supplied cache digest,
builds the embedded UI and release binary without network access, creates an
isolated `target/rpm-console` rpmbuild tree, and emits the package there. CI
installs that RPM after platform migrations inside Fedora 44 with systemd as
PID 1, then checks readiness, HTTPS delivery, response security headers, the
systemd seccomp and `NoNewPrivs` settings, Unix proxy access for allowed and
disallowed peer UIDs, and reinstall preservation of local configuration, TLS
files, and service state.

## Failure behaviour

**Now (C0, C1, and the C3 local-auth slice):**

- The development listener answers only loopback `Host` names (`localhost`,
  `127.0.0.1`, `[::1]`, any port); any other `Host` gets 421, so a
  DNS-rebinding page cannot read it. Requests without `Host` pass.
- Authenticated runtime startup refuses absent/unreachable databases and any
  schema version other than 16; it does not migrate. The configured Host
  authority is enforced for authenticated requests. Login uses trusted socket
  peer information from the capped listener; forwarded headers are ignored.
- Login, logout, pre-auth, session refresh, and password-hash upgrade persist
  through `platform-store` transactions. Login failures have a generic shape;
  password work has a four-operation concurrency bound.
- The embedded UI requests the current session without caching, gates
  application routes unless that request succeeds, obtains one-use pre-auth
  state before enabling local login, and sends logout with the synchronizer
  CSRF token. It never reads the opaque session cookie.
- The full Content Security Policy is enforced on every public response,
  including `frame-ancestors 'none'`; `X-Frame-Options: DENY` is also set.
- A wrong method on an API route is a 405 Problem Details response with
  `Cache-Control: no-store`, like every API error.
- The public and development routers cap extractor request bodies at 1 MiB,
  request handling at 15 seconds, and in-flight requests at 128 per process.
  The public TCP or Unix listener accepts at most 256 concurrent connections
  and the health listener accepts at most 16; excess connections wait in the
  OS accept queue until a slot opens.
- Problem Details errors log their request ID, stable code, and HTTP status;
  request fields and secret values are not logged.
- An `embedded-ui` build fails if the shared route/public-asset contract,
  generated frontend manifest, SPA entry, exact public-file inventory, or a
  referenced embedded asset is missing or inconsistent. It also refuses a
  stale build stamp whose sorted input/output inventory or SHA-256 digest does
  not match the files being embedded.
- Frontend tests refuse brand SVGs with scripts, animation, embedded raster,
  external references, text/fonts, or background rectangles, and verify the
  PNG signatures, alpha channel, and declared dimensions.
**Implemented runtime behavior:**

- In authenticated mode, `/ready` is refreshed every five seconds using a
  bounded database connection and schema-version check. It returns 503 on
  timeout, database failure, or schema drift; `/health` remains a
  process-liveness check.
- Development mode and its synthetic seeded routes remain loopback-only. They
  cannot access production state. Production data and control-plane routes
  require database-backed authentication; there is no permissive production
  authentication mode.
- In authenticated mode, `/api/v1/session` validates the database session and
  resolves active role bindings on every request.
- API failures are bounded Problem Details responses and never expose SQL,
  credentials, tokens, certificates, IdP payloads, or authorisation detail.
- Authorisation is applied in database queries before aggregation, filtering,
  and pagination. An object outside the caller's asset scope looks absent.
- A mutation whose audit append fails rolls back. Token plaintext is shown
  once and cannot be recovered afterward.
- Direct TLS 1.3, trusted loopback-TCP proxying, and UID-allow-listed Unix
  socket proxying are available. Other proxy peers are rejected. Forwarded
  headers are ignored; the Fedora systemd integration covers the direct TLS
  package path and Unix-socket peer-UID enforcement.

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
checks the sidecar, allow-lists archive paths, refuses links and special files,
confirms the current lock digest and platform, then runs `npm ci --offline`
and a Vite build in a scratch directory. Packaging extraction also requires an
independently pinned digest from trusted RPM source metadata:
`scripts/check-console-npm-cache.sh ARCHIVE CACHE_DIR EXPECTED_SHA256`.
`scripts/build-console.sh
--offline-cache-dir CACHE_DIR` then checks the lock digest/platform again,
verifies npm's cache, and runs every npm command with networking disabled by
`unshare -rn`. The first package target is Fedora Linux x86_64, so caches for
other platforms are deliberately distinct. Console RPM source metadata
supplies the expected archive digest independently of the archive and its
sidecar. The one-argument checker mode used in CI validates corruption only.

Build the Fedora x86_64 console package with:

```sh
scripts/build-console-rpm.sh "$CACHE_ARCHIVE" "$EXPECTED_SHA256"
```

The script verifies the pinned source cache, runs the frontend package checks
and build with networking disabled, builds the Rust binary with Cargo offline,
and packages it through `packaging/rpm/openvibes-console.spec`. RPM `%check`
verifies the expected cache digest again. The resulting service is disabled
until the operator provisions its database and certificate.

For a network-isolated package build, persist the validated cache and pass it
to the frontend build:

```sh
scripts/check-console-npm-cache.sh "$CACHE_ARCHIVE" target/console-npm-cache/extracted "$EXPECTED_SHA256"
scripts/build-console.sh --offline-cache-dir target/console-npm-cache/extracted
```

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
asset tests. Playwright starts the embedded `dev-seed` example on loopback in
Chromium, Firefox, and WebKit. It covers axe accessibility analysis, target
CSP headers and browser violations, first-paint theme persistence, keyboard
entry, native menu/dialog/combobox focus behaviour, reserved-route fall-through,
bounded 50,000-agent rendering, and seeded permission/error states. The seeded
server is test-only and is not the production binary. Later contract tests
exercise the complete Axum router first against deterministic seeded data and
then against PostgreSQL. Security coverage expands from the current route
fall-through, cache-header, and CSP checks to session/CSRF handling, object
scope, audit atomicity, trusted proxies, secret redaction, and bounded CSV
export.
