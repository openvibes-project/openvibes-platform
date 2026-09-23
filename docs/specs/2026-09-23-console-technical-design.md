# OpenVIBES Console Technical Design

Status: **approved by the project owner, 2026-09-23**. Product companion:
[`2026-09-23-console-product-design.md`](2026-09-23-console-product-design.md).

## 1. Goal and Boundaries

`openvibes-console` is the human-facing administration service on port 443.
It owns the browser application, versioned human API, authentication sessions,
RBAC enforcement, browser security headers, and static assets.

It does not own agent protocol endpoints, database SQL, rule signing, CA
private-key operations, correlation, CMDB sync, or deployment-package logic.

Trust domains stay physically and logically separate:

- agents authenticate only with mTLS to ingest/distribution ports 18423 and
  18424;
- humans authenticate only through console identity providers and sessions;
- service accounts use console API bearer tokens in the first release;
- none of these credentials is accepted in another domain.

## 2. Recommended Stack and Deployment Model

Use a client-rendered React + TypeScript application built by Vite and served
same-origin from an Axum `openvibes-console` binary.

The console is the remote web GUI and human/service-account API. It never
starts, stops, or restarts platform services and does not edit host TOML files.
Those local operating-system concerns belong to `openvibes-admin tui`, which
has no network listener and is outside the console trust boundary.

Browser capabilities:

- React with TypeScript strict mode;
- Vite at build time only;
- client-side routing;
- TanStack Query for bounded server state;
- TanStack Table for headless table state with native HTML table rendering;
- reviewed accessible primitives only where native HTML is insufficient, such
  as focus-managed dialogs, menus, and comboboxes; C0 must prove that the
  selected primitives work under the target CSP before the library is fixed;
- extracted plain CSS/CSS Modules and design tokens; no runtime CSS-in-JS;
- a generated TypeScript client from the checked Rust OpenAPI snapshot.

Exact dependency versions are pinned when implementation starts. The design
fixes capabilities and boundaries, not today's patch releases.

Why this shape:

- one Rust process and one RPM-installable service in production;
- Node.js is only a reproducible build dependency;
- no SSR, React Server Components, or Node production runtime;
- the admin API remains useful to service accounts and future integrations;
- mature accessible interaction, browser testing, and data-table ecosystems;
- frontend work can use the real Axum routes with a seeded repository before
  the console's PostgreSQL adapter and mutation schema are complete.

Alternatives considered:

| Approach | Advantage | Reason not selected |
|---|---|---|
| Svelte/Vite | Concise components and small output | Smaller accessibility/component/testing ecosystem; no benefit from a second server framework |
| Axum templates plus htmx | Minimal JavaScript and simple CSP | Rich URL-addressable filters and asynchronous workflows would duplicate HTML and required JSON API representations |
| Rust/WASM UI | One implementation language | Extra WASM/toolchain complexity and weaker accessible-component/browser-testing ecosystem |

## 3. Repository Layout

```text
crates/openvibes-console/
  Cargo.toml
  build.rs                    # validates assets; never runs a package manager
  src/
    main.rs
    lib.rs                    # router construction for tests/dev harness
    api/v1/
    auth/
    rbac.rs
    assets.rs
    export_openapi.rs         # builds without embedded frontend output
    errors.rs
    config.rs
  tests/
  examples/seeded_server.rs   # dev-seed feature only; never packaged
  web/
    package.json
    package-lock.json
    tsconfig.json
    vite.config.ts
    index.html
    src/
      app/
      api/
      routes/
      features/
      components/
      styles/
      test/
    e2e/
    dist/                     # generated; not hand-edited

docs/api/console-v1.openapi.json
scripts/build-console.sh
scripts/test-console-e2e.sh
```

The web source lives inside the console crate because it has one owner,
release cadence, and deployable artefact.

## 4. Dependency Boundaries

- `platform-store` remains the only crate that accesses PostgreSQL. It exposes
  bounded typed query and mutation functions, never raw SQL to the console.
- Store records are domain data, not HTTP response types.
- `openvibes-console` maps store results to versioned API DTOs and owns HTTP,
  auth, session, CSRF, RBAC, errors, and asset serving.
- Browser code knows only `/api/v1`, never Rust internals or database schema.
- The human API is a platform contract and does not belong in
  `openvibes-protocol`, which remains the agent/platform wire contract.
- Enrollment-token creation and agent revocation reuse the same transactional
  store functions as `openvibes-admin`; the console does not duplicate SQL or
  domain rules.
- Rust DTOs generate an OpenAPI document. CI checks the snapshot for drift,
  then generates TypeScript types/client code from that snapshot.

## 5. HTTP Surface

```text
/api/v1/*    JSON human/service-account API
/auth/*      login starts and provider callbacks
/assets/*    exact content-hashed embedded assets
/            SPA index
/<route>     SPA index only for known browser routes
```

Unknown API, auth, and asset paths return a real 404 and never fall through to
the SPA index.

Conventions:

- closed JSON request validation; response objects may gain additive fields;
- breaking changes require `/api/v2`;
- RFC Problem Details-style errors use `application/problem+json` with stable
  `code`, `title`, `status`, and `request_id` plus bounded field errors;
- errors never expose SQL, IdP payloads, tokens, certificates, or internal
  authorisation detail;
- API and auth responses use `Cache-Control: no-store`;
- state-changing routes accept `Idempotency-Key` where retries could duplicate
  effects;
- mutable resources use ETag/`If-Match` where concurrent stale edits matter;
- signed-envelope bodies retain the platform 1 MiB bound; every other request
  has a smaller route-specific bound.

Page responses have a common bounded form:

```json
{
  "items": [],
  "next_cursor": "opaque",
  "generated_at": "2026-09-23T14:00:00Z"
}
```

Object-scoped resources outside the caller's asset scope return 404, not 403.

## 6. First-Release API

### 6.1 Session and authentication

| Method and path | Purpose |
|---|---|
| `GET /api/v1/session` | Current user, auth/MFA level, effective capabilities/scopes, CSRF value |
| `POST /api/v1/session/logout` | Revoke the current session |
| `POST /auth/local/login` | First-release username/password login |
| `POST /api/v1/session/password` | Change the current local user's password after re-authentication |
| `GET /auth/oidc/{provider}/start` | Later adapter: begin OIDC Authorization Code + PKCE |
| `GET /auth/oidc/{provider}/callback` | Later adapter: validate OIDC flow |
| `GET /auth/saml/{provider}/start` | Later adapter: begin SAML flow |
| `POST /auth/saml/{provider}/acs` | Later adapter: validate SAML assertion |
| `POST /auth/local/mfa/*` | Later adapter: TOTP/WebAuthn challenge completion |

Local username/password ships first. OIDC, SAML, TOTP, and WebAuthn come later
behind the same internal identity, session, and RBAC boundary.

Local login uses a one-use, short-lived pre-auth CSRF cookie/token bound to the
initiating browser, exact Origin, and allow-listed return path. Later OIDC and
SAML flows add provider/callback/replay correlation without changing the
authenticated session cookie.

### 6.2 Overview

Use permission-specific summary routes so a broad dashboard query cannot
bypass scope checks:

| Path | Permission |
|---|---|
| `GET /api/v1/agents/summary` | `agents.read` |
| `GET /api/v1/findings/summary` | `findings.read` |

Service-health state remains outside the public console API until an
authoritative persisted health contract exists. Process `/health` and
`/ready` are served only on a separate loopback listener and are absent from
the public TLS router.

### 6.3 Agents

| Method and path | Permission |
|---|---|
| `GET /api/v1/agents` | `agents.read` |
| `GET /api/v1/agents/{agent_id}` | `agents.read` |
| `GET /api/v1/agents/{agent_id}/certificates` | `agents.read` |
| `POST /api/v1/agents/{agent_id}/revoke` | `agents.revoke` |
| `PUT /api/v1/agents/{agent_id}/tags/{key}` | global `asset_groups.manage` |
| `DELETE /api/v1/agents/{agent_id}/tags/{key}` | global `asset_groups.manage` |

Certificate responses expose metadata only, never PEM chains. Tag mutation is
global-only because changing a tag can move an agent across authorisation
boundaries.

### 6.4 Findings

| Method and path | Permission |
|---|---|
| `GET /api/v1/findings/latest` | `findings.read` |
| `GET /api/v1/findings/latest/{agent_id}/{rule_id}` | `findings.read` |
| `GET /api/v1/findings/latest/{agent_id}/{rule_id}/triage` | `findings.read` |
| `PUT /api/v1/findings/latest/{agent_id}/{rule_id}/triage` | `findings.triage` |
| `GET /api/v1/findings/history` | `findings.read` |
| `GET /api/v1/findings/history/{observed_day}/{finding_id}` | `findings.read` |

The latest-detail resource requires `current_findings` to retain a complete
latest snapshot. The composite history URL matches the current partitioned
primary key. A response subject is a tagged union: an enrolled `agent`, or an
unauthenticated imported `installation` with `install_id` and optional
hostname. Imported installations have no agent link and require global
`findings.read` until a later association contract exists.

First-release triage is a versioned human workflow record attached to the
latest subject/rule pair. `PUT` requires `If-Match`, an allowed transition,
bounded assignee/note fields, and an atomic audit event. Its states never
change or reinterpret the immutable observation. The states are `Open`,
`Investigating`, `Mitigated`, `Accepted Risk`, and `False Positive`.
The API and database use stable values `open`, `investigating`, `mitigated`,
`accepted_risk`, and `false_positive`; the UI renders the approved labels.
`Investigating` may transition to any of the latter three states. A new
observation reopens `Mitigated`; it reopens expired `Accepted Risk`, and a new
rule version reopens `False Positive`. Reopening sets the state to `Open` and
is recorded in triage history and audit. New observations leave an active
`Investigating` assignment intact.

### 6.5 Enrollment tokens

| Method and path | Permission |
|---|---|
| `GET /api/v1/enrollment-tokens` | `tokens.read` |
| `POST /api/v1/enrollment-tokens` | `tokens.create` |
| `GET /api/v1/enrollment-tokens/{token_id}` | `tokens.read` |
| `POST /api/v1/enrollment-tokens/{token_id}/revoke` | `tokens.revoke` |

Plaintext is returned only in the first successful creation response. The
idempotency record is keyed by authenticated principal, route, and key; it
stores the request hash and token ID in the same transaction, never the
secret. Same key and same body returns metadata with `replayed: true`,
`secret: null`, and `secret_available: false`; a different body returns 409.
If the first response was lost, the operator revokes the unusable token and
creates another. Records have a bounded retention period and uniqueness
constraint; recoverable plaintext is not stored merely to support retries.

### 6.6 Rule sets

| Method and path | Permission |
|---|---|
| `GET /api/v1/rule-sets` | `rules.read` |
| `GET /api/v1/rule-sets/{id}` | `rules.read` |
| `GET /api/v1/rule-sets/{id}/versions` | `rules.read` |
| `GET /api/v1/rule-sets/{id}/versions/{version}` | `rules.read` |
| `POST /api/v1/rule-sets/{id}/versions/validate` | `rules.upload` |
| `POST /api/v1/rule-sets/{id}/versions` | `rules.upload` |

The non-mutating validation route accepts an already signed envelope and
returns verified metadata plus its digest. Final publication sends the exact
bytes and expected digest, then repeats every verification inside the store
transaction against current trust keys and version floor. Same
rule-set/version and same bytes is idempotent; different bytes is 409. The
console stores the exact signed bytes and never accepts private signing keys.
Rule trust-key management remains an audited local CLI operation in the first
release and has no console endpoint.

### 6.7 Access, audit, and service accounts

| Route family | Read permission | Mutation permission |
|---|---|---|
| `/api/v1/access/roles` | `rbac.read` | `rbac.manage` |
| `/api/v1/access/users` | `rbac.read` | none in v1 |
| `/api/v1/access/bindings` | `rbac.read` | `rbac.manage` |
| `/api/v1/access/asset-groups` | `rbac.read` | `asset_groups.manage` |
| `/api/v1/audit-events` | `audit.read` | none |
| `POST /api/v1/audit-events/export` | none | `audit.export` |
| `/api/v1/audit-retention` | `audit.read` | `audit.retention.manage` |
| `/api/v1/service-accounts` | `service_accounts.read` | `service_accounts.manage` |
| `/api/v1/service-accounts/{id}/tokens` | `service_accounts.read` | `service_accounts.manage` |

Service-account tokens are hashed, expiring, shown once, and mutually
exclusive with browser-cookie authentication. Deployment packages are later.
Rule trust keys and CA operations remain local break-glass CLI operations in
the first release.

## 7. Authentication and Sessions

### 7.1 Local username and password

Local accounts are the first-release authentication method. The first Admin is
created only by an audited, local break-glass command:

```text
openvibes-admin user create --username USER --role Admin
```

The CLI reads and confirms the password from a TTY. Passwords are never
accepted in an argument, environment variable, configuration file, audit
detail, or log. The same local authority can list, disable, unlock, and reset
accounts for recovery from forgotten credentials or accidental lockout.

Password rules follow the single-factor guidance used for this release:

- minimum 15 Unicode characters and maximum 128; spaces and paste are allowed;
- no character-class composition rules and no periodic forced rotation;
- reject a bounded local blocklist of common/compromised choices;
- normalise Unicode consistently before hashing and never silently truncate;
- store only a per-password salted Argon2id PHC string, with parameters at or
  above the project's reviewed floor and upgrade the hash after a later
  successful login when policy increases;
- password change requires the current password and revokes other sessions.

Login performs bounded Argon2id work even for an unknown user, returns the same
status/body for unknown user, wrong password, disabled account, and temporary
lockout, and applies both per-account and per-source throttling. Temporary
lockout, unlock, reset, success, and failure are audited without recording the
password. There is no email recovery flow in the first release.

Local login uses the pre-auth CSRF and exact-Origin checks described above.
The web UI never creates the first Admin implicitly and never exposes whether
a username exists.

### 7.2 Session

The browser receives only an opaque random session token:

```text
__Host-openvibes-session=<opaque>
Secure; HttpOnly; SameSite=Lax; Path=/
```

Only a cryptographic hash is stored. Rotate on login, MFA/elevation, password
or recovery changes. Suggested defaults are 30 minutes idle and eight hours
absolute, bounded by configuration. Logout, account disablement, provider
disablement, or credential compromise revoke affected sessions.

Sessions contain identity and, for later federated adapters, a group-assertion
revision—never effective permissions. Role and binding data is resolved on
every request, optionally through a per-principal/versioned cache invalidated
in the RBAC transaction. RBAC edits therefore take effect immediately without
logging the user out. Do not place authorisation claims in browser JWTs or
local storage.

### 7.3 CSRF

Every cookie-authenticated unsafe method requires:

- an unpredictable per-session value from `/api/v1/session` in
  `X-CSRF-Token`;
- exact configured `Origin` validation;
- cross-site Fetch Metadata rejection where supplied;
- no permissive CORS.

SameSite is defence in depth, not the only control. Bearer-token service
accounts do not use cookies and are not subject to browser CSRF handling.
Cookie and bearer mechanisms are mutually exclusive: a request containing
both the session cookie and `Authorization: Bearer` is rejected. CSRF
exemption applies only after a valid bearer token is selected with no session
cookie, and service tokens cannot call browser session/auth endpoints.

### 7.4 Later OIDC, SAML, and MFA adapters

OIDC later uses Authorization Code with PKCE, server-held state and nonce,
exact redirect URI, and strict issuer/audience validation. Tokens remain
server-side. External identities are keyed by stable provider, issuer, and
subject—not email. A first-seen external identity gets no implicit privilege;
cross-provider linking is a separate audited administrator action.

SAML later validates signed response/assertion policy, exact audience,
recipient, `InResponseTo`, bounded clock skew, and assertion-ID replay. SAML
ACS is the narrow cross-site POST exception; any correlation cookie is a
dedicated short-lived `SameSite=None; Secure` cookie, never the authenticated
session cookie.

OIDC discovery and SAML metadata URLs are administrator-configured SSRF
boundaries. Group-derived roles require complete stable group IDs and fail
closed on missing, partial, stale, or over-limit claims.

TOTP/WebAuthn are later MFA adapters. OIDC/SAML client secrets and application
encryption keys live in service-readable configuration or a defined external
secret provider, never beside ciphertext in PostgreSQL. If MFA material is
encrypted in the database, the format is versioned AEAD under an external key
with documented rotation, readiness failure, backup, and restore procedures.

## 8. RBAC and Asset Scope

Permissions:

```text
agents.read             agents.revoke
findings.read           findings.triage
tokens.read             tokens.create            tokens.revoke
rules.read              rules.upload
audit.read              audit.export             audit.retention.manage
rbac.read               rbac.manage
asset_groups.manage
service_accounts.read   service_accounts.manage
```

Reserved for later/web-excluded: `findings.export`, `rules.trust.manage`,
`packages.create`, and `ca.manage`.
`ca.manage` is not granted through the first web console.

Every permission has a server-defined scope class: agent-bound or global.
Built-ins:

- Viewer: `agents.read`, `findings.read`, `rules.read`;
- Analyst: Viewer plus `findings.triage`;
- Operator: Viewer plus agent revocation, token management, and rule upload;
- Admin: every console permission, except CLI-only CA operations.

A first-release binding joins a role to a local user or service account and is
either global or scoped to one asset group. Later adapters add stable IdP
groups to the same model. Effective access is the union of bindings.

Asset-group scope applies only to agent-bound data: agents, certificate
metadata, findings, their facets, and their summaries. Tokens, rules, audit,
RBAC, service accounts, audit retention, and other console control-plane
administration require global permission.
A scoped binding contributes only the role's agent-bound permissions; its
global permissions are inert. For example, a scoped Operator may read/revoke
matching agents but may not create tokens or upload rules. The binding review
shows this effective subset, and every mixed-role case has an authorisation
test.

Version 1 asset groups are conjunctions of exact tag `key=value` selectors.
No CEL, regex, or negation. A group has at least one selector, with a bounded
selector count and bounded key/value lengths. Canonical `(group,key,value)`
rows are unique and case sensitivity is fixed by the tag contract. Membership
requires every selector to match. Tag changes and their membership-impact
audit event commit atomically. Untagged agents require a global binding. SQL
enforces scope before filtering, sorting, pagination, aggregation, or facet
counts; the application never loads global rows and filters afterward.

IdP adapters must produce complete stable group IDs. Missing, partial,
over-limit, or failed group resolution fails closed for group-derived
bindings; a previous group set is never silently retained beyond a configured
maximum claim age. If a provider cannot refresh complete groups during a
session, the session expires no later than that maximum age.

## 9. Pagination and Query Rules

Use opaque keyset cursors bound to the normalised filters, stable sort, and
authorisation context. Default page size is 50; maximum 100. Large lists do
not compute exact totals on each request; summary routes provide deliberate
counts.

Agent/latest-finding lists are live views, not repeatable database snapshots;
the UI preserves rows during refresh and offers an explicit restart when a
cursor expires. Cursor tests guarantee stable traversal when sort keys do not
change and bounded, non-crashing behaviour during concurrent updates rather
than claiming impossible snapshot semantics. Audit pagination is different:
the first page fixes an `as_of_id` carried in every later cursor, so the
`audit.viewed` insert cannot shift that traversal.

Stable sorts:

- agents: `last_seen_at DESC NULLS LAST, agent_id ASC`;
- latest findings: `last_observed_at DESC, agent_id ASC, rule_id ASC`;
- history: `observed_at DESC, observed_day DESC, finding_id ASC`;
- tokens: `created_at DESC, token_id ASC`;
- rule versions: version descending;
- audit: `at DESC, id DESC`.

Filters are allow-listed and bounded. History has a required/default recent
window capped by retention. Free text waits for indexed labels/hostnames.

## 10. Audit Contract

Authentication events, privileged mutations, secret issuance, denials, and
sensitive administrative reads/exports append an audit event. A successful
state change and its successful audit event share one database transaction;
failure to audit rolls the change back.

Denied authentication/authorisation stays denied if persistent audit storage
is unavailable; it also emits a redacted operational error/metric rather than
turning audit failure into an authentication bypass or retry amplification.
Repeated denials are rate-limited or aggregated. Shared store mutation
functions receive a transaction so a domain change and its audit event cannot
accidentally use different pooled connections.

Event families include:

```text
auth.login.succeeded       auth.login.failed       auth.logout
auth.mfa.failed            auth.session.revoked    authorization.denied
agent.revoked              agent.tag.set           agent.tag.removed
enrollment_token.created   enrollment_token.revoked
rule_bundle.uploaded       rule_bundle.rejected
rbac.role.*                rbac.binding.*           asset_group.*
service_account.*          service_account_token.*
audit.viewed               audit.exported
```

Each event has a stable ID, timestamp, request ID, actor kind/ID and display
snapshot, auth/MFA method, action, target kind/ID, result, reason code,
trusted source address, user agent, and bounded detail.

Audit detail never contains credentials, sessions, CSRF values, bearer or
enrollment tokens, password/TOTP/WebAuthn secrets, signed envelope bodies,
certificate PEM, or raw IdP assertions.

Ordinary scoped list reads need not create a row. Denials, audit access,
exports, control-plane reads, and every privileged mutation do.

`POST /api/v1/audit-events/export` accepts the same bounded filters and stable
ordering as the audit list. It renders UTF-8 CSV into a private mode-0600 spool
while enforcing configured row and byte limits, neutralising spreadsheet
formulas, and computing a digest. Exceeding either limit deletes the spool and
returns 422 with guidance to narrow the filters; partial exports are never
presented as complete. Only after `audit.exported` commits with actor, filters,
row count, and digest does the response begin. It uses `Cache-Control: no-store`,
an exact `Content-Length`, and a safe `Content-Disposition` filename. A failed
audit append deletes the spool and discloses no CSV. The spool is removed after
the response; startup maintenance removes only stale files from the console's
dedicated export-spool directory.

Audit events are retained for 365 days by default. A versioned global policy
allows an administrator with `audit.retention.manage` to change that period.
`PUT /api/v1/audit-retention` requires `If-Match`; reductions require an
explicit confirmation field and return the resulting UTC cutoff in the review
and committed response. The policy change and its audit event commit together.
Cleanup is an asynchronous `openvibes-admin maintenance` operation that
deletes only events older than the effective cutoff in bounded batches; the
web request never performs the purge. The effective policy and cutoff remain
readable with `audit.read`.

## 11. Browser and Asset Security

The target is no inline script/style, `eval`, external resources, runtime
style injection, or remote fonts. This is a restrictive same-origin CSP, not
a nonce/hash "strict CSP." C0 must exercise the actual dialog, menu,
combobox, and overlay primitives in browsers before claiming compatibility.
A target policy is:

```text
default-src 'none';
script-src 'self';
script-src-attr 'none';
style-src 'self';
style-src-attr 'none';
img-src 'self';
font-src 'none';
connect-src 'self';
form-action 'self';
base-uri 'none';
object-src 'none';
frame-ancestors 'none';
worker-src 'none';
manifest-src 'self'
```

Also send HSTS, `Referrer-Policy: no-referrer`, `X-Content-Type-Options:
nosniff`, and a restrictive Permissions Policy. Begin report-only during
development; enforce before release. Configure Vite with
`build.assetsInlineLimit = 0` so images are not silently converted to `data:`
URLs. If a chosen overlay primitive requires inline positioning, either
replace it or document and test the narrow `style-src-attr` exception; never
feed an operator-controlled value into a style attribute.

React policy:

- no `dangerouslySetInnerHTML`;
- render finding text, evidence, labels, rule metadata, audit content, and IdP
  claims as text;
- no remote images unless a later reviewed proxy policy exists;
- ignore forwarded headers unless the connection is from an explicitly
  configured trusted proxy.

Hashed assets use a one-year immutable cache policy. `index.html` is no-store.
The production binary verifies its entry document and referenced assets before
binding. Vite sets `build.manifest = true`; validation covers every
manifest-referenced file. Browser routes have one shared declaration, or a
test-generated equivalent, proving that known routes receive the index while
`/api`, `/auth`, `/assets`, `/health`, and `/ready` never do.

### 11.1 Brand assets and themes

The supplied full-wordmark (2172×724) and compact-mark (1254×1254) PNGs are
opaque RGB visual references, not production-ready transparent assets. Before
C0 completes, prepare and review an asset set that preserves their geometry:
transparent light- and dark-surface SVG variants plus required PNG/favicon
derivatives. SVG sources have no scripts, animation, external references,
fonts, or embedded raster/network content; reproducible builds generate the
derivatives. Preserve aspect ratio and never recolour the logo from
severity/status tokens.

All UI colours are semantic CSS custom properties with complete light and dark
token sets. `color-scheme` and `prefers-color-scheme` implement the default
System choice. A `system|light|dark` override is a non-sensitive, same-site
preference; the server may reflect it as the root `data-theme` value in the
no-store entry document so refresh does not flash the wrong theme. The value is
strictly allow-listed and never participates in authentication, authorisation,
CSRF, or session handling. The theme control has a text label, keyboard access,
and an announced selected value.

## 12. Build Model

Production build:

1. build/run the Rust OpenAPI exporter without the `embedded-ui` feature;
2. compare the OpenAPI snapshot and generate/check the TypeScript client;
3. run `npm ci` from the committed lock file, typecheck, frontend tests, and
   `vite build`;
4. verify the manifest, build stamp, and every referenced entry;
5. build `openvibes-console --release --features embedded-ui`; the asset
   module/macro—not `build.rs`—embeds the generated files;
6. package the binary, config, unit, and documentation in the RPM.

The feature split breaks the Rust DTO → OpenAPI → TypeScript → Vite → embedded
Rust dependency cycle. `build.rs` validates the manifest/build stamp only when
`embedded-ui` is enabled; it never invokes npm or the network. A normal source
checkout retains `web/dist/.gitkeep`, while the asset module is compiled only
with `embedded-ui`.

RPM construction is network-free. Before packaging is accepted, the project
must define a lockfile-derived, checksummed npm source cache included as a
separate source artefact; the RPM build uses `npm ci --offline` against that
cache. A networked CI build is not evidence of a reproducible RPM. Node/npm
remain build dependencies only.

The public TLS listener serves only UI/API/auth routes. `health_listen` is a
separate loopback-only listener for `/health` and `/ready` and refuses a
non-loopback configuration.

Direct TLS 1.3 termination in `openvibes-console` is the secure default. An
explicit reverse-proxy mode is allowed only with a configured canonical
external HTTPS origin and an allow-list of trusted proxy addresses. Plain HTTP
may bind only to loopback or a Unix socket; a non-loopback upstream remains
TLS-protected. Forwarded headers are ignored unless the immediate peer is
trusted, and Host/Origin validation uses the configured external origin rather
than untrusted forwarding data. Wildcard plaintext proxy binds are refused.

During development, Vite proxies `/api` and `/auth` to the loopback seeded
Axum server. Production serves the same API DTOs and handlers.

## 13. Seeded Repository

Introduce a narrow console repository interface with PostgreSQL and
deterministic in-memory implementations. The dev implementation:

- is available only through a `dev-seed` feature and
  `examples/seeded_server.rs`;
- binds loopback only;
- has an unmistakable seeded-data banner;
- offers fixed Viewer, Analyst, Operator, scoped Operator, and Admin sessions;
- is never built into the RPM or production binary.

Handlers and contract tests use this implementation first. The same behavioural
cases later run through `platform-store` against PostgreSQL. This is an
implementation seam, not a second mock API.

## 14. Required Schema Work

Append-only migrations after the current schema 3 must add or extend:

1. human users, required local Argon2id credentials, server sessions, local
   pre-auth CSRF state, password-attempt state, and idempotency records;
2. permission registry, roles, local-user bindings, and authorisation
   generation; later migrations add external identities, provider
   configuration, stable IdP groups, assertion replay state, and MFA material;
3. `agent_tags`, asset groups, and exact-match selectors;
4. service accounts and hashed, expiring API tokens;
5. finding-triage state (`open`, `investigating`, `mitigated`, `accepted_risk`,
   or `false_positive`), assignee, version, required terminal note, history,
   rule version, and accepted-risk expiry;
6. rule sets, trusted public keys, and exact signed bundle versions;
7. structured append-only audit metadata while preserving CLI compatibility;
8. a versioned singleton audit-retention policy, defaulting to 365 days, plus
   a timestamp index for bounded maintenance cleanup;
9. least-privilege `openvibes_console` role without DDL or unrestricted audit
   update/delete; cleanup uses a narrowly scoped store operation;
10. measured indexes for every stable cursor and filter tuple.

Existing schema facts and gaps:

- migration 3 adds the indexed optional `agents.hostname` column, and ingest
  stores the latest present authenticated-heartbeat value while retaining the
  stored value when a heartbeat omits it; the hostname remains a spoofable
  label and never identity;
- `current_findings` lacks confidence, message, evidence, origin,
  authentication, receive time, scan ID, and `observed_day`, so it cannot
  serve a complete latest detail or reliably join a partitioned row;
- the partitioned finding primary key includes `observed_day`, although the
  online contract treats `finding_id` as idempotent; global dedup needs an
  unpartitioned receipt table or another mechanism;
- imported files may have no `agent_id`, while current findings require one;
  import idempotency needs `install_id`, also absent;
- rule storage and asset scopes do not exist;
- the current audit helper cannot transactionally record structured human
  actor/request metadata;
- enrollment-token creator is free text, so console issuance needs a nullable
  stable principal reference while retaining CLI history.

All schema and SQL stay in `platform-store`. PM4 and schema 3 are integrated
in the console branch; the console takes the next available migration number
only at implementation start, after checking the current shared base and any
active platform branch.

## 15. Security Acceptance Tests

At minimum, test:

- the console TLS/auth stack never treats an agent certificate as a human
  session; the reverse-direction proof is a joint test with the available
  ingest service and later extends to distribution when it exists;
- scope applies to objects, lists, summaries, filter facets, and counts;
- out-of-scope objects do not leak existence;
- token values do not enter logs, traces, analytics, errors, or audit detail;
- local login does not reveal username existence through body, status, or
  materially different hash work;
- password creation/change enforces length, blocklist, no truncation, and the
  reviewed Argon2id floor; successful login upgrades older hash parameters;
- login throttling, temporary lockout, audited CLI reset/unlock, and password
  change session revocation work without storing or logging passwords;
- sessions revoke on account/credential changes; RBAC mutations take
  effect immediately through per-request resolution/cache invalidation;
- missing/wrong CSRF, bad Origin, insufficient permission, and stale ETag fail;
- requests containing both session cookie and bearer token fail;
- service-account tokens are shown once, hashed at rest, expire, revoke, and
  cannot be used after their account is disabled;
- triage rejects stale or illegal transitions, preserves immutable observation
  data, and commits each state/assignment/note change atomically with audit;
- audit retention defaults to 365 days; stale policy updates fail; reductions
  require confirmation; cleanup preserves events at the cutoff and newer and
  cannot bypass the audited policy mutation path;
- audit export requires `audit.export`, applies the requested filters exactly,
  rejects over-limit results before download, neutralises spreadsheet formulas,
  is not cached, records success/failure without logging row contents, and
  creates/removes only private files inside its dedicated spool directory;
- tag mutation requires global authority;
- forwarded headers are ignored outside trusted proxies; proxy mode refuses
  wildcard plaintext binds and rejects requests outside the canonical external
  HTTPS origin;
- API/auth 404s cannot fall through to the SPA index;
- state mutation and audit append are atomic;
- static assets have correct type, cache headers, CSP, and `nosniff`;
- audit CSV export neutralises spreadsheet formula injection.

Later OIDC/SAML tests add callback replay, fixation, issuer/audience mismatch,
arbitrary redirect/metadata, and incomplete/stale IdP group failure paths.

## 16. Primary Implementation References

- [Vite backend integration](https://vite.dev/guide/backend-integration)
- [TanStack Table server pagination](https://tanstack.com/table/latest/docs/framework/react/guide/pagination)
- [W3C WAI table guidance](https://www.w3.org/WAI/tutorials/tables/)
- [OWASP CSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [NIST SP 800-63B password requirements](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)
- [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [MDN Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)

## 17. Decision Status

1. Same-origin React/TypeScript SPA plus `/api/v1`, embedded in one Rust
   production binary.
2. Opaque server-side cookie sessions; never browser JWT authorisation.
3. **Approved:** local username/password first; OIDC, SAML, TOTP, and WebAuthn
   are later adapters over the same session/RBAC boundary.
4. Keyset pagination, SQL-level authorisation, and native semantic tables.
5. Exact tag conjunctions for first-version asset groups.
6. Asset scopes apply only to agent-bound data; control-plane permissions are
   global.
7. CA operations remain CLI-only in the first release.
8. `platform-store` retains all PostgreSQL ownership and shared domain
   mutations.
9. **Approved:** authenticated heartbeats carry an optional OS-reported
   hostname as a mutable, spoofable operator label; ingest stores/indexes the
   latest present value through schema 3, and it is never identity or
   authorisation input.
10. **Approved:** service accounts and expiring API tokens are in the
    first-release UI and API.
11. **Approved:** rule trust-key management remains CLI-only in the first
    release.
12. **Approved:** manual exact tags are sufficient until CMDB integration.
13. **Approved:** first-release triage states are Open, Investigating,
    Mitigated, Accepted Risk, and False Positive. Re-observation reopens
    Mitigated, expired Accepted Risk, and False Positive after a rule-version
    change; an active Investigating assignment remains intact.
14. **Approved:** audit events default to 365 days of retention. A global
    administrator can change the versioned policy; reductions are confirmed
    and audited, and maintenance applies the cutoff asynchronously.
15. **Approved:** the first release includes bounded, filtered CSV audit export
    behind `audit.export`; every export is audited and spreadsheet formulas are
    neutralised.
16. **Approved:** the first release supports System, Light, and Dark themes and
    uses the supplied full wordmark plus compact V-with-signal mark. Production
    logo assets are transparent, local, and have reviewed light/dark variants.
17. **Approved:** `openvibes-console` terminates TLS 1.3 directly by default.
    Reverse-proxy mode is explicit, trusts only configured proxy peers, and
    never permits a wildcard plaintext upstream listener.
