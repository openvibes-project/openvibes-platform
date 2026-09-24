# OpenVIBES Console Implementation Plan

Status: **approved by the project owner, 2026-09-23**. PM4 and platform schema
3 are integrated in the `console` worktree; C0 implementation may proceed.

Design inputs:

- [`../specs/2026-09-23-console-product-design.md`](../specs/2026-09-23-console-product-design.md)
- [`../specs/2026-09-23-console-technical-design.md`](../specs/2026-09-23-console-technical-design.md)
- [`../specs/2026-09-23-platform-architecture-design.md`](../specs/2026-09-23-platform-architecture-design.md)

## 1. Parallel Ownership

While Claude's platform work continues:

| Area | Console branch | Claude platform branch |
|---|---|---|
| Product/technical console specs | owns | reads |
| `crates/openvibes-console` and its `web/` directory | owns | does not edit |
| Seeded console repository and UI data | owns | does not edit |
| `platform-store`, migrations, token/revoke domain logic | proposes only | owns |
| `platform-config` | proposes only | owns |
| Workspace members and `Cargo.lock` | expected integration conflict | expected integration conflict |
| RPM spec and CI | console changes wait for integration window | owns current changes |
| Component index | update in small integration commit | update in current work |

Every shared-store change is a small independent commit merged to the common
base first; the other worktree rebases. Existing migrations are never edited
after merge. Whoever merges second assigns the next migration number.

## 2. Milestone C0 — Contract and Build Skeleton

Goal: one minimal, security-hardened console binary with a reproducible
frontend build and no production database dependency.

Deliverables:

- add `crates/openvibes-console` and its component documentation;
- add the crate to the root workspace on the console branch immediately and
  accept the expected `Cargo.toml`/`Cargo.lock` rebase conflict;
- add web workspace with locked package dependencies and strict TypeScript;
- add the app shell, complete light/dark semantic design tokens and System/
  Light/Dark theme control; prepare/review transparent local brand assets from
  the supplied logo references; add the skip link, navigation landmarks, safe
  fallback route, and seeded-data banner primitive;
- establish `/api/v1/session` DTO, Problem Details error DTO, pagination DTO,
  OpenAPI generation/snapshot, and TypeScript client generation using an
  OpenAPI-export build that does not require embedded frontend assets;
- add explicit `scripts/build-console.sh` build sequence;
- embed the Vite build output in the Rust binary;
- route API/auth/assets/browser paths without SPA fall-through leaks;
- apply no-store/immutable cache rules and report-only target security headers;
- add `/health` and `/ready` on a separate loopback-only listener, absent from
  the public TLS router;
- configure Vite manifest output and disable asset inlining;
- prove chosen dialog/menu/combobox primitives against the target CSP in real
  browsers before fixing the component dependency;
- define and test the lockfile-derived, checksummed npm source cache used by
  network-free RPM builds;
- keep production auth disabled/refused until C3 rather than introducing a
  permissive temporary mode.

Verification:

- `cargo fmt --check`, clippy with warnings denied, docs, and Rust tests;
- `npm ci`, strict typecheck, lint, unit tests, production build;
- binary serves the shell and exact assets with correct types/cache headers;
- System/Light/Dark selection, persistence, and first-paint behaviour work
  without weakening CSP or coupling theme state to authentication;
- API, auth, and unknown asset routes return JSON/real 404, never index HTML;
- release build fails clearly if generated assets/build stamp are missing;
- build scripts never invoke a package manager implicitly or access network.
- OpenAPI export → TypeScript generation → Vite → `embedded-ui` release build
  runs from a clean checkout without a dependency cycle;
- an offline package-build test uses the supplied npm cache successfully.

Shared-file integration required: workspace member and lockfile are changed on
the console branch now; CI Node setup and RPM entries wait for a coordinated
rebase point.

## 3. Milestone C1 — Seeded Read Vertical Slice

Goal: validate product interaction, API contracts, permissions, scale, and
accessibility before shared schema changes.

Deliverables:

- narrow console repository trait with deterministic in-memory implementation;
- loopback-only `seeded_server` behind a `dev-seed` feature, absent from the
  production package;
- fixed Viewer, Analyst, Operator, scoped Operator, and Admin personas;
- empty, mixed, 50,000-agent, stale, partial-failure, expired-session, and
  permission-removed data modes;
- Overview, Agents list/detail, and Findings list/detail;
- URL-owned bounded filters, stable sort, and opaque-cursor simulation;
- semantic server-paginated tables without virtualization;
- loading, empty, unavailable, stale, and forbidden states;
- text/icon status vocabulary and exact timestamps;
- no production-only fields invented in seed data.

Verification:

- handler tests through the complete Axum router and in-memory repository;
- Testing Library/Vitest behavioural tests, not visual snapshots alone;
- automated accessibility checks and keyboard/focus tests;
- Playwright journeys in Chromium, Firefox, and WebKit;
- 50,000 seeded agents never become 50,000 browser rows or DOM nodes;
- scoped summaries, facets, lists, and item lookups contain no hidden assets;
- manual 200% zoom, forced-colour, reduced-motion, tablet-width checks;
- light and dark contrast/state review plus brand placement at expanded,
  collapsed, sign-in, and favicon sizes;
- NVDA/Firefox and VoiceOver/Safari review before release, not necessarily
  before early C1 iterations.

No shared migration is required.

## 4. Milestone C2 — PostgreSQL Read Adapter

Prerequisite satisfied: PM4 and platform schema 3 are integrated in the
console branch.

Goal: prove agents and findings read models against PostgreSQL with measured
query plans. Public production data routes remain disabled until C3 supplies
authentication and SQL-enforced asset scope.

Work:

1. Resolve the latest-finding read model: extend `current_findings` with the
   complete display snapshot or retain a reliable partition key and fields.
2. Use the existing indexed `agents.hostname` read model. Ingest already
   stores the latest present authenticated-heartbeat value through migration
   3; the console treats it only as a mutable, spoofable operator label.
3. Add small typed `platform-store` query modules for summaries, agents,
   certificates, latest observations, and history.
4. Add indexes only from representative query plans.
5. Run the same global read-model cases against PostgreSQL behind a test-only
   harness; do not expose an unauthenticated production path.

Verification:

- real PostgreSQL integration tests fail, never skip, if the test database is
  unavailable;
- pagination is stable when sort keys do not change and behaves safely when a
  live sort key changes; it does not claim repeatable-snapshot semantics;
- query plans and latency are recorded for representative 50,000-agent data;
- an unknown/newer schema keeps readiness false and prevents serving data.

## 5. Milestone C3 — Authentication, Sessions, and RBAC

Goal: production local username/password login and server-enforced, auditable
permissions.

Work:

- finalise local-account/password policy and trusted-proxy rules;
- add the next available append-only migration (0007 or later: main has
  schema 5, and 0006 is reserved for sub-project 2's rule tables): local users,
  Argon2id credentials, sessions, local pre-auth state, RBAC, asset groups,
  and structured audit;
- add least-privilege `openvibes_console` database role;
- add audited, interactive `openvibes-admin user` commands for create, list,
  disable, unlock, and reset-password; this is first-Admin bootstrap and
  lockout recovery;
- implement local login with generic failures, reviewed Argon2id parameters,
  common-password blocklist, per-account and per-source throttling, and
  temporary lockout;
- add one-use local pre-auth CSRF state and exact-Origin enforcement;
- implement hashed opaque sessions, rotation, idle/absolute expiry, and
  revocation generation;
- implement synchroniser CSRF value, exact Origin, Fetch Metadata, and no CORS;
- implement permission middleware plus handler-level object scope;
- extend the C2 store queries so asset scope is enforced inside SQL before
  aggregation, facets, sorting, filtering, and pagination;
- add access-control and audit read pages, including the effective 365-day
  default retention policy and its globally authorised, audited update flow;
- add a permission-gated CSV audit export of the exact filtered result set,
  with a private bounded spool, formula neutralisation, no caching, and an
  audit record committed before download begins;
- extend bounded maintenance to delete audit events older than the effective
  cutoff without granting the console unrestricted audit deletion;
- enforce the final CSP and browser headers.

OIDC, SAML, TOTP, and WebAuthn are later adapters over this identity/session
boundary.

Verification includes unknown/wrong/disabled/locked account
indistinguishability, Argon2id floor and hash upgrade, password bounds and
blocklist, throttling, CLI reset/unlock, no session, expired/revoked session,
fixation, missing/wrong CSRF, bad Origin, insufficient permission, hidden
object, and mid-session RBAC change. Login, denial, logout, password change,
and audit access events are audited without secrets. Scope-leak tests cover
item, list, summary, count, and facet paths.

## 6. Milestone C4 — Safe Mutations

Goal: expose only shared, transactionally audited domain operations.

Order:

1. Enrollment-token list/create/revoke.
2. Agent revoke.
3. Rule-set read and pre-signed bundle upload after distribution storage lands.
4. Asset tags and access bindings.
5. Service accounts and expiring API tokens.
6. Analyst triage using the approved Open, Investigating, Mitigated, Accepted
   Risk, and False Positive state contract and its reopening rules.

Rules:

- reuse the same `platform-store` transaction functions as the CLI;
- successful change and audit event commit together;
- use idempotency keys for create/action routes;
- use `If-Match` for stale editable resources;
- return enrollment/service-account token plaintext exactly once; a replay of
  the same idempotency key returns metadata with no secret, and a lost first
  response requires revoke-and-recreate;
- require review and deliberate confirmation for trust-changing actions;
- never introduce rule signing or CA private keys into the console.

Verification covers duplicate submit/retry, audit failure rollback, permission
loss between render and submit, stale precondition, secret non-retrievability,
redaction in logs/errors/audit, service-account disable/expiry, illegal triage
transitions, triage/observation separation, and successful/failed accessibility
states.

## 7. Milestone C5 — Packaging and Hardening

Goal: production-ready RPM and systemd service.

Work:

- bounded console TOML configuration and absolute-path checks;
- direct TLS 1.3 server configuration by default; explicit proxy mode requires
  a canonical external HTTPS origin, trusted proxy allow-list, and loopback/
  Unix-socket plaintext or TLS-protected non-loopback upstream;
- RPM build order including deterministic frontend assets;
- network-free `npm ci --offline` against the verified source cache;
- hardened systemd unit and dedicated service/database roles;
- final CSP enforcement, HSTS, no-referrer, nosniff, Permissions Policy;
- structured safe logs with request IDs and no finding/token body content;
- readiness for database/schema and local-auth state;
- upgrade, rollback-safety, backup/restore notes, and operator documentation;
- final `docs/components/openvibes-console.md` and component index update.

Verification:

- clean RPM build installs without Node runtime;
- service starts, serves local login and assets/API over HTTPS, and has expected
  headers;
- upgrade preserves sessions/data according to migration policy;
- browser matrix and accessibility review pass;
- Cargo and npm dependency audits pass;
- no CDN or runtime third-party resource request occurs.

## 8. Later Capabilities

Only after their contracts exist:

- deployment package builder and multi-use deployment tokens;
- OIDC, SAML, TOTP, and WebAuthn authentication adapters;
- remediation workflow and detector-level suppression semantics beyond the
  approved first-release analyst triage contract;
- inventory/package explorer, correlation, and CMDB views;
- saved views, general report/findings export, and SIEM integration;
- live updates, charts, or table virtualisation based on measured need;
- mobile-specific adaptations.

## 9. Collision Checklist Before Each Rebase

- Did Claude's active platform work add or renumber a migration?
- Did `SCHEMA_VERSION` or the embedded migration list change?
- Did token creation/revocation or agent revocation semantics change?
- Did the audit helper or schema gain structured fields?
- Did `platform-config` gain console-relevant shared types?
- Did workspace members, `Cargo.lock`, CI, component index, or RPM spec change?
- Does the schema 3 ingest implementation still match the optional heartbeat
  hostname contract, and did later protocol changes add health, inventory
  upload, or match-end semantics that alter UI vocabulary?
- Are local changes isolated into reviewable commits before conflict
  resolution?

## 10. Approval Gate

Begin C0/C1 only after approving the core stack and seeded-first boundary.
The core design gate is approved: direct TLS is the default with a constrained
trusted-proxy mode; hostname, manual tags, service accounts, CLI-only rule
trust-key management, the complete first-release triage contract,
administrator-configurable audit retention defaulting to 365 days, and bounded
CSV audit export are also approved.
