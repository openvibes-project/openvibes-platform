# Console server split by area — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** `crates/openvibes-console/src` is organised in one folder per area of
the console, with no file over 500 lines, and nothing a client, test or other
crate can see changes.

**Architecture:** today 41 flat modules; `router.rs` (7,059 lines) holds the
route table, the middleware and the handlers of most areas, and `api.rs`
(1,605) the response types of all of them. Each area becomes a folder holding
its handlers, its request/response types and a `routes()` function; the router
only merges the areas' routes and adds the shared middleware.

**Tech stack:** Rust 2024, axum, utoipa (OpenAPI), tokio-postgres via
platform-store.

**Approved layout (user, 2026-10-16):**

```
src/
  http/            router assembly, request limits and logging, host checks,
                   frontend and asset serving, problem + error types, OpenAPI
  access/          sign-in (session, login, throttle, first admin), roles
                   (rbac), users, service accounts, role bindings, asset
                   groups, host tags; guard.rs: the session and permission
                   checks every area uses
  audit/           audit events, export, retention
  hosts/           host list/detail/certificates, enrollment tokens, agent
                   package and install command, assets, software, ports,
                   presence, fleet
  compliance/      findings, finding groups, history, triage, bulk triage,
                   triage detail
  vulnerabilities/ summary, list, advisories
  alarms/          alarms, suppressions, detection evidence
  cases/           cases
  rules/           rule sets and bundles, assignment, drafts, rule tests,
                   coverage
  assistant/       chat endpoints, internet lookups (the folder exists)
  dashboards/      dashboards, metrics
  about.rs config.rs server.rs seeded/ lib.rs main.rs bin/
```

## Global constraints

- **No behaviour change.** Moves only: no handler, status code, problem code,
  route path, method, permission check, SQL or response field changes. A
  function moves whole, with its doc comment. Renames only where a name would
  now stutter (`hosts::hosts_x`), never for public items.
- **Public surface unchanged:** every `pub use` in `lib.rs` keeps its name and
  meaning (`openvibes-admin` and the integration tests import them); the
  OpenAPI snapshot (`docs/api/console-v1.openapi.json`, checked by
  `tests/api_contract.rs`) stays byte-identical. utoipa schema names come from
  the type names, so moving a type does not change them.
- Visibility: `pub(crate)` across areas, private inside one; nothing becomes
  `pub` that was not.
- Files under 500 lines (tests included where touched). A `mod.rs` holds only
  `mod` lines, re-exports and `routes()`.
- Every new folder gets a `README.md` (what the folder is for, one line per
  file, link to `docs/components/openvibes-console.md`), in the task that
  creates it; `scripts/check-folder-readmes.sh` covers `crates/openvibes-console/src`
  from Task 1 on.
- Code style as it is: comment density, naming, `ponytail:` notes kept.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Verification for every task

From the worktree root, with `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target`
and `eval "$(scripts/test-db.sh)"` (this host is the user's production
platform: use only the test database; `nice -n 19`; never /tmp):

```sh
cargo fmt --all --check
nice -n 19 cargo clippy --locked -p openvibes-console -p openvibes-admin --all-targets --all-features -- -D warnings -F unsafe-code
nice -n 19 cargo test --locked -p openvibes-console --all-features
bash scripts/check-folder-readmes.sh
```

Expected: all green; `generated_openapi_matches_the_committed_snapshot`
passes without touching the snapshot.

## Tasks

### Task 1: `http/` and `access/guard.rs`

Move from `router.rs`: the router builders (`public_router`,
`authenticated_router*`, `health_router`, `development_router`,
`with_request_limits`, `request_logging`, `request_limits`, the host checks,
`misdirected*`, `asset_router`, `frontend_router`, `spa_index`, `hashed_asset`,
not-found responses, security headers) into `http/` (`router.rs` for the
builders and the route table, `middleware.rs`, `frontend.rs`), plus
`problem.rs`, `error.rs`, `openapi.rs`, `frontend_contract.rs` and
`misdirected.css`. Move the session and permission helpers every area calls
(`session_user`, `checked_session`, `authenticated_permission`,
`authenticated_agent_scope`, `session_capabilities`, `authentication_required`,
`unavailable_auth`, and the like) to `access/guard.rs`. `AuthHttpState` lives
in `http/`. The route table stays one function for now, pointing at handlers
wherever they are. Widen `scripts/check-folder-readmes.sh` roots to
`crates/openvibes-console/src`, with READMEs for `src`, `http`, `access` (and
existing `assistant`, `bin`).

### Task 2: `access/`

`auth.rs`, `auth_first.rs`, `rbac.rs`, `users.rs`; from `router.rs`: session,
login, logout, preauth, password change, throttle, service accounts and their
tokens, role bindings, asset groups, host tags (preview/apply), the access
inventory; their types from `api.rs`.

### Task 3: `audit/` and `hosts/`

Audit events, export, retention (router.rs + types). Hosts: agent list,
summary, detail, certificates, revoke, enrollment tokens, agent package and
command (`agent_package.rs`), `assets.rs`, `software.rs`, `ports.rs`,
`presence.rs`, `site_fleet.rs`, and their types.

### Task 4: `compliance/` and `vulnerabilities/`

Findings (latest, groups, endpoints, history, events, triage, group triage),
`bulk.rs`, `triage_detail.rs`; vulnerability summary, list, advisory, CPE
helpers; their types.

### Task 5: `alarms/` and `cases/`

`alarms.rs`, `alarm_suppressions.rs`, `detection.rs`; `cases.rs` (1,180 lines)
split along its seams (handlers, validation, views) under 500 each.

### Task 6: `rules/`, `assistant/`, `dashboards/`

Rule sets and bundles (router.rs), `rule_assignment.rs`, `rule_drafts.rs`
(979, split), `rule_test.rs`, `coverage.rs`; `assistant.rs`,
`assistant_internet.rs` into the existing `assistant/`; `dashboards.rs`,
`metrics.rs`.

### Task 7: routes per area; `router.rs` and `api.rs` gone

Each area's `mod.rs` exposes `routes() -> Router<AuthHttpState>`; the route
table in `http/router.rs` merges them (same paths, methods and layers; mind
that one path may be served by two areas with different methods). Whatever is
left in `api.rs` moves to the area that owns it, or to `http/` if shared.
`seeded.rs` (1,266) splits into `seeded/` by area. `about.rs` with its tests
stays at the top. No file in `src/` over 500 lines except test-only files
already over (name them in the report).

### Task 8: docs

`docs/components/openvibes-console.md` (and any other page naming a moved
file) points at the new paths; a short "Where code lives" section like the
web's. Final READMEs pass the check.
