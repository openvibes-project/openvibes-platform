# Hosts list and host page: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship step 4 of the roles spec:
- the Hosts list (screen 16), with server-side filters, per-value counts, saved views, remembered columns and a summary line;
- the host page `/hosts/{agent_id}` (screen 17), which replaces the side panel.

Along the way it builds the shared pieces that step 5's list pages reuse: `FilterBar`, `SummaryLine`, the columns menu, saved views, `DetailPage`, and the list-count query pattern.

**Architecture:**
- **One store query per list.** It returns rows, the total, the summary line and, for every filter, the count of each value with the other filters applied, all from one filtered base set scoped by §6.
- **Saved views and hidden columns are per-user rows** keyed by page (`console_saved_views`, `console_list_columns`).
- **The host page is one summary route plus existing cards.**
  - `GET /v1/hosts/{id}/summary` returns everything above the fold. Each section is present only when the viewer holds its permission on this host.
  - Cards that already have their own routes keep them: rule sets, hardening, labels.
  - Full lists are today's tables, reached with a host filter.
- **The web gets shared components** in `web/src/ui/list/` and `web/src/ui/detail/`. Hosts is their first user.

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres, `platform-store` migrations;
- React and TypeScript web, with the in-browser demo server;
- vitest and Playwright.

**Spec:** `docs/specs/2026-10-16-roles-permissions-design.md` §6, §10.1, §10.2, §10.3 (shared pieces and the server rules), §13 and §15. Approved screens: `docs/specs/rbac-ui/approved.md`, the shared layout and screens 16 and 17.

**Base:** `origin/main` dbaeb1f (steps 1–3 merged). Branch `hosts-pages`, worktree `openvibes-platform-hosts`.

## Global Constraints

**List (§10.1)**
- **Search** covers the host name and IP address.
- **Filters** all combine, and each value shows how many hosts it matches:
  - Status (online/offline);
  - OS family;
  - Group;
  - Label;
  - Problems: has critical, has open alarms, none open;
  - Agent: older than the latest release, or latest. This comes from the version check of #285, and "unknown" matches neither.
- **Filters live in the URL,** so a view can be bookmarked.
- **Save view** stores a named filter set for the person (`console_saved_views`, per user, keyed by page).
- **Columns:** Host and IP; OS (distribution and family); Groups (two, then "+n"); Labels; Open problems; Last heartbeat and online/offline; Agent version (amber when older than the latest release).
  - Columns can be hidden, and the choice is remembered per user and page.
- **Paging is server-side,** so the list stays fast at large fleets. Counts come from the same filtered query, so the numbers always agree.
- **The summary line** reads "9 online · 4 with an older agent · 4 with critical vulnerabilities". Clicking a host opens its page.
- **The FilterBar** has search and filter chips. A chosen value becomes a chip with ×. On the right are Clear all, Save view and Columns.

**Host page (§10.2)**
- **Route:** `/hosts/{agent_id}` replaces the side panel and its tabs. Everything the panel showed is kept.
- **Header:**
  - an OS badge, the name and the status;
  - a line with agent ID · OS · IP · agent version · heartbeat · enrolled;
  - actions: Compare, Export, Add to case, Ask about this, and ⋯ (Revoke).
- **Tiles,** one number each: open alarms, compliance failing, vulnerabilities and software. Each leads to its full list filtered to the host.
- **Left column:**
  - Details;
  - Protection (threat alarms, hardening, last test);
  - Rule sets;
  - Groups and labels, with labels editable with `hosts.label`;
  - Certificates.
- **Right column:**
  - the top three open alarms, vulnerabilities and failing checks, each with "Show all n";
  - a software, ports and services summary.
- **Permissions:** each card and action appears only with its permission on this host.

**Server (§10.3)**
- **List counts:** the list route accepts its page's filters. It returns the rows, the total, and the count for every value of every filter with the other filters applied, from the same query.
- **Detail summary:** one route returning everything above the fold.
- **Scoping:** all of it is scoped by §6. Counts never include hosts the viewer cannot see.
- **Saved views:** `GET/POST/DELETE /saved-views`.

**Project rules**
- Files under 500 lines.
- Every code folder has a README naming its files.
- `docs/components/` pages are updated in the same change.
- The OpenAPI snapshot and the web client are regenerated on any API change.
- The demo server mirrors every route.
- Side panels and their tabs are removed once their page exists, and deep links to a panel redirect to the page.

**Environment (binding for every task)**
- This host is the user's production host and desktop. Never touch its own openvibes services or database. Tests use only `eval "$(scripts/test-db.sh)"`, then stop it.
- Every cargo command runs as `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` under `nice -n 19 ionice -c3`. Run one heavy command at a time.
- Playwright: demo `--workers=4`, live `--workers=2`.
- The web build deletes `web/dist/.gitkeep`. Restore it before committing.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.

## Rulings in this plan (spec amendments, 2026-10-20)

Task 1 writes these into spec §10 as "Plan rulings, 2026-10-20".

1. **Paths:** the list moves from `/agents` to `/hosts`, and the page is `/hosts/{agent_id}`.
   - Old URLs redirect:
     - `/agents?…` → `/hosts?…`, with `status=active` → `online` and `stale` → `offline`;
     - `?open=agent:ID` and `/agents?agent=ID` → `/hosts/ID`.
   - Every `nav.open({kind:"agent"})` goes to the page.
   - The assistant's citation links point at `/hosts/{id}`.
2. **Status values:** online, offline, revoked and imported. Today's list shows all four, and the spec's online/offline are the two a person filters by most.
3. **Each filter takes one value,** a single URL parameter. Filters AND together.
4. **Problems:**
   - "has critical" means at least one critical vulnerability;
   - "has open alarms" means at least one open agent alarm;
   - "none open" means no open alarm, no critical vulnerability and no failing compliance check.

   Each problem count is shown only for hosts in the viewer's reach for that kind: `alarms.read`, `vulnerabilities.read` and `compliance.read` respectively. Elsewhere it is "—" and is not counted in that filter.
5. **The group filter** lists groups with at least one host the viewer can see, plus the group currently chosen. It never names a group only on hosts out of reach. The label filter lists the 50 most-used labels on visible hosts, plus the label currently chosen.
6. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50. Order is the chosen sort (host name, heartbeat, agent version or problems, ascending or descending), ties broken by agent ID.
7. **Agent version:**
   - "Older" uses the same rules as today's web check (`olderThan` in `views/lists/rows.ts`): numeric segments compared, a pre-release is older than its release, build metadata is ignored.
   - It is computed in SQL by `console_version_older(v, latest)`, which returns null for unknown. Its Rust twin is tested against the same table.
   - The latest version is the update checker's `latest_agent_version`. When that is unknown, both values count 0 and the column has no amber.
8. **Saved views and columns:**
   - A saved view stores the URL query (at most 1000 characters) under a name (1–60 characters, unique per person and page regardless of case), at most 50 per person and page.
   - Hidden columns are stored per person and page, and the Host column cannot be hidden.
   - The routes are `GET/POST/DELETE /v1/saved-views` and `GET/PUT /v1/list-columns/{page}`. They need a signed-in browser session; writes check CSRF.
   - Pages are a fixed list in code; `hosts` is the first.
   - Views saved in the browser under `openvibes.v2.views./agents` are imported once into the server and then removed from the browser.
9. **Full lists from the host page:**
   - Open alarms, Compliance failing and Vulnerabilities link to `/alarms?host=ID`, `/compliance?host=ID` and `/vulnerabilities?host=ID`. Those views gain a `host` filter shown as a removable chip with the host name, and their APIs already accept it.
   - Software, ports and services link to `/hosts/{id}/software`, `/hosts/{id}/ports` and `/hosts/{id}/services`. These sub-pages show today's per-host tables at full width.
10. **The summary route** covers:
    - the header facts;
    - the tiles;
    - Details;
    - Protection's threat alarms and last test;
    - groups and labels;
    - certificates;
    - the top-three lists;
    - the software, ports and services counts.

    The Rule sets card and the hardening row keep their existing components and routes (`/agents/{id}/rule-set-assignments`, `/rule-sets`), which are already permission-aware.
11. **`DetailPage` builds only what screen 17 uses:** the header, four tiles and the two columns. The hosts table with segment chips and the Related card come with step 5's first page that needs them.

## Review Focus

1. **A person reaching only some hosts filters by a group or label.** The counts, total, summary line and the group and label value lists include only hosts they can see, and never name a group whose hosts are all out of reach. Pinned in Task 2 by `counts_and_values_stay_inside_the_scope`.
2. **A person with `hosts.read` but no `alarms.read` on a host.** They see "—" for its open alarms, the "has open alarms" count excludes that host, and the host page shows no alarms tile or card. Pinned in Task 2 by `problem_counts_follow_each_permission`, and in Task 4 by `summary_sections_follow_permissions`.
3. **Two people filter at the same time.** Saved views and hidden columns stay per person: one person never sees or deletes another's view. Pinned in Task 1 by `saved_views_are_per_person`.
4. **An old bookmark or link** (`/agents?status=stale`, `?open=agent:ID`, an assistant citation) lands on the right Hosts view or host page, and the browser history keeps no dead entry. Pinned in Task 6 by the redirect tests, and in Task 7 by `old_panel_links_open_the_page`.
5. **The update check is off, so the latest agent release is unknown.** Agent filter counts are 0, no version is amber, and nothing errors. Pinned in Task 2 by `unknown_latest_version_matches_neither`.

---

### Task 1: Saved views and list columns: store and API

**Files:**
- Create: `migrations/0056_saved_views.sql`. Set `SCHEMA_VERSION = 56` and fix the version assertions in the existing upgrade tests.
- Create: `crates/platform-store/src/saved_views.rs`, and register it.
- Create: `crates/openvibes-console/src/lists/{mod.rs,saved_views.rs,README.md}`. Mount `routes()` with the other areas.
- Modify: `http/openapi.rs`, the snapshot and the web client.
- Modify: the spec §10, pasting "Rulings in this plan" as "Plan rulings, 2026-10-20".
- Docs: `docs/components/platform-store.md`, `openvibes-console.md`, and a new `docs/components/saved-views.md` indexed in `docs/components/README.md`.
- Tests: `crates/platform-store/tests/saved_views.rs` and `crates/openvibes-console/tests/saved_views_http.rs`.

**Interfaces:**
- Produces, in the store:
  - `saved_views::list(client, user_id: &str, page: &str) -> Vec<SavedView { id, page, name, query, created_at }>` (name order, regardless of case);
  - `saved_views::create(client: &mut Client, user_id, page, name, query, now) -> Result<ViewWrite /* Saved(SavedView) | NameTaken | TooMany */, StoreError>`;
  - `saved_views::delete(client, user_id, id) -> Result<bool /*found*/, StoreError>`;
  - `saved_views::hidden_columns(client, user_id, page) -> Vec<String>`;
  - `saved_views::set_hidden_columns(client, user_id, page, &[String], now) -> Result<(), StoreError>`.
- Produces, in the console:
  - `lists::PAGES: &[&str] = &["hosts"]`;
  - `GET /api/v1/saved-views?page=hosts` → `{ items: SavedViewView[] }`;
  - `POST /api/v1/saved-views` `{page, name, query}` → 201;
  - `DELETE /api/v1/saved-views/{id}` → 204;
  - `GET /api/v1/list-columns/{page}` → `{ hidden: string[] }`;
  - `PUT /api/v1/list-columns/{page}` `{hidden}` → 200.

- [ ] **Step 1: Write the failing tests.** Store tests, using `common::migrated()` and two users seeded the way `tests/dashboards*.rs` seeds them:

```rust
// saved_views_are_per_person: alice creates "Prod online" (page hosts); bob lists hosts → empty;
//   bob delete(alice's id) → false and alice still has it; alice delete → true.
// names_are_unique_per_person_and_page_regardless_of_case: "Prod" then "prod" → NameTaken;
//   bob may use "Prod"; alice may use "Prod" on another page.
// at_most_50_views_per_person_and_page: the 51st → TooMany.
// hidden_columns_round_trip: set ["labels","agent"] then get → same; set [] → [].
// deleting_a_person_deletes_their_views (ON DELETE CASCADE).
```

  HTTP tests, using the `common::people::Fx` fixture:
  - GET without a session → 401;
  - `page=nope` → 404 `list_page_not_found`;
  - POST checks:
    - a name of 0 or 61 characters → 422 `invalid_saved_view`, field `name`;
    - a query over 1000 characters → 422, field `query`;
    - a duplicate → 409 `view_name_taken`;
    - the 51st → 409 `too_many_views`.
  - DELETE another person's id → 404 `saved_view_not_found`;
  - PUT columns:
    - with `host` → 422 `invalid_columns` ("The Host column can't be hidden");
    - with an unknown key → 422;
    - with 33 keys → 422;
  - writes without CSRF → 403.

- [ ] **Step 2: Run them to see them fail.**

- [ ] **Step 3: Write the migration** `migrations/0056_saved_views.sql`:

```sql
-- Saved views and hidden list columns, per person and page (roles spec §10).
CREATE TABLE console_saved_views (
    view_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES console_users ON DELETE CASCADE,
    page text NOT NULL CHECK (page ~ '^[a-z][a-z-]{0,31}$'),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 60),
    query text NOT NULL CHECK (length(query) <= 1000),
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX console_saved_views_name_unique
    ON console_saved_views (user_id, page, lower(name));
CREATE TABLE console_list_columns (
    user_id uuid NOT NULL REFERENCES console_users ON DELETE CASCADE,
    page text NOT NULL CHECK (page ~ '^[a-z][a-z-]{0,31}$'),
    hidden text[] NOT NULL CHECK (cardinality(hidden) <= 32),
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (user_id, page)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON console_saved_views, console_list_columns TO "openvibes-console";
```

  If `gen_random_uuid()` is not available in the migrations' Postgres setup, generate the id in Rust as other tables do.

- [ ] **Step 4: Write the store and handlers.**
  - The store's create runs in one transaction: count, then insert. A violation of `console_saved_views_name_unique` is mapped to `NameTaken`.
  - Handlers use `session_user(&state, &headers, mutating)`, as the dashboards handlers do.
  - The page key is validated against `lists::PAGES`.
  - Column keys are validated against a per-page list. For `hosts`: `os`, `groups`, `labels`, `problems`, `heartbeat`, `agent`.

- [ ] **Step 5: Run the tests until they pass.** Then regenerate OpenAPI and the client, and run `api_contract`.

- [ ] **Step 6: Commit:** `lists: saved views and hidden columns per person and page`.

---

### Task 2: The hosts list query: filters, counts, summary, scope

**Files:**
- Create: `migrations/0057_version_order.sql`, containing `console_version_older(v text, latest text) RETURNS boolean`. Set `SCHEMA_VERSION = 57`.
- Create: `crates/platform-store/src/host_list.rs` (the query and its types), and `host_list_counts.rs` if `host_list.rs` passes 450 lines.
- Create: `crates/platform-store/src/version_order.rs`, the Rust twin of the SQL function, used by the tests and the demo port.
- Tests: `crates/platform-store/tests/host_list.rs` and `version_order.rs`.
- Docs: `docs/components/platform-store.md`, plus `console-read.md` for scope and performance.

**Interfaces:**
- Produces:

```rust
pub struct HostQuery<'a> {
    pub q: Option<&'a str>,                 // host name (contains, case-insensitive) or IP (prefix of host(last_address), or CIDR containment when q parses as one)
    pub status: Option<HostStatus>,         // Online | Offline | Revoked | Imported
    pub os_family: Option<&'a str>,         // "linux" | "windows"
    pub group: Option<&'a str>,             // asset_group_id (uuid text)
    pub label: Option<&'a str>,
    pub problems: Option<Problems>,         // Critical | OpenAlarms | NoneOpen
    pub agent: Option<AgentAge>,            // Older | Latest
    pub sort: HostSort, pub descending: bool, // Host | Heartbeat | Version | Problems
    pub offset: i64, pub limit: i64,
}
pub struct HostScopes<'a> { pub hosts: &'a AgentScope, pub alarms: Option<&'a AgentScope>,
    pub vulnerabilities: Option<&'a AgentScope>, pub compliance: Option<&'a AgentScope> }
pub struct HostRow { pub agent_id: String, pub hostname: Option<String>, pub address: Option<String>,
    pub os_id: Option<String>, pub os_version: Option<String>, pub distribution: Option<String> /*display*/,
    pub os_family: Option<String>, pub status: HostStatus, pub last_seen_at: Option<DateTime<Utc>>,
    pub groups: Vec<(String, String, GroupKind)> /*first 2 by name*/, pub group_count: i64,
    pub labels: Vec<String>, pub open_alarms: Option<i64>, pub critical: Option<i64>, pub failing: Option<i64>,
    pub scanner_version: Option<String>, pub agent_older: Option<bool> }
pub struct HostCounts { pub status: Vec<(HostStatus, i64)>, pub os_family: Vec<(String, i64)>,
    pub groups: Vec<(String, String, GroupKind, i64)>, pub labels: Vec<(String, i64)>,
    pub problems: Vec<(Problems, i64)>, pub agent: Vec<(AgentAge, i64)> }
pub struct HostSummaryLine { pub online: i64, pub older_agent: i64, pub critical: i64 }
pub struct HostListPage { pub rows: Vec<HostRow>, pub total: i64, pub counts: HostCounts, pub summary: HostSummaryLine }
pub async fn hosts(client: &Client, query: &HostQuery<'_>, scopes: &HostScopes<'_>, latest: Option<&str>, now: DateTime<Utc>) -> Result<HostListPage, StoreError>;
```

- [ ] **Step 1: Write the failing tests** in `tests/host_list.rs`. Seed with `common` helpers: 8 agents, mixed OS, hostnames, addresses, a rule group and a manual group, labels, open alarms, critical vulnerabilities (`host_vulnerability_counts`), failing `current_findings`, versions 0.4.1 and 0.4.2, one revoked and one imported.
  - `search_matches_name_and_address`: q `web` finds web-01 and web-02; q `10.0.1.` finds the two hosts in 10.0.1.x; q `10.0.0.0/16` finds by containment; q `WEB-01` matches regardless of case.
  - `filters_combine_and_counts_apply_the_other_filters`: with `os_family=linux` and `status=online`, the status counts are linux hosts by status, the os counts are online hosts by family, and the total equals the row count when below the limit.
  - `counts_and_values_stay_inside_the_scope` (Review Focus 1): a scope holding one group gives totals, counts and summary of its hosts only. The group values never list a group whose hosts are all outside, and the label values never list a label found only outside.
  - `problem_counts_follow_each_permission` (Review Focus 2): with `alarms` None, `open_alarms` is None on every row, the OpenAlarms count is 0, and NoneOpen still counts hosts using the other two kinds. With `alarms` limited to group A, hosts in B show None.
  - `agent_age_uses_the_latest_release`: latest `0.4.2` gives 0.4.1 Older, 0.4.2 Latest, 0.4.2-rc1 Older, `0.4.2+build` Latest, and a missing version neither.
  - `unknown_latest_version_matches_neither` (Review Focus 5): latest None gives `agent_older` None everywhere, Older and Latest both 0, and the Agent filter matches nothing.
  - `paging_and_sort_are_stable`: limit 3 with offsets 0, 3 and 6 covers every host once in host-name order. Descending, heartbeat and problems sorts are checked with agent ID as the tie-break.
  - `groups_column_shows_two_and_a_count`: a host in 3 groups gives 2 names, alphabetically, and `group_count` 3.

  In `tests/version_order.rs`, one table runs through both the SQL function and the Rust twin with the same answers: `0.4.1 < 0.4.2`, `0.10.0 > 0.9.9`, `1.0.0-rc1 < 1.0.0`, `1.0.0+abc = 1.0.0`, and `abc` or empty gives null.

- [ ] **Step 2: Run them to see them fail.**

- [ ] **Step 3: Write migration 57** with `console_version_older`, `LANGUAGE sql IMMUTABLE`:
  1. Strip `+…`.
  2. Split off `-pre`.
  3. Turn the numeric segments into `int[]` with `string_to_array` and `regexp_match` guards. Any non-numeric segment, or an empty input, returns null.
  4. Compare the arrays, padding the shorter one with zeros.
  5. When the arrays are equal, the side with a pre-release is older.

  Grant EXECUTE as the other functions are (PUBLIC by default).

- [ ] **Step 4: Write the query.** It is one statement built from these parts, each under 80 lines of SQL with a comment. Bind every parameter: never interpolate user input.
  - **CTE `base`:** visible agents (`agent_visibility` with the hosts scope) matched by `q`. It computes:
    - `status`, the same CASE as `agents_in_scope` with `OFFLINE_AFTER_MINUTES`;
    - `os_family`;
    - `older := console_version_older(scanner_version, $latest)`;
    - `open_alarms`, `critical` and `failing`, each `CASE WHEN {visibility for that scope} THEN (count…) END` (null when that scope is None);
    - the facet flags.
  - **CTE `filtered`:** `base` with every chosen filter applied.
    - The group filter uses `console_host_in_group(agent_id, $group::uuid)`.
    - The label filter uses `EXISTS (… console_host_labels …)`.
  - **Rows:** `SELECT … FROM filtered ORDER BY {sort} {dir}, agent_id LIMIT $limit OFFSET $offset`. They carry the first two groups by name, `group_count` and the labels, using the same subqueries as `host_groups::hosts()`.
  - **Total and summary:** `count(*)`, `count(*) FILTER (WHERE status='online')`, `… older`, `… critical>0` over `filtered`.
  - **Counts:** for each facet, group `base` with every other chosen filter applied and that facet's own filter dropped. Write one helper that builds the "all filters except X" predicate, so each facet reuses it.
    - The group values come from a lateral join on `console_asset_groups` restricted to groups where `console_host_in_group` holds for at least one row. Mark it with a `ponytail:` comment, since it evaluates per host and group, with the step-2 measurement as the ceiling.
    - The label values are limited to the top 50, plus the chosen one.

- [ ] **Step 5: Write a timing test,** `#[ignore]`d like the existing 50k-agent one in `console_read.rs`. Seed 20,000 agents with 20 groups. Record the time in `console-read.md`, and keep it under 1 s on this host with the default filters.

- [ ] **Step 6: Run the tests until they pass,** then the platform-store suite. **Commit:** `store: the hosts list with filters, per-value counts and a summary, inside the viewer's scope`.

---

### Task 3: `GET /v1/hosts`

**Files:**
- Create: `crates/openvibes-console/src/hosts/list.rs` and `hosts/list_types.rs`.
- Modify: `hosts/mod.rs` (the route) and `about.rs`. Expose `pub(crate) fn latest_agent_version(state) -> Option<String>`, the cached value `about_update` already uses, with no network call on the request path.
- Modify: OpenAPI, the snapshot and the client.
- Tests: `crates/openvibes-console/tests/hosts_list_http.rs`.
- Docs: `openvibes-console.md`.

**Interfaces:**
- `GET /api/v1/hosts?q=&status=online|offline|revoked|imported&os=linux|windows&group=<uuid>&label=&problems=critical|alarms|none&agent=older|latest&sort=host|heartbeat|version|problems&dir=asc|desc&offset=&limit=`. The query uses `deny_unknown_fields`.
- The answer is `HostListView`:
  - `items: [HostRowView { id, hostname, address, os: {id, version, distribution, family}, status, last_seen_at, groups: [{id, name, kind}], group_count, labels, problems: {open_alarms?, critical?, failing?}, agent: {version?, older?} }]`;
  - `total`;
  - `counts`:

    ```
    { status: [{value, count}], os: [...],
      group: [{value, name, kind, count}],
      label: [{value, count}],
      problems: [...], agent: [...] }
    ```
  - `summary: {online, older_agent, critical}`;
  - `latest_agent_version?`;
  - `generated_at`.
- Needs `hosts.read`. The alarms, vulnerabilities and compliance scopes are computed from the caller's capabilities with `scope_of`, so a missing permission gives None. Bearer tokens may read.
- Invalid values give 400 `invalid_query` naming the parameter. A `group` that is not a uuid gives 400; an unknown group gives an empty result. `limit` must be 1..=100 and `offset` 0..=100000.

- [ ] **Step 1: Write the failing tests:**
  - every parameter's validation;
  - the shape and counts for an admin;
  - a scoped team lead sees only their hosts (Review Focus 1, over HTTP);
  - a role without `alarms.read` gets null `open_alarms`;
  - `latest_agent_version` null when the checker is off, as in tests.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement.** Map the store types to the views, and map `StoreError` to 503.
- [ ] **Step 4: Run the tests until they pass.** Regenerate OpenAPI and the client, then run `api_contract` and `cargo test -p openvibes-console`.
- [ ] **Step 5: Commit:** `console: GET /v1/hosts with filters, counts and a summary line`.

---

### Task 4: `GET /v1/hosts/{id}/summary`

**Files:**
- Create: `crates/platform-store/src/host_summary.rs`.
- Create: `crates/openvibes-console/src/hosts/summary.rs` and `summary_types.rs`.
- Tests: `crates/platform-store/tests/host_summary.rs` and `crates/openvibes-console/tests/host_summary_http.rs`.
- Docs: `openvibes-console.md` and `platform-store.md`.

**Interfaces:**
- `GET /api/v1/hosts/{agent_id}/summary` answers `HostSummaryView`:
  - **`host`:** id, hostname, status, address, os `{id, version, distribution, family}`, running_kernel, scanner_version, agent_older, enrolled_at, revoked_at, last_seen_at, inventory_at, capabilities.
  - **`tiles`:** `{ open_alarms?, compliance_failing?, vulnerabilities?, software? }`. Each is null without its permission on this host.
    - `software` and the inventory need only `hosts.read`.
    - `vulnerabilities` counts open advisories on the host.
  - **`protection`:** `{ threat_alarms: AgentAlarmsView?, last_test: {alarm_at?, finding_at?} }`.
  - **`groups`:** `[{id, name, kind}]` and **`labels`:** `string[]`, from `host_labels::host_labels`.
  - **`certificates`:** the newest 5, plus `certificate_count`.
  - **Top-three lists,** each `null` without its permission:
    - `top_alarms: { items: [{id, rule_id, message, severity, last_seen}], total }`;
    - `top_vulnerabilities: { items: [{advisory, severity, kev}], total }`;
    - `top_failing: { items: [{rule_set_id, rule_id, severity, message}], total }`.
  - **`inventory`:** `{ packages, listening_ports, exposed_ports, services }`.
  - **`can`:** `{ label, revoke, export, add_to_case, ask }`. These are booleans for this host, from the caller's capabilities and their scopes.
- **404 `host_not_found`** when the host is outside `hosts.read`, the same as a missing host.
- **The store** has `host_summary::summary(client, agent_id, scopes: &HostScopes, latest, now) -> Result<Option<HostSummary>, StoreError>`. It runs a handful of small queries: reuse `PROBLEMS`, `latest_findings_in_scope` and the vulnerability list query with a host filter, plus the packages, ports and services counts.

- [ ] **Step 1: Write the failing tests:**
  - `summary_sections_follow_permissions` (Review Focus 2): without `alarms.read` on this host, `tiles.open_alarms` and `top_alarms` are null while the rest is present. Without `compliance.read`, the failing tile and list are null.
  - Out-of-reach and missing hosts are the same 404.
  - A revoked host still answers, and `can.revoke` is false.
  - The top-three order is newest and most severe first, and `total` counts all.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests until they pass.** Regenerate OpenAPI and the client.
- [ ] **Step 5: Commit:** `console: one summary route for the host page`.

---

### Task 5: Shared list and detail pieces in the web, with the demo

**Files:**
- Create in `web/src/ui/list/`:
  - `FilterBar.tsx`: the search box (URL `q`, "/" focuses it) and filter chips. Each chip opens a menu of values with counts; a chosen value becomes a chip with ×. On the right sit Clear all, Save view and Columns.
  - `SummaryLine.tsx`: joins `parts` with " · " and skips zero parts when asked.
  - `ColumnsMenu.tsx`: checkboxes, with the Host column disabled. It saves through PUT.
  - `savedViews.ts`: hooks `useSavedViews(page)` and `useHiddenColumns(page)`, and `importBrowserViews(page, legacyKey, mapQuery)`, which imports once and then removes the key.
  - `filters.ts`: the `ListFilter` type (`{ param, label, values: {value, label, count}[] }`) and URL helpers.
  - `README.md`.
- Create in `web/src/ui/detail/`:
  - `DetailPage.tsx`: header (icon, title, status, facts line, actions), four tiles, and left and right columns. It reuses `Card` from `views/admin/people/PersonPage.tsx`, or moves `Card` here and updates its importers.
  - `Tile.tsx`;
  - `README.md`.
- Create: `web/src/demo/routes/lists.ts`, with saved views and columns mirroring Task 1 (codes, caps, per-persona storage validated on load like the Task 2 settings route of step 3).
- Tests: `FilterBar.test.tsx`, `savedViews.test.ts`, `DetailPage.test.tsx`, and demo `server.test.ts` cases.
- Docs: `console-web.md`, with a "Shared list and detail pieces" section.

- [ ] **Step 1: Write the failing tests:**
  - **FilterBar:**
    - it renders chips from `ListFilter[]` with counts;
    - choosing a value sets the URL parameter and shows "Status: Online ×";
    - × clears it;
    - Clear all clears every filter parameter but keeps `sort` and `dir`;
    - Save view appears only with filters set and posts `{page, name, query}`;
    - a 409 shows "You already have a view with that name";
    - saved views are listed, applying one replaces the filters, and deleting one asks first;
    - the Columns menu disables Host and saves on change.
  - **`importBrowserViews`:** imports and maps (`status=active` → `online`), removes the key, and does nothing on a second run.
  - **DetailPage:** it renders its slots, tiles are links with an accessible name ("Open alarms: 3"), and empty slots render nothing.
  - **Accessibility basics:** chip menus are buttons with `aria-haspopup` and `aria-expanded`, the value menu is a listbox or menu with keyboard support, and focus returns to the chip.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement.** Follow the console's existing CSS tokens and classes, and add classes to `shell.css` (or the list stylesheet) the way step 1–3 pages did.
- [ ] **Step 4: Write the demo routes and their vitests.**
- [ ] **Step 5: Run vitest, tsc, eslint and build.** Restore `.gitkeep`. **Commit:** `console web: shared FilterBar, SummaryLine, columns, saved views and DetailPage`.

---

### Task 6: The Hosts list (screen 16), with the demo and redirects

**Files:**
- Rewrite: `web/src/views/investigate/Agents.tsx` into `Hosts.tsx`, using FilterBar, SummaryLine and server paging (DataTable with a page control). Update the registry with path `/hosts`, label "Hosts", keys "g a", and prefix `/hosts/` for Task 7.
- Modify: `web/src/app/location.ts` and `nav.ts`. Redirect `/agents?…` to `/hosts?…` with replaceState, mapping `status` values. Add a `location.test.ts` case for each redirect.
- Modify: `web/src/views/lists/filters.ts` and `rows.ts`, removing the client-side agents filtering that the server now does. Keep the dashboard List widget working: it may keep using `/api/v1/agents`.
- Create: `web/src/demo/routes/hostList.ts`, mirroring `GET /api/v1/hosts`. The demo needs to know:
  - the same filters, counts and summary;
  - scope through `visible`, and per-permission problem counts through `reaches`;
  - groups through `demo/hostGroups.ts` and labels from `data.labels`;
  - versions through a TS port of `version_order` with the same table test;
  - each agent gets demo `address`, open alarm and critical counts from the demo data;
  - `latest_agent_version` comes from the demo's about/update.
- Modify: the demo e2e specs that use `/agents` (`smoke`, `assets`, `phone`, `rule-set-assignment`). Create `web/e2e/demo/hosts.spec.ts`.
- Docs: `console-web.md`.

- [ ] **Step 1: Write the failing tests.** Unit tests:
  - the Hosts view renders rows from a `HostListView` fixture;
  - the Groups cell shows two names and "+1";
  - an older agent version is amber with a title;
  - an unknown latest version shows no amber;
  - a problem of null shows "—";
  - hidden columns are not rendered;
  - the summary line reads "9 online · 4 with an older agent · 4 with critical vulnerabilities".

  `location.test.ts`:
  - `/agents?status=stale&q=web` → `/hosts?status=offline&q=web`;
  - `/agents?open=agent:agent-00005` → `/hosts/agent-00005`;
  - `/agents?agent=agent-00005` → `/hosts/agent-00005`.

  Demo e2e `hosts.spec.ts`:
  - filter by OS, then Group, and see the counts change and the URL hold both;
  - reload and keep them;
  - save a view, clear all, apply the view;
  - hide the Labels column, reload, and it stays hidden;
  - page to the second page;
  - axe.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement.** Run `importBrowserViews("hosts", "openvibes.v2.views./agents", map)` once on mount. Clicking a row opens `/hosts/{id}`, which Task 7 builds. Until then the route shows the old panel content, so nothing is unreachable between tasks.
- [ ] **Step 4: Run vitest, tsc, eslint and build, then the changed demo specs, then the full demo e2e** (`--workers=4`). Restore `.gitkeep`.
- [ ] **Step 5: Commit:** `console web: the Hosts list with filters, counts, saved views and columns (screen 16)`.

---

### Task 7: The host page (screen 17) and host sub-pages; the side panel goes

**Files:**
- Create: `web/src/views/investigate/host/HostPage.tsx` (the DetailPage with header, tiles and cards), `HostCards.tsx` (Details, Protection, Certificates and the top-three cards), `HostSubPage.tsx` (`/hosts/{id}/software|ports|services`, reusing `SoftwareTab` and `HostServicesTab`), and `README.md`.
- Reuse, moving them out of `panels/hosts/` where that keeps imports sane:
  - `HostLabels` (`LabelsCard`), `HostRuleSets`, `HardeningRows`, `ThreatAlarms` and `LastTestSection`;
  - `HostExport`, `AddToCase` and the Compare action (it opens the compare panel as today);
  - "Ask about this" (`assistant.askAbout`);
  - Revoke under ⋯, with `Confirm` and a reason.
- Remove: the `agent` panel. `AgentPanel.tsx` and its tabs go, and the registry panel kind `agent` is deleted.
  - `nav.open({kind:"agent", id})` becomes `nav.view("/hosts/" + id)`. Do this in `nav.ts`, so all ~16 call sites follow without edits.
  - `ObjectLink` hrefs `?open=agent:ID` are redirected by Task 6's `location.ts`.
- Modify: the Alarms, Compliance and Vulnerabilities views. Each gains a `host` URL filter, shown as a removable chip "Host: web-01 ×", passed to their API (`agent_id` for alarms and compliance, `host` for vulnerabilities).
- Modify: `crates/openvibes-console/src/assistant/types.rs:79` (citation links → `/hosts/{id}`), and its test.
- Create: `web/src/demo/routes/hostSummary.ts`, mirroring Task 4 with the same permission rules.
- Modify: the demo e2e specs that used the host panel or its tabs (`assets.spec.ts` tabs, Compare and Export; `smoke.spec.ts` host panel, palette and assistant citation; `rule-set-assignment.spec.ts`). Move them to the page and sub-pages. Create `web/e2e/demo/host-page.spec.ts`.
- Docs: `console-web.md` (replace the "Host page" side-panel text) and the folder READMEs.

- [ ] **Step 1: Write the failing tests.** Unit tests:
  - the HostPage renders the header facts line "agent-00005 · Debian 12 · 10.0.1.5 · 0.4.2 · 2 min ago · enrolled 3 Oct";
  - the four tiles link to `/alarms?host=…`, `/compliance?host=…`, `/vulnerabilities?host=…` and `/hosts/{id}/software`;
  - each card and action is absent when its section is null or its `can` flag is false;
  - "Show all 12" links to the filtered list.

  Demo e2e `host-page.spec.ts`:
  - `old_panel_links_open_the_page` (Review Focus 4): open `/agents?open=agent%3Aagent-00005`, land on `/hosts/agent-00005`, and Back does not bounce to the dead URL;
  - the tiles navigate, and the host chip on Alarms removes the filter;
  - add and remove a label;
  - Revoke under ⋯ asks for a reason;
  - a viewer without `alarms.read` sees no alarms tile;
  - the software sub-page filters;
  - axe on the page, in light and dark.
- [ ] **Step 2: Run them to see them fail.**
- [ ] **Step 3: Implement.** Delete the panel last, after every call site goes through `nav.open`'s redirect, and grep for `"agent"` panel uses to prove it.
- [ ] **Step 4: Run vitest, tsc, eslint and build, then the changed specs, then the full demo e2e.** Run `cargo test -p openvibes-console` for the assistant link change. Restore `.gitkeep`.
- [ ] **Step 5: Commit:** `console web: the host page and its sub-pages replace the host panel (screen 17)`.

---

### Task 8: Live e2e, docs and the gate

**Files:**
- Modify: `web/e2e/live/console.spec.ts` (`/agents` → `/hosts`), `teams.spec.ts` (members land on `/hosts`), and a new live journey in `web/e2e/live/hosts.spec.ts`:
  1. A team lead sees only their team's hosts, and the counts agree with the rows.
  2. They save a view and it reloads.
  3. They open a host page; it has no Revoke without `hosts.revoke`.
  4. An admin's counts include both teams.
- Docs: one pass over every page these tasks touched. Add an "Upgrading" note in `console-web.md`: Hosts moved to `/hosts`, old links redirect, and views saved in the browser are imported to the person's account the first time they open Hosts.

- [ ] **Step 1: Write the live journey and run it** (`--workers=2`, chromium and firefox).
- [ ] **Step 2: Run the full local gate** (`~/Projects/OpenVIBES/testing.md` §2, including the browser items) once. Expected: all green. WebKit can't launch on this host, a known limitation.
- [ ] **Step 3: Commit.** No push and no PR; the controller opens it.

---

## Self-review notes

- **Spec coverage:**
  - §10.1 search, filters, counts, URL, Save view, columns, paging and summary → Tasks 1, 2, 3, 5 and 6;
  - §10.2 header, tiles, both columns, permissions and full lists → Tasks 4 and 7;
  - §10.3 shared FilterBar, SummaryLine, DetailPage and saved views → Task 5 (the bulk bar is unchanged in step 4; the hosts list has no bulk actions);
  - list counts and scoping → Tasks 2 and 3;
  - summary route → Task 4;
  - panels removed and deep links redirected → Tasks 6 and 7;
  - §13 routes → Tasks 1, 3 and 4;
  - §15 e2e items "Hosts filters and the URL" and "the host page" → Tasks 6, 7 and 8.
- **Not here:**
  - the other list pages (step 5);
  - the hosts table with segment chips and the Related card in DetailPage (step 5);
  - dashboard sharing (step 6);
  - pictures (step 7).
- **Interfaces across tasks:**
  - `lists::PAGES` and the column keys (Task 1) are used by Tasks 5 and 6;
  - `HostQuery` and `HostScopes` (Task 2) are used by Tasks 3 and 4;
  - `latest_agent_version(state)` (Task 3) is used by Task 4;
  - the redirects (Task 6) are relied on by Task 7's panel removal.
- **Interim state:** after Task 6 a row opens `/hosts/{id}`, where Task 7 builds the page; until Task 7, Task 6 keeps the old panel content reachable at that route. The full demo e2e is green after Tasks 5, 6 and 7. The live e2e is touched only in Task 8.
