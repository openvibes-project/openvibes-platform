# The Ports list, a port's page and the change log: implementation plan (step 5e)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the fifth page of step 5 of the roles spec:
- the Ports list (screen 19), one row per port (protocol and number), with server-side filters, per-value counts, saved views, remembered columns and a summary line;
- a port's page, `/ports/{port}/{protocol}` (screen 20), which replaces the port side panel;
- the shared change log (user decision 2): what appeared and went away on each host, for packages, listeners and services, written at ingest. Only Ports reads it in this step.

**Architecture:**
- **The list follows steps 5a–5d.** One store query (`port_list`) groups the listeners of hosts in reach by `(protocol, port)`, one host counted once. It returns rows, the total, the per-value counts and the summary, all scoped by §6.
- **The change log is a diff at ingest.** The three writers that already replace a host's rows (`host_services::replace`, `inventory::replace`, `inventory::apply_changes`) compare the old and new keys inside their transaction and insert only the differences. An unchanged digest returns before any write, as today, so a report with no changes writes nothing. A host's first report is its baseline. No agent or protocol change.
- **Usual names and "Needs a look"** come from a fixed port map in code (`port_names.rs`), as the spec asks ("a fixed list of plain rules in code").
- **One summary route** (`GET /v1/ports/{protocol}/{port}/summary`) returns everything above the fold. The hosts table is paged (`…/hosts`).
- **Add to case** adds a fleet-wide `port` item, like `software` (user decision 4).

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres, `platform-store`, `openvibes-ingest`, `openvibes-admin`;
- React and TypeScript web, with the demo server;
- vitest and Playwright.

**Spec:**
- `docs/specs/2026-10-16-roles-permissions-design.md`: §6 (scope), §10.3 (the shared pattern, routes, server rules, "This week" and "Needs a look"), §16 (order), and the step 5a–5d plan rulings.
- Approved screens: `docs/specs/rbac-ui/approved.md`, screens 19 and 20. Mockup: `docs/specs/rbac-ui/gen.py` (`PORTSUI`, `portsList`, `portPage`, lines ~1009–1127). Add to case on Services and Software (screens 22, 24) is the same header button.
- Scope brief: `~/.cache/openvibes-scratch/5e-scope.md`.
- Port owners: workspace `decisions.md`, 2026-10-01 and 2026-10-09 (owners are opt-in; the service is known without privilege, the program often not).
- Pattern: `docs/superpowers/plans/2026-10-24-roles-5c-compliance-pages.md` and `2026-10-25-roles-5d-cases-pages.md`.

**Base:** `origin/main` 649a91b (steps 1–5d merged). Branch `ports-pages`, worktree `openvibes-platform-ports`.

## Questions for the user

None. The calls the spec, the screens and the decisions leave open are rulings below.

## User decision (2026-10-25, before this plan)

1. Three PRs in dependency order: 5e Ports (this plan), 5f Services, 5g Software.
2. A new change log written at ingest for packages, listeners and services (appeared / went away), no agent change, first report is the baseline (no "appeared" flood on first report or on upgrade), 90-day retention. 5e builds it for all three kinds (Services and Software reuse it later) but only Ports reads it in this step.
3. (For 5g; note only) A Software row is the package name across managers.
4. Add to case on the port and service pages adds fleet-wide items of new kinds `port` (and later `service`), like `software`: no outcome, and they do not make a case visible on their own ("hosts decide"). 5e adds `port`.

## Global Constraints

**List (screen 19)**
- **Filters:** Exposure (exposed somewhere / local only), Protocol (TCP / UDP), Group, Service, Changes (new this week / needs a look), plus the Host chip from step 4.
- **Columns:**
  - Port, with its usual name ("Not a well-known port" when none);
  - Hosts ("5 of 11");
  - Exposed on ("All 5", "2 of 5", or "Local only");
  - Services;
  - Groups (two, then "+n");
  - This week ("+1 host this week" / "No change");
  - Needs a look (for example "Database reachable from the network", "New this week, not a usual port").
- **Summary:** "n exposed on some host · n with new hosts this week · n need a look · from n hosts' last reports".
- **Search:** "Search port, name or service…".
- **No bulk bar** (gen.py `portsList` has none; no row checkboxes).
- **Shared pattern (§10.3):** `FilterBar` (search, chips with per-value counts, filters in the URL, Clear all, Save view, Columns), `SummaryLine`, rows that open a page.

**Page (screen 20)**
- **Header:** the protocol badge, `22/tcp` and its usual name; the facts line "Listening on n of m hosts · exposed on n · services · first seen …"; buttons Export, Add to case, Ask about this.
- **Tiles:** hosts listening (of m hosts), exposed (reachable from the network), local only (bound to loopback), this week.
- **Left column:** Details (protocol, usual use, services, programs, first seen); By group, with bars; Recent changes.
- **Right column:** Hosts, with All / Exposed / Local only; each row shows the host, where it is bound, the service and program, its exposure and last report. Related: compliance checks, vulnerabilities and alarms.

**Server and scope:** `hosts.read` for everything (no new permission); Export needs `hosts.export`. Everything is scoped by §6; counts never include hosts the viewer cannot see; revoked hosts are left out, as today. A card or action is shown only with its permission (Related compliance needs `compliance.read`, vulnerabilities `vulnerabilities.read`, alarms `alarms.read`; Add to case `cases.write`; Ask `assistant.use`).

**Port owners are opt-in.** Where a host's report is `services_owners = 'partial'` and an owner is null, the page and list say "not collected", never a blank cell.

**Ingest is the hot path.** A report whose digest is unchanged writes no change-log row and no extra statement. A changed report writes one extra `INSERT … SELECT FROM unnest` per kind, only when there is a difference.

**Project rules**
- Files under 500 lines.
- Every code folder has a README.
- `docs/components/` pages are updated in the same change.
- The OpenAPI snapshot and the client are regenerated.
- The demo mirrors every route.
- Nothing users relied on may silently disappear: compare with the port panel (hosts per bound address, owner, last seen) and today's Ports list (`exposed` chip, search by port or service).

**Environment (binding for every task)**
- This host is the user's production host. Never touch its own openvibes services or its system PostgreSQL (`/var/lib/pgsql`). Tests use only `eval "$(scripts/test-db.sh)"`, then stop it.
- Cargo commands run with `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target-ports CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` under `nice -n 19 ionice -c3`. This is a separate target dir for this worktree: shared dirs overwrite other worktrees' rlibs. Run one heavy command at a time.
- Playwright: demo `--workers=4`, live `--workers=2` with `--project=chromium --project=firefox`.
- Restore `web/dist/.gitkeep` before committing.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.
- **One implementer at a time** in this worktree.

## Rulings in this plan (spec amendments, 2026-10-25)

Task 1 writes the user decision and these rulings into spec §10.3 as "Plan rulings, 2026-10-25 (step 5e)". Each: what, why, cost if wrong.

1. **Order and size.** §16's "Software, Services and Ports" becomes Ports, Services, Software (user decision 1). The change log lands here because Ports is first. *Why:* services link ports, software links services. *Cost if wrong:* none in code; only the spec's order line.
2. **The change log table** (migration 0065): `change_log (at timestamptz, agent_id text REFERENCES agents ON DELETE CASCADE, kind text CHECK IN ('package','listener','service'), key text, change text CHECK IN ('appeared','went_away','exposed','local'), detail jsonb)`. Keys: listener `tcp/22` (the API's spelling); service the unit; package the name, with `detail = {manager, version, arch}` where `version` is `epoch:version-release`. Indexes `(kind, key, at DESC)` (a page) and `(kind, at)` (lists, pruning). A one-row `change_log_start (at)` set by the migration. *Why:* one table serves all three kinds and the three pages; package key = name matches decision 3. *Cost if wrong:* a rename or a key migration in 5g.
3. **What counts as a change.**
   - **Listener:** per host, the set of `(protocol, port)`; exposed = any bound address is non-loopback. A port that appears or goes away writes `appeared` / `went_away`. A port that stays but flips exposure writes `exposed` or `local`. Addresses alone changing (0.0.0.0 → ::) write nothing. *Why:* screen 20's Recent changes shows "db-02 now listens only locally"; decision 2's appeared/went-away cannot say that. *Cost if wrong:* one CHECK value and one branch to drop.
   - **Service:** the set of units; process-count, program or user changes write nothing (5f may add more).
   - **Package:** the set of package versions; an upgrade is `went_away` of the old version plus `appeared` of the new, at the same `at` (5g reads the pair as "updated"). *Cost if wrong:* 5g recomputes "updated" differently; no data lost.
4. **Baseline and upgrade.** A host's first report (stored digest null: `services_sha256` / `inventory_sha256`) writes nothing. After the upgrade, existing hosts already have stored rows, so their next report diffs against them: no flood. A P11 resync (full inventory) diffs against the stored rows. *Cost if wrong:* a missed "appeared" on a host's very first report, which decision 2 asks for.
5. **No change, no write.** An unchanged digest returns before any change-log work (today's early return). A changed digest with the same keys (for example a process count) computes the diff and inserts zero rows, with no INSERT statement issued. *Cost if wrong:* ingest load on a 10,000-host fleet.
6. **Retention.** `change_log::prune(client, now)` deletes rows older than 90 days, per kind, from `openvibes-admin maintenance` next to `prune_alarm_hourly`. Partitioning is not needed at the sized volume (`ponytail:` comment naming daily partitions as the upgrade path). *Cost if wrong:* a slower daily delete.
7. **"First seen"** = the earliest of: the earliest `appeared` in reach, and, for each host in reach listening now, `greatest(enrolled_at, floor)`, where `floor = greatest(change_log_start.at, now − 90 days)`. When the result equals `floor`, it shows "Before {floor date}". *Why:* a port seen in a host's baseline report or before the log has no event, and 90-day pruning removes old ones; this never claims a date later than the truth. *Cost if wrong:* a "first seen" that is earlier than needed.
8. **This week** = the last 7 days: hosts in reach with an `appeared` (`added`) and with a `went_away` (`removed`) for this port; exposure flips count in the page's Recent changes, not here. The list cell shows "+n hosts" and "−n hosts"; "No change" when both are 0. The page tile shows the same, or "no host started or stopped".
9. **The port map** (`crates/platform-store/src/port_names.rs`): `pub fn port_info(protocol: &str, port: u16) -> Option<PortInfo>`, `PortInfo { name, usual_use, class: PortClass (Database | RemoteAdmin | Other), area: Option<&'static str>, packages: &'static [&'static str] }`. About 40 well-known ports: at least 21, 22 (SSH, area "SSH", packages `openssh-server`, `openssh`), 23, 25, 53 (tcp, udp), 80, 110, 111, 123/udp, 137–139, 143, 161/udp, 389, 443, 445, 465, 587, 631, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5984, 5985, 5986, 6379, 8080, 8443, 9042, 9200, 11211, 27017. Database class: 1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 27017. Remote-admin class: 23, 2375, 3389, 5900, 5985, 5986. *Cost if wrong:* a wrong label; the map is one file.
10. **Needs a look** (fixed rules, first match first, codes on the wire, text in the web):
    - `database_exposed` "Database reachable from the network": Database class, exposed on a host in reach;
    - `remote_admin_exposed` "Remote admin reachable from the network": RemoteAdmin class, exposed;
    - `new_unusual` "New this week, not a usual port": not in the map, an `appeared` in reach this week.
    A row carries every matching code; the cell shows the first and "+n". SSH (22) is not flagged. *Cost if wrong:* noise or a missed flag; one list to edit.
11. **A new list route, `GET /v1/port-list`.** `GET /v1/ports`, `/v1/ports/{protocol}/{port}` stay for their current users (API, assistant). *Why:* the 5c/5d rule.
12. **What a row is.** Key `(protocol, port)`. One host counts once whatever its bound addresses. "n of m": n = hosts in reach listening; m = active hosts in reach that have sent a services report (`services_at IS NOT NULL`), the same m as the summary's "from n hosts' last reports".
13. **Filter values** (one value per filter; all combine):
    - **Exposure:** `exposed` (exposed on at least one host in reach), `local` (on none);
    - **Protocol:** `tcp`, `udp`;
    - **Group:** groups with a listening host in reach, plus the chosen one; matches when a host in that group listens;
    - **Service:** owner units seen on rows in reach, plus `~none` "Owner not collected" (a listening host with a null service); matches when a host listens with that owner;
    - **Changes:** `new` (an `appeared` this week), `look` (any Needs a look code);
    - **Host:** the Host chip.
14. **Search** covers the port number, `22/tcp`, the usual name (resolved in Rust from the map to a bound list of keys) and owner units.
15. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50. **Sorts:** port (the default, ascending, then protocol), hosts, exposed, week (most added first). Ties by key.
16. **Groups column** shows automatic and rule groups with a listening host in reach, most hosts first, as `portsList`'s `groupsFor` does (manual groups left out). *Cost if wrong:* manual groups invisible in the cell; the Group filter still offers them.
17. **Columns:** `hideable("ports")` = `hosts, exposed, services, groups, week, look`. Port is never hidden.
18. **Routes for the page:** `/ports/{port}/{protocol}` (reads like "22/tcp"; the spec's `/ports/{port}` lacks the protocol), with `GET /v1/ports/{protocol}/{port}/summary` and `GET /v1/ports/{protocol}/{port}/hosts?segment=all|exposed|local&offset&limit`. Invalid protocol or port → 400 `invalid_port`. A port with no listening host in reach and no change in reach in 90 days → 404 `port_not_found`; one that went away from every host stays viewable for 90 days with zero tiles.
19. **Old links.** `parsePortId(id)` in `app/location.ts` accepts `tcp/443`, `tcp:443`, `443/tcp` and `443` (TCP). `nav.open({kind:"port"})` and `?open=port:…` go to the page through `PAGES`, with replace. The `port` panel kind and `PortPanel` go; `UnitPanel` stays until 5f, moved to `UnitPanel.tsx`. Old list URL `?exposed=true` maps to `exposure=exposed`. Views saved in the browser under `openvibes.v2.views./ports` are imported once. *Fixes the 5c bug:* `CheckCards.tsx:237` passes `tcp:22` while `splitPortId` splits on `/`; the shared parser handles both, and CheckCards passes `tcp/22`.
20. **The summary view:** header `{protocol, port, name?, usual_use?, listening, of, exposed, services, first_seen {at, before}}`; tiles `{listening, exposed, local, week {added, removed}}`; details `{programs, owners {collected, of}}`; `by_group: [{group_id, name, listening, of}]` (of = group members in reach); `changes`: the 20 newest events in reach `{at, agent_id, hostname, change}`; `related` (ruling 22); `can {export, add_to_case, ask}`.
21. **Hosts rows:** one per host: `{agent_id, hostname, os, ip, bound: [addresses], exposed, service?, program?, owners_partial, reported_at}` with `reported_at = services_at`, shown in warning colour after 24 hours (step-4 rule). Segments: all / exposed (any address non-loopback) / local. Sort by hostname, agent id. "Lab-ws-04 stopped reporting" (mockup) is not a log event; it shows here as a stale last report.
22. **Related** (each only with its read permission, counted on listening hosts in reach):
    - **Compliance:** failing checks (5c's meaning) whose rule names this port (`rule_port` over `console_rule_meta` rows with `port.%` ids) or, when the map gives an area, whose `check_area` is that area. At most 5, worst first, each linking to its check page, then "n more" linking to `/compliance?area=…`.
    - **Vulnerabilities:** for each package in the map's `packages`, open vulnerabilities on listening hosts: "openssh: n open on m hosts", linking to `/vulnerabilities?package=NAME`. Omitted for unmapped ports (no port→package link exists yet).
    - **Alarms:** open alarms on listening hosts whose `process->>'exe'` basename equals that host's listener program for this port; "None open" when 0; "Program not collected" when no listening host names a program.
23. **Export** (header button, with `hosts.export`): a CSV of the port's hosts in reach (the hosts route, all pages), as 5c's `exportRows` does.
24. **Add to case** (with `cases.write`): item kind `port`, ref `tcp/22` (migration 0066). Like `software`: `agent_id` null, no outcome, visible inside a case only to a viewer with a listening host in reach, and it never makes a case visible by itself. Adding it is refused as `item_not_found` when no host in reach listens. The case list counts it in a new `ports` kind count.
25. **Ask about this** sends `{kind:"port", id:"tcp/22"}` with `assistant.use`, if the assistant resolves it (`assistant/lookups.rs` has `host_services`); if it does not, the button is omitted and the report says so (as 5d ruling 14).
26. **Performance:** the list answers within 2 s at full reach on 10,000 hosts with 20 listeners each (200,000 rows, about 300 distinct ports, 10 % exposed) and 500,000 change-log rows; record the scoped time too. The change log's ingest cost is measured on the same fleet (Task 2): median extra time per changed services report ≤ 5 ms, per 150-package upgrade report ≤ 50 ms, and zero rows and zero extra statements for an unchanged report.

## Review Focus

1. **A person reaching some groups opens a port listened on in and out of reach.** Counts, m, groups, This week, first seen, Recent changes and Related must not count or name out-of-reach hosts; a port only out of reach answers 404. Pinned in Task 3 by `port_list_counts_stay_inside_the_scope` and in Task 5 by `port_summary_stays_inside_the_scope`.
2. **A report with no changed keys writes nothing:** unchanged digest, changed digest with the same keys, a host's first report, and the first report after the upgrade. Pinned in Task 2 by `a_report_with_no_changes_writes_nothing`, `first_report_is_the_baseline` and `upgrade_writes_no_flood`.
3. **Owners not collected** (default installs): the Service · program cell, the Services column and the Details card say "not collected" instead of blank. Pinned in Task 5 by `owners_not_collected_is_said` and in Task 7 by the vitest `says when owners are not collected`.
4. **One host bound on several addresses** (`0.0.0.0` and `::`, or `127.0.0.1` and `10.0.0.5`) counts once, exposed if any address is non-loopback. Pinned in Task 3 by `a_host_counts_once_per_port` and in Task 5 by `hosts_rows_join_addresses`.
5. **Old links** (`tcp:22` from the check page, `?open=port:tcp/443`, `?open=port:tcp%3A443`, the host sub-page rows) land on `/ports/443/tcp` with no dead history entry. Pinned in Task 7 by `old_port_links_open_the_page` and the `parsePortId` unit test.

---

### Task 1: Spec rulings

**Files:**
- Modify: `docs/specs/2026-10-16-roles-permissions-design.md`. Add "Plan rulings, 2026-10-25 (step 5e)" after the step 5d section, with the user decision and rulings 1–26. Amend §10.3 "This week": it now reads the change log (the inventory history it named does not exist), and §16's order line.

- [ ] **Step 1: Write the section.** **Step 2: Commit** ("spec: step 5e rulings (ports, change log)").

---

### Task 2: The change log at ingest

**Files:**
- Create: `migrations/0065_change_log.sql` (ruling 2; grants: ingest `INSERT`, console `SELECT`, maintenance `DELETE`, as `alarm_hourly_starts` in 0060). Set `SCHEMA_VERSION = 65`.
- Create: `crates/platform-store/src/change_log.rs`:
  - `pub enum ChangeKind { Package, Listener, Service }`, `pub enum Change { Appeared, WentAway, Exposed, Local }`;
  - `pub(crate) struct Event { key: String, change: Change, detail: Option<serde_json::Value> }`;
  - `pub(crate) async fn record(tx: &Transaction<'_>, agent_id: &str, kind: ChangeKind, at: DateTime<Utc>, events: &[Event]) -> Result<(), StoreError>`: returns at once for an empty slice; otherwise one `INSERT … SELECT FROM unnest`;
  - `pub(crate) fn listener_diff(old: &[(String, i32, bool)], new: &[Listener]) -> Vec<Event>` and `pub(crate) fn key_diff(old: &BTreeSet<String>, new: &BTreeSet<String>) -> Vec<Event>` (ruling 3), pure, unit-tested;
  - `pub async fn prune(client: &Client, now: DateTime<Utc>) -> Result<u64, StoreError>` (ruling 6).
- Modify: `crates/platform-store/src/host_services.rs` `replace`: on a changed digest with a non-null stored digest, read the old listener keys and units (`DELETE … RETURNING`), diff, and `record`. Null stored digest: no diff (ruling 4).
- Modify: `crates/platform-store/src/inventory.rs`: `replace` diffs the old `package_version_id`s (`DELETE … RETURNING`) against the linked ones; `apply_changes` records its `added` / `removed` rows directly. Both skip when the stored digest was null. Split the file if it passes 500 lines.
- Modify: `crates/openvibes-admin/src/main.rs` (Maintenance calls `change_log::prune`), `crates/platform-store/src/lib.rs` (export).
- Tests: `crates/platform-store/tests/change_log.rs`; an `#[ignore]`d `change_log_ingest_timing.rs` (ruling 26 fleet).

**Interfaces:** produces `change_log` rows read by Tasks 3 and 5; `ChangeKind::code() -> &'static str` (`package`, `listener`, `service`).

- [ ] **Step 1: Write the failing tests:**
  - `a_report_with_no_changes_writes_nothing` (Review Focus 2): the same report twice, then a report with only a process count changed; `change_log` stays empty;
  - `first_report_is_the_baseline`: a new host's first services and inventory reports write nothing;
  - `upgrade_writes_no_flood`: hosts with stored rows and digests (as before the upgrade) send the same keys under a new digest; nothing is written;
  - a port appearing, going away, and flipping to local; `0.0.0.0` → `::` writes nothing;
  - a unit appearing and going away;
  - a package upgrade writes the two version events with the same `at`; a P11 change set writes exactly its added and removed rows; a resync diffs against stored rows;
  - `prune` removes rows older than 90 days only;
  - the timing test: median `replace` time on the fleet for an unchanged report, one changed listener, and a 150-package upgrade, with and without `record` (time `record` alone); assert the ruling 26 budgets and print the numbers.
- [ ] **Step 2: Implement.** **Step 3: Run the platform-store and openvibes-ingest suites.** **Step 4: Commit.**

---

### Task 3: The port map and the port list query

**Files:**
- Create: `crates/platform-store/src/port_names.rs` (ruling 9) with a unit test that every Database and RemoteAdmin entry has a name and that `port_info("tcp", 8081)` is `None`.
- Create: `crates/platform-store/src/port_list.rs` and `port_list_sql.rs`, following `check_list.rs` / `check_list_sql.rs`: listening hosts in reach through the shared scope helpers, one row per host per port first (`bool_or(exposed)`), then per port; counts with `except(skip)`; this week from `change_log` (`kind = 'listener'`, `at > now − 7 days`); map-derived values (names for search, Database / RemoteAdmin / known keys for Needs a look) passed as bound arrays; one statement.
- Tests: `crates/platform-store/tests/port_list.rs`, plus an `#[ignore]`d `port_list_timing.rs` at the ruling 26 scale.

**Interfaces:** produces
- `PortQuery { q, exposure: Option<Exposure (Exposed | Local)>, protocol, group, service: Option<ServiceFilter (Unit(String) | NotCollected)>, changes: Option<Changes (New | Look)>, host, sort: PortSort (Port | Hosts | Exposed | Week), descending, offset, limit }`;
- `port_list(client, &query, scope: &AgentScope, now) -> PortListPage { rows, total, counts, summary }`;
- `PortListRow { protocol, port, name: Option<&'static str>, hosts, exposed_hosts, services: Vec<String> (≤ 8), owners_missing: bool, groups: Vec<GroupRef> (≤ 3, ruling 16), week_added, week_removed, look: Vec<&'static str> }`;
- `PortListSummary { exposed, new_this_week, need_a_look, reporting_hosts }`.

- [ ] **Step 1: Write the failing tests:**
  - one row per port; `a_host_counts_once_per_port` (Review Focus 4);
  - every filter and its counts with the other filters applied, including Service `~none`;
  - `port_list_counts_stay_inside_the_scope` (Review Focus 1), including m and this week;
  - each Needs a look rule, and 22/tcp exposed is not flagged;
  - search by `22`, `22/tcp`, `postgres` (the name) and a unit;
  - every sort, with stable paging;
  - the summary line;
  - revoked hosts are left out;
  - the timing test (full-reach and scoped medians, both under 2 s; print both).
- [ ] **Step 2: Implement.** **Step 3: Run the tests**, then the timing test once. **Step 4: Commit.**

---

### Task 4: `GET /v1/port-list`, and ports as a saved-views page

**Files:**
- Create: `crates/openvibes-console/src/ports/mod.rs`, `list_page.rs`, `list_page_types.rs`, `README.md`, following `compliance/list_page.rs`. The route needs `hosts.read`; validation gives 400 `invalid_query` naming the field. Mount it where `compliance` mounts.
- Modify: `crates/openvibes-console/src/lists/mod.rs`: `PAGES` gains `"ports"`; `hideable("ports")` per ruling 17; the doc comment names Port as never hidden.
- Modify: OpenAPI, the snapshot, the client; the demo route `web/src/demo/routes/portList.ts`, with demo data covering every filter: a database port exposed, a new unusual port, a local-only port, a port with an owner not collected, a port only on a host outside a team lead's reach.
- Tests: `crates/openvibes-console/tests/port_list_http.rs` and `web/src/demo/routes/portList.test.ts`.

- [ ] **Step 1: Write the failing tests:** validation of every parameter; the response shape; a scoped team lead; the saved-views page `ports` is accepted and its hideable columns enforced; the demo answers the same shape and counts.
- [ ] **Step 2: Implement.** **Step 3: Run the tests**, then regenerate OpenAPI and the client. **Step 4: Commit.**

---

### Task 5: The port summary and hosts routes, and `port` case items

**Files:**
- Create: `crates/platform-store/src/port_summary.rs` (rulings 7, 8, 20, 21) and `port_related.rs` (ruling 22, reusing `check_related::rule_port`, `check_area::check_area` and 5c's failing-pair SQL).
- Create: `crates/openvibes-console/src/ports/page.rs` and `page_types.rs` (ruling 18).
- Create: `migrations/0066_case_port_items.sql`: `case_items` kind CHECK gains `port`; the agent check becomes `(kind IN ('software', 'port')) = (agent_id IS NULL)`. Set `SCHEMA_VERSION = 66`.
- Modify: `crates/platform-store/src/console_cases/` (`mod.rs` `ItemKind::Port`, `items.rs` `parse_ref` and `resolve_item` like `Software`, `visibility.rs` treats `port` like `software`), `case_list_sql.rs` and the case list row (`ports` count), `case_summary.rs` if it lists kinds; the console's case types and `responses.rs`.
- Modify: the demo, `web/src/demo/routes/portSummary.ts` (summary and hosts) and `demo/cases.ts` (port items).
- Tests: `crates/platform-store/tests/port_summary.rs`, `crates/openvibes-console/tests/port_page_http.rs`, and port items in `crates/platform-store/tests/console_cases/` and `crates/openvibes-console/tests/cases_http_items.rs`.

**Interfaces:**
- `port_summary(client, scope: &AgentScope, perms: RelatedReach { compliance, vulnerabilities, alarms }, protocol, port, now) -> Option<PortSummary>` (None → 404);
- `port_hosts_page(client, scope, protocol, port, segment: PortSegment (All | Exposed | Local), offset, limit) -> PortHostsPage { rows, total, segments { all, exposed, local } }`;
- the views follow rulings 20 and 21; `can` from the session's permissions.

- [ ] **Step 1: Write the failing tests:**
  - `port_summary_stays_inside_the_scope` (Review Focus 1): tiles, by group, first seen, changes and related;
  - 404 for a port only out of reach; a port gone from every host but with a change in 90 days still answers;
  - first seen: an `appeared` event, a baseline host enrolled after the log start, and the "before" floor (ruling 7);
  - `hosts_rows_join_addresses` (Review Focus 4); segments add up and page;
  - `owners_not_collected_is_said` (Review Focus 3): `owners_partial` true and `owners.collected` < `owners.of`;
  - Related: each section hidden without its permission; the SSH area check; the openssh package line; an alarm matched by program; "Program not collected";
  - `can` flags per permission (export needs `hosts.export`);
  - port case items: added with a listening host in reach, refused otherwise, take no outcome, never make a case visible alone, counted under `ports`; the migration keeps existing rows.
- [ ] **Step 2: Implement.** **Step 3: Run the tests**, regenerate OpenAPI and the client. **Step 4: Commit.**

---

### Task 6: The Ports list (screen 19), with the demo

**Files:**
- Move: `Services()` from `web/src/views/investigate/Ports.tsx` to `Services.tsx`, unchanged (pure move, own commit; 5f rewrites it).
- Rewrite: `web/src/views/investigate/Ports.tsx` with FilterBar, SummaryLine, ColumnsMenu, server paging and the columns of screen 19. Rows link to `/ports/{port}/{protocol}` with a real `<a>`. The Needs a look text map (ruling 10) lives here. "Owner not collected" shows in the Services cell when `owners_missing`.
- Modify: the registry (`/ports` with prefix `/ports/`), the old-URL mapping (`exposed=true`) and the browser-views import (ruling 19).
- Modify: the demo e2e specs that use the old list (`assets.spec.ts`). Create `web/e2e/demo/port-list.spec.ts`: filter by Exposure and Changes, reload and keep the filters; save a view; hide a column; search by usual name; old `?exposed=true` keeps its meaning; axe.
- Tests: `web/src/views/investigate/Ports.test.tsx`.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 7: A port's page (screen 20); the port panel goes

**Files:**
- Create: `web/src/views/investigate/port/PortPage.tsx`, `PortCards.tsx`, `README.md`, on `DetailPage`, `Tile`, `SegmentChips` and `RelatedCard`:
  - **Header:** protocol badge, port and name, facts line (ruling 20), Export (ruling 23), Add to case (kind `port`), Ask about this (ruling 25).
  - **Tiles**, **Details** (with "Programs: not collected on n of m hosts" when `owners.collected < owners.of`), **By group** bars (linking to `/hosts?group=ID`), **Recent changes** (text per change: "web-01 started listening", "web-01 stopped listening", "db-02 now listens only locally", "db-02 is now exposed").
  - **Hosts** with segments and paging; Service · program shows "not collected" for a null owner on a partial host. **Related** per ruling 22.
- Modify: `app/location.ts`: `parsePortId(id): [protocol, port]` and `portPath(protocol, port)`; `PAGES.port`. Update `CheckCards.tsx:237` to pass `tcp/22` (the 5c bug); `HostServices.tsx` port rows link to the page; `CaseItems.tsx` and AddToCase render and accept `port` items; the case list's kinds cell shows ports.
- Remove: the `port` panel kind in `registry.tsx`, `PortPanel` and `splitPortId`; keep `UnitPanel` in `panels/hosts/UnitPanel.tsx` (ruling 19). Grep to prove nothing still opens a port panel.
- Modify: the demo e2e specs that use the panel. Create `web/e2e/demo/port-page.spec.ts`: `old_port_links_open_the_page` (Review Focus 5); switch segments; add the port to a case; export downloads a CSV; axe in light and dark.
- Tests: `web/src/app/location.test.ts` (`parsePortId` for all four spellings; the existing `tcp:443` cases now open the page) and `PortPage.test.tsx` (`says when owners are not collected`, Related hidden without permissions).

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 8: Live e2e, docs and the gate

**Files:**
- **Live e2e:** `web/e2e/live/ports.spec.ts`, retry-safe (restores state in `finally`). A team lead sees only ports on their hosts; the counts agree with the rows; a new listener reported through ingest shows in This week and in the page's Recent changes; they open the page, switch segments, add the port to a case. Seed per browser.
- **Docs:**
  - a new `docs/components/console-ports.md`, indexed: the list, the page, the port map and Needs a look, owners, routes;
  - a new `docs/components/change-log.md`, indexed: table, what counts as a change, baseline, retention, ingest cost (with the Task 2 numbers), how to test;
  - updates to `platform-store.md` (timings from Tasks 2 and 3), `openvibes-ingest.md`, `openvibes-admin.md` (maintenance prunes the log), `console-cases.md` (`port` items), `console-web.md`;
  - an Upgrading note in `console-web.md`: the port panel became a page and old links redirect; This week and Recent changes start empty and fill from the upgrade on; "first seen" before the upgrade shows as "Before {date}"; ports can be added to cases.
- Add `port_list_timing` and `change_log_ingest_timing` to `~/Projects/OpenVIBES/testing.md`'s timing line (a workspace commit).

- [ ] **Step 1: Write the live journey and run it twice (`--repeat-each=2`).**
- [ ] **Step 2: Run the full local gate** (`testing.md` §2, the browser items and the timing tests) once, in this worktree's own target dir. Expected: all green.
- [ ] **Step 3: Commit.**

---

## Self-review notes

- **Spec coverage:**
  - screen 19: filters, columns, summary → Tasks 3, 4 and 6;
  - screen 20: header, tiles, both columns → Tasks 5 and 7;
  - §10.3: the shared pattern → Task 6; routes and panel removal → Task 7; list counts and scope → Tasks 3 and 4; detail summary → Task 5; "This week" and "Needs a look" → Tasks 2, 3 and 5;
  - user decisions 2 and 4 → Tasks 2 and 5; the 5c port-link bug → Task 7.
- **New data:** migration 0065 (change log), 0066 (`port` case items). No protocol or agent change.
- **Not here:** Services (5f: its list, page, `service` items and the unit panel) and Software (5g); port→package links beyond the fixed map; exact per-address history.
