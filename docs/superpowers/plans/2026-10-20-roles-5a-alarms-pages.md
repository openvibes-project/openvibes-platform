# The Alarms list and an alarm's page: implementation plan (step 5a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the first page of step 5 of the roles spec:
- the Alarms list (screen 29), with server-side filters, per-value counts, saved views, remembered columns and a summary line;
- an alarm's page, `/alarms/{id}` (screen 30), which replaces the alarm side panel;

plus the new data these pages need: commands seen, the last 24 hours, rule explanations and techniques.

**Architecture:**
- **The list is built on step 4's shared pieces.** One store query (`alarm_list`) returns rows, the total, the per-value counts and the summary, all scoped by §6.
- **One summary route** (`GET /v1/alarms/{id}/summary`) returns everything above the fold.
- **"Commands seen"** are the alarm's siblings: alarms on the same host from the same rule, program and parent, one per distinct command line. This follows how agents already split alarms.
- **The last 24 hours** come from a new per-hour starts table filled by ingest.
- **The rule's explanation, what to check, its title and ATT&CK techniques** come from a rule-metadata index. The index is filled when signed rule bundles are stored, and reads optional `explain` and `check` fields that a protocol change adds to rules.

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres, `platform-store` migrations;
- React and TypeScript web, with the demo server;
- vitest and Playwright;
- one small PR in `openvibes-protocol`.

**Spec:**
- `docs/specs/2026-10-16-roles-permissions-design.md`: §6, §10.3 (shared pattern, routes, server rules, "Distinct command lines per alarm"), §13 and §15.
- Approved screens: `docs/specs/rbac-ui/approved.md`, the shared layout and screens 29 and 30.
- The step 4 plan, `docs/superpowers/plans/2026-10-20-roles-4-hosts-pages.md`, which built the shared pieces.

**Base:** `origin/main` 66d4c3f (steps 1–4 merged). Branch `alarms-pages`, worktree `openvibes-platform-alarms`.

## User decisions (2026-10-20, before this plan)

1. **Commands seen = siblings.** The page lists every alarm on the same host with the same rule set, rule, program (`exe`) and parent (`ancestors[0].exe`). Each sibling is one distinct command line, with its count, first and last seen, state, case and suppression. The spec's `alarm_commands` table is dropped. Agents already split alarms by command line (contracts-v1, alarm collapse), so the siblings are those lines. Old data works as is.
2. **The last 24 hours = per-hour starts.** Ingest records the growth of each alarm's count, bucketed by the hour the report arrived. Rows are kept 7 days. The page draws 24 hourly bars for the alarm and its siblings together.
3. **"What happened" and "what to check" come from rules.**
   - Rules gain optional `explain` and `check` text, at most 600 characters each. This is changed in `openvibes-protocol` first.
   - Old agents ignore the fields: the agent's `Rule` has no `deny_unknown_fields`, and the rule-set schema allows extra properties.
   - The platform reads the fields from the verified bundle JSON, so no agent release is needed.
   - Until a rule has the text, the card shows the rule's title and its message.

## Global Constraints

**List (screen 29)**
- **Filters:** Severity, State, Suppressed (hidden by default), Host, Group, Technique (ATT&CK), Case and Assignee.
- **Columns:**
  - Severity;
  - Alarm, with its process chain and technique;
  - Host, with its OS;
  - Count;
  - Last and first seen;
  - State;
  - Assignee;
  - Case.
- **Suppress:** the per-row "Suppress…" is removed. Suppress… is in the bulk bar and on the alarm's page.
- **Shared pattern (§10.3):**
  - `FilterBar`: search, filter chips with per-value counts, filters in the URL, Clear all, Save view (per user and page) and Columns (remembered per user and page);
  - `SummaryLine`;
  - the bulk bar: Set state ▾, Assign ▾, Add to case, Suppress…;
  - every row opens a page instead of a side panel.

**Page (screen 30)**
- **Header:** Set state ▾, Assign ▾, Suppress…, Ask about this, ⋯.
- **Tiles:** starts matched, different commands, first seen, confidence.
- **Left column:**
  - What happened, in plain words, plus what to check;
  - Details;
  - History.
- **Right column:**
  - **Commands seen:** every distinct command line with its count.
    - The usual one (the highest count) has "Suppress this command…", which opens the screen-12 form.
    - A command seen once is highlighted, with Add to case.
  - Process chain.
  - Last 24 hours, as a timeline.
  - Related: alarms on the host, vulnerabilities, and the same rule elsewhere.

**Server (§10.3)**
- **List counts:**
  - the list route accepts the page's filters;
  - it returns rows, the total, and the count of every value of every filter with the other filters applied, all from the same query.
- **Detail summary:** one route.
- **Scope:** everything is scoped by §6. Counts never include hosts the viewer cannot see.
- **Panel links:** the side panel and its tabs are removed, and today's deep links to the panel redirect to the page.
- **Unchanged:** the triage states and rules, the evidence agents send, and what each permission allows.
- **Masking:** masking of secrets stays as today, on the agent.

**Project rules**
- Files under 500 lines.
- Every code folder has a README.
- `docs/components/` pages are updated in the same change.
- The OpenAPI snapshot and the client are regenerated.
- The demo mirrors every route.
- Anything crossing the agent/platform boundary is changed in `openvibes-protocol` first.

**Environment (binding for every task)**
- This host is the user's production host. Never touch its own openvibes services or its system PostgreSQL (`/var/lib/pgsql`). Tests use only `eval "$(scripts/test-db.sh)"`, then stop it.
- Cargo commands run with `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` under `nice -n 19 ionice -c3`. Run one heavy command at a time.
- Playwright: demo `--workers=4`, live `--workers=2` with `--project=chromium --project=firefox`.
- Restore `web/dist/.gitkeep` before committing.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.

## Rulings in this plan (spec amendments, 2026-10-20)

Task 1 writes the user's decisions and these rulings into spec §10.3 as "Plan rulings, 2026-10-20 (step 5a)".

1. **A new list route, `GET /v1/alarm-list`.** The keyset-paged `GET /v1/alarms` stays for its current users: live alarms, dashboards and the host page. `/alarms/{id}` is the page.
2. **Filter values** (one per filter, all combining):
   - **State:** open, mitigated, accepted_risk, false_positive. The default view is "open"; a `state=all` value shows every state.
   - **Severity:** the five levels.
   - **Suppressed:** hidden (default), shown. Shown means suppressed alarms are included.
   - **Host:** the host chip from step 4.
   - **Group:** groups with at least one host the viewer can see, plus the chosen one.
   - **Technique:** techniques of alarms in reach, from the rule-metadata index. An alarm whose rule has no technique matches none.
   - **Case:** in a case, not in a case.
   - **Assignee:** me, unassigned, and people with at least one alarm in reach.
3. **Search** covers the message, rule ID, host name, program and parent program.
4. **Paging is by offset,** as on Hosts: `offset` 0..=100000, `limit` 1..=100, default 50.
   - **Sorts:** last seen (default, newest first), first seen, count, severity.
   - Ties are broken by id.
5. **The summary line:** "N open · N critical or high · N on hosts with alarms off". The last part shows only with `hosts.read`.
6. **Ask about this** on the page uses the host page's pattern (`assistant.askAbout`), shown with `assistant.use` on that host.
7. **⋯** holds Export (a CSV of this alarm and its siblings, with `alarms.export`) and Copy link.
8. **The rule-metadata index:**
   - `console_rule_meta` (rule_set_id, rule_set_version, rule_id, rule_version, title, message, explain, check, attack jsonb) is filled from verified bundles when a rule set is stored or uploaded.
   - On console start, a one-time background backfill indexes every stored bundle not yet indexed.
   - An alarm whose rule is not indexed falls back to `GET /alarms/{id}/rule`, which resolves it as today.
9. **"Same rule elsewhere"** shows the count of other hosts in reach with an open alarm from this rule, and links to the list filtered by the rule (`?q=<rule_id>`). Rule ID is not a separate filter.
10. **Hourly starts:**
    - a new alarm adds its whole count to the hour it was received;
    - a growing count adds the difference to the hour of the report;
    - a shrinking count is ignored.

    The table is `alarm_hourly_starts (alarm_row_id bigint, hour timestamptz, starts int, PK (alarm_row_id, hour))`. It is not partitioned, and maintenance deletes hours older than 7 days.

## Review Focus

1. **A person reaching some groups opens an alarm by id, or follows a sibling's link, on a host out of reach.** It must 404 like a missing alarm, and "commands seen" and "same rule elsewhere" must not count or name out-of-reach hosts. Pinned in Task 6 by `summary_stays_inside_the_scope`.
2. **An alarm whose rule bundle was never indexed (old data, or an unverifiable bundle).** The page still renders with the title and message fallback, and the technique filter simply doesn't match it. Pinned in Task 2 by `unindexed_rules_fall_back`.
3. **A report whose count did not grow (an agent restart re-sends), or a shrinking count.** It adds no hourly starts. Pinned in Task 3 by `only_count_growth_is_recorded`.
4. **Old panel links** (`?open=alarm:ID` from dashboards, cases, suppressions, the host page and the attention list) land on `/alarms/ID` with no dead history entry. Pinned in Task 9 by `old_alarm_links_open_the_page`.
5. **Suppress this command…** on a sibling suppresses that sibling's command line, not the opened alarm's. Pinned in Task 9 by `suppress_this_command_uses_that_line`.

---

### Task 1: Protocol: optional `explain` and `check` on rules

**Repo:** `~/Projects/OpenVIBES/openvibes-protocol` (its own branch `rule-explain`; a separate PR, opened by the controller).

**Files:**
- Modify: `schemas/v1/rule-set.schema.json`. Add the optional string properties `explain` and `check` to rule items, each `maxLength` 600 with a description.
- Modify: the contracts doc that defines rule fields (`spec/contracts-v1.md`, the rules section):
  - **What:** `explain` says in plain words what a match means; `check` says what a person should look at.
  - **Who reads them:** both are for people. Agents ignore them.
  - **Compatibility:** older agents accept them, because rule items allow extra properties.
- Add: a fixture rule set with both fields, and a test, if the repo has schema fixture tests.
- Modify: `PLAN.md` with a line under the synced plan.
- Also, in this platform worktree: paste the user decisions and the plan rulings into the spec §10.3 as "Plan rulings, 2026-10-20 (step 5a)" (one commit here).

- [ ] **Step 1: Write the fixture and the schema test, and see it fail** (the schema rejects nothing yet, so add a negative case: 601 characters is refused).
- [ ] **Step 2: Change the schema and the docs, then run the repo's checks.**
- [ ] **Step 3: Commit in both repos.** No push; the controller opens the protocol PR.

---

### Task 2: The rule-metadata index

**Files:**
- Create: `migrations/0059_rule_meta.sql` (`console_rule_meta`, with grants for whoever stores bundles and for the console's read). Set `SCHEMA_VERSION = 59`.
- Create: `crates/platform-store/src/rule_meta.rs` with `upsert_from_bundle(client, set, version, &[RuleMetaRow])`, `get(client, set, set_version, rule_id, rule_version) -> Option<RuleMeta>`, `missing_bundles(client, limit)`, and the techniques used by alarms.
- Create: `crates/openvibes-console/src/rules/meta.rs`. It builds `RuleMetaRow`s from a verified bundle by reusing `alarms/detection.rs::resolve`'s verification (`rules::trust_keys`, `openvibes_rules::RuleLoader`). It then re-reads each rule's JSON value from the verified payload for `explain` and `check`, and caps their length.
- Hook it where rule sets are stored or uploaded. Find the console upload path and any signer/distribution store path that writes bundles. Add the startup backfill task (it is bounded and logs progress).
- Tests: `crates/platform-store/tests/rule_meta.rs`, and a console test with a signed test bundle (reuse the detection tests' signing helpers).

**Interfaces:** produces `RuleMeta { title, message, explain: Option<String>, check: Option<String>, attack: Vec<(tactic, Option<technique>)> }`, plus the SQL table for joins.

- [ ] **Step 1: Write the failing tests:**
  - an uploaded bundle is indexed with its title, message, attack, explain and check;
  - `unindexed_rules_fall_back` (Review Focus 2): `get` returns None and the caller falls back;
  - an unverifiable bundle is not indexed;
  - the backfill indexes stored bundles once.
- [ ] **Step 2: Implement.** **Step 3: Run the tests** (platform-store, console). **Step 4: Commit.**

---

### Task 3: Hourly starts

**Files:**
- Create: `migrations/0060_alarm_hourly_starts.sql`, as in ruling 10. Grants: ingest INSERT and UPDATE, console SELECT, and DELETE for whoever runs maintenance. Set `SCHEMA_VERSION = 60`.
- Modify: `crates/platform-store/src/alarms.rs` `insert_batch`.
  - **New alarm:** upsert `+count` into `date_trunc('hour', now)`.
  - **Known alarm whose count grew:** upsert `+delta` into the same hour.
  - Both happen in the same transaction.
- Modify: `crates/platform-store/src/maintenance.rs`, deleting hours older than 7 days in the existing maintenance pass.
- Tests: `crates/platform-store/tests/alarm_hourly.rs`.

- [ ] **Step 1: Write the failing tests:**
  - a new alarm with count 3 gives one row of 3;
  - a later report with count 5 adds 2 in that hour;
  - `only_count_growth_is_recorded` (Review Focus 3): resending count 5, or count 4, adds nothing;
  - maintenance removes rows older than 7 days.
- [ ] **Step 2: Implement.** **Step 3: Run the tests** (platform-store, ingest). **Step 4: Commit.**

---

### Task 4: The alarms list query

**Files:**
- Create: `crates/platform-store/src/alarm_list.rs` and `alarm_list_sql.rs`, following `host_list.rs` and `host_list_sql.rs` (base CTE, `except(skip)` counts, one statement).
- Tests: `crates/platform-store/tests/alarm_list.rs`, plus a 200,000-alarm, 20,000-host `#[ignore]`d timing test like `host_list_timing.rs`, with a scoped case.

**Interfaces:** produces `AlarmQuery { q, state, severity, suppressed, host, group, technique, case: Option<bool>, assignee: Assignee (Me | Unassigned | User(uuid)), sort, descending, offset, limit }` and `alarm_list(client, &query, scope: &AgentScope, actor_id, now) -> AlarmListPage { rows, total, counts, summary }`.
- `AlarmListRow` has: `id`, `agent_id`, `hostname`, `os` (family and distribution display), `rule_set_id`, `rule_id`, `severity`, `message`, `exe`, `parent_exe`, `techniques` (`Vec<String>`), `count`, `first_seen`, `last_seen`, `state`, `assignee` (`Option<(uuid, display name)>`), `case` (`Option<(case_id, number)>`) and `suppressed_by`.
- Only agent alarms (`source = 'agent'`) are listed, joined to `agents a` with `agent_visibility`.

- [ ] **Step 1: Write the failing tests:**
  - each filter;
  - counts with the other filters applied;
  - the scope (counts and values never include out-of-reach hosts or groups);
  - search;
  - every sort, with stable paging;
  - the techniques from `console_rule_meta`;
  - the case and assignee values;
  - suppressed hidden by default;
  - the timing test (record the time; it must stay under 1 s at full reach, and record the scoped time).
- [ ] **Step 2: Implement.** Bind every parameter. **Step 3: Run the tests** (platform-store). **Step 4: Commit.**

---

### Task 5: `GET /v1/alarm-list`, and alarms as a saved-views page

**Files:**
- Create: `crates/openvibes-console/src/alarms/list.rs` and `list_types.rs`, following `hosts/list.rs`. Validation gives `invalid_query` naming the field; the route needs `alarms.read`.
- Modify: `crates/openvibes-console/src/lists/mod.rs`. Add `PAGES` `"alarms"`, and `hideable("alarms")` = `alarm, host, count, seen, state, assignee, case`. The first column, severity, is never hidden.
- Modify: OpenAPI, the snapshot, the client and the demo route (`web/src/demo/routes/alarmList.ts`).
- Tests: `crates/openvibes-console/tests/alarm_list_http.rs` and demo vitest.

- [ ] **Step 1: Write the failing tests:**
  - validation of every parameter;
  - the response shape;
  - a scoped team lead;
  - assignee "me" resolved from the session;
  - the saved-views page "alarms" is accepted.
- [ ] **Step 2: Implement.** **Step 3: Run the tests.** Regenerate the OpenAPI document and the client. **Step 4: Commit.**

---

### Task 6: `GET /v1/alarms/{id}/summary`

**Files:**
- Create: `crates/platform-store/src/alarm_summary.rs` and `crates/openvibes-console/src/alarms/summary.rs` and `summary_types.rs`.
- Tests: `crates/platform-store/tests/alarm_summary.rs` and `crates/openvibes-console/tests/alarm_summary_http.rs`.

**Interfaces:** `AlarmSummaryView` has:
- `alarm`: the list-row fields plus `confidence`, `rule_set_version`, `rule_version`, `process`, `ancestors`, `received_at` and `triage`;
- `tiles`: `{ starts, different_commands, first_seen, confidence }`;
- `rule`: `{ title, message, explain?, check?, techniques }`;
- `commands`: siblings in reach, sorted by count descending, each with `{ id, args (masked, as stored), count, first_seen, last_seen, state, suppressed_by, case }`;
- `hourly`: 24 numbers, oldest first, for the alarm and its siblings;
- `related`:
  - `host_alarms`: up to 5 other open alarms on the host, plus the total;
  - `host_vulnerabilities`: the top 3 and the total, using the step-4 summary rules; null without `vulnerabilities.read` on the host;
  - `same_rule_elsewhere`: `{ hosts, open }`, counted in reach;
- `can`: `{ triage, assign, suppress, add_to_case, ask, export }`, each for this host.

The route answers 404 `alarm_not_found` for an alarm out of reach, the same as for a missing one.

- [ ] **Step 1: Write the failing tests:**
  - `summary_stays_inside_the_scope` (Review Focus 1);
  - siblings exclude other programs, parents and hosts;
  - the usual command is first;
  - the hourly window covers exactly the last 24 hours;
  - the rule fallback when not indexed;
  - the `can` flags per permission.
- [ ] **Step 2: Implement.** **Step 3: Run the tests.** Regenerate OpenAPI and the client, and add the demo route (`alarmSummary.ts`). **Step 4: Commit.**

---

### Task 7: Shared web additions

**Files:**
- Create: `web/src/ui/detail/FactTile.tsx`, a non-link tile with `{ label, value: ReactNode }`. It is used for "first seen" and "confidence".
- Create: `web/src/ui/charts/HourlyBars.tsx`. It draws 24 accessible bars: an SVG with a `<title>` per bar, and a visually hidden table of the values. If the console already has a chart helper, reuse it.
- Modify: the `BulkBar` so it works on a server-paged list: it receives selected ids, and "select all n matching" sends the filter (if the bulk route supports a filter) or caps at the page. Read `bulk.rs`, and keep today's behaviour if a filter-based bulk action does not exist; the page select stays as today.
- Tests: unit tests for each.

- [ ] **Steps: failing tests, implement, then vitest, tsc, eslint and build. Commit.**

---

### Task 8: The Alarms list (screen 29), with the demo

**Files:**
- Rewrite: `web/src/views/investigate/Alarms.tsx` with FilterBar, SummaryLine, ColumnsMenu, server paging, the bulk bar and the columns of screen 29.
  - Remove the per-row Suppress… button and the waiting-request badge column.
  - Rows link to `/alarms/{id}`, with a real `<a>` on the message.
- Modify: the registry. Give `/alarms` the prefix `/alarms/`, and keep the menu count from `liveAlarms`.
- Create: the demo route `alarmList.ts` (Task 5 made it; make it complete here if needed), and extend the demo data with commands, OS and techniques so the filters have values.
- Modify: the demo e2e specs `alarms.spec.ts` and `bulk.spec.ts`, and the smoke spec as needed. Create `web/e2e/demo/alarm-list.spec.ts`:
  - filter by Severity and Technique, then reload and keep the filters;
  - save a view;
  - hide a column;
  - bulk Suppress… from the bar;
  - axe.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 9: An alarm's page (screen 30); the alarm panel goes

**Files:**
- Create: `web/src/views/investigate/alarm/AlarmPage.tsx`, `AlarmCards.tsx` and `README.md`.
  - **Header actions:** Set state ▾ and Assign ▾ (the inline BulkBar), Suppress…, Ask about this, and ⋯ with Export and Copy link.
  - **Tiles:** Tile for starts, Tile for different commands linking to the Commands card anchor, and FactTile for first seen and confidence.
  - **Left column:** What happened (`explain`, then `check`, else title and message), Details (rule, set, versions, received, suppression), History (`HistoryTab`).
  - **Right column:**
    - **Commands seen:** the usual one has "Suppress this command…", which opens `SuppressDialog` with that sibling's id. Commands seen once are highlighted, with Add to case for that sibling.
    - **Process chain** (the existing tree);
    - **Last 24 hours** (HourlyBars);
    - **Related.**
- Remove: the `alarm` panel kind and `AlarmPanel.tsx`, after redirecting.
  - In `nav.ts`, `nav.open({kind:"alarm"})` goes to `/alarms/{id}` and closes panels.
  - In `location.ts`, `?open=alarm:ID` goes to `/alarms/ID`.
  - `ObjectLink` hrefs follow.
  - Grep to prove no `kind: "alarm"` panel use remains.
- Modify: the demo e2e specs that use the panel (`alarms.spec.ts`, `detection.spec.ts`, `cases.spec.ts`, `alarm-suppressions.spec.ts`, `host-page.spec.ts`).
- Create: `web/e2e/demo/alarm-page.spec.ts`:
  - `old_alarm_links_open_the_page`;
  - `suppress_this_command_uses_that_line` (Review Focus 5: the request body's `alarm_id` is the sibling's);
  - Set state from the header;
  - Add to case on a once-seen command;
  - the timeline renders;
  - axe in light and dark.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 10: Rule text, live e2e, docs and the gate

**Files:**
- **Rules repo** (`~/Projects/OpenVIBES/openvibes-rules`, its own branch and PR, opened by the controller): add `explain` and `check` to the `baseline-alarms` rules. Write short plain sentences, at most 600 characters. The user reviews the wording in that PR.
- **Live e2e:**
  - `web/e2e/live/alarms.spec.ts` (new): a team lead sees only their hosts' alarms, the counts agree with the rows, they open an alarm's page, and the commands and timeline render;
  - `scripts/alarms-e2e.sh`: after the existing checks, `GET /api/v1/alarms/{id}/summary` shows `tiles.starts == 3` and one hourly bucket of 3.
- **Docs:**
  - a new `docs/components/console-alarms.md`, indexed, covering the list, the page, the summary, the hourly starts and the rule metadata;
  - updates to `console-triage.md`, `console-detection.md`, `platform-store.md`, `openvibes-ingest.md` and `console-web.md` (move the alarm sections out);
  - an Upgrading note: the alarm panel became a page, old links redirect, the timeline starts filling after upgrade, and rules without text show their title.

- [ ] **Step 1: Rules text** (commit in the rules repo; no push).
- [ ] **Step 2: Write the live journey and run it.**
- [ ] **Step 3: Run the full local gate** (`~/Projects/OpenVIBES/testing.md` §2 and the browser items) once. Expected: all green.
- [ ] **Step 4: Commit.**

---

## Self-review notes

- **Spec coverage:**
  - screen 29: filters, columns, per-row suppress removed, bulk Suppress… → Tasks 4, 5, 7 and 8;
  - screen 30: header, tiles, left and right columns → Tasks 6 and 9;
  - §10.3:
    - shared pattern → Tasks 7 and 8;
    - routes and panel removal → Task 9;
    - list counts and scoping → Tasks 4 and 5;
    - detail summary → Task 6;
    - "Distinct command lines" → user decision 1 (siblings) plus Task 6;
  - the new data the page needs: hourly starts (Task 3) and rule explanations and techniques (Tasks 1 and 2).
- **Not here:**
  - the other list pages (5b onward: Vulnerabilities, Compliance with rule titles, Cases with new outcomes, Software, Services, Ports);
  - DetailPage's hosts table with segment chips and the Related card as shared pieces (built for alarms inline here; generalised when a second page needs them).
- **Cross-repo:** the protocol PR (Task 1) and the rules PR (Task 10) are opened by the controller. The platform reads `explain` and `check` from the verified bundle JSON, so no agent release is needed.
