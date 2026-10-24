# The Compliance list and a check's page: implementation plan (step 5c)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the third page of step 5 of the roles spec:
- the Compliance list (screen 27), one row per check (a rule in a rule set), with server-side filters, per-value counts, saved views, remembered columns and a summary line;
- a check's page, `/compliance/{rule_set_id}/{rule_id}` (screen 28), which replaces the finding side panel.

**Architecture:**
- **The list is built on the shared pieces of steps 4–5b.** One store query (`check_list`) groups host and rule pairs in reach by check. It returns rows, the total, the per-value counts and the summary, all scoped by §6.
- **"Passing" is inferred from rule-set health** (user decision 1). There is no per-rule pass record.
- **The page's 14 days come from current findings** (user decision 2), and **each host's evidence** comes from the finding's detection inputs, with a file from a fixed fact-to-file map (user decision 3).
- **"Why it matters" and "How to fix"** come from the rules' optional `explain` and `check` text (user decision 4). The rules repository writes it, and the platform already indexes it in `console_rule_meta` (step 5a).
- **No protocol or agent change.** Rule titles are already required by the protocol, and every baseline and hardening rule has one. That satisfies the spec's "Short names for compliance checks".

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres, `platform-store`;
- React and TypeScript web, with the demo server;
- vitest and Playwright;
- one PR in `openvibes-rules`.

**Spec:**
- `docs/specs/2026-10-16-roles-permissions-design.md`: §6, §10.3 (the shared pattern, routes, server rules, "Short names for compliance checks"), and the step 5a and 5b plan rulings.
- Approved screens: `docs/specs/rbac-ui/approved.md`, screens 27 and 28. Mockup: `docs/specs/rbac-ui/gen.py` (`complianceList`, `checkPage`, ~lines 1420–1510).
- The step 5b plan, `docs/superpowers/plans/2026-10-22-roles-5b-vulnerabilities-pages.md`, is the pattern this plan follows.

**Base:** `origin/main` 5ff22c0 (steps 1–5b merged). Branch `compliance-pages`, worktree `openvibes-platform-compliance`.

## User decisions (2026-10-24, before this plan)

1. **Passing is inferred from rule-set health.** A host passes a check when all of these hold:
   - it is active and in reach;
   - its last heartbeat (`agents.health`, within 24 hours) lists the check's rule set as assigned (`state` not `not_assigned`) and not refused;
   - the collector the check needs ran ok in its last scan;
   - it has no failing finding for the check.

   The agent reports only a count of rules it could not evaluate, so a host whose facts for this one rule were missing can be counted as passing.
2. **The last 14 days come from current findings.** For each day, the count is the hosts whose current finding was open that day, from first seen to fixed. An earlier episode (a check that failed, was fixed, then failed again) is not counted.
3. **Evidence is the fact and its value, plus the file.**
   - The fact and value come from the finding's detection inputs, for example `sshd.permitrootlogin = yes`.
   - The file comes from a small fact-to-file map, for example `sshd.*` → `/etc/ssh/sshd_config`.
   - There is no line number. Passing hosts have no evidence to show.
4. **The rule text comes from the existing optional fields.** `explain` is shown as "Why it matters", and `check` as "How to fix" (the exact setting and command). The rules repository adds both to the 85 baseline and hardening rules; the user reviews the wording and re-signs the sets. Until then the page shows the rule's message.

## Global Constraints

**List (screen 27)**
- **Each check shows a short name** (its title), with its rule ID and rule set under it. The long explanation moves to the check's page.
- **Filters:** Severity, State, Rule set, Area (Network exposure, SSH, Accounts, Packages, Kernel…), Group, Assignee, plus the Host chip from step 4.
- **Columns:**
  - Severity;
  - Check;
  - Area;
  - Failing ("2 of 5");
  - Hosts: a colour bar with words under it ("3 open · 2 mitigated · 6 pass");
  - Since;
  - Assignee.
- **Bulk:** the bulk bar stays (Set state ▾, Assign ▾, Add to case, Clear).
- **Shared pattern (§10.3):** `FilterBar` (search, chips with per-value counts, filters in the URL, Clear all, Save view, Columns), `SummaryLine`, the bulk bar, and rows that open a page.

**Page (screen 28)**
- **Header:** Set state ▾, Assign ▾, Add to case, Ask about this, ⋯.
- **Tiles:** failing on, passing, first seen, and the last 14 days as bars.
- **Left column:**
  - Why it matters;
  - How to fix (the exact setting and command);
  - Details (rule, rule set, applies to, reference);
  - History.
- **Right column:**
  - Hosts, with All / Failing / Passing. Each row shows its evidence.
  - Related: port, service, and checks in the same area.

**Server (§10.3)**
- **List counts:**
  - the list route accepts the page's filters;
  - it returns rows, the total, and the count of every value of every filter with the other filters applied, all from the same query.
- **Detail summary:** one route. The hosts table is paged.
- **Scope:** everything is scoped by §6. Counts never include hosts the viewer cannot see.
- **Panel links:** the finding side panel goes, and today's links to it redirect to the page.
- **Unchanged:** the triage states and their rules, the evidence agents send, and what each permission allows.

**Project rules**
- Files under 500 lines.
- Every code folder has a README.
- `docs/components/` pages are updated in the same change.
- The OpenAPI snapshot and the client are regenerated.
- The demo mirrors every route.
- Nothing users relied on may silently disappear: compare with the finding panel's tabs (Hosts, Evidence, History, trend) and the dashboard tiles.

**Environment (binding for every task)**
- This host is the user's production host. Never touch its own openvibes services or its system PostgreSQL (`/var/lib/pgsql`). Tests use only `eval "$(scripts/test-db.sh)"`, then stop it.
- Cargo commands run with `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target-compliance CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` under `nice -n 19 ionice -c3`. This is a separate target dir per worktree: shared dirs overwrite other worktrees' rlibs. Run one heavy command at a time.
- Playwright: demo `--workers=4`, live `--workers=2` with `--project=chromium --project=firefox`.
- Restore `web/dist/.gitkeep` before committing.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.

## Rulings in this plan (spec amendments, 2026-10-24)

Task 1 writes the user's decisions and these rulings into spec §10.3 as "Plan rulings, 2026-10-24 (step 5c)".

1. **A new list route, `GET /v1/compliance-list`.** The existing `/v1/compliance/*` routes stay for their current users: dashboards, the host page, the assistant and cases.
2. **What a row is.**
   - **The key** is (`rule_set_id`, `rule_id`).
   - **Pairs under a row:** every host in reach with a current finding for the check (`current_findings`), plus the hosts that pass it (user decision 1).
   - **Failing** means a current finding with `ended_at IS NULL`, seen within the window the current Compliance list uses by default. Ended findings are no longer failing.
   - **Title, message, explain and check** come from `console_rule_meta`, using the newest indexed version of the rule. A check without metadata shows its rule ID.
   - **Severity** is the severity of the newest finding.
   - **Since** is the earliest first-seen time among the failing pairs.
   - **"n of m":** n is failing hosts; m is failing plus passing hosts.
   - **The hosts bar** shows open, mitigated, accepted and false-positive counts among the failing pairs (by triage state, with an expired acceptance counting as open), then pass.
   - **Assignee** follows the 5b rule: One when exactly one person is assigned among the open failing pairs; Several(n) for n people; None when no open failing pair is assigned.
3. **Area** is derived from the rule ID, using a fixed map in code (`check_area(rule_id) -> &'static str`):
   - `port.*` → Network exposure;
   - `package.*` → Packages;
   - `harden.ssh.*` → SSH;
   - `harden.net.*` → Network;
   - `harden.kernel.*` and `harden.modules.*` → Kernel;
   - `harden.files.*` and `harden.fs.*` → Files;
   - `harden.accounts.*` and `harden.login.*` → Accounts;
   - `harden.lsm.*` → Security modules;
   - `harden.services.*` → Services;
   - `test.*` → Tests;
   - anything else → Other.
4. **Filter values** (one value per filter; all filters combine):
   - **State:**
     - `open` (the default), `mitigated`, `accepted_risk`, `false_positive`, `passing` and `all`;
     - a row matches when at least one of its pairs is in that state. A failing pair's state is its triage state, with no triage row counting as open.
   - **Severity:** the five levels.
   - **Rule set:** the sets of rows in reach, plus the chosen one.
   - **Area:** the areas of rows in reach.
   - **Group, Assignee and Host:** as on Alarms and Vulnerabilities.
5. **Search** covers the title, rule ID and rule set.
6. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50.
   - **Sorts:** severity (the default, worst first, then most failing), failing, since and title.
   - Ties are broken by key.
7. **The summary line:** "N checks failing on N hosts · N critical · N unassigned", followed by a count per rule set ("baseline N, hardening-linux-l1 N").
8. **Routes for the page:** `/compliance/{rule_set_id}/{rule_id}`, with `GET /v1/compliance/checks/{rule_set_id}/{rule_id}/summary` and `/hosts`. The spec's `/compliance/{rule_id}` is extended with the set, because rule IDs can repeat across sets.
9. **Old links.**
   - The `finding` panel kind and `FindingPanel.tsx` are removed.
   - `nav.open({kind:"finding", id:"set/rule"})` and `?open=finding:set/rule` go to the page, through `settle()` with replace.
   - Case items and the audit panel keep their refs and link through `nav`.
   - Old list URLs map: `state=all` stays; `severity` stays; the old `window`/`since` parameter is dropped.
   - Views saved in the browser under `openvibes.v2.views./compliance` are imported once.
10. **Bulk on rows** follows step 5b (user decision 2 of 5b, ruling 8 and the `open_only` refinement):
    - rows send compliance items `{rule_set_id, rule_id, open_only: true}`, plus `agent_id` when the Host chip is set;
    - Set state and Assign change only open, failing pairs in reach;
    - Reopen is offered only on the page's Hosts table;
    - passing hosts are never touched.

    Task 5 extends `open_only` to compliance items and checks what rule-wide compliance items do today.
11. **Hosts card segments:**
    - **All:** failing and passing;
    - **Failing:** a failing pair in any triage state;
    - **Passing:** inferred passing hosts.

    Rows show the host, OS and address, state, evidence, assignee and checked (the last observation for failing hosts; `health_at` for passing hosts). Failing rows have checkboxes. Passing rows have none, because there is nothing to triage.
12. **The 14 days** are 14 numbers, oldest first. Each is the failing hosts in reach on that UTC day: `first_observed_at` ≤ end of day, and `ended_at` null or after the start of day. They are shown with the existing `HourlyBars` pattern (generalised to N bars) or a new `DayBars`.
13. **Details:**
    - **Rule:** the rule ID and version.
    - **Rule set:** a link to it, with the version.
    - **Applies to:** from the rule set (`hardening-linux-*` → "Linux hosts"; baseline → "All hosts"; site sets → "Hosts with this rule set").
    - **Reference:** the rule's ATT&CK techniques from `attack` (there is no other reference field).
14. **History:** the triage history of pairs in reach, the episode starts and ends (first seen and `ended_at`, labelled "passes again"), and rule-set version publishes. Newest first, at most 50.
15. **Related:**
    - **Port:** for `port.*` checks, the port parsed from the rule expression (`'N' in facts['port.tcp.exposed']`) joined to `host_listeners` in reach (exposed on n hosts), linking to `/ports/{port}`.
    - **Service:** for `harden.services.*`, the unit parsed from the expression, joined to `host_services`, linking to `/services/{unit}`.
    - **Same area:** other failing checks in reach with the same area, as a count with their worst severity.
16. **Ask about this** sends `{kind:"finding", id:"set/rule"}`, as the panel does today. It is shown with `assistant.use`.
17. **⋯** holds Export (a CSV of the check's hosts in reach, with `compliance.export` or the existing findings export permission) and Copy link.
18. **Performance:** the list must answer within 2 s at full reach on a fleet of 10,000 hosts with 500,000 current findings (50 per host, `docs/sizing.md` "Finding changes"), with heartbeat health for every host. Record the scoped time too. Migration 0063 adds an index on `current_findings (rule_set_id, rule_id) WHERE ended_at IS NULL`, plus any other index the timing test needs.

## Review Focus

1. **A person reaching some groups opens a check failing on hosts in and out of reach.** Counts, passing, Hosts, the 14 days, History and Related must not count or name out-of-reach hosts. A check only on out-of-reach hosts answers 404. Pinned in Task 4 by `check_summary_stays_inside_the_scope` and in Task 2 by `check_list_counts_stay_inside_the_scope`.
2. **Passing never includes a host that does not run the rule set:** it is not assigned, refused, its heartbeat is stale, or its collector failed. Pinned in Task 2 by `passing_needs_an_assigned_healthy_rule_set`.
3. **An ended finding (the host was fixed)** is not failing. It counts as passing only when the host is otherwise healthy. Pinned in Task 2 by `ended_findings_are_not_failing`.
4. **Bulk Set state or Assign on a check row** changes only open, failing pairs in reach, with or without the Host chip, and never touches passing hosts. Pinned in Task 5 by `compliance_rows_change_only_open_failing_pairs`.
5. **Old links** from dashboards, the host page, cases, the audit panel and the palette land on the page with no dead history entry. Pinned in Task 8 by `old_finding_links_open_the_page`.

---

### Task 1: Spec rulings

**Files:**
- Modify: `docs/specs/2026-10-16-roles-permissions-design.md`. Add "Plan rulings, 2026-10-24 (step 5c)" after the step 5b section, with the user decisions and rulings 1–18. Also note that rule titles are already required by the protocol (`rule-set.schema.json` `required`), so the spec's planned `title` change is done.

- [ ] **Step 1: Write the section.** **Step 2: Commit** ("spec: step 5c rulings (compliance by check)").

---

### Task 2: The compliance list query

**Files:**
- Create: `crates/platform-store/src/check_list.rs` and `check_list_sql.rs`, following `vuln_list.rs` and `vuln_list_sql.rs`: hosts in reach from `console_host_group_membership` through the existing scope helpers, counts with `except(skip)`, one statement, and every parameter bound.
- Create: `crates/platform-store/src/check_area.rs` with `pub fn check_area(rule_id: &str) -> &'static str` (ruling 3), its SQL twin `console_check_area(text)` in migration 0063, and a parity test over every baseline and hardening rule ID.
- Create: `migrations/0063_compliance_checks.sql`: the index from ruling 18 and `console_check_area`. Set `SCHEMA_VERSION = 63`.
- Tests: `crates/platform-store/tests/check_list.rs`, plus an `#[ignore]`d timing test `check_list_timing.rs` at the ruling 18 scale.

**Interfaces:** produces
- `CheckQuery { q, state: CheckState (Open | Mitigated | AcceptedRisk | FalsePositive | Passing | All), severity, rule_set, area, group, host, assignee: Assignee, sort: CheckSort (Severity | Failing | Since | Title), descending, offset, limit }`;
- `check_list(client, &query, scope: &AgentScope, actor_id, now) -> CheckListPage { rows, total, counts, summary }`;
- `CheckListRow { rule_set_id, rule_id, title, severity, area, failing, passing, open, mitigated, accepted_risk, false_positive, since, assignee: AssigneeSummary }`;
- `pub fn passing_hosts_sql()`: the shared SQL fragment for user decision 1, reused by Task 4. It needs the collector per rule prefix: read the agent's collector names in `agents.health->'last_scan'->'collectors'` and map `harden.*` → `hardening`, `port.*` → the ports collector, `package.*` → the packages collector, and so on. Write the map in `check_area.rs` next to the area map.

- [ ] **Step 1: Write the failing tests:**
  - one row per check;
  - every filter and its counts with the other filters applied;
  - `check_list_counts_stay_inside_the_scope` (Review Focus 1);
  - `passing_needs_an_assigned_healthy_rule_set` (Review Focus 2): not assigned, refused, stale health and a failed collector each exclude the host;
  - `ended_findings_are_not_failing` (Review Focus 3);
  - triage counts, with an expired acceptance counting as open;
  - the assignee summary;
  - every sort, with stable paging;
  - search;
  - the summary line;
  - `check_area` parity;
  - the timing test (record full-reach and scoped medians, both under 2 s).
- [ ] **Step 2: Implement.** **Step 3: Run the tests** (platform-store). **Step 4: Commit.**

---

### Task 3: `GET /v1/compliance-list`, and compliance as a saved-views page

**Files:**
- Create: `crates/openvibes-console/src/compliance/list_page.rs` and `list_page_types.rs`, following `vulnerabilities/list_page.rs`. The route needs the permission today's Compliance list needs (findings read).
- Modify: `crates/openvibes-console/src/lists/mod.rs`. Add `PAGES` `"compliance"`, and `hideable("compliance")` = `area, failing, hosts, since, assignee`. Severity and Check are never hidden.
- Modify: OpenAPI, the snapshot, the client, and the demo route `web/src/demo/routes/checkList.ts`, with demo data that covers every filter, at least one passing-only check, an ended finding and an expired acceptance.
- Tests: `crates/openvibes-console/tests/check_list_http.rs` and demo vitest.

- [ ] **Step 1: Write the failing tests:**
  - validation of every parameter;
  - the response shape;
  - a scoped team lead;
  - assignee "me" resolved from the session;
  - the saved-views page "compliance" is accepted.
- [ ] **Step 2: Implement.** **Step 3: Run the tests**, then regenerate OpenAPI and the client. **Step 4: Commit.**

---

### Task 4: `GET /v1/compliance/checks/{set}/{rule}/summary` and `/hosts`

**Files:**
- Create: `crates/platform-store/src/check_summary.rs` (split into `check_summary_sql.rs` and `check_related.rs` if it nears 500 lines), and `crates/openvibes-console/src/compliance/page.rs` and `page_types.rs`.
- Create: `crates/openvibes-console/src/compliance/evidence.rs` with `fact_file(fact_key: &str) -> Option<&'static str>`, a fixed map: `sshd.*` → `/etc/ssh/sshd_config`; `file.<name>.*` → the path that `<name>` encodes; `sysctl.*` → `/etc/sysctl.conf and /etc/sysctl.d/`; and so on. Read the agent's hardening collectors in `../openvibes-agent/crates/openvibes-collectors/src/hardening/` for the real sources, and map only what they read.
- Tests: `crates/platform-store/tests/check_summary.rs` and `crates/openvibes-console/tests/check_page_http.rs`.

**Interfaces:** `CheckSummaryView` has:
- `header`: `{ title, severity, rule_set_id, rule_set_version, rule_id, rule_version, area, failing, checked, assignee }`;
- `tiles`: `{ failing, passing, first_seen: { at, hostname }?, days: [u32; 14] }`;
- `text`: `{ explain?, check?, message }`;
- `details`: `{ applies_to, techniques }`;
- `history`: up to 50 events (ruling 14);
- `related`: `{ port: { port, hosts }?, service: { unit, hosts }?, same_area: { checks, worst } }`;
- `can`: `{ triage, assign, add_to_case, ask, export }`.

`CheckHostsPage { rows: [{ agent_id, hostname, os, address, state (open|mitigated|accepted_risk|false_positive|passing), evidence: [{ fact, value, file? }], assignee, checked_at, triage_version? }], total, segments: { all, failing, passing } }`.
- Evidence comes from `current_findings.detection->'inputs'`. Masked, summarized or truncated inputs show their status, never a value. For a passing row, or a finding without detection, evidence is empty.

The routes answer 404 `check_not_found` when the check is out of reach.

- [ ] **Step 1: Write the failing tests:**
  - `check_summary_stays_inside_the_scope` (Review Focus 1);
  - passing in the tiles agrees with the list;
  - the 14 days on a fixture with a start, an end and a stale host;
  - the evidence mapping, including masked inputs;
  - segments add up and page;
  - Related port and service parsing;
  - the `can` flags.
- [ ] **Step 2: Implement.** **Step 3: Run the tests.** Regenerate OpenAPI and the client, and add the demo routes (`checkSummary.ts`). **Step 4: Commit.**

---

### Task 5: Bulk on check rows

**Files:**
- Modify: `crates/platform-store/src/bulk_triage.rs` (the compliance half) and `crates/openvibes-console/src/compliance/bulk.rs`.
  - Accept `open_only` on compliance items. Today `parse_items` refuses it there; the flag stays refused on alarm items.
  - A rule-wide or `open_only` compliance item makes Set state and Assign change only open, failing pairs. Pairs that are not open are skipped as "not open".
  - Ended findings are never expanded.
  - The cap counts only those pairs.
  - First read what rule-wide compliance items do today, and keep reopen and named-pair behaviour.
- Tests: extend `tests/bulk_triage.rs` and `bulk_http.rs`; mirror in the demo (`triage.ts`).

- [ ] **Step 1: Write the failing tests:** `compliance_rows_change_only_open_failing_pairs` (Review Focus 4), with and without `agent_id`; an ended finding is not touched; an expired acceptance is assigned as open.
- [ ] **Step 2: Implement.** **Step 3: Run the tests.** **Step 4: Commit.**

---

### Task 6: The Compliance list (screen 27), with the demo

**Files:**
- Rewrite: `web/src/views/investigate/Findings.tsx` as the Compliance list, in its own folder if it passes 500 lines. Use FilterBar, SummaryLine, ColumnsMenu, server paging, the bulk bar (ruling 10, with the 5b confirmation and note), and the columns of screen 27.
  - The hosts bar has an accessible name and `aria-valuetext`.
  - Rows link to `/compliance/{set}/{rule}` with a real `<a>` whose accessible name includes the rule ID.
- Modify: the registry (`/compliance` with prefix `/compliance/`), the old-URL mapping and the browser-views import (ruling 9).
  - Keep every helper the dashboard List tile still uses for `/compliance`, and keep the tile's filter catalogue (step 5b's lesson).
- Modify: the demo e2e specs that use the old list. Create `web/e2e/demo/check-list.spec.ts`:
  - filter by Area and Rule set, then reload and keep the filters;
  - save a view;
  - hide a column;
  - bulk Set state shows the host count;
  - old URLs keep their meaning;
  - axe.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 7: The rules text (rules repository)

**Repo:** `~/Projects/OpenVIBES/openvibes-rules`, its own branch `compliance-text` in a worktree, a separate PR opened by the controller.

**Files:**
- `baseline/rules.json` and `hardening/linux-l1/rules.json`: add `explain` (why it matters) and `check` (how to fix, with the exact setting and command) to all 85 rules, each at most 600 characters, in short plain sentences.
- Change no other field, and never touch `*.key` or the signed envelopes. The user reviews the wording in the PR and re-signs both sets on the branch, as for the alarm rules.
- Run the repo's checkers with `--sources-only`.

- [ ] **Step 1: Write the text.** **Step 2: Run the checks.** **Step 3: Commit** (no push; the controller opens the PR).

---

### Task 8: A check's page (screen 28); the finding panel goes

**Files:**
- Create: `web/src/views/investigate/check/CheckPage.tsx`, `CheckCards.tsx` and `README.md`.
  - **Header:** Set state ▾ and Assign ▾ (open_only items, with the 5b confirmation; hidden when nothing is open), Add to case (per row for case-only users, as in 5b), Ask about this, and ⋯ with Export and Copy link.
  - **Tiles:** Tile for failing on (linking to Hosts), FactTile for passing and first seen, and the 14 bars.
  - **Left column:**
    - Why it matters: `explain`, else the message;
    - How to fix: `check`, else nothing — the card says "No fix text yet" and links to the rule;
    - Details;
    - History.
  - **Right column:** Hosts (SegmentChips, the paged table, evidence as `fact = value` plus the file, checkboxes on failing rows only, a BulkBar with pair items and Reopen) and Related (RelatedCard).
- Remove: the `finding` panel kind and `panels/findings/FindingPanel.tsx` (ruling 9).
  - Grep to prove nothing still opens it.
  - Anything the panel offered that the page lacks must be added or kept: its Evidence tab's per-observation detail (`DetectionEvidence`) stays reachable from a host row.
- Modify: the demo e2e specs that use the panel. Create `web/e2e/demo/check-page.spec.ts`:
  - `old_finding_links_open_the_page` (Review Focus 5);
  - switch segments;
  - tick a failing host and set its state;
  - passing rows have no checkbox;
  - axe in light and dark.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 9: Live e2e, docs and the gate

**Files:**
- **Live e2e:** `web/e2e/live/compliance.spec.ts`. A team lead sees only their hosts' checks, the counts agree with the rows, and passing appears for a healthy host with the rule set assigned. They open a check page, switch segments, set one host's state, and the list row follows. Seed per browser, as `vulnerabilities.spec.ts` does.
- **Docs:**
  - a new `docs/components/console-compliance.md`, indexed, covering the list, the page, passing inference, the 14 days, evidence and the routes;
  - updates to `console-triage.md`, `platform-store.md`, `console-read.md` and `console-web.md`;
  - an Upgrading note: the finding panel became a page, old links redirect, passing is inferred, and rules without text show their message.
- Add the `check_list_timing` test to `~/Projects/OpenVIBES/testing.md`'s timing line (a workspace commit).

- [ ] **Step 1: Write the live journey and run it.**
- [ ] **Step 2: Run the full local gate** (`testing.md` §2, the browser items and both timing tests) once, in this worktree's own target dir. Expected: all green.
- [ ] **Step 3: Commit.**

---

## Self-review notes

- **Spec coverage:**
  - screen 27: filters, columns and bulk → Tasks 2, 3, 5 and 6;
  - screen 28: tiles, both columns and the header → Tasks 4, 7 and 8;
  - §10.3:
    - the shared pattern → Task 6;
    - routes and panel removal → Task 8;
    - list counts and scope → Tasks 2 and 3;
    - detail summary → Task 4;
    - "Short names for compliance checks" → already done in the protocol (Task 1 records it), and titles shown → Tasks 2 and 6.
- **New data:** migration 0063 (an index and the area function only). No agent or protocol change, by user decisions 1–4.
- **Not here:**
  - exact per-rule pass records, and file and line evidence (both need agent changes, if wanted later);
  - Cases (5d), Software, Services and Ports.
