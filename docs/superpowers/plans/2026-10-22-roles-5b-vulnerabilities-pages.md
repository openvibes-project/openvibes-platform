# The Vulnerabilities list and a vulnerability's page: implementation plan (step 5b)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the second page of step 5 of the roles spec:
- the Vulnerabilities list (screen 25), one row per CVE, with server-side filters, per-value counts, saved views, remembered columns and a summary line;
- a vulnerability's page, `/vulnerabilities/{key}` (screen 26), which replaces the advisory side panel.

**Architecture:**
- **The list is built on the shared pieces of steps 4 and 5a.** One store query (`vuln_list`) groups the host and advisory pairs in reach by CVE, and returns rows, the total, the per-value counts and the summary, all scoped by §6.
- **One summary route** (`GET /v1/vulnerabilities/{key}/summary`) returns everything above the fold. The hosts table has its own paged route with segment counts.
- **Triage is unchanged:** it is still stored per host and distribution advisory (`vulnerability_triage`). A CVE row acts on the pairs under it, through the existing bulk route.
- `GET /v1/vulnerabilities` stays as it is for its current users: dashboards, list widgets, the assistant and the host page.

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres, `platform-store`;
- React and TypeScript web, with the demo server;
- vitest and Playwright.

**Spec:**
- `docs/specs/2026-10-16-roles-permissions-design.md`: §6, §10.3 (the shared pattern, routes, server rules, "Due dates on advisories"), §13 and §15.
- Approved screens: `docs/specs/rbac-ui/approved.md`, the shared layout and screens 25 and 26. The interactive mockups are in `docs/specs/rbac-ui/gen.py` (`VULNSUI`, `advisoryPage`).
- The step 5a plan, `docs/superpowers/plans/2026-10-20-roles-5a-alarms-pages.md`, is the pattern this plan follows.

**Base:** `origin/main` 42649e6 (steps 1–5a merged). Branch `vulns-pages`, worktree `openvibes-platform-vulns`.

## User decisions (2026-10-22, before this plan)

1. **One row and one page per CVE,** as in the mockups.
   - An advisory without a CVE appears under its own ID.
   - Triage is still saved per host and advisory. Setting a CVE's state on a host changes that host's covering advisory. When that advisory also covers other CVEs, the page and the confirmation say which ones.
2. **Set state and Assign on a list row, and the page header's Set state, change the open hosts in reach.**
   - "In reach" means hosts where the viewer holds `vulnerabilities.triage`.
   - A confirmation says how many hosts will change.
   - Mitigated, accepted, false-positive and fixed pairs are left as they are.
   - To change only some hosts, tick them in the page's Hosts table.

## Global Constraints

**List (screen 25)**
- **Filters:** Severity, State (replaces "Include resolved"), Signals (Known exploited, Due within 30 days, No fix yet, Reboot needed, Lower confidence), Package, Group and Assignee, plus the Host chip from step 4.
- **Columns:**
  - Severity;
  - Advisory (the CVE), with Exploited;
  - Package, with "fixed in x" or "no fix yet";
  - CVSS;
  - EPSS;
  - Hosts ("n open of m", with a progress bar);
  - Due (the CISA date, amber when close);
  - Assignee.
- **Bulk:** ticking rows shows a bar with Set state ▾, Assign ▾, Add to case and Clear.
- **Shared pattern (§10.3):** `FilterBar` (search, chips with per-value counts, filters in the URL, Clear all, Save view, Columns), `SummaryLine`, the bulk bar, and rows that open a page.

**Page (screen 26)**
- **Header:** Set state ▾, Assign ▾, Add to case, ⋯. The CISA due date is a banner below the header.
- **Tiles:** open on, fix available, EPSS, CVSS.
- **Left column:**
  - What to do: the fixed build per distribution, and whether a reboot is needed;
  - Details: the distribution advisories, confidence and vector;
  - History.
- **Right column:**
  - Hosts, with All / Open / Mitigated / Resolved. Each row shows the installed version, state, assignee and covering advisory, with checkboxes for bulk triage.
  - Related: alarms, cases and same-package advisories.

**Server (§10.3)**
- **List counts:**
  - the list route accepts the page's filters;
  - it returns rows, the total, and the count of every value of every filter with the other filters applied, all from the same query.
- **Detail summary:** one route. The hosts table is paged.
- **Scope:** everything is scoped by §6. Counts never include hosts the viewer cannot see.
- **Panel links:** the advisory side panel goes, and today's links to it redirect to the page.
- **Due dates** come from `cve_enrichment.kev_due`.
- **Unchanged:** the triage states and their rules, the evidence agents send, and what each permission allows.

**Project rules**
- Files under 500 lines.
- Every code folder has a README.
- `docs/components/` pages are updated in the same change.
- The OpenAPI snapshot and the client are regenerated.
- The demo mirrors every route.

**Environment (binding for every task)**
- This host is the user's production host. Never touch its own openvibes services or its system PostgreSQL (`/var/lib/pgsql`). Tests use only `eval "$(scripts/test-db.sh)"`, then stop it.
- Cargo commands run with `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` under `nice -n 19 ionice -c3`. Run one heavy command at a time.
- Playwright: demo `--workers=4`, live `--workers=2` with `--project=chromium --project=firefox`.
- Restore `web/dist/.gitkeep` before committing.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.

## Rulings in this plan (spec amendments, 2026-10-22)

Task 1 writes the user's decisions and these rulings into spec §10.3 as "Plan rulings, 2026-10-22 (step 5b)".

1. **A new list route, `GET /v1/vulnerability-list`.** `GET /v1/vulnerabilities` stays as it is.
2. **What a row is.**
   - **The key** is the CVE ID, or the advisory ID for an advisory without CVEs.
   - **Pairs under a row:** every host and advisory pair in reach whose advisory names that CVE. This includes fixable pairs (`vulnerabilities`), pairs with no fix (`version_vulnerabilities` through `host_packages`), and, with the Lower confidence signal only, CPE matches (`cpe_findings`) for that CVE.
   - **Severity** is the worst severity among the covering advisories in reach.
   - **Title** is the title of the covering advisory with the most hosts in reach (ties by advisory ID).
   - **Exploited** means KEV or EUVD. **Due** is the earliest `kev_due`. **CVSS** and **EPSS** come from `cve_enrichment` for that CVE.
   - **Package** shows the first affected package name, plus "+n" for more. Under it:
     - "fixed in V" when every pair with a fix names the same fixed version;
     - "fixed in n versions" when the fixed versions differ;
     - "no fix yet" when no pair has a fix.
   - **Hosts** shows "n open of m". n is the open pairs (triage state open, and not fixed); m is every pair, whatever its state.
   - **Assignee** shows the one name when every open pair has the same assignee, "n people" when they differ, and "—" when none is assigned.
3. **Filter values** (one value per filter; all filters combine):
   - **State:**
     - `open` (the default), `mitigated`, `accepted_risk`, `false_positive`, `resolved` (fixed by an update) and `all`;
     - a row matches when at least one of its pairs is in that state.
   - **Severity:** critical, important, moderate, low and unrated, shown as today's labels.
   - **Signals:**
     - `exploited`;
     - `due30`: `kev_due` within 30 days of today, overdue included;
     - `nofix`;
     - `reboot`;
     - `lowconf`: only rows with a lower-confidence match (below today's `MIN_CONFIDENCE`), showing those matches. Without it, lower-confidence matches are left out, as today.
   - **Package:** the 50 package names with the most rows in reach, plus the chosen one.
   - **Group, Assignee and Host:** as on Alarms (5a rulings 2 and 3).
   - **Advisory** (`advisory=ID`): a removable chip, used by redirects (ruling 7). It keeps the CVEs that advisory names.
4. **Search** covers the CVE ID, advisory IDs, title and package names.
5. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50.
   - **Sorts:** priority (the default, today's rank: exploited, EPSS percentile, severity, CVSS), severity, CVSS, EPSS, hosts open and due.
   - Ties are broken by key.
6. **The summary line:** "N open on N hosts · N known exploited · N with a due date · N without a fix · N unassigned". The counts are rows, except hosts.
7. **Old links.** The `advisory` panel kind and `AdvisoryPanel.tsx` are removed. `nav.open({kind:"advisory", id})` and `?open=advisory:ID` go to `/vulnerabilities/ID`, and the summary route resolves the key:
   - **a CVE ID:** that page;
   - **an advisory with one CVE:** that CVE's page, with `key` set to the CVE, and the web replaces the URL;
   - **an advisory with no CVE:** its own page;
   - **an advisory with several CVEs:** 409 `advisory_has_several_cves`, and the web replaces the URL with `/vulnerabilities?advisory=ID&state=all`.

   Old list URLs map onto the new filters: `state=all`, `exploited=true` → `signal=exploited`, `reboot=true` → `signal=reboot`, `nofix=true` → `signal=nofix` and `lowconf=true` → `signal=lowconf`. When an old URL sets several flags, the first in that order wins.

   Views saved in the browser under `openvibes.v2.views./vulnerabilities` are imported once, as on Alarms.
8. **Bulk on rows** (user decision 2):
   - Each ticked row sends `{advisory_id}` items, one per covering advisory in reach, plus `agent_id` when the Host chip is set.
   - `set_state` and `assign` with advisory-wide items change only open pairs. The other states are skipped, with the reason "not open".
   - Reopen is not offered on list rows. It stays on the page's Hosts table, which sends `{agent_id, advisory_id}` pairs.
   - The confirmation shows the sum of the rows' open-in-reach counts, and names the other CVEs that the changed advisories also cover.
9. **Hosts card segments:**
   - **Open:** triage open and not fixed;
   - **Mitigated:** triage mitigated;
   - **Resolved:** fixed by an update, accepted risk or false positive;
   - **All:** every pair.

   The route is `GET /v1/vulnerabilities/{key}/hosts?segment=&offset=&limit=`. It returns rows (host, OS and address, installed version, state, assignee, covering advisory, triage version) and the four segment counts.
10. **Ask about this** sends the assistant the covering advisory with the most hosts in reach (`{kind:"advisory"}` as today), so the assistant does not change. It is shown with `assistant.use`.
11. **⋯** holds Export (a CSV of the CVE's hosts in reach, with `vulnerabilities.export`) and Copy link.
12. **Related:**
    - **Alarms:** open alarms on the affected hosts in reach, the top 3 and the total, shown only with `alarms.read`.
    - **Cases:** cases holding any pair of this CVE, shown only with `cases.read`.
    - **Same package:** other CVEs in reach on the same package names, as a count with their severities, linking to `/vulnerabilities?package=NAME`.
13. **Performance:**
    - The list must answer within 2 s at full reach on the `docs/sizing.md` fleet: 10,000 Debian hosts, 3.2 M fixable pairs, plus the pairs with no fix. Record the scoped time as well.
    - An index may be added in migration 0061 if the timing test needs one. No other schema change is planned.

## Review Focus

1. **A person reaching some groups opens a CVE whose hosts are partly out of reach.** The counts, Hosts table, What to do, History and Related must not count or name out-of-reach hosts. A CVE only on out-of-reach hosts must answer 404, like a missing one. Pinned in Task 4 by `cve_summary_stays_inside_the_scope` and in Task 3 by `list_counts_stay_inside_the_scope`.
2. **A Fedora advisory covering several CVEs.** Setting the state from one CVE row changes that pair, and the advisory's other CVE rows show the change. The confirmation names those CVEs. Pinned in Task 5 by `triage_on_one_cve_shows_on_its_siblings`.
3. **Bulk Set state or Assign on a CVE row** changes only the open pairs in reach. It leaves mitigated, accepted, false-positive and fixed pairs alone. Pinned in Task 5 by `bulk_on_cve_rows_changes_only_open_pairs`.
4. **Old links and URLs:**
   - `?open=advisory:FEDORA-…` from dashboards, cases, software, the palette and the host page lands on the right page, or on the filtered list, with no dead history entry;
   - old flag URLs keep their meaning.

   Pinned in Task 8 by `old_advisory_links_open_the_page` and in Task 7 by `old_vulnerability_urls_keep_their_filters`.
5. **The fleet at scale.** Debian hosts carry thousands of pairs with no fix, and the list must stay within ruling 13's budget. Pinned in Task 2 by the timing test.

---

### Task 1: Spec rulings

**Files:**
- Modify: `docs/specs/2026-10-16-roles-permissions-design.md`. Add "Plan rulings, 2026-10-22 (step 5b)" after the step-5a section, with the user decisions and rulings 1–13 above.

- [ ] **Step 1: Write the section.** **Step 2: Commit** ("spec: step 5b rulings (vulnerabilities by CVE)").

---

### Task 2: The vulnerabilities list query

**Files:**
- Create: `crates/platform-store/src/vuln_list.rs` (types and the function) and `vuln_list_sql.rs` (SQL). Follow `alarm_list.rs` and `alarm_list_sql.rs`: one base CTE of the pairs in reach, rows grouped by key, counts with `except(skip)`, one statement, and every parameter bound.
- Tests: `crates/platform-store/tests/vuln_list.rs`, plus an `#[ignore]`d timing test `vuln_list_timing.rs` at the ruling 13 scale, with a scoped case.

**Interfaces:**
- `VulnQuery { q, state: VulnState (Open | Mitigated | AcceptedRisk | FalsePositive | Resolved | All), severity, signal: Option<Signal> (Exploited | Due30 | NoFix | Reboot | LowConf), package, group, host, advisory, assignee: Assignee (from alarm_list), sort: VulnSort (Priority | Severity | Cvss | Epss | Open | Due), descending, offset, limit }`.
- `vuln_list(client, &query, scope: &AgentScope, actor_id, today: NaiveDate) -> VulnListPage { rows, total, counts, summary }`.
- `VulnListRow` has:
  - `key`, `title`, `severity`, `exploited`, `kev_due`, `cvss`, `epss`, `epss_percentile`;
  - `packages: Vec<String>` and `fixed: Fixed` (One(String) | Several(u32) | None);
  - `open`, `total`, `reboot`, `low_confidence: bool`;
  - `advisories: Vec<String>` (the covering advisories in reach);
  - `assignee: AssigneeSummary` (None | One(uuid, name) | Several(u32)).
- `VulnSummary { open_rows, hosts, exploited, with_due, no_fix, unassigned }`.

- [ ] **Step 1: Write the failing tests:**
  - an advisory with two CVEs gives two rows;
  - a CVE on Fedora and Debian advisories gives one row listing both advisories;
  - a CVE-less advisory is keyed by its ID;
  - no-fix pairs appear under their CVE with `fixed = None`;
  - each state, including `resolved` and `all`;
  - each signal: `due30` takes a date 10 days ahead and one 5 days past, and leaves out one 40 days ahead; `lowconf` shows CPE matches only then;
  - package, group, host, advisory and assignee;
  - `list_counts_stay_inside_the_scope` (Review Focus 1): no count, value, group or package comes from out-of-reach hosts;
  - search on CVE, advisory, title and package;
  - every sort, with stable paging;
  - the assignee summary (one, several, none);
  - the summary line;
  - the timing test (Review Focus 5): record the full-reach and scoped times, and keep both under 2 s.
- [ ] **Step 2: Implement.** **Step 3: Run the tests** (platform-store). **Step 4: Commit.**

---

### Task 3: `GET /v1/vulnerability-list`, and vulnerabilities as a saved-views page

**Files:**
- Create: `crates/openvibes-console/src/vulnerabilities/list_page.rs` and `list_page_types.rs`, following `alarms/list.rs`. Validation gives `invalid_query` naming the field; the route needs `vulnerabilities.read`.
- Modify: `crates/openvibes-console/src/lists/mod.rs`. Add `PAGES` `"vulnerabilities"`, and `hideable("vulnerabilities")` = `package, cvss, epss, hosts, due, assignee`. Severity and Advisory are never hidden.
- Modify: OpenAPI, the snapshot, the client, and the demo route `web/src/demo/routes/vulnList.ts`.
- Tests: `crates/openvibes-console/tests/vuln_list_http.rs` and demo vitest.

- [ ] **Step 1: Write the failing tests:**
  - validation of every parameter;
  - the response shape;
  - a scoped team lead;
  - assignee "me" resolved from the session;
  - the saved-views page "vulnerabilities" is accepted.
- [ ] **Step 2: Implement.** **Step 3: Run the tests**, then regenerate OpenAPI and the client. **Step 4: Commit.**

---

### Task 4: `GET /v1/vulnerabilities/{key}/summary` and `/{key}/hosts`

**Files:**
- Create: `crates/platform-store/src/vuln_summary.rs` (and `vuln_summary_sql.rs` if it nears 500 lines), and `crates/openvibes-console/src/vulnerabilities/page.rs` and `page_types.rs`.
- Tests: `crates/platform-store/tests/vuln_summary.rs` and `crates/openvibes-console/tests/vuln_page_http.rs`.

**Interfaces:** `VulnerabilitySummaryView` has:
- `key`, the canonical key (ruling 7);
- `header`: `{ title, packages, fixed, open, total, assignee, kev_due, ransomware }`;
- `tiles`: `{ open, total, fix: (All | Some(n_of_m distributions) | None), epss, epss_percentile, cvss, cvss_version }`;
- `what_to_do`: one entry per distribution (`os_id`, `os_version`), each with `{ advisory_id, url, packages: [{ name, fixed }], hosts, reboot }`;
- `details`: `{ advisories: [{ id, url, source }], published (min issued_at), confidence: { min, max, basis }, cvss_vector, cwe, description }`;
- `history`: up to 50 `vulnerability_triage_history` events for pairs in reach, newest first;
- `related`: `{ alarms: { top: [..3], total }?, cases: [{ id, number, title }]?, same_package: { cves, severities } }`;
- `also_covers`: other CVEs named by the covering advisories, for the confirmation in ruling 8;
- `can`: `{ triage, assign, add_to_case, ask, export }`, true when the viewer holds the permission on at least one host in reach.

`VulnerabilityHostsPage { rows: [{ agent_id, hostname, os, address, installed, state, assignee, advisory_id, triage_version }], total, segments: { all, open, mitigated, resolved } }`.

The routes answer 404 `vulnerability_not_found` out of reach, and 409 `advisory_has_several_cves` as in ruling 7.

- [ ] **Step 1: Write the failing tests:**
  - `cve_summary_stays_inside_the_scope` (Review Focus 1);
  - key resolution for each case of ruling 7;
  - what to do per distribution, with reboot;
  - the four segments add up and page;
  - history is scoped and capped;
  - related respects `alarms.read` and `cases.read`;
  - `also_covers` lists the sibling CVEs;
  - the `can` flags per permission.
- [ ] **Step 2: Implement.** **Step 3: Run the tests.** Regenerate OpenAPI and the client, and add the demo routes (`vulnSummary.ts`). **Step 4: Commit.**

---

### Task 5: Bulk on CVE rows

**Files:**
- Modify: `crates/platform-store/src/bulk_triage.rs` (and the console's `compliance/bulk.rs` if needed). With an advisory-wide vulnerability item (no `agent_id`), `set_state` and `assign` change only open pairs, and report the others as skipped "not open". First read what they do today, and keep pair items (`agent_id` and `advisory_id`) unchanged.
- Tests: `crates/platform-store/tests/bulk_triage.rs` (extend it) and an HTTP test.

- [ ] **Step 1: Write the failing tests:**
  - `bulk_on_cve_rows_changes_only_open_pairs` (Review Focus 3): advisory-wide `set_state` and `assign` skip mitigated, accepted and false-positive pairs, and never touch out-of-reach hosts;
  - `triage_on_one_cve_shows_on_its_siblings` (Review Focus 2): after the change, `vuln_list` shows the new state on both CVE rows of the advisory.
- [ ] **Step 2: Implement** (it may already hold; then only the tests land). **Step 3: Run the tests.** **Step 4: Commit.**

---

### Task 6: Shared detail pieces

**Files:**
- Create: `web/src/ui/detail/SegmentChips.tsx`, a radio group of `{ key, label, count }` with keyboard support, used by the Hosts card.
- Create: `web/src/ui/detail/RelatedCard.tsx`, with `{ sections: { label, value: ReactNode, href? }[] }`.
- Modify: `web/src/ui/detail/README.md`. Leave the alarm page's inline Related as it is.
- Tests: a unit test for each.

- [ ] **Steps: failing tests, implement, then vitest, tsc, eslint and the build. Commit.**

---

### Task 7: The Vulnerabilities list (screen 25), with the demo

**Files:**
- Rewrite: `web/src/views/investigate/Vulnerabilities.tsx` with FilterBar, SummaryLine, ColumnsMenu, server paging, the bulk bar (ruling 8, with the confirmation) and the columns of screen 25.
  - Rows link to `/vulnerabilities/{key}`, with a real `<a>` on the CVE.
  - The progress bar has an accessible name ("3 open of 5 hosts").
  - The due date is amber within 30 days and red when overdue.
- Modify: `views/lists/filters.ts`, removing the five `/vulnerabilities` flags. Keep `vulnerabilityQuery`, `groupByAdvisory` and `selectAdvisories` only if `useListRows` still uses them, and otherwise remove them.
- Modify: the registry: give `/vulnerabilities` the prefix `/vulnerabilities/`. Add the old-URL mapping (ruling 7) and the browser-views import.
- Modify: the demo (`vulnList.ts` complete, and demo data with CVEs shared across distributions, a multi-CVE advisory, no-fix pairs, due dates and assignees).
- Modify: the demo e2e specs that use the old list (`vulnerabilities.spec.ts`, `bulk.spec.ts` and smoke as needed). Create `web/e2e/demo/vuln-list.spec.ts`:
  - filter by Signals and Package, then reload and keep the filters;
  - save a view;
  - hide a column;
  - bulk Set state shows the host count and the other CVEs;
  - `old_vulnerability_urls_keep_their_filters` (Review Focus 4);
  - axe.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 8: A vulnerability's page (screen 26); the advisory panel goes

**Files:**
- Create: `web/src/views/investigate/vulnerability/VulnPage.tsx`, `VulnCards.tsx` and `README.md`.
  - **Header actions:** Set state ▾ and Assign ▾ (ruling 8, with the confirmation), Add to case, Ask about this, and ⋯ with Export and Copy link. The due banner sits below the header.
  - **Tiles:** Tile for "open on n of m" linking to the Hosts card, and FactTile for fix available, EPSS and CVSS.
  - **Left column:** What to do, Details, History.
  - **Right column:** Hosts (SegmentChips, the paged table, checkboxes and a BulkBar with pair items, Reopen included) and Related (RelatedCard).
  - The key resolution of ruling 7 uses `replace`.
- Remove: the `advisory` panel kind and `panels/findings/AdvisoryPanel.tsx`.
  - `nav.open({kind:"advisory"})` goes to `/vulnerabilities/{id}` and closes panels.
  - `?open=advisory:ID` goes to `/vulnerabilities/ID`.
  - `ObjectLink` hrefs follow.
  - Grep to prove no advisory panel use remains (the attention list, `cases.ts`, PackagePanel, CommandPalette, `rows.ts`, AlarmCards and HostCards still pass `{kind:"advisory"}` to `nav`, which now routes it).
- Modify: the demo e2e specs that use the panel. Create `web/e2e/demo/vuln-page.spec.ts`:
  - `old_advisory_links_open_the_page` (Review Focus 4: one CVE, no CVE, several CVEs);
  - switch segments;
  - tick two hosts and Set state;
  - the header Set state confirms the host count;
  - the due banner;
  - axe in light and dark.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 9: Live e2e, docs and the gate

**Files:**
- **Live e2e:** create `web/e2e/live/vulnerabilities.spec.ts`:
  - a team lead sees only their hosts' CVEs;
  - the counts agree with the rows;
  - they open a CVE page, switch segments, and set one host's state;
  - the list row's "n open of m" follows.

  Seed through the store, the way the other live specs do.
- **Docs:**
  - a new `docs/components/console-vulnerabilities.md`, indexed, covering the list, the page, the routes, the CVE grouping and the bulk semantics;
  - updates to `console-triage.md`, `platform-store.md` and `console-web.md` (move the vulnerability sections out);
  - an Upgrading note: the advisory panel became a page, rows are now CVEs, and old links and saved URLs redirect.

- [ ] **Step 1: Write the live journey and run it.**
- [ ] **Step 2: Run the full local gate** (`~/Projects/OpenVIBES/testing.md` §2 and the browser items) once. Expected: all green.
- [ ] **Step 3: Commit.**

---

## Self-review notes

- **Spec coverage:**
  - screen 25: filters, columns and bulk → Tasks 2, 3, 5 and 7;
  - screen 26: header, banner, tiles, both columns → Tasks 4, 6 and 8;
  - §10.3:
    - the shared pattern → Tasks 6 and 7;
    - routes and panel removal → Task 8;
    - list counts and scoping → Tasks 2 and 3;
    - detail summary → Task 4;
    - due dates from `kev_due` → Tasks 2 and 4.
- **New data:** none. Everything is already stored: advisories, CVEs, enrichment, triage, history and CPE matches. Migration 0061 is only for an index, if the timing test needs one.
- **Not here:**
  - Compliance, Cases, Software, Services and Ports (5c onward);
  - moving the alarm page onto `RelatedCard`.
