# The Cases list and a case's page: implementation plan (step 5d)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the fourth page of step 5 of the roles spec:
- the Cases list (screen 31), with server-side filters, per-value counts, saved views, remembered columns and a summary line;
- a case's page, `/cases/{id}` (screen 32), which replaces the case side panel;
- the new item outcomes, Confirmed malicious and Expected activity, plus the console renames.

**Architecture:**
- **The list follows steps 5a–5c.** One store query (`case_list`) returns rows, the total, the per-value counts and the summary, all scoped by §6.
- **One summary route** (`GET /v1/cases/{id}/summary`) returns everything above the fold.
- **Outcomes live on items** (user decision). Closing a case needs a closing note, and every item that takes an outcome must have one.
- **Risk accepted** gets a re-open date per item.
- **Visibility** follows spec §6: a case with no items is visible to holders of `cases.read` on all hosts.

**Tech Stack:**
- Rust: axum, utoipa, tokio-postgres, `platform-store`;
- React and TypeScript web, with the demo server;
- vitest and Playwright.

**Spec:**
- `docs/specs/2026-10-16-roles-permissions-design.md`: §6 (case visibility), §10.3 ("Outcomes on case items", routes), and the 5a–5c plan rulings.
- Approved screens: `docs/specs/rbac-ui/approved.md`, screens 31 and 32. Mockup: `docs/specs/rbac-ui/gen.py` (around line 1668) and `docs/specs/rbac-ui/base/base-cases.json`.
- The current design: `docs/specs/2026-10-04-console-cases-design.md` and `docs/components/console-cases.md`.
- Pattern: `docs/superpowers/plans/2026-10-24-roles-5c-compliance-pages.md`.

**Base:** `origin/main` 16d23bc (steps 1–5c merged). Branch `cases-pages`, worktree `openvibes-platform-cases`.

## User decision (2026-10-25, before this plan)

1. **"Close case…" asks for a closing note only.**
   - Items carry the outcomes, and closing needs a short required summary note.
   - The case-level `resolution` stays on old closed cases and is shown on them, but new closes no longer set it.
   - Risk accepted keeps a re-open date, now per item.

## Global Constraints

**List (screen 31)**
- **Filters:** Status (closed hidden by default), Severity, Assignee, Contains (alarms / vulnerabilities / findings), Host, Group, and Updated (today / this week / quiet for 7 days or more).
- **Columns:**
  - Case;
  - Title, with who opened it and the latest note;
  - Severity;
  - Status;
  - Assignee;
  - Hosts;
  - Items (the kinds, and "n/m with an outcome" with a bar);
  - Updated.
- **Shared pattern (§10.3):** `FilterBar` (search, chips with per-value counts, filters in the URL, Clear all, Save view, Columns), `SummaryLine`, and rows that open a page.

**Page (screen 32)**
- **Header:** Edit, Assign ▾, Ask about this, Close case…, ⋯.
- **Tiles:** items, need an outcome (it counts down to "ready to close"), hosts, open for.
- **Left column:**
  - Details;
  - Hosts in this case, with their open problems;
  - Who can see it.
- **Right column:**
  - Items, with an Outcome per item: Confirmed malicious, Expected activity, False positive, Fixed, Risk accepted;
  - Notes and timeline: write a note at the top, newest first.

**Outcomes (§10.3)**
- Today's three outcomes stay, renamed in the console: `resolved` → Fixed, `false_positive` → False positive, `accepted_risk` → Risk accepted.
- Two are added: `confirmed_malicious` (Confirmed malicious) and `expected` (Expected activity).
- Every outcome except Fixed still needs a note.
- "Close case…" requires every item to have an outcome.

**Server and scope:** everything is scoped by §6, and counts never include hosts the viewer cannot see. The triage states and their rules, the evidence agents send, and what each permission allows are unchanged. A page shows a card or action only when the viewer holds its permission.

**Project rules**
- Files under 500 lines.
- Every code folder has a README.
- `docs/components/` pages are updated in the same change.
- The OpenAPI snapshot and the client are regenerated.
- The demo mirrors every route.
- Nothing users relied on may silently disappear: compare with the case panel and the current list.

**Environment (binding for every task)**
- This host is the user's production host. Never touch its own openvibes services or its system PostgreSQL (`/var/lib/pgsql`). Tests use only `eval "$(scripts/test-db.sh)"`, then stop it.
- Cargo commands run with `export CARGO_TARGET_DIR=~/.cache/openvibes-scratch/target-cases CARGO_BUILD_JOBS=6 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` under `nice -n 19 ionice -c3`. This is a separate target dir for this worktree. Run one heavy command at a time.
- Playwright: demo `--workers=4`, live `--workers=2` with `--project=chromium --project=firefox`.
- Restore `web/dist/.gitkeep` before committing.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.
- **One implementer at a time** in this worktree.

## Rulings in this plan (spec amendments, 2026-10-25)

Task 1 writes the user decision and these rulings into spec §10.3 as "Plan rulings, 2026-10-25 (step 5d)".

1. **Outcome values.** The wire values are `resolved`, `false_positive`, `accepted_risk`, `confirmed_malicious` and `expected`. The labels are Fixed, False positive, Risk accepted, Confirmed malicious and Expected activity.
   - A note is required for every outcome except `resolved`.
   - `resolved` still needs the evidence to be gone (today's rule).
   - `accepted_risk` needs `outcome_until`, a future date at most 365 days ahead (the same bound as today's case date).
2. **Which items take an outcome.** Alarms, compliance findings and vulnerabilities take one, as today. Host and software items are context and take none.
   - "n/m with an outcome" and "need an outcome" count only the items that take one.
   - Close needs every one of them in the case, hidden ones included: today's `HiddenItemsUnresolved` stays.
3. **Close and reopen.**
   - Closing needs `closing_note` (1–4000 characters), stored in `resolution_note`. `resolution` stays null for new closes, and old rows keep theirs.
   - When an item's `outcome_until` passes, the case reopens (lazily, as today) and that item's outcome clears. Today's case-level `accepted_until` reopen still works for old rows.
   - Reopen stays on ⋯.
4. **Visibility (spec §6).** A case is visible to its creator, its assignee, and anyone who can see one of its items' hosts. A case with no items is also visible to holders of `cases.read` on all hosts. Today's SQL lacks that last part, so this plan adds it.
5. **A new list route, `GET /v1/case-list`.** `GET /v1/cases` stays for its current users: Add to case, the palette and the badges.
6. **Filter values** (one value per filter; all filters combine):
   - **Status:** active (the default: not closed), open, investigating, closed, all.
   - **Severity:** critical, high, medium, low.
   - **Assignee:** me, unassigned, and people with at least one case visible to the viewer.
   - **Contains:** alarms, vulnerabilities, findings. A case matches when it holds at least one visible item of that kind.
   - **Host:** the Host chip; a case matches when it has a visible item on that host.
   - **Group:** groups with at least one host the viewer can see, plus the chosen one; a case matches when it has a visible item on a host in the group.
   - **Updated:** today, this week (the last 7 days), quiet (not updated for 7 days or more).
7. **Search** covers the title, `C-<number>`, the number alone, and the opener's name.
8. **Paging is by offset:** `offset` 0..=100000, `limit` 1..=100, default 50.
   - **Sorts:** updated (the default, newest first), severity, number and opened.
   - Ties are broken by case id.
9. **Row fields:**
   - number, title, opened by (name), the latest note (its first 120 characters and the time), severity, status, assignee;
   - hosts: distinct visible item hosts;
   - kinds: counts per kind among visible items;
   - `with_outcome` / `takes_outcome` counts, among visible items;
   - updated at.
10. **The summary line:** "N open · N investigating · N unassigned · N ready to close". A case is ready to close when it is not closed and every visible item that takes an outcome has one.
11. **Routes for the page:** `/cases/{id}`, with `GET /v1/cases/{id}/summary`. The existing `GET /v1/cases/{id}` stays as the full detail.
    - Old links: `nav.open({kind:"case", id})` and `?open=case:ID` go to the page, with replace.
    - `{kind:"case", id:"new"}` goes to `/cases/new`, which shows today's new-case form.
12. **The summary view:**
    - header facts: number, status, severity, opener, created, assignee;
    - tiles:
      - items, the count of visible items;
      - need an outcome, the visible items still without one, or "Ready to close";
      - hosts;
      - open for: created → now, or created → closed_at.
    - Details: title, severity, status, opener, created, updated, and the old resolution with its note if present;
    - hosts: each visible host with its open problems — open alarms, critical vulnerabilities and failing checks — using the step-4 problem rules and `open_failing` from 5c, counted only where the viewer holds that kind's read permission;
    - who can see it (ruling 13);
    - `can`: `{ edit, assign, close, reopen, note, outcome, ask, export }`.
13. **Who can see it:**
    - the opener and the assignee;
    - enabled people whose live role binding holds `cases.read` on all hosts, or on a group containing one of the case's item hosts.
    - At most 20 names are listed, plus "and N more". The names are shown only to viewers holding `access.read`; everyone else sees the count only.
14. **Ask about this** is shown when the assistant supports a `case` reference (check `assistant/`). If it doesn't, the page omits the button and the report says so.
15. **⋯** holds Export (a CSV of the items and timeline, with `cases.read`), Copy link, and Reopen (on a closed case, with `cases.write`).
16. **Performance:** the list must answer within 2 s at full reach on 10,000 hosts, 20,000 cases and 200,000 items. Record the scoped time too. Add indexes in migration 0064 if needed.

## Review Focus

1. **A person reaching some groups lists or opens a case whose items are partly out of reach.** Counts, hosts, kinds, "n/m", Hosts and Who can see it must not count or name out-of-reach hosts. A case invisible to them answers 404. Pinned in Task 3 by `case_list_counts_stay_inside_the_scope` and in Task 5 by `case_summary_stays_inside_the_scope`.
2. **A case with no items:** visible to its creator, its assignee, and `cases.read`-on-all-hosts holders, and to nobody else. Pinned in Task 2 by `an_empty_case_is_visible_to_all_hosts_readers`.
3. **Closing a case with a hidden item that has no outcome** is refused for someone who can't see that item, with a reason that names no host. Pinned in Task 2 by `close_needs_every_outcome_even_hidden`.
4. **Risk accepted per item:** when the date passes, the case reopens and only that item's outcome clears. Pinned in Task 2 by `an_expired_item_acceptance_reopens_the_case`.
5. **Old links** to the case panel from alarms, the check page, bulk results, Add to case and the badges land on the page, and `new` lands on the form. Pinned in Task 7 by `old_case_links_open_the_page`.

---

### Task 1: Spec rulings

**Files:**
- Modify: `docs/specs/2026-10-16-roles-permissions-design.md`. Add "Plan rulings, 2026-10-25 (step 5d)" after the step 5c section, with the user decision and rulings 1–16.

- [ ] **Step 1: Write the section.** **Step 2: Commit** ("spec: step 5d rulings (cases)").

---

### Task 2: Outcomes, close and visibility in the store

**Files:**
- Create: `migrations/0064_case_outcomes.sql`. Set `SCHEMA_VERSION = 64`.
  - `case_items.outcome` CHECK gains `confirmed_malicious` and `expected`.
  - Add `case_items.outcome_until timestamptz`, with `CHECK ((outcome = 'accepted_risk') = (outcome_until IS NOT NULL))`. Backfill existing `accepted_risk` items from their case's `accepted_until` when the case is closed with `accepted_risk`; otherwise use their `added_at` + 90 days and record it in the migration comment.
  - Relax the `cases` checks so a closed case needs `resolution_note` and `closed_at` but no `resolution`.
  - The note rule (`outcome IS NULL OR outcome='resolved' OR outcome_note IS NOT NULL`) stays.
- Modify: `crates/platform-store/src/console_cases.rs`. It is 2265 lines, so first split it into `console_cases/` (mod.rs plus `visibility.rs`, `list.rs` (the existing list), `items.rs`, `close.rs`, `reopen.rs` and `events.rs`), as a pure move, before changing anything.
  - `set_outcome` takes the new values and `outcome_until`.
  - `update` closes with `closing_note` and no resolution, keeping `blocking_items`.
  - `reopen_due` also reopens on an expired item `outcome_until` and clears that item.
  - `case_visible` adds the empty-case rule (ruling 4).
- Tests: extend `crates/platform-store/tests/console_cases.rs` (split it by area if it passes 500 lines).

- [ ] **Step 1: Write the failing tests:**
  - each new outcome, and its note rule;
  - accepted_risk needs a future date of at most 365 days;
  - `close_needs_every_outcome_even_hidden` (Review Focus 3);
  - close with a closing note only;
  - an old closed case keeps its resolution;
  - `an_expired_item_acceptance_reopens_the_case` (Review Focus 4);
  - `an_empty_case_is_visible_to_all_hosts_readers` (Review Focus 2);
  - the migration backfill.
- [ ] **Step 2: Split (pure move; suites green), then implement.** **Step 3: Run the platform-store suite.** **Step 4: Commit.**

---

### Task 3: The case list query

**Files:**
- Create: `crates/platform-store/src/case_list.rs` and `case_list_sql.rs`, following `check_list*.rs`: visible items through the shared scope base, counts with `except(skip)`, one statement, bound parameters.
- Tests: `crates/platform-store/tests/case_list.rs`, plus an `#[ignore]`d `case_list_timing.rs` at the ruling 16 scale.

**Interfaces:** produces
- `CaseQuery { q, status, severity, assignee, contains, host, group, updated, sort, descending, offset, limit }`;
- `case_list(client, &query, scope, actor_id, now) -> CaseListPage { rows, total, counts, summary }`, with the row fields of ruling 9.

- [ ] **Step 1: Write the failing tests:**
  - every filter and its counts with the other filters applied;
  - `case_list_counts_stay_inside_the_scope` (Review Focus 1);
  - search on the title, `C-104`, 104 and the opener's name;
  - every sort, with stable paging;
  - the latest-note preview;
  - the "n/m" counts take only outcome-taking items;
  - the summary line;
  - the timing test (full and scoped medians, both under 2 s).
- [ ] **Step 2: Implement.** **Step 3: Run the tests.** **Step 4: Commit.**

---

### Task 4: `GET /v1/case-list`, and cases as a saved-views page

**Files:**
- Create: `crates/openvibes-console/src/cases/list_page.rs` and `list_page_types.rs`, following `compliance/list_page.rs`. The route needs `cases.read`; validation gives `invalid_query` naming the field; "me" comes from the session.
- Modify: `crates/openvibes-console/src/lists/mod.rs`. Add `PAGES` `"cases"`, and `hideable("cases")` = `severity, status, assignee, hosts, items, updated`. Case and Title are never hidden.
- Modify: the outcome routes and types, so `SetCaseItemOutcomeRequest` takes the new values and `outcome_until`, and the close takes `closing_note`; plus the `responses.rs` messages, OpenAPI, the snapshot and the client.
- Modify: the demo, `web/src/demo/routes/caseList.ts` and `demo/cases.ts`. It mirrors the outcomes and close, and its seed has every outcome, an empty case, a case with a hidden item, an expired acceptance and a quiet case.
- Tests: `crates/openvibes-console/tests/case_list_http.rs`, plus the existing `cases_http.rs` updated for the new close and outcomes; demo vitest.

- [ ] **Steps: failing tests, implement, run the console suite and vitest, regenerate OpenAPI and the client. Commit.**

---

### Task 5: `GET /v1/cases/{id}/summary`

**Files:**
- Create: `crates/platform-store/src/case_summary.rs` (with `case_people.rs` for ruling 13), and `crates/openvibes-console/src/cases/page.rs` and `page_types.rs`.
- Tests: `crates/platform-store/tests/case_summary.rs` and `crates/openvibes-console/tests/case_page_http.rs`; the demo route `caseSummary.ts`.

**Interfaces:** `CaseSummaryView { header, tiles { items, need_outcome, hosts, open_for_seconds, ready }, details, hosts: [{ agent_id, hostname, os, problems { alarms?, critical_vulns?, failing_checks? } }], people { names?: [..20], total }, can }`. The route answers 404 `case_not_found` when the case is invisible.

- [ ] **Step 1: Write the failing tests:**
  - `case_summary_stays_inside_the_scope` (Review Focus 1);
  - host problems only for kinds the viewer can read;
  - people: names only with `access.read`, at most 20, with the total;
  - the `can` flags per permission;
  - the tiles, closed and open.
- [ ] **Step 2: Implement.** **Step 3: Run the tests**, then regenerate OpenAPI and the client. **Step 4: Commit.**

---

### Task 6: The Cases list (screen 31), with the demo

**Files:**
- Rewrite: `web/src/views/investigate/Cases.tsx` with FilterBar, SummaryLine, ColumnsMenu, server paging and the columns of screen 31.
  - The items cell shows kind icons with counts and an "n/m" bar with an accessible name.
  - Rows link to `/cases/{id}` with a real `<a>`.
  - "New case" links to `/cases/new`.
- Modify: the registry (`/cases` with prefix `/cases/`), the old-URL mapping and the browser-views import (`openvibes.v2.views./cases`).
- Modify: the demo e2e specs that use the old list (`cases.spec.ts`). Create `web/e2e/demo/case-list.spec.ts`:
  - filter by Contains and Updated, then reload and keep the filters;
  - save a view;
  - hide a column;
  - the "ready to close" summary;
  - axe.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 7: A case's page (screen 32); the case panel goes

**Files:**
- Create: `web/src/views/investigate/case/CasePage.tsx`, `CaseCards.tsx`, `NewCasePage.tsx` and `README.md`.
  - **Header:** Edit (title, severity, status), Assign ▾, Ask about this (ruling 14), and Close case…. The dialog asks for the closing note; when items lack an outcome it shows "N items still need an outcome" and blocks the close.
  - **⋯:** Export, Copy link, Reopen.
  - **Tiles** per ruling 12. **Left column:** Details, Hosts with their problems (linking to the host page and the filtered lists), Who can see it.
  - **Right column:** Items, each with an Outcome control. It offers the five outcomes; Fixed is disabled while the evidence is present; a note is required except for Fixed; Risk accepted needs a date. Remove item, and Add item, stay. Then Notes and timeline, with the note box at the top, newest first.
- Modify: `panels/cases/cases.ts` (labels, `outcomeChoices`, `outcomeNeedsNote`, `eventText` for the new values) and `ui/auditActions.ts` if case outcome labels appear there.
- Remove: the `case` panel kind, `panels/cases/CasePanel.tsx` (keep its pieces only where the page reuses them), and the `new` panel. Route every caller through `nav`: AlarmCards, Alarms, BulkBar results, CheckPage, AlarmPage, AddToCase, CaseBadge and the palette. Grep to prove nothing still opens the panel.
- Modify: the demo e2e specs that use the panel. Create `web/e2e/demo/case-page.spec.ts`:
  - `old_case_links_open_the_page` (Review Focus 5);
  - set each outcome, and the note rule;
  - close blocked, then allowed;
  - reopen;
  - a note at the top;
  - axe in light and dark.

- [ ] **Steps: failing tests, implement, vitest, then the changed specs, then the full demo e2e. Commit.**

---

### Task 8: Live e2e, docs and the gate

**Files:**
- **Live e2e:** `web/e2e/live/cases.spec.ts`, retry-safe (it restores state in `finally`).
  - A team lead sees only cases with items on their hosts, plus their own.
  - The counts agree with the rows.
  - They open a case, set an outcome, close it and reopen it.
  - Seed per browser.
- **Docs:**
  - `docs/components/console-cases.md` (list, page, outcomes, close, visibility, who can see it), indexed;
  - `console-web.md` and `platform-store.md`;
  - an Upgrading note: the case panel became a page; old links redirect; two new outcomes; closing asks for a note, not a resolution; Risk accepted dates are per item (old ones backfilled); empty cases are visible to all-hosts readers.
- Add `case_list_timing` to `~/Projects/OpenVIBES/testing.md`'s timing line (a workspace commit).

- [ ] **Step 1: Write the live journey and run it twice (`--repeat-each=2`).**
- [ ] **Step 2: Run the full local gate** (`testing.md` §2, the browser items and the timing tests) once, in this worktree's own target dir. Expected: all green.
- [ ] **Step 3: Commit.**

---

## Self-review notes

- **Spec coverage:**
  - screen 31 → Tasks 3, 4 and 6;
  - screen 32 → Tasks 5 and 7;
  - "Outcomes on case items" → Tasks 2 and 7;
  - §6 case visibility → Task 2;
  - routes and panel removal → Task 7.
- **New data:** migration 0064 (outcome values, item `outcome_until`, relaxed close checks). No protocol or agent change.
- **Not here:** Software, Services and Ports (5e onward).
