# console-compliance (the Compliance list and a check's page)

The console's Compliance list (`/compliance`, approved screen 27) and a
check's page (`/compliance/{rule_set_id}/{rule_id}`, screen 28), from roles
step 5c (spec §10.3 and its "Plan rulings, 2026-10-24 (step 5c)", plan
`docs/superpowers/plans/2026-10-24-roles-5c-compliance-pages.md`). One row
and one page per check, a rule of a rule set; triage is still saved per
host and check. They are built from the shared list and detail pieces in
[console-web.md](console-web.md#shared-list-and-detail-pieces), like the
Alarms and Vulnerabilities pages. This page ties the parts together; the
details live with each part:

- API: [openvibes-console.md](openvibes-console.md#compliance-list) ("Compliance list" and "A check's page");
- store: [platform-store.md](platform-store.md#the-compliance-list-check_listcheck_list-check_area-schema-63) and the section after it;
- web: [console-web.md](console-web.md) (Views, Compliance; "A check's page");
- bulk: [console-triage.md](console-triage.md#compliance-in-bulk);
- timings: [console-read.md](console-read.md#acceptance-measurement).

## Interfaces

| Route | What | Code |
|---|---|---|
| `GET /api/v1/compliance-list` | the list, filtered, counted, sorted and paged (`compliance.read`) | `src/compliance/list_page.rs`; store `check_list*.rs`, `check_area.rs` |
| `GET /api/v1/compliance/checks/{set}/{rule}/summary` | the page above the Hosts card | `src/compliance/page.rs`; store `check_summary*.rs`, `check_related.rs` |
| `GET /api/v1/compliance/checks/{set}/{rule}/hosts?segment=&state=&offset=&limit=` | the Hosts card (All, Failing by triage state, Passing) | `src/compliance/page.rs`; store `check_states.rs` |
| `GET /api/v1/compliance/latest/{agent}/{set}/{rule}` | one host's latest observation, for View evidence | `src/compliance/latest.rs` |
| `POST /api/v1/compliance/bulk` | Set state, Assign, Reopen, Add to case | `src/compliance/bulk.rs`; store `bulk_triage/compliance.rs` |
| `GET /api/v1/compliance/*` (summary, groups, latest) | unchanged, for dashboards, the host page, the assistant and cases | `src/compliance/groups.rs`, `latest.rs` |

Web: `views/investigate/Findings.tsx` (the list) and
`views/investigate/check/` (the page). The demo mirrors the routes in
`src/demo/routes/checkList.ts` and `checkSummary.ts`, with hand-made checks
in `src/demo/checkSeed.ts`. A finding from before rule sets (an empty set)
is addressed as `~unknown`.

## What a row counts

- **Failing:** a current finding, not ended (`ended_at IS NULL`), seen in
  the last 24 hours (`check_list_sql::WINDOW`). A fixed (ended) finding is
  not failing here or anywhere else in the console.
- **Open failing:** failing, and its triage state is open: no triage row,
  open, or an accepted risk past its date (`check_list_sql::open_failing`).
  The host page's tile and top failing and the Hosts list count exactly
  this, so all three agree with the list.
- **Passing** is inferred (user decision 1); no agent reports it. A host
  passes when it is active and in reach, its heartbeat health is at most
  24 hours old and lists the rule set with a version, neither
  `not_assigned` nor refused, that version's indexed bundle has the rule,
  the rule's collectors ran `ok` in its last scan, and no finding blocks
  it. **Ceilings:** the agent reports only a count of rules it could not
  evaluate, so a host whose facts for this one rule were missing passes;
  a site rule with no known prefix needs every reported collector `ok`;
  a host stuck in a resync with an unended P13 match is neither failing
  nor passing. Passing hosts have no evidence and nothing to triage.
- **"n of m"**: n failing hosts, m failing plus passing. The hosts bar
  shows open, mitigated, accepted and false positive among the failing,
  then pass.
- **Severity:** the newest finding's, else the rule's indexed severity.
  **Title:** the newest indexed title, else the rule ID (a rule without
  metadata).
- **A stale host** (last contact older than the 24-hour window) has no
  current findings to count: the host page shows "—" ("No report in the
  last day") instead of a failing count, and the Hosts list shows "—" in
  its Problems column and leaves it out of "none open".

## The page

Header (severity, rule ID, set and version, area, "failing on N of M hosts
checked", assignee; Set state, Assign and Add to case on the open failing
hosts; Ask about this; ⋯ Export and Copy link). Tiles: Failing on,
Passing, First seen, and **the last 14 days**: per UTC day, oldest first,
the failing hosts in reach whose current finding was open that day, from
first seen to its end (user decision 2). An earlier episode of the same
check on the same host is not counted, since only the current finding is
kept. Cards: Why it matters (`explain`, else the message), How to fix
(`check`, else "No fix text yet"), Details, History (triage, started
failing, passes again, rule-set publishes; 50 at most), Hosts and Related
(the port or service the rule names, and the same area's other failing
checks).

**Evidence** (user decision 3) is the fact and its value from the
finding's detection inputs (`sshd.permitrootlogin = yes`; a masked,
summarized or truncated value shows only its status), plus the file the
agent's collector reads, from the fixed map `compliance/evidence.rs`
`fact_file` (`sshd.*` → `/etc/ssh/sshd_config`, `os.*` → `/etc/os-release`,
`kernel.modules.disabled` → `/etc/modprobe.d/`, and so on; one label where
the collector reads several sources). There is no line number. View
evidence on a host opens its latest observation with "Why it triggered".

## Bulk

Rows send `{rule_set_id, rule_id, open_only: true}` (plus `agent_id` with
the Host chip). Set state and Assign change only open, failing pairs in
reach; mitigated, accepted and false-positive pairs, ended findings,
passing hosts and hosts out of reach are never touched or counted toward
the 10,000 cap, and a row with none open left is skipped as "not open".
There is no Reopen on the list: it is on the page's Hosts card, which
sends named `{agent_id, rule_set_id, rule_id}` pairs. **Add to case** from
a row adds only its failing (not ended) findings, closed ones included; a
named pair is added as before.

## Configuration

None of its own. The 24-hour window and the collector map are fixed in
code (`check_list_sql::WINDOW`, `check_area::check_collectors`). Rule text
comes from the signed rule sets' optional `explain` and `check` fields.

## Failure behaviour

- The list answers 400 `invalid_query` naming the parameter, 401 signed
  out, 403 without `compliance.read`, 503 when the store fails; the last
  page stays on screen while the next loads.
- The page's routes answer 404 `check_not_found` for a check with no
  failing or passing host in reach (out-of-reach hosts are never counted
  or named), and 400 `invalid_query` naming the parameter for a bad
  `segment`, `state`, `offset` or `limit`.
- Bulk changes skip pairs out of reach and report the rest in `skipped`
  with their reason.

## Upgrading

- The finding panel became the check's page. Old links redirect with no
  dead history entry: `?open=finding:set/rule`, and links from dashboards,
  the host page, cases, the audit log, the palette and assistant
  citations. Old list URLs keep `state=all` and `severity`; the old
  `window`/`since` is dropped. Views saved in the browser under
  `/compliance` or `/findings` move to the person's account once.
- Bulk on list rows changed: Add to case from a row now adds only the
  check's failing (not ended) findings, never a fixed host, and list rows
  have no Reopen; reopen hosts from the check page's Hosts card.
- Passing is inferred from heartbeat health (above), so a host shows as
  passing only once it sends health with its rule sets.
- Rules without `explain` and `check` text show their message and "No fix
  text yet" until the rule sets carry them.
- Fixed (ended) findings no longer count as failing anywhere, so existing
  compliance counts (host page, dashboards, Hosts list) may drop.
- Hosts with no report in the last day show "—" for failing checks
  instead of their last-known count, and are no longer "none open".

## How to test

- Store: `tests/check_list.rs`, `tests/check_list_filters.rs`,
  `tests/check_area.rs`, `tests/check_summary.rs`,
  `tests/bulk_triage_compliance.rs`, `tests/ended_findings.rs`,
  `tests/host_list_stale.rs`, `tests/host_summary.rs`; timing
  (ignored, the ruling 18 fleet; the list and a widespread check's page,
  full and scoped, under 2 s):
  `cargo test -p platform-store --test check_list_timing -- --ignored --nocapture --test-threads=1`.
  Any change to `check_list*.rs`, `check_summary*.rs` or `check_related.rs`
  runs it before its PR (the workspace `testing.md` gate).
- Console HTTP: `tests/check_list_http.rs`, `tests/check_page_http.rs`,
  `tests/bulk_http_compliance.rs`, `tests/hosts_list_http.rs`.
- Unit: `views/investigate/Findings.test.tsx`,
  `views/investigate/check/CheckPage.test.tsx`,
  `demo/routes/checkList.test.ts`, `demo/routes/checkSummary.test.ts`.
- Demo e2e (`npm run test:e2e:demo`): `e2e/demo/check-list.spec.ts`,
  `e2e/demo/check-page.spec.ts`.
- Live e2e (`scripts/test-console-e2e.sh`): `e2e/live/compliance.spec.ts`,
  a team lead's list holds only their hosts' checks, its counts agree with
  the rows, a healthy host running the set passes, and one host's state
  set on a check's page moves the row's hosts bar.
