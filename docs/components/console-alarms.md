# console-alarms (the Alarms list and an alarm's page)

The console's Alarms list (`/alarms`, approved screen 29) and an alarm's
page (`/alarms/{id}`, screen 30), from roles step 5a (spec §10.3, plan
`docs/superpowers/plans/2026-10-20-roles-5a-alarms-pages.md`). They are
built from the shared list and detail pieces in
[console-web.md](console-web.md#shared-list-and-detail-pieces), like the
Hosts pages ([console-hosts.md](console-hosts.md)).

## Interfaces

- `GET /api/v1/alarm-list`: filtered, counted, sorted and paged list
  (`crates/openvibes-console/src/alarms/list.rs`, store `alarm_list.rs`;
  [openvibes-console.md](openvibes-console.md), [platform-store.md](platform-store.md)).
- `POST /api/v1/alarms/bulk`: the bulk bar's actions ([console-triage.md](console-triage.md)).
- `GET|POST|DELETE /api/v1/saved-views`, `GET|PUT /api/v1/list-columns/alarms`
  ([saved-views.md](saved-views.md)).
- `GET /api/v1/agents/{id}`: the host chip's name, with `hosts.read`.
- `GET /api/v1/alarms/{id}/summary`: the page above the fold
  (`src/alarms/summary.rs`); `GET /api/v1/alarms/{id}` and
  `GET /api/v1/alarms/{id}/rule`: the evidence; `GET /api/v1/triage-history`:
  History; `GET|POST /api/v1/alarm-suppressions…`: Suppress…, a waiting
  request and Withdraw ([console-detection.md](console-detection.md)).

## The list (screen 29)

`views/investigate/Alarms.tsx` (`g m`, `alarms.read`).

- **Search** (`q`): message, rule id, host name, program and parent program.
- **Filters**, each value with the server's count under the other filters:
  - Severity;
  - State (open by default; mitigated, accepted risk, false positive, or
    All states, `state=all`);
  - Suppressed (Hidden by default, or Shown);
  - Host: only a chip, set by a host page's tiles and "Show all n"
    (`ListFilter.chipOnly`), named by `useHostName` (`views/lists/HostChip.tsx`);
  - Group;
  - Technique (ATT&CK ids from the rule-metadata index; the chips show
    ids only, and technique names are a follow-up);
  - Case (in a case, or not);
  - Assignee (me, unassigned, people).
  Saved views and columns are the page `alarms`; a saved view restores the
  host too. Views the old list kept in this browser
  (`openvibes.v2.views./alarms`) are moved to the console once
  (`importBrowserViews` with `alarmViewQuery`): `suppressed=true` becomes
  `shown`, the sort `last` becomes `seen`, and sorts that no longer exist
  are dropped with their direction.
- **Columns:**
  - Severity, never hidden;
  - Alarm: the message as a real link to `/alarms/{id}` (a new tab works),
    a Test badge for the test-trigger rules, and `parent → program · techniques`;
  - Host: name (or agent id) and its distribution or OS family;
  - Count;
  - Last seen and First seen: two columns that the Columns menu shows and
    hides together as "Last and first seen" (key `seen`);
  - State;
  - Assignee;
  - Case: the open case's number.

  Empty cells show "—", with their meaning for screen readers.
- **Sort:** on the server, by last seen (the default, newest first), first
  seen, count or severity. In the URL, `seen` is the API's `last_seen` and
  `first` is its `first_seen`.
- **Summary line:** "N open · N critical or high · N on hosts with alarms
  off". The last part shows only when the server sends it (`hosts.read`),
  and counts only hosts inside both the `alarms.read` and `hosts.read`
  reach.
- **Paging:** by offset, 50 a page, with Previous and Next (`Pager` from
  `Hosts.tsx`). The last page stays on screen while the next loads.
- **Selection:**
  - it is of the page on screen in its order (`selectionKey`, the whole
    list query), so a new filter, sort, direction or page empties it;
  - it holds only ids of rows on screen (`onPage`), so after a refresh the
    bar counts exactly the ids it sends;
  - the header box selects the page, and the table says "All n on this
    page are selected." (`DataTable serverPaged`), never "select all
    matching", because the bulk route takes ids, not a filter.
- **Bulk bar:**
  - Set state ▾ (Mitigate, Accept risk, False positive, and Suppress… with
    `alarms.suppress` everywhere);
  - Reopen, when closed alarms are selected;
  - Assign ▾;
  - Add to case.

  Rows have no Suppress… of their own; an alarm's page has one.
- **Empty states:** with no filter and nothing open, one request
  (`state=all&suppressed=shown&limit=1`) checks whether any alarm exists.
  If none does, "No alarms" says how alarms start. Otherwise "Nothing matches these filters" says closed and
  suppressed alarms are hidden unless State or Suppressed says otherwise.
- **Freshness:**
  - a change from the bulk bar, the suppress form, Add to case on an alarm or the alarm's page
    invalidates the prefix `/api/v1/alarm` (`ALARMS_PREFIX`, `app/liveAlarms.ts`);
  - that prefix covers `/alarm-list`, `/alarms` and `/alarm-suppressions`;
  - a change seen by the live poll refreshes `/alarms` and
    `/alarm-suppressions` at once (the alarm's page, the old list), but the
    heavier `/alarm-list` at most every 30 s and only while the tab is
    visible (`listRefresh`).

  The menu's count stays on `app/liveAlarms.ts`.
- **Old links:** `?suppressed=true` is rewritten in place to
  `suppressed=shown` (a history replace). Unknown
  parameters (such as `window`) are never sent, because the API refuses them.

## An alarm's page

`/alarms/{id}` belongs to the Alarms view (`prefix: "/alarms/"`;
`views/investigate/alarm/`, see its README). It replaced the alarm panel,
which is gone. A path that is not an id (a sub-path, a bad escape), a
missing alarm and one on a host out of reach (404) show "No such alarm".

- **Header:** the message, severity and state; the host (to its page), the
  program chain and last seen. Set state ▾ and Assign ▾ (the inline bulk
  bar, with `can.triage`), Suppress… (screen 12, with `can.suppress`; not
  while a request waits or once suppressed), Ask about this (ruling 6,
  `can.ask`), and ⋯ with Export (ruling 7, `can.export`: a CSV of the
  alarm and its siblings) and Copy link (the address without its anchor;
  an error toast when the clipboard refuses). Assign ▾ offers other people
  only with the page's per-host `can.assign`.
- **Tiles:** starts matched (to Last 24 hours), different commands (to
  Commands seen), first seen (any command) and confidence.
- **Left:** What happened (the rule's `explain`, then `check`, as plain text
  with line breaks kept; until the rule has them, its title and message;
  then the evidence, "Why it triggered"); Details (a closed alarm's
  decision with Reopen; rule and set with versions, ATT&CK, this alarm's
  first seen, last seen,
  received, assignee, case with Add to case, and the suppression: the one
  that closed it, or a waiting request with Withdraw); History.
- **Right:** Commands seen (every sibling, most starts first; each links to
  its page; the usual one has "Suppress this command…", the screen-12 form
  for *that sibling's* id, preset to the exact command, or "A request for
  this command is waiting for approval" when one already waits; one seen once is
  highlighted with Add to case for that sibling); the process chain; Last
  24 hours (`HourlyBars`); Related (other open alarms on the host,
  vulnerabilities with `vulnerabilities.read`, and the same rule elsewhere
  linking to `/alarms?q=<rule_id>`, ruling 9).
- **Old links:** an alarm panel link (`?open=alarm:ID` on any view, from
  dashboards, cases, suppressions, the host page or the attention list) is
  `/alarms/ID` with no panels (`app/location.ts` `redirect`, `pagePath`);
  `nav.open` and `ObjectLink` go there too, and a direct load replaces the
  URL so history keeps no dead entry. A popped-out alarm window from before
  is dropped. The server serves `/alarms/{alarm_id}` (`frontend-contract.json`).

## The suppress form (screen 12)

Suppress… on an alarm's page (with `can.suppress`), "Suppress this
command…" on a command seen, and Suppress… in the list's bulk bar open the
suppress form (`panels/alarms/SuppressForm.tsx`):

- **What:** this program (its path) or this exact command (path and
  masked arguments, shown).
- **Where:** this host, each group from
  `GET /api/v1/alarm-suppressions/options`, then All hosts when the
  caller's suppress reach is global.
- **For:** 7 days (the default), 30 days or until removed.
- **Reason:** required; the button stays off until it is filled.
With approval on, the note reads "Someone who can approve on those hosts
must accept it. Until then these alarms keep arriving." and the button
says Request; otherwise Suppress. An active result toasts "Suppressed ·
recorded in the audit log" (the server has closed the alarm); a waiting
one toasts "Requested · waiting for approval". Refusals show the
server's field message in `role="alert"`; the controls are disabled
while it sends. `bodyOf` (the POST body) and `whereChoices` are pure and
tested. Keys typed in any dialog or textarea never move a table cursor;
closing the form returns focus to the button that opened it (the shared
`Modal`). An alarm with a waiting request shows it instead of
Suppress…; until the waiting list has loaded, or if it fails, none is
offered, so nobody asks twice.

## Data behind the page

- **Summary** (`GET /api/v1/alarms/{id}/summary`, store
  `alarm_summary::alarm_summary`): the alarm, its tiles, rule text, siblings
  (agent alarms on the same host with the same rule set, rule, program and
  parent; user decision 1), the 24 hourly sums and the Related card, in one
  call scoped like the list
  ([openvibes-console.md](openvibes-console.md#an-alarms-page-summary),
  [platform-store.md](platform-store.md#an-alarms-page-alarm_summaryalarm_summary-roles-5a)).
- **Hourly starts** (`alarm_hourly_starts`, schema 60): ingest adds a new
  alarm's count, or a resend's growth, to the hour it receives it
  ([openvibes-ingest.md](openvibes-ingest.md)). Hours before the upgrade
  have no rows, so the timeline starts filling then; maintenance keeps 7 days.
- **Rule metadata** (`console_rule_meta`, schema 59): each stored bundle's
  rule title, message, ATT&CK pairs and optional `explain` and `check`
  (at most 600 characters, protocol rule fields agents ignore), indexed
  from the verified bundle ([console-detection.md](console-detection.md)).
  A rule without text shows its title and message; an unindexed rule shows
  the alarm's message. The baseline alarm rules carry text from the rules
  repository's next release.

## Upgrading

The alarm panel became this page and old links redirect; the timeline
starts filling after the upgrade; rules without text show their title;
sorting by message, host or state is gone; alarm views saved in the
browser move to the account. List rows no longer carry their own
Suppress… or "Requested / Waiting for approval" badge (both are on the
alarm's page), search no longer matches the agent id, popped-out alarm
windows are dropped, and "Load more" became paging. See [console-web.md](console-web.md#upgrading).

## Failure behaviour

- A refused or failed load shows the error box; on the page, a failed
  waiting-request load shows it in Details and offers no Suppress….
- A refused bulk action is a toast, and the selection stays.

## Demo

`demo/routes/alarmList.ts` answers like the server. The seed
(`demo/data.ts`) has:

- two siblings of alarm 9000 on its host (same rule, program and parent;
  other arguments), so the page's commands have a usual one and one seen
  once;
- a suppressed, closed alarm, so Suppressed has a value, with its active
  exact-command suppression #900 (`demo/suppressions.ts` seeds it when
  storage lacks it).

## How to test

- **Unit:**
  - `views/investigate/Alarms.test.tsx`: the API query, columns, no row
    Suppress…, hidden columns, the summary line, filters and the id;
  - `ui/DataTable.test.tsx`: the server-paged selection bar;
  - `ui/list/FilterBar.test.tsx`: chip-only filters;
  - `app/liveAlarms.test.ts`: the prefixes and the list's 30 s throttle;
  - `demo/routes/alarmList.test.ts`, `demo/routes/alarmSummary.test.ts`;
  - `views/investigate/alarm/AlarmPage.test.tsx`: tiles, rule text and its
    fallback, Commands seen, actions by permission, suppression, Related,
    Export, the waiting request;
  - `app/location.test.ts` (`old_alarm_links_open_the_page`), `app/registry.test.tsx`.
- **E2E (demo):**
  - `e2e/demo/alarm-list.spec.ts`: Severity and Technique, then a reload;
    a saved view; a hidden column; bulk Suppress…; the row link; axe;
  - `e2e/demo/alarm-page.spec.ts`: `old_alarm_links_open_the_page`,
    `suppress_this_command_uses_that_line`, Set state and Reopen, Add to
    case on a command seen once, the timeline, axe light and dark;
  - `alarms.spec.ts`, `bulk.spec.ts`, `alarm-suppressions.spec.ts`,
    `detection.spec.ts`, `cases.spec.ts`.
- **E2E (live, `scripts/test-console-e2e.sh`):** `e2e/live/alarms.spec.ts`:
  a team lead reaching only `page-1` (seeded with an alarm and two
  siblings by `scripts/console-e2e-server.sh`) sees only its three alarms,
  the counts agree with the rows, and the page shows the tiles, Commands
  seen and the last 24 hours.
- **Real agent (CI `alarms-e2e`):** `scripts/alarms-e2e.sh` checks the
  summary after three starts: `tiles.starts` is 3 in one hourly bucket.
- **Server:** `cargo test -p openvibes-console --test alarm_list_http
  --test alarm_summary_http`; `cargo test -p platform-store --test
  alarm_list --test alarm_summary --test alarm_hourly --test rule_meta`.
