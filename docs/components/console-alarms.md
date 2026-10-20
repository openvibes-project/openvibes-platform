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
  off". The last part shows only when the server sends it (`hosts.read`).
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
  - so does a new alarm seen by the live poll;
  - that prefix covers `/alarm-list`, `/alarms` and `/alarm-suppressions`.

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
  alarm and its siblings) and Copy link.
- **Tiles:** starts matched (to Last 24 hours), different commands (to
  Commands seen), first seen and confidence.
- **Left:** What happened (the rule's `explain`, then `check`, as plain text
  with line breaks kept; until the rule has them, its title and message;
  then the evidence, "Why it triggered"); Details (a closed alarm's
  decision with Reopen; rule and set with versions, ATT&CK, last seen,
  received, assignee, case with Add to case, and the suppression: the one
  that closed it, or a waiting request with Withdraw); History.
- **Right:** Commands seen (every sibling, most starts first; each links to
  its page; the usual one has "Suppress this command…", the screen-12 form
  for *that sibling's* id, preset to the exact command; one seen once is
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
  - `app/liveAlarms.test.ts`: the prefix;
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
