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
  - Technique (ATT&CK ids from the rule-metadata index);
  - Case (in a case, or not);
  - Assignee (me, unassigned, people).
  Saved views and columns are the page `alarms`; a saved view restores the
  host too.
- **Columns:**
  - Severity, never hidden;
  - Alarm: the message as a real link to `/alarms/{id}` (a new tab works),
    a Test badge for the test-trigger rules, and `parent → program · techniques`;
  - Host: name (or agent id) and its distribution or OS family;
  - Count;
  - Seen: last seen, then "first …";
  - State;
  - Assignee;
  - Case: the open case's number.

  Empty cells show "—", with their meaning for screen readers.
- **Sort:** last seen (newest first by default), count and severity, on the
  server; `seen` in the URL is the API's `last_seen`.
- **Summary line:** "N open · N critical or high · N on hosts with alarms
  off". The last part shows only when the server sends it (`hosts.read`).
- **Paging:** by offset, 50 a page, with Previous and Next (`Pager` from
  `Hosts.tsx`). The last page stays on screen while the next loads.
- **Selection:**
  - it is of the page on screen, and a new filter, order or page empties it;
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
- **Empty states:** "No alarms" says how alarms start when nothing exists
  at all. Otherwise "Nothing matches these filters" says closed and
  suppressed alarms are hidden unless State or Suppressed says otherwise.
- **Freshness:**
  - a change from the bulk bar, the suppress form or the alarm panel
    invalidates the prefix `/api/v1/alarm` (`ALARMS_PREFIX`, `app/liveAlarms.ts`);
  - so does a new alarm seen by the live poll;
  - that prefix covers `/alarm-list`, `/alarms` and `/alarm-suppressions`.

  The menu's count stays on `app/liveAlarms.ts`.
- **Old links:** `suppressed=true` is sent as `suppressed=shown`. Unknown
  parameters (such as `window`) are never sent, because the API refuses them.

## An alarm's page

`/alarms/{id}` belongs to the Alarms view (`prefix: "/alarms/"`). Until
screen 30 lands, it shows the alarm's panel content full width, with
"← Alarms", so a row never dead-ends. `?open=alarm:ID` still opens the
panel. A path that is not an id (a sub-path, a bad escape) shows
"No such alarm".

## Failure behaviour

- A refused or failed load shows the error box.
- A refused bulk action is a toast, and the selection stays.

## Demo

`demo/routes/alarmList.ts` answers like the server. The seed
(`demo/data.ts`) has:

- two siblings of alarm 9000 on its host (same rule, program and parent;
  other arguments), so the page's commands have a usual one and one seen
  once;
- a suppressed, closed alarm, so Suppressed has a value.

## How to test

- **Unit:**
  - `views/investigate/Alarms.test.tsx`: the API query, columns, no row
    Suppress…, hidden columns, the summary line, filters and the id;
  - `ui/DataTable.test.tsx`: the server-paged selection bar;
  - `ui/list/FilterBar.test.tsx`: chip-only filters;
  - `app/liveAlarms.test.ts`: the prefix;
  - `demo/routes/alarmList.test.ts`.
- **E2E (demo):**
  - `e2e/demo/alarm-list.spec.ts`: Severity and Technique, then a reload;
    a saved view; a hidden column; bulk Suppress…; the row link; axe;
  - `alarms.spec.ts`, `bulk.spec.ts`, `alarm-suppressions.spec.ts`,
    `detection.spec.ts`.
