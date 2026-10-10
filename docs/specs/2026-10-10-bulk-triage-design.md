# Bulk triage and one detail view (alarms, compliance, vulnerabilities)

Issues #237, #239, #240 (user, production feedback on v0.2.6). Decisions
from the design session with the user, 2026-10-10:

1. **No investigation step.** Cases replace it.
2. **Bulk closes always need a note.**
3. **Selection:** single rows, the visible page, or **everything matching
   the filter**.
4. **One detail layout** for all three kinds: a summary on top, then tabs.
5. **Vulnerabilities get triage**, per host, like compliance findings.
6. **Bulk "Add to case"** picks an open case or creates one.

The interface comes first: every flow below is designed for the fewest
clicks that are still safe. The console-controls rules of #227 apply: no
native controls; `Select`, `Segmented`, `Switch`, `SelectField` only.

## 1. One state model for all three kinds

| State | Meaning | Note required |
|---|---|---|
| `open` | needs attention | — |
| `mitigated` | handled (fixed, removed, compensating control) | always |
| `accepted_risk` | known and accepted until a date | always |
| `false_positive` | not a real problem here | always |

- **Any state can move to any other in one step** (today's workflow forced
  `open → investigating → closed`). Reopening is `→ open`.
- **"Being worked on" means "in a case"**: a case badge on the row and in
  the detail view, from `case_items` (an item is active in at most one
  case).
- **`investigating` is removed.** A migration moves every `investigating`
  alarm and finding to `open`, keeps its assignee, note and case links, and
  writes a history row ("investigating retired; see the case"). The state
  CHECKs drop the value; the API refuses it with a clear message.
- The rules that exist stay: a recurrence reopens `mitigated` and expired
  `accepted_risk` (alarms and findings), test alarms close on arrival, and
  suppressions mark matching alarms `false_positive`. An accepted risk
  needs an expiry date (default 90 days, at most 1 year).
- **Assign** is separate from state: any item can be assigned or
  unassigned in one step, alone or in bulk.
- **Closing always requires a note** (`mitigated`, `accepted_risk`,
  `false_positive`), one item or many, as the server already enforces for
  one item; in bulk it goes on every item's history. Reopening, assigning
  and adding to a case need none.

## 2. Vulnerability triage (new, #240)

- Per **host × vulnerability**, the same key cases already use for
  vulnerability items (`agent/advisory`), so triage, cases and history
  line up. A new table `vulnerability_triage` (state, assignee, note,
  accepted_until, version, updated_at/by) and its history; migration
  next in line.
- **Fixed stays automatic**: when the host's package no longer has the
  vulnerability, the row leaves the open list whatever its triage state.
  A fix never reopens anything. A vulnerability that comes back on the
  same host (downgrade) keeps its old triage only if it was
  `accepted_risk` or `false_positive` and not expired; else it is `open`.
- Counts and the Overview treat `mitigated`, `accepted_risk` and
  `false_positive` vulnerabilities as not open, like the other kinds.
- Permissions: `vulnerabilities.triage` (agent-scoped), given to the same
  roles that have `compliance.triage`.

## 3. Selection and the bulk bar (all three lists)

- **Checkboxes** on every row of the Alarms, Compliance and
  Vulnerabilities lists, and on the Hosts tab of a detail view. Click a
  row to open it, click its box to select it; shift-click selects a range;
  `x` toggles the row under the keyboard cursor.
- **The header box** selects the visible page. Then a bar offers **"Select
  all 1,284 matching this filter"**: every row the list shows under the
  current filter, up to **10,000 items** (above that, the bar asks to
  narrow the filter). The lists filter in the browser, so the browser
  sends exactly those rows' ids: what you see is what changes, and
  nothing that arrives later is included (no second, server-side filter
  that could disagree). Where a list holds only its first results
  (vulnerabilities over the page bound), the bar says so.
- **The bulk bar** appears at the bottom of the view while anything is
  selected: "**12 selected** · Mitigate · Accept risk… · False positive… ·
  Assign… · Add to case… · (alarms) Suppress… · Clear".
  - Each action opens one small dialog: the note (required), plus the
    expiry for Accept risk, the person for Assign, the case for Add to
    case. The confirm button names the count: "Mitigate 12 alarms".
  - After the action: a toast with the result ("1,280 mitigated, 4
    skipped: already in another case"). History records every change,
    so a mistake is reopened from the list like any other item.
- Rows a user may not change (scope or permission) are skipped and
  counted, never silently changed.

## 4. Add to case, in bulk

- The dialog: a searchable list of open cases (`Select`, grouped by
  status) plus **New case…**, prefilled with a title from the selection
  ("12 alarms: A web server started a shell") and the highest severity.
- Items already active in another case are **skipped and listed** (an
  item is in at most one open case); the dialog offers "Open that case".
- Adding does not change an item's state. Closing the case later sets its
  items' outcome, as today.

## 5. One detail view: summary, then tabs

The same template for an alarm, a compliance finding (a rule across its
hosts) and a vulnerability (an advisory across its hosts):

```
┌ Redis is exposed                 High · 37 hosts · T1190 ┐
│ What it checks · why it matters (ATT&CK chips)           │
│ ▸ What to do: bind to loopback, or firewall and …        │
│ [Mitigate] [Accept risk…] [False positive…] [Add to case…] [Assign…] │
├ Hosts (37) │ Evidence │ History ──────────────────────────┤
│ ☐ host        state      last seen   case   assignee     │
│ ☐ web-01      open       2 min ago   —      —            │
│ ☐ web-02      open       5 min ago   #12    ola          │
│ 1–25 of 37                               ‹ 1 2 ›         │
└───────────────────────────────────────────────────────────┘
```

- **Summary:** title, severity, how many hosts, ATT&CK chips, one or two
  sentences on what it checks and why (rule `finding_message`; advisory
  summary for vulnerabilities), and **What to do** (the rule's fix text;
  the fixed package version for vulnerabilities). The action buttons act
  on **every open host**; the dialog says how many.
- **Hosts tab** (default): a real `DataTable` with its own filter, sort,
  checkboxes, the same bulk bar, and paging; it scrolls inside the panel
  and is never cut off (#239). An alarm has one host; its Hosts tab
  becomes **Process** (the process tree, as today).
- **Evidence tab:** the detection explanation (P17) and the rule
  definition, as today, for the selected host.
- **History tab:** state changes, notes, case links, with who and when.
- On a phone the summary stays; tabs become a segmented control
  (`Segmented`), and the Hosts table drops columns by width.

## 6. API

- `POST /api/v1/{alarms|compliance|vulnerabilities}/bulk` with
  `{action, items[], note, accepted_until?, assignee?, case_id? |
  new_case?}`, at most 10,000 items: alarm ids; compliance `{rule_set_id,
  rule_id, agent_id?}` (without `agent_id`: every host of that rule in
  the caller's scope); vulnerabilities `{advisory_id, agent_id?}` (the
  same). `action` is `state:<state>`,
  `assign`, `case` or (alarms) `suppress`. CSRF, idempotency key, the
  kind's triage permission (and `cases.manage` for case actions), scope
  enforced in SQL. Returns `{changed, skipped: [{id, reason}]}`.
- Single-item triage endpoints stay; they accept the new state model.
- One audit event per bulk action (`*.bulk_triage`, count, filter or ids),
  plus each item's history row.

## 7. Out of scope

Bulk actions on hosts or software; saved bulk rules ("always mitigate test
alarms": test alarms already close themselves); changing case workflows.
