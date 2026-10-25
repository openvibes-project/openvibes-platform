# console-cases

Cases over `/api/v1` (module `crates/openvibes-console/src/cases/`, store
`platform_store::console_cases`, schemas 35, 36 and 64). Spec:
[2026-10-04-console-cases-design.md](../specs/2026-10-04-console-cases-design.md).
The API, store and tests are built, and so are the web pages (list, case
panel, "Add to case"; see [console-web.md](console-web.md#cases)).

## Purpose

A case is where one investigation happens: a title, a status, items that
link to existing objects (alarm, finding, vulnerability on a host, host,
software), notes, an assignee, and a timeline of everything that was done.
Cases do not replace the alarm, finding and vulnerability views; they gather
what belongs together. Nothing is closed without evidence that it is gone, or
a recorded decision to accept the risk or call it a false positive.

A case stores links (kind and id), never copies. Each item's scope is that of
its host, so a user with a limited scope never learns that an item outside it
exists: it is left out of the case's items, counts and timeline, with no
placeholder. Hosts decide (user decision 2026-10-25): a user sees a case if
one of its host-bound items is on a host in their scope, or they opened it,
or it is assigned to them; any other case answers 404, the same as one that
does not exist. A software item has no host, so it never makes a case
visible: a case with no item, or with only software items, is seen by who
opened it, who it is assigned to, and anyone whose scope is every host (step
5d ruling 4). Software items are still shown inside a case the user can
already see. The rule is one SQL fragment (`visibility::case_visible`, with
`item_in_scope` deciding and `item_visible` choosing the items shown), used by
every read, change, lock and count.
A change uses the scope that `cases.write` and `cases.read` share (by asset
group), so it never reaches a case or item the caller cannot read.

## Interfaces

Browser session only; a service-account bearer token gets 403, for reads too.
Changes also check CSRF and the browser origin. `cases.read`,
`cases.write` and `cases.assign` are host-scoped permissions (Analyst and
Admin hold all three since schema 51; `cases.manage` became `cases.write`
and `cases.assign`); changes need `cases.write` and `cases.read`, and
setting or changing the assignee also `cases.assign`.

| Route | Needs | Result |
|---|---|---|
| `GET /api/v1/cases` | `cases.read` | `CasePage` `{items, next_cursor}`. Filters `status` (`open`, `investigating`, `closed`, `all`; default open and investigating), `severity`, `assignee` (a user id, `me`, `none`), `q` (title text or `C-104`), `cursor`, `limit` 1–100 (50). Newest change first. Kept for Add to case, the palette and the badges |
| `GET /api/v1/case-list` | `cases.read` | `CaseListView`: the Cases list page (see below) |
| `GET /api/v1/cases/{id}/summary` | `cases.read` | `CasePageSummaryView`: a case's page above the fold (see below) |
| `POST /api/v1/cases` | `cases.write` (`cases.assign` with an assignee) | `201 CaseDetailView` + `ETag`. Body `{title, severity?, assignee_user_id?, items?: [{kind, ref}]}`, at most 50 items |
| `GET /api/v1/cases/{id}` | `cases.read` | `CaseDetailView` + `ETag` (the version) |
| `PUT /api/v1/cases/{id}` | `cases.write` (`cases.assign` to change the assignee), `If-Match` | `CaseDetailView` + new `ETag` |
| `POST /api/v1/cases/{id}/notes` | `cases.write` | `201 CaseEventView`; body `{body}` |
| `POST /api/v1/cases/{id}/items` | `cases.write` | `201 CaseItemView`; body `{kind, ref}` |
| `DELETE /api/v1/cases/{id}/items/{item_id}` | `cases.write` | 204; open cases only |
| `PUT /api/v1/cases/{id}/items/{item_id}/outcome` | `cases.write` | `CaseItemView`; body `{outcome: "resolved" \| "false_positive" \| "accepted_risk" \| "confirmed_malicious" \| "expected" \| null, note?, outcome_until?}` (`outcome_until` an RFC 3339 time, only with `accepted_risk`; a malformed one is 422 `invalid_timestamp` on that field) |
| `GET /api/v1/cases/for-item?kind=&ref=` | `cases.read` | `{items: [{case: CaseSummaryView, item_id, outcome}]}` |
| `GET /api/v1/cases/assignees` | `cases.assign` | `{items: [{user_id, username, display_name}]}`: enabled users who hold `cases.read` |

`CaseSummaryView` (also the head of `CaseDetailView`, which adds
`resolution_note`, `items` and `events`): `case_id`, `number` (shown as
`C-<number>`, never reused), `title`, `status` (`open`, `investigating`,
`closed`), `resolution` (`mitigated`, `false_positive`, `accepted_risk`; only
on cases closed before step 5d), `accepted_until` (the same), `severity` (`critical`, `high`, `medium`, `low`),
`assignee` and `opened_by` (`{user_id, username, display_name}`),
`created_at`, `updated_at`, `closed_at`, `version`, `item_count` and
`pending_item_count` (items the viewer can see; the second counts alarms,
findings and vulnerabilities without an outcome).

`CaseItemView`: `item_id`, `kind` (`alarm`, `finding`, `vulnerability`,
`host`, `software`), `ref`, `agent_id`, `hostname`, `active`, `outcome`,
`outcome_note`, `outcome_until` (accepted risk's re-open date), `added_by`,
`added_at`, `title`, `severity`, `evidence_gone`.

| `kind` | `ref` (as the web panels write it) | Exclusive | Needs an outcome |
|---|---|---|---|
| `alarm` | the platform's alarm id (`42`) | yes | yes |
| `finding` | `agent/rule_set/rule`; the rule set may be empty (`agent//rule`) | yes | yes |
| `vulnerability` | `agent/advisory` (one advisory on one host) | yes | yes |
| `host` | the agent id | no | no |
| `software` | `manager/name`; the name may contain `/` | no | no |

An exclusive item is in at most one open case. A database index enforces it,
so two requests racing cannot both win. Closing a case frees its items;
reopening takes them back and fails with 409 if one has since joined another
open case.

`CaseEventView`: `event_id`, `at`, `actor` (null for the platform), `kind`
(`created`, `note`, `status`, `assigned`, `severity`, `item_added`,
`item_removed`, `item_outcome`, `resolved`, `reopened`), `body` (a note's
text; the resolution note for `resolved`; the outcome note for
`item_outcome`) and `detail`: `{from, to}` for `status`, `severity` and
`assigned` (usernames); `{item_id, item_kind, item_ref, item_agent_id}` on
item entries, plus `{from, to, until}` on `item_outcome`; `{}` for `resolved`
(before step 5d `{resolution, accepted_until}`); `{reason}` for `reopened`
(`manual`, `accepted_risk_expired` or `evidence_returned`). The timeline is oldest
first and append-only (a trigger refuses UPDATE and DELETE).

### The Cases list page (`GET /api/v1/case-list`)

Step 5d rulings 5–10, following the other list pages (`compliance-list`):
query parameters `q` (title, `C-<number>`, the number, or the opener's
name), `status` (`active`, the default: not closed; `open`,
`investigating`, `closed`, `all`), `severity`, `assignee` (`me` from the
session, `unassigned`, or a user id), `contains` (`alarms`,
`vulnerabilities`, `findings`: a visible item of that kind), `host` (an
agent id), `group` (a host group id), `updated` (`today` since midnight
UTC, `week`, `quiet`: not for 7 days or more), `sort` (`updated`, the
default, `severity`, `number`, `opened`; ties by case id), `dir`, `offset`
0–100000 and `limit` 1–100 (50). Empty values count as absent; anything
else, an unknown parameter included, is 400 `invalid_query` naming it.
The lazy reopen checks run first. The answer is `{items, total, counts,
summary, generated_at}`: each row has `case_id`, `number`, `title`,
`status`, `severity`, `opened_by`, `assignee`, `latest_note` (`{text, at}`,
the newest note's first 120 characters), `hosts` (the first five visible
hosts, `{agent_id, hostname}`), `host_count`, `kinds` (visible items per
kind), `with_outcome` / `takes_outcome` (visible alarms, findings and
vulnerabilities), `ready` (not closed, and close would take it now: close's
own rule, hidden items included; only this boolean is revealed) and
`updated_at`; `counts` has every value of `status`,
`severity`, `contains`, `updated`, `group` and `assignee` with the other
filters applied; `summary` is `{open, investigating, unassigned,
ready_to_close}` over the cases that are not closed under every filter but
status, ready by close's own rule (hidden items included). The page
`cases` keeps saved views and hidden columns (`severity`, `status`,
`assignee`, `hosts`, `items`, `updated`; case and title never hide).

### A case's page (`GET /api/v1/cases/{id}/summary`)

Step 5d rulings 12–14 (store `case_summary.rs` and `case_people.rs`, route
`cases/page.rs`). Session only; the lazy reopen checks run first; a missing,
malformed or invisible case is 404 `case_not_found`. The answer
(`CasePageSummaryView`; the name `CaseSummaryView` was already the list
item) is:

- `header`: `case_id`, `number`, `title`, `status`, `severity`,
  `opened_by`, `created_at`, `assignee`, `version`;
- `tiles`: `items` (visible), `need_outcome` (visible alarms, findings and
  vulnerabilities without an outcome), `hosts` (distinct visible hosts),
  `open_for_seconds` (created to now, or to `closed_at`) and `ready` (not
  closed and close's own rule, `blocking_item`, passes over every item,
  hidden ones included: the same as the list's "ready to close");
- `details`: title, severity, status, opener, created, updated, closed,
  the pre-5d `resolution` and the `resolution_note`;
- `hosts`: each visible item's host by name, `{agent_id, hostname, os,
  problems: {alarms, critical_vulns, failing_checks, compliance_stale}}`;
  each count is null unless the caller's `alarms.read`,
  `vulnerabilities.read` or `compliance.read` reaches that host (open
  agent alarms, `host_listed_critical` and `open_failing`, as the Hosts
  list counts them). A host in compliance reach with no report in the
  last day has `compliance_stale` true and a null failing count, since 0
  would be wrong;
- `people`: who can see it, `{names, total, complete}`: enabled people
  with a live binding to Administrator or to a role holding `cases.read`
  on all hosts, on a group holding a host of one of the case's host-bound
  items in the caller's reach, or (the opener and the assignee) at any
  scope. A person who sees the case only through a host the caller cannot
  see is neither named nor counted, so `complete` is true exactly when
  the caller reads cases on every host (the page shows "N", otherwise "at
  least N"); it never depends on the case's hidden items. `names` (at most
  20, by name) only with `access.read`, else null;
- `can`: `edit` and `note` (`cases.write`, and the case visible in the
  scope `cases.write` and `cases.read` share), `assign` (that and
  `cases.assign`), `close` / `outcome` (that, not closed), `reopen` (that,
  closed), `ask` (always false: the assistant takes no case reference) and
  `export` (`cases.read`).

### Changing a case

`PUT` replaces the editable fields, so send them all: `title` (1–120
characters, trimmed), `severity`, `status`, `assignee_user_id` (absent or
`null` means nobody) and, to close, `closing_note` (1–4000 characters,
stored as the detail's `resolution_note`; a case that stays closed sends the
one it has). `resolution` and `accepted_until` are refused since step 5d
(400 `invalid_request` naming the field; `null` counts as absent), as the
items carry how a case ended; an old case's own stay readable. Sending
the current values
changes nothing and writes nothing. The version rises with each change to
those fields; notes, items and outcomes move `updated_at` only, so adding a
note does not make someone else's edit stale. `If-Match` is the quoted
version from the last `ETag`.

Statuses move freely between `open` and `investigating`. `closed` needs:

1. a closing note (`closing_note` in the store, field errors
   `closing_note_required`, `closing_note_not_allowed` on any other status,
   `invalid_note`); new closes set no resolution;
2. an outcome on every alarm, finding and vulnerability, `resolved` only
   while its evidence is still gone. Items the closing user cannot see are
   not theirs to clear: if any has no outcome, the answer is 409
   `hidden_items_unresolved` until someone with that scope clears them.

Setting a status other than `closed` on a closed case reopens it and clears
its note (and an old case's resolution and date). A closed case keeps how it
ended: a different closing note, adding or removing items, and setting
outcomes are 409
`case_closed` until it is reopened. Title, severity, assignee and notes can
still change.

An item outcome is `resolved` (only when `evidence_gone`; a note is
optional), `false_positive`, `accepted_risk`, `confirmed_malicious` or
`expected` (a note is required). `accepted_risk` also needs `outcome_until`,
a time after now and at most 365 days ahead (`outcome_until_required`,
`_past`, `_too_far`); the other outcomes take none (`_not_allowed`). Any
other outcome, or clearing it, drops the date. Evidence is gone when:

- finding: the agent's current finding is missing or has ended
  (`ended_at` set);
- vulnerability: no open row (`fixed_at` empty) for that host and advisory,
  and no no-fix match through the host's package versions;
- alarm: the alarm's own triage is `mitigated`, or the alarm no longer exists.
  An alarm in another state, even `false_positive` or `accepted_risk`, still
  stands: those are decisions, so mark the item the same way.

The evidence is checked when the outcome is set and again when the case
closes; a `resolved` item whose evidence came back blocks the close (409
`items_unresolved`). Hosts and software take no outcome (422).

Severity is set when the case is created (the highest item severity, with
`important` counted as high, `moderate` as medium, and `info` and `unrated` as
low; medium with none) and is changed only by hand.

When an item's `outcome_until` passes, its closed case reopens as `open`
(audit actor `system`, timeline `reopened` with reason
`accepted_risk_expired`, then an `item_outcome` entry per expired item, shown
only to those who can see it) and only those items lose their outcome, so
someone decides again; the case's note clears. A case closed before step 5d
with a case-level `accepted_until` still reopens on that date, and then all
its `accepted_risk` items lose the outcome. On a case that is not closed,
an acceptance that runs out clears the same lazy way (`item_outcome`
with reason `accepted_risk_expired`, audit `case.item.outcome` by
`system`) and the status stays, so the case is no longer ready to close.
The checks skip closed cases one of whose items another open case holds,
so those never fill the 100-case batch. Migration 64 dated the existing
`accepted_risk` items: the case's `accepted_until` when it was closed as
accepted risk, otherwise the upgrade time + 90 days, so nothing reopens or
clears on upgrade day. This runs when cases are listed or read, so it happens
the next time anyone looks. A case whose item has since joined another open
case stays closed.

When the evidence of a `resolved` item comes back (the agent reports the
finding again, the host matches the advisory again, the alarm recurs and
reopens), the case reopens as `open` in the same lazy way (audit actor
`system`, `case.reopen` with reason `evidence_returned` and the items'
kinds and refs). The rules:

- **Which cases are re-checked.** Only cases closed within the last 30 days
  (`EVIDENCE_WATCH_DAYS`) that hold an alarm, finding or vulnerability item
  with the outcome `resolved`, at most 100 per call, newest closing first. This
  keeps every list and read cheap (one indexed query on `closed_at`, plus the
  evidence lookups of a few `resolved` items) and covers the cases people still
  care about. After 30 days a recurrence is a new matter: the item was freed
  when the case closed, so it can go into a new case.
- **The returning item** loses its outcome and note, so someone decides again.
  The case's other outcomes stay, including `resolved` ones whose evidence is
  still gone. The case's resolution, note and date clear.
- **Decisions are never re-checked.** `false_positive` and `accepted_risk`
  items stay as decided even while the object is plainly still there; accepted
  risk reopens on its date, as above. A case closed as accepted risk does
  reopen if one of its `resolved` items comes back.
- **Exclusivity.** If a returning item has since joined another open case, the
  case stays closed.
- **Timeline.** One `reopened` entry (`detail.reason` `evidence_returned`)
  that names no item, then one `item_outcome` entry per returning item (`from`
  `resolved`, `to` null, `reason` `evidence_returned`). As with any item
  entry, a viewer who cannot see an item is not shown its entry, so a hidden
  item is never named. The `reopened` entry itself is shown to everyone who
  sees the case.

### Audit

`case.create`, `case.update`, `case.note`, `case.item.add`,
`case.item.remove`, `case.item.outcome`, `case.close`, `case.reopen` (target
kind `case`), each in the same transaction as the change and its timeline
entry. The audit detail holds the case number and facts such as the status,
resolution or item `kind` and `ref`; never a note's text (`case.note` records
its length). Notes are plain text, visible to everyone who can see the case:
authors are told not to write about items outside the readers' scope.

## Limits

500 items and 2,000 timeline entries per case; 50 items when creating. Page
size 1–100. Titles 120 characters, notes 4,000.

## Configuration

None.

## Failure behaviour

| Situation | Result |
|---|---|
| no session | 401 |
| bearer token, no `cases.read` or `cases.write` | 403 |
| missing or wrong CSRF token or origin on a change | 403 |
| unknown, malformed or invisible case | 404 `case_not_found` (the same answer) |
| item missing, or outside the caller's scope, or not in the case | 404 `item_not_found` (the same answer, so nothing is revealed) |
| invalid JSON body, unknown field, invalid query or cursor, invalid `If-Match` | 400 |
| missing `If-Match` / stale version | 428 / 412 `stale_case` |
| invalid title, severity, status, note, date, kind or ref, assignee who cannot read cases, an outcome on a host or software, too many items | 422 `invalid_case` with `field_errors` (e.g. `closing_note` / `closing_note_required`) |
| item already in another open case | 409 `item_in_case`; `case_number` names that case only when the caller can see it, and the item |
| item already in this case | 409 `item_already_in_case` |
| case closed | 409 `case_closed` |
| closing with items that need an outcome | 409 `items_unresolved` (the case's `pending_item_count` says how many are visible) / `hidden_items_unresolved` |
| `resolved` while the evidence is still there | 409 `evidence_present` |
| 500 items / 2,000 timeline entries | 422 `too_many_items` / `timeline_full` |
| database unavailable | 503 |

Refused changes write nothing: no timeline entry, no audit row, no new
version.

## How to test

With `eval "$(scripts/test-db.sh)"`:

```sh
cargo test -p platform-store --test console_cases        # tests/console_cases/: rules, scope, exclusivity, close, outcomes, reopen, evidence, audit, limits, migration 64
cargo test -p openvibes-console --lib cases              # cursors, validation messages
cargo test -p openvibes-console --test cases_http        # routes, auth, CSRF, bearer, scope, versions
cargo test -p openvibes-console --test case_list_http    # the Cases list page: validation, rows, counts, reach, saved views
cargo test -p platform-store --test case_summary         # the case page: scope, problems per kind, people, tiles
cargo test -p openvibes-console --test case_page_http    # the case page route: shape, reach, names, can flags
cargo test -p openvibes-console --test case_outcomes_http # the five outcomes, outcome_until, closing_note
cargo test -p openvibes-console --test auth_http database_builtin_permissions_match_the_rust_role_table
```

The web list: `npx vitest run src/views/investigate/Cases.test.tsx
src/demo/routes/caseList.test.ts` and, in a browser, the demo e2e
`e2e/demo/case-list.spec.ts` (filters across a reload, a saved view, a
hidden column, the ready-to-close summary, old addresses, axe) and
`e2e/demo/cases.spec.ts`.
