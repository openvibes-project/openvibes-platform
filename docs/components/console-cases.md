# console-cases

Cases over `/api/v1` (module `crates/openvibes-console/src/cases.rs`, store
`platform_store::console_cases`, schema 35). Spec:
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
placeholder. A user sees a case if they can see at least one of its items, or
opened it, or it is assigned to them; any other case answers 404, the same as
one that does not exist. A case with no item is therefore seen only by who
opened it or is assigned to it.

## Interfaces

Browser session only; a service-account bearer token gets 403, for reads too.
Changes also check CSRF and the browser origin. `cases.read` and
`cases.manage` are agent-scoped permissions (Analyst and Admin hold both;
migration 34 adds `cases.manage`); changes need both.

| Route | Needs | Result |
|---|---|---|
| `GET /api/v1/cases` | `cases.read` | `CasePage` `{items, next_cursor}`. Filters `status` (`open`, `investigating`, `closed`, `all`; default open and investigating), `severity`, `assignee` (a user id, `me`, `none`), `q` (title text or `C-104`), `cursor`, `limit` 1–100 (50). Newest change first |
| `POST /api/v1/cases` | `cases.manage` | `201 CaseDetailView` + `ETag`. Body `{title, severity?, assignee_user_id?, items?: [{kind, ref}]}`, at most 50 items |
| `GET /api/v1/cases/{id}` | `cases.read` | `CaseDetailView` + `ETag` (the version) |
| `PUT /api/v1/cases/{id}` | `cases.manage`, `If-Match` | `CaseDetailView` + new `ETag` |
| `POST /api/v1/cases/{id}/notes` | `cases.manage` | `201 CaseEventView`; body `{body}` |
| `POST /api/v1/cases/{id}/items` | `cases.manage` | `201 CaseItemView`; body `{kind, ref}` |
| `DELETE /api/v1/cases/{id}/items/{item_id}` | `cases.manage` | 204; open cases only |
| `PUT /api/v1/cases/{id}/items/{item_id}/outcome` | `cases.manage` | `CaseItemView`; body `{outcome: "resolved" \| "false_positive" \| "accepted_risk" \| null, note?}` |
| `GET /api/v1/cases/for-item?kind=&ref=` | `cases.read` | `{items: [{case: CaseSummaryView, item_id, outcome}]}` |
| `GET /api/v1/cases/assignees` | `cases.manage` | `{items: [{user_id, username, display_name}]}`: enabled users who hold `cases.read` |

`CaseSummaryView` (also the head of `CaseDetailView`, which adds
`resolution_note`, `items` and `events`): `case_id`, `number` (shown as
`C-<number>`, never reused), `title`, `status` (`open`, `investigating`,
`closed`), `resolution` (`mitigated`, `false_positive`, `accepted_risk`),
`accepted_until`, `severity` (`critical`, `high`, `medium`, `low`),
`assignee` and `opened_by` (`{user_id, username, display_name}`),
`created_at`, `updated_at`, `closed_at`, `version`, `item_count` and
`pending_item_count` (items the viewer can see; the second counts alarms,
findings and vulnerabilities without an outcome).

`CaseItemView`: `item_id`, `kind` (`alarm`, `finding`, `vulnerability`,
`host`, `software`), `ref`, `agent_id`, `hostname`, `active`, `outcome`,
`outcome_note`, `added_by`, `added_at`, `title`, `severity`, `evidence_gone`.

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
item entries; `{resolution, accepted_until}` for `resolved`; `{reason}` for
`reopened` (`manual` or `accepted_risk_expired`). The timeline is oldest
first and append-only (a trigger refuses UPDATE and DELETE).

### Changing a case

`PUT` replaces the editable fields, so send them all: `title` (1–120
characters, trimmed), `severity`, `status`, `assignee_user_id` (absent or
`null` means nobody) and, to close, `resolution`, `resolution_note` (1–4000
characters) and `accepted_until` (RFC 3339). Sending the current values
changes nothing and writes nothing. The version rises with each change to
those fields; notes, items and outcomes move `updated_at` only, so adding a
note does not make someone else's edit stale. `If-Match` is the quoted
version from the last `ETag`.

Statuses move freely between `open` and `investigating`. `closed` needs:

1. a `resolution` (`mitigated`, `false_positive`, `accepted_risk`) and a
   note;
2. for `accepted_risk`, an `accepted_until` in the future (and no date for the
   others);
3. an outcome on every alarm, finding and vulnerability, `resolved` only
   while its evidence is still gone. Items the closing user cannot see are
   not theirs to clear: if any has no outcome, the answer is 409
   `hidden_items_unresolved` until someone with that scope clears them.

Setting a status other than `closed` on a closed case reopens it and clears
its resolution. A closed case keeps how it ended: changing the resolution,
note or date, adding or removing items, and setting outcomes are 409
`case_closed` until it is reopened. Title, severity, assignee and notes can
still change.

An item outcome is `resolved` (only when `evidence_gone`; a note is optional),
`false_positive` or `accepted_risk` (a note is required). Evidence is gone
when:

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

When `accepted_until` passes, the case reopens as `open` (audit actor
`system`, timeline `reopened` with reason `accepted_risk_expired`), the items
marked `accepted_risk` lose that outcome so someone decides again, and the
resolution fields clear. This runs when cases are listed or read, so it happens
the next time anyone looks. A case whose item has since joined another open
case stays closed.

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
| bearer token, no `cases.read` or `cases.manage` | 403 |
| missing or wrong CSRF token or origin on a change | 403 |
| unknown, malformed or invisible case | 404 `case_not_found` (the same answer) |
| item missing, or outside the caller's scope, or not in the case | 404 `item_not_found` (the same answer, so nothing is revealed) |
| invalid JSON body, unknown field, invalid query or cursor, invalid `If-Match` | 400 |
| missing `If-Match` / stale version | 428 / 412 `stale_case` |
| invalid title, severity, status, resolution, note, date, kind or ref, assignee who cannot read cases, an outcome on a host or software, too many items | 422 `invalid_case` with `field_errors` (e.g. `resolution_note` / `resolution_note_required`) |
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
cargo test -p platform-store --test console_cases        # rules, scope, exclusivity, close, evidence, audit, limits
cargo test -p openvibes-console --lib cases              # cursors, validation messages
cargo test -p openvibes-console --test cases_http        # routes, auth, CSRF, bearer, scope, versions
cargo test -p openvibes-console --test auth_http database_builtin_permissions_match_the_rust_role_table
```
