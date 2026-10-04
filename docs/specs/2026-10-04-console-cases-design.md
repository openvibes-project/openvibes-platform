# Console cases: one place to investigate

**Status:** all questions answered, awaiting final approval to start
implementation (2026-10-04). Nothing here is built except the
`/cases` rail entry, the `cases.read` permission and an empty page.

Every item below is **Decided** by the author.

## Purpose

A case is where an investigation happens. When something is going on (for
example, SSH on one host), the analyst opens a case, adds the host, the SSH
alarm, the related findings and vulnerabilities, writes notes, decides, and
closes it with a reason. Everything about the matter is in one place.

## Principles

**Decided**

- Cases do not replace the other views. Alarms, Findings, Vulnerabilities,
  Hosts and Software stay.
- Anything in the platform can be added to a case.
- Nothing is closed or removed without evidence that it is gone. A person may
  accept a risk instead, but then it is recorded as accepted, not as fixed.

## Changes to earlier specs

The console product design
([2026-09-23](2026-09-23-console-product-design.md)) lists
"correlation/incidents" as excluded from the first release and says the
console is not an incident-management product. This spec adds cases and
supersedes that exclusion for cases only.

## Phases

**Decided**

1. **Phase 1:** cases ship alongside the existing alarm and finding triage,
   which stays as it is.
2. **Phase 2:** users add existing vulnerabilities, alarms and findings to a
   case from their own pages ("Add to case").
3. **Later:** cases eventually replace per-item triage. A separate spec and
   migration plan will cover that; this spec does not remove anything.

**Decided:** Phase 1 must already let a user add items to a case (even if
only from the case page), otherwise a new case is empty and cannot be tried.

## Case

| Field | Notes |
|---|---|
| Number | Shown as `C-104`; unique, never reused. **Decided** |
| Title | Required, set by the creator. |
| Status | See below. |
| Resolution | Set when closing; see below. |
| Severity | **Decided:** starts as the highest item severity, can be changed by hand. |
| Assignee | One user, or nobody. |
| Opened by, opened at, updated at | Set by the console. |
| Version | For `If-Match`, like dashboards and triage, so two analysts do not overwrite each other. |

## Statuses and resolutions

**Decided:** the six words in the author's list (open, under investigation,
mitigated, false positive, accepted risk, closed) are split in two, because
three say how a case ended and the others say where it is. This also matches
today's triage.

- **Status:** `open` → `investigating` → `closed`.
- **Resolution** (required to close): `mitigated`, `false_positive` or
  `accepted_risk`.
- Every resolution needs a note (as today).
- `accepted_risk` also needs an "accepted until" date (as today). **Decided:**
  when it passes, the case reopens.

## Items

**Decided:** anything can be added: host, alarm, finding, vulnerability,
software, port, service, advisory and so on.

A case stores each item as a link (kind and id) plus when it was added and by
whom.

### Which items can be in more than one case

**Decided**

- A specific **finding** and a specific **alarm** are never in two open cases
  at the same time, so analysts do not duplicate work.
- A **vulnerability on a host** (the advisory and host together) is never in
  two open cases at the same time. The advisory alone can be in many cases,
  and so can the host alone.
- **Hosts, software** and other things that exist on many hosts can be in
  several cases.

**Decided**

- The rule applies to **open** cases only. Closing a case frees its items.
- A recurring alarm (alarms count occurrences) stays in the case it is
  already in; a new occurrence after the case closes may be added to a new
  case.

## Closing a case

**Decided:** what happens to each item depends on its kind, and only
evidence closes it.

| Item | Can be marked | Goes away only when |
|---|---|---|
| Vulnerability | false positive, accepted risk | it is no longer found (the advisory no longer matches the host) |
| Alarm | closed; suppression stays available | it stops happening, unless suppressed |
| Finding | closed, accepted risk, false positive | the agent no longer reports it |

**Decided**

- A case can close only when every item has an outcome: resolved by evidence,
  or marked false positive or accepted risk with a note.
- When evidence comes back for an item in a closed case (the same behaviour
  existing triage has for mitigated items), the case reopens.

## Assignment and permissions

**Decided:** a user can assign themselves or others to a case, based on
roles. Anyone who manages cases can assign to themselves or to any other user
who can see cases.

- `cases.read`: see cases (exists today; analyst and admin).
- `cases.manage` : create, edit, add items, change status,
  assign, close.
- An assignee must be a user who has `cases.read`.

## Who sees what

**Decided:** a case can hold items from several asset groups. The console
enforces scope in SQL, so a user with a limited scope never sees items
outside it. Those items are hidden completely: no placeholder, no count.

**Decided**, because of that choice:

- A user sees a case only if they can see at least one of its items, or they
  opened it or are its assignee.
- Counts, search results and the item list include only items the user can
  see.
- The case's severity is set when the case is created (from the highest item
  at that moment) and then changed by hand, never recomputed, so it cannot
  reveal items the viewer cannot see.
- Notes are visible to everyone who can see the case. Authors are told not to
  write about items outside the readers' scope. This is a known limit of
  free text.

## Timeline and audit

**Decided**

- Every note, status change, assignment and item added or removed is an
  entry on an append-only timeline (author, time, text).
- Every change also writes an audit event, like the other console changes.
- Notes are plain text.

## Interface

**Decided**

- `/cases`: the list (filters by status, severity, assignee; default shows
  open and investigating).
- **Decided (first version):** the case opens in the inspector panel, and
  each item is a row that opens its own panel (host, alarm, finding) next to
  it, so nothing is duplicated. Showing item details inside the case is a
  later option.
- "Add to case" on alarm, finding, vulnerability, host and software pages,
  and on their rows.
- Cases appear in the Ctrl+K palette.

## Out of scope for this spec

Notifications, due dates and SLAs, tags, a dashboard widget, and the
assistant reading cases.

## Tests

The usual unit and demo tests, plus negative tests (required for
security-sensitive changes): no `cases.read` is refused, a scoped user does
not see out-of-scope items, an item cannot join a second open case, a stale
version is refused, and closing with items still unresolved is refused.

## Technical design (first version)

### Tables (migration 0034, schema 34; append-only)

- `cases`: `case_id uuid`, `number bigint` (identity, unique, shown as
  `C-n`), `title` (1 to 120 characters), `status` (`open`, `investigating`,
  `closed`), `resolution` (null, `mitigated`, `false_positive`,
  `accepted_risk`), `resolution_note`, `accepted_until`, `severity`
  (`critical`, `high`, `medium`, `low`), `assignee_user_id` (null),
  `opened_by_user_id`, `created_at`, `updated_at`, `closed_at`, `version`.
- `case_items`: `item_id`, `case_id`, `kind` (`alarm`, `finding`,
  `vulnerability`, `host`, `software`), `ref` (the object's id as the
  console's panels already write it: alarm id; `agent/rule_set/rule` for a
  finding; `agent/advisory` for a vulnerability on a host; agent id for a
  host; `manager/name` for software), `agent_id` (null for software; used
  for scope), `active` (true while the case is not closed), `outcome` (null,
  `resolved`, `false_positive`, `accepted_risk`), `outcome_note`,
  `added_by_user_id`, `added_at`. Unique `(case_id, kind, ref)`. Exclusive
  kinds (alarm, finding, vulnerability) are unique on `(kind, ref)` among
  `active` items, so one item is in at most one open case. Host and
  software are not exclusive.
- `case_events`: append-only timeline: `event_id`, `case_id`, `at`,
  `actor_user_id`, `kind` (`created`, `note`, `status`, `assigned`,
  `severity`, `item_added`, `item_removed`, `item_outcome`, `resolved`,
  `reopened`), `body` (note text, at most 4000 characters) and `detail`
  (json, never the note).
- Permission `cases.manage` (scope class `agent`) for analyst and admin;
  `cases.read` already exists. Both are agent-bound.

### Rules

- A user sees a case if they hold `cases.read` and the case has at least
  one item they can see (host or agent in their scope; software is visible
  to every reader), or they opened it, or it is assigned to them. A case
  they cannot see answers 404.
- Adding an item requires `cases.manage` and that the user can see the
  item (its agent is in their scope). A failed add does not reveal whether
  the item exists.
- An item in another open case answers 409 naming that case's number only
  if the user can see that case; otherwise a generic 409.
- Closing needs a resolution, a note, `accepted_until` for accepted risk
  (a future date), and every alarm, finding and vulnerability item must have
  an outcome. `resolved` is accepted only when the evidence is gone (the
  finding is no longer reported by its agent, the vulnerability no longer
  matches the host, the alarm is closed); otherwise the user marks
  `false_positive` or `accepted_risk` with a note. Host and software items
  need no outcome. Items the closing user cannot see are not checked by the
  user, so closing is refused for them with 409 unless someone with the
  scope clears them; this is a known limit.
- Closing sets `active=false` on all items. Reopening (by `cases.manage`,
  or automatically when `accepted_until` passes) sets `active=true` and
  fails with 409 if an item has since joined another open case.
- Updates use `If-Match` with the case version (412 stale, 428 missing),
  like dashboards. Every change and its audit row commit together.
- Assignee: a user with `cases.read`. Severity is set at creation (default:
  the highest item severity) and then by hand.
- Browser session only; a bearer token gets 403, like dashboards.

### Routes

| Route | Permission | Result |
|---|---|---|
| `GET /api/v1/cases` | `cases.read` | page, filters `status` (default open + investigating, or `all`), `severity`, `assignee`, `q`; newest update first; cursor |
| `POST /api/v1/cases` | `cases.manage` | `201` case + `ETag`; body title, severity (optional), assignee (optional), items (optional, 50 max) |
| `GET /api/v1/cases/{id}` | `cases.read` | case, visible items, timeline + `ETag` |
| `PUT /api/v1/cases/{id}` | `cases.manage`, `If-Match` | title, severity, status, assignee, resolution fields |
| `POST /api/v1/cases/{id}/notes` | `cases.manage` | timeline entry |
| `POST /api/v1/cases/{id}/items` | `cases.manage` | add one item |
| `DELETE /api/v1/cases/{id}/items/{item_id}` | `cases.manage` | remove (on an open case only) |
| `PUT /api/v1/cases/{id}/items/{item_id}/outcome` | `cases.manage` | set or clear an outcome |
| `GET /api/v1/cases/for-item?kind=&ref=` | `cases.read` | the open case holding an exclusive item, or the cases holding a host or software item, visible ones only |
| `GET /api/v1/cases/assignees` | `cases.manage` | users with `cases.read`: id, username, display name |

Audit actions: `case.create`, `case.update`, `case.note` (never the text),
`case.item.add`, `case.item.remove`, `case.item.outcome`, `case.close`,
`case.reopen`.

### Order of work

1. Migration, store module and store tests (`platform-store`, separate
   commits).
2. Console API, OpenAPI snapshot, RBAC and HTTP tests.
3. Web: demo API, list, case panel, "Add to case".
4. Component documentation and end-to-end tests.

## Open questions

None. Everything above is decided; implementation follows once the author
approves the spec.
