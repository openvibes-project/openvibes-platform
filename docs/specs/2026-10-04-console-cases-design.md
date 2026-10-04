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

## Open questions

None. Everything above is decided; implementation follows once the author
approves the spec.
