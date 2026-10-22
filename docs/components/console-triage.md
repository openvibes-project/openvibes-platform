# Console finding triage

`platform_store::console_triage` stores operator workflow state for the latest
finding keyed by `(agent_id, rule_set_id, rule_id)`. Finding observations remain
immutable evidence; triage notes and state are separate metadata.

## Interfaces

- `GET /api/v1/compliance/latest/{agent_id}/{rule_set_id}/{rule_id}/triage`
  returns default `open` state or the saved state and an ETag version.
- `PUT` on the same route requires `compliance.triage`, browser origin and CSRF
  validation, and `If-Match`. Stale writes return 412.
- `update_many` applies one transition to 1–100 endpoints in a single
  transaction. It locks current findings in ID order, verifies each version
  and SQL scope, and writes one history and audit record per changed endpoint;
  any stale, missing, or invalid member aborts the entire batch.
- States are `open`, `investigating`, `mitigated`, `accepted_risk`, and
  `false_positive`. Completed states need a note; accepted risk needs a future
  RFC 3339 expiry. Assignees must be enabled analysts or admins.
- A genuinely new latest observation automatically reopens mitigated triage,
  accepted risk observed after expiry, and false positives whose rule version
  advanced. Investigating remains active. Automatic changes are audited.
- Migration 11 adds assignment, expiry, and rule version to the triage history.

## Alarms

Alarm triage uses the same four states (open, mitigated, accepted risk,
false positive). One alarm: `PUT /api/v1/alarms/{id}/triage`; many:
`POST /api/v1/alarms/bulk` (state, reopen, assign, Add to case, Suppress…),
both described in [openvibes-console.md](openvibes-console.md). The web
side is the Alarms list's bulk bar and the alarm page's header; see
[console-alarms.md](console-alarms.md). The alarm panel's triage is gone.

## Vulnerabilities in bulk

`POST /api/v1/vulnerabilities/bulk` takes items `{advisory_id}` (a CVE row
acts through its covering advisories; the advisory expands to its hosts in
reach) or `{agent_id, advisory_id}` (that pair, as asked). An advisory-wide
`state` close or `assign` changes only open pairs: no triage row, or an
accepted risk whose expiry has passed, counts as open, and fixed pairs are
never expanded. Mitigated, accepted and false-positive pairs come back in
`skipped` with reason `not open` and keep their note and assignee. Hosts out
of the actor's reach are never touched. A reopen (`state: open`) is the
exception: it reopens the closed pairs and skips the open ones ("already
open"). Triage on one CVE row shows on its sibling rows, which share the
advisory's pairs.

## Configuration and failures

The module uses the existing PostgreSQL pool and schema migration. Missing
findings return 404, missing permission returns 403, stale `If-Match` returns
412, invalid transitions return 409, and invalid fields or assignees return
400. State, history, and audit writes share a transaction.

## How to test

Run `cargo test --offline -p platform-store -p openvibes-console` with the
workspace test PostgreSQL database configured. Run the console web lint,
typecheck, and unit suite from `crates/openvibes-console/web`.
