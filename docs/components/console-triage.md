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

`POST /api/v1/vulnerabilities/bulk` (CVE rows acting through their covering
advisories, open-only closes and assigns, `open_only` items) is in
[console-vulnerabilities.md](console-vulnerabilities.md#bulk).

## Compliance in bulk

`POST /api/v1/compliance/bulk` takes one item per check row (`rule_set_id`,
`rule_id`), with `agent_id` for the Host chip and `open_only` for a list
row (`open_only` stays refused on alarm items, 400). A rule-wide item, or any
item with `open_only`, makes Set state and Assign change only the pairs that
are failing (not ended) and open: no triage, open, or an accepted risk whose
expiry has passed. Other pairs are not expanded, so they neither count toward
the 10,000 cap nor appear in `skipped`; when none is left the row is skipped
as "not open" (a named pair too). An assign on an expired acceptance writes it
back open with no expiry, as in vulnerabilities. Ended findings and hosts out
of reach are never touched; passing hosts have no finding. A reopen and a
named host without `open_only` behave as before. Add to case from a row (rule-wide or `open_only`) takes
every failing finding, closed ones included, never an ended one; a named host
without `open_only` is added as before. A named host with `open_only` whose
finding has ended is "not found or out of scope". Code: `platform-store`
`bulk_triage/compliance.rs`; demo `web/src/demo/routes/triage.ts`. The
Compliance list and a check's page that send these items:
[console-compliance.md](console-compliance.md#bulk).

## Configuration and failures

The module uses the existing PostgreSQL pool and schema migration. Missing
findings return 404, missing permission returns 403, stale `If-Match` returns
412, invalid transitions return 409, and invalid fields or assignees return
400. State, history, and audit writes share a transaction.

## How to test

Run `cargo test --offline -p platform-store -p openvibes-console` with the
workspace test PostgreSQL database configured. Run the console web lint,
typecheck, and unit suite from `crates/openvibes-console/web`.
