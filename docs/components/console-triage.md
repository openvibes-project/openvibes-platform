# Console finding triage

`platform_store::console_triage` stores operator workflow state for the latest
finding keyed by `(agent_id, rule_set_id, rule_id)`. Finding observations remain
immutable evidence; triage notes and state are separate metadata.

## Interfaces

- `GET /api/v1/findings/latest/{agent_id}/{rule_set_id}/{rule_id}/triage`
  returns default `open` state or the saved state and an ETag version.
- `PUT` on the same route requires `findings.triage`, browser origin and CSRF
  validation, and `If-Match`. Stale writes return 412.
- States are `open`, `investigating`, `mitigated`, `accepted_risk`, and
  `false_positive`. Completed states need a note; accepted risk needs a future
  RFC 3339 expiry. Assignees must be enabled analysts or admins.
- A genuinely new latest observation automatically reopens mitigated triage,
  accepted risk observed after expiry, and false positives whose rule version
  advanced. Investigating remains active. Automatic changes are audited.
- Migration 11 adds assignment, expiry, and rule version to the triage history.

## Configuration and failures

The module uses the existing PostgreSQL pool and schema migration. Missing
findings return 404, missing permission returns 403, stale `If-Match` returns
412, invalid transitions return 409, and invalid fields or assignees return
400. State, history, and audit writes share a transaction.

## How to test

Run `cargo test --offline -p platform-store -p openvibes-console` with the
workspace test PostgreSQL database configured. Run the console web lint,
typecheck, and unit suite from `crates/openvibes-console/web`.
