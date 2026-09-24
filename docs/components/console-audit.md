# Console audit storage

`platform_store::audit` records platform audit events and manages the
singleton console retention policy. The policy defaults to 365 days and uses a
monotonic version to reject stale administrator updates. Updating a changed
policy and appending its audit event happen in one transaction.

## Interfaces

- `record` appends an operator or system event with no secret-bearing detail.
- `events` performs exact-filtered, bounded keyset reads ordered by timestamp
  and event id. A mandatory lower time bound keeps queries indexable. Its safe
  view omits detail JSON, source address, and user agent.
- `retention_policy` reads the current day limit, version, update timestamp,
  and actor.
- `update_retention_policy` accepts 1–36500 days and an expected version. It
  returns `None` on a stale version, leaves the version/audit history unchanged
  for a no-op update, and commits changed policy plus `audit.retention.updated`
  atomically.

The console API requires global `audit.read` to show policy and events and global
`audit.retention.manage` to update it. The API mutation also requires a current
session CSRF token, exact configured Origin, same-origin Fetch Metadata, and a
matching `If-Match` version. Audit cleanup remains a bounded maintenance
operation and must use the effective policy cutoff.

`GET /api/v1/audit-events` accepts a required `since`, optional exclusive
`until`, exact `actor`/`action`/`result` filters, and a limit from 1 to 100.
Opaque cursors bind all filters. Successful reads append `audit.accessed`; the
response does not include event details or request source metadata.

## Failure behaviour

Database failures return the fixed `StoreError` value; SQL text and values are
not exposed. A stale expected version causes no change or audit event. Invalid
retention values are refused before opening a transaction.

## How to test

```sh
eval "$(scripts/test-db.sh)"
cargo test --locked -p platform-store --test console_audit
cargo test --locked -p openvibes-console --test auth_http
```
