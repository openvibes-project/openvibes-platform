# platform-store

The only crate that talks to PostgreSQL. Every other crate goes through its
functions, so schema knowledge and SQL live in one place.

## Interface

- `Client` and `Pool` are re-exported from `deadpool-postgres`, so callers
  need no pool dependency.
- `connect(url) -> Result<Pool, StoreError>`: a `deadpool-postgres` pool of
  up to 16 connections. `url` is a libpq URL or key/value string; Unix
  sockets work (`postgresql:///openvibes?host=/run/postgresql&user=...`).
  Connections open lazily.
- `SCHEMA_VERSION` (currently 2), `schema_version(&client)` (`None` on an
  empty database), `migrate(&mut client)`.
- `StoreError`: `Unavailable` (connection or pool), `NewerSchema(v)`,
  `Query` (a statement failed). Messages never contain SQL, parameters, or
  connection strings.

## Migrations

Numbered SQL files in `/migrations`, embedded at build time. `migrate` runs
in one transaction with `schema_version` locked exclusively, so concurrent
runs serialize; already-applied migrations are skipped. A database at a
**newer** version is refused with `NewerSchema`, never rolled back.

Schema 1 (`0001_initial.sql`): `agents`, `certificates`,
`enrollment_tokens`, `token_uses`, `findings` (partitioned by
`observed_day`), `current_findings`, `audit_log`, and the least-privilege
role `openvibes_ingest` (which may also read `schema_version`, for its
readiness check). The migrating role needs `CREATEROLE`.

## Tokens, agents, CA certificates (schema 2)

- `tokens::create(&client, &NewToken) -> token_id`, `tokens::list` (never
  returns the token or its hash; includes `uses` and `revoked`),
  `tokens::revoke(&client, id, now) -> bool` (was usable; an unknown id is
  `false`, a malformed id `StoreError::Query`). Ids are UUIDs, passed as
  text.
- `agents::list(&client, Filter::{All, Offline, Revoked}, now)`,
  `agents::show(&client, id)` (with certificate count),
  `agents::revoke(&client, id, now) -> Revoke::{Revoked, AlreadyRevoked,
  Unknown}`.
- `ca::record(&client, role, fingerprint, pem, not_after)` (idempotent on the
  fingerprint), `ca::list`. Migration 2 adds `ca_certificates` (readable by
  `openvibes_ingest`).

## Audit log

`audit::record(&client, actor, action, target, result)` appends one row.
The `detail` column is never given secrets.

## Partitions and retention

- `ensure_partitions(&client, today, days_ahead)`: creates `findings_YYYYMMDD`
  partitions for today and the next `days_ahead` days that are missing;
  returns how many it created. Safe to run repeatedly.
- `drop_partitions_before(&client, cutoff)`: drops partitions for days before
  `cutoff`, **never today's**, even if `cutoff` is later.
- Partition names come only from dates, never from input.

## Status

`status(&client, now) -> Status`: schema version; active, offline (no
heartbeat for `OFFLINE_AFTER_MINUTES` = 15, well above the 5-minute
`last_seen_at` write throttle), and revoked agents; usable tokens (not
revoked, not expired, uses left); oldest and newest partition. All zeros and
`None` on an empty database.

## Test

```sh
eval "$(scripts/test-db.sh)"     # throwaway cluster under target/pg
cargo test --locked -p platform-store
```

Each test creates and drops its own database. Tests fail, never skip,
when `OPENVIBES_TEST_DATABASE_URL` is unset.
