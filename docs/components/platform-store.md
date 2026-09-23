# platform-store

The only crate that talks to PostgreSQL. Every other crate goes through its
functions, so schema knowledge and SQL live in one place.

## Interface

- `connect(url) -> Result<Pool, StoreError>`: a `deadpool-postgres` pool of
  up to 16 connections. `url` is a libpq URL or key/value string; Unix
  sockets work (`postgresql:///openvibes?host=/run/postgresql&user=...`).
  Connections open lazily.
- `SCHEMA_VERSION` (currently 1), `schema_version(&client)` (`None` on an
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
role `openvibes_ingest`. The migrating role needs `CREATEROLE`.

## Test

```sh
eval "$(scripts/test-db.sh)"     # throwaway cluster under target/pg
cargo test --locked -p platform-store
```

Each test creates and drops its own database. Tests fail, never skip,
when `OPENVIBES_TEST_DATABASE_URL` is unset.
