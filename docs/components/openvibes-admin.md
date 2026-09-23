# openvibes-admin

Local operator CLI. Until the admin API exists it is **break-glass access**:
whoever can run it with the admin database role has full rights. Every
command, including failed ones, appends an `audit_log` entry with the
invoking OS user and `ok` or `error`. The actor is the real uid, which the
caller cannot choose, with `$USER` as a readable hint: `alice (uid 1000)`,
or `uid 1000` when `USER` is unset (timers, containers).

## Configuration

`/etc/openvibes/admin.toml` (or `--config PATH`), bounded and strict like
every platform config:

```toml
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_admin"
```

The admin role owns the schema and needs `CREATEROLE` (migration 1 creates
`openvibes_ingest`).

## Commands

| Command | Does | Prints |
|---|---|---|
| `migrate` | applies pending migrations; refuses a newer schema | `schema version N` |
| `status` | summary (requires the current schema) | `schema version`, `agents active/offline/revoked`, `tokens usable`, `partitions OLDEST..NEWEST` or `none` |
| `maintenance [--retention-days 90]` | creates any missing partition from the retention cutoff to today + 7 days, so late or backlogged findings always have a partition; drops older ones, never today's. `--retention-days` must be 1 to 36500 (else exit 2, before any change) | `created N partitions, dropped M` |

Commands other than `migrate` refuse to run on an outdated schema ("run
openvibes-admin migrate") or a newer one ("upgrade openvibes-admin"). Errors
never print SQL or connection strings. If the audit entry cannot be
written, the command exits non-zero with a warning.

Later milestones add `ca`, `token`, and `agent` commands (PM2).

## Test

```sh
eval "$(scripts/test-db.sh)"
cargo test --locked -p openvibes-admin
```

`tests/cli.rs` runs the built binary against a fresh database.
