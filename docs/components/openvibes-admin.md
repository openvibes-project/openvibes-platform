# openvibes-admin

Local operator CLI. Until the admin API exists it is **break-glass access**:
whoever can run it with the admin database role has full rights. Every
command, including failed ones, appends an `audit_log` entry with the
invoking OS user and `ok` or `error`. The actor is the real uid, which the
caller cannot choose, with `$USER` as a readable hint: `alice (uid 1000)`,
or `uid 1000` when `USER` is unset (timers, containers). Run through sudo
(`sudo -u openvibes_admin …`), the person is appended from `SUDO_USER`:
`openvibes_admin (uid 994) via sudo by alice`.

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

## Agent commands

| Command | Prints |
|---|---|
| `agent list [--offline \| --revoked]` | one line per agent: id, status, last seen, version. `--offline` = active with no heartbeat for 15 minutes. |
| `agent show ID` | id, status, enrolled, revoked, last seen, version, certificate count; `unknown agent` (exit 1) if absent |
| `agent revoke ID` | `revoked ID`; `agent already revoked` or `unknown agent` are errors. The agent's next request gets `identity_revoked` (PM3). |

`show` and `revoke` are audited with the agent id as target.

## Token commands

| Command | Does |
|---|---|
| `token create --expires Nh\|Nd [--uses N] [--label TEXT]` | 32 random bytes, base64url; printed **once** with its id. Only the SHA-256 is stored. `--expires` 1h to 365d, `--uses` 1 to 100000 (default 1); out-of-range values exit 2 before any change. |
| `token list` | id, state (usable, expired, used up, revoked), uses/max, expiry, label. Never shows tokens. |
| `token revoke ID` | revokes; an already-revoked or unknown id is an error. |

The audit target is the token id, never the token.

## CA commands

The built-in CA (architecture spec, section 5). Keys are written `0600`,
certificates `0644`, always with create-new: **nothing is ever
overwritten**. A key and its certificate (or CSR) are written as a pair: if
either file already exists, neither is written, so no key is left without
its certificate.

| Command | Where | Writes | Audited |
|---|---|---|---|
| `ca init-root --out DIR` | offline machine | `root.crt`, `root.key` | no (no database there) |
| `ca intermediate-request --out DIR` | ingest host | `intermediate.key`, `intermediate.csr` | no |
| `ca sign-intermediate --root DIR --csr FILE --out FILE` | offline machine | intermediate certificate | no |
| `ca import-intermediate --cert F --key F --root-cert F` | ingest host | records root + intermediate in `ca_certificates` | yes, target = intermediate SHA-256 |
| `ca issue-server NAME [--san X]... --issuer-cert F --issuer-key F --out DIR` | ingest host | `NAME.crt` (leaf + intermediate), `NAME.key` | yes, target = NAME |

Operator flow: `init-root` offline, then `intermediate-request` on the ingest
host, carry only the **CSR** to the offline machine, `sign-intermediate`
there, carry only the **certificate** back, then `import-intermediate`.
The intermediate key never leaves the ingest host and the root key never
leaves the offline machine. `import-intermediate` refuses a key that does
not match the certificate, a certificate the given root did not sign, one
that is not an intermediate (the root itself, a leaf, or a CA without path
length 0), or one outside its validity, and records nothing then. Offline commands work without any config file.

## Test

```sh
eval "$(scripts/test-db.sh)"
cargo test --locked -p openvibes-admin
```

`tests/cli.rs` runs the built binary against a fresh database.
