# platform-store

The only crate that talks to PostgreSQL. Every other crate goes through its
functions, so schema knowledge and SQL live in one place.

## Interface

- `Client` and `Pool` are re-exported from `deadpool-postgres`, so callers
  need no pool dependency.
- `connect(url)` / `connect_sized(url, size)`: a `deadpool-postgres` pool
  (16 by default). Waiting for, creating, and recycling a connection are
  bounded to 5 s; every statement to 10 s (`statement_timeout`). `url` is a libpq URL or key/value string; Unix
  sockets work (`postgresql:///openvibes?host=/run/postgresql&user=...`).
  Connections open lazily.
- `SCHEMA_VERSION` (currently 18; a compile-time check ties it to the last
  migration), `schema_version(&client)` (`None` on an
  empty database), `migrate(&mut client)`.
- `StoreError`: `Unavailable` (connection or pool), `NewerSchema(v)`,
  `Query` (a statement failed), `InvalidUrl` (the configured URL does not
  parse: a configuration error, not an outage). Messages never contain SQL, parameters, or
  connection strings.

## Migrations

Numbered SQL files in `/migrations`, embedded at build time. Migration 4
revokes UPDATE on `findings`, `certificates`, and `token_uses` from
`openvibes_ingest`, which only inserts them; a test checks the role is
refused every write, read, or DDL it does not use. Migration 5 adds `rule_set_id`
to `findings` and `current_findings` (`''` = unknown sender) and keys
current state by agent, rule set, and rule: rule ids are unique only within
a rule set. Migration 6 adds rule distribution (below) and the role
`openvibes_distribution`. `migrate` runs
in one transaction that first takes an advisory lock (before even creating
`schema_version`), so concurrent runs serialize and both succeed;
already-applied migrations are skipped. A database at a
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

## Ingest queries (`ingest::…`)

All run within the `openvibes_ingest` role's grants (the tests use
`SET ROLE openvibes_ingest`).

- `token_by_hash(&client, sha256) -> Option<TokenRow>`.
- `enroll(&mut client, token_id, spki_sha256, now, issue) -> Enrolled`: one
  transaction under `pg_advisory_xact_lock(hashtext(token_id))`, so
  concurrent enrollments with a single-use token yield exactly one identity.
  `Existing` when this token already enrolled this key (the protocol's retry
  rule, same chain returned), `AgentRevoked` when that same-key retry belongs to an agent revoked since
  (a revoked identity is never handed out again), `TokenInvalid` when the token is revoked or
  expired at `now` (checked under the lock, so a revocation racing the
  request cannot slip through), `Exhausted` when no uses remain, else `New`
  after creating the agent (`agent.<uuid>`), its certificate, the token use,
  and an `enroll` audit row.
- `add_certificate` (renewal), `authenticate(&client, serial, spki) ->
  Authenticated::{Active(id), Revoked, Unknown}`: the serial **and** the key
  hash must match a recorded certificate.
- `heartbeat` writes `last_seen_at`, version, capabilities, and the hostname
  at most every 5 minutes, or at once when the hostname or the capabilities
  change; an absent
  hostname keeps the stored one (migration 3 adds `agents.hostname`,
  indexed). Returns whether it wrote.
- `store_findings(&mut client, agent_id, &[StoredFinding], now) -> new`: one
  transaction, `ON CONFLICT DO NOTHING`, and a `current_findings` upsert
  keeping the newest observation and the first-seen time.
- Certificate chains are stored as a JSON array in `certificates.chain_pem`.

## Rule distribution (`rules::…`, schema 6)

Tables: `rule_sets` (id, `created_at`, `retired_at`), `rule_trust_keys`
(per set and issuer key id: 32-byte Ed25519 key, `added_at`, `removed_at`),
and `rule_bundles` (per set and version: the exact envelope bytes, at most
1 MiB, its SHA-256, issuer, signed creation and expiry, `published_at`,
`published_by`). The current bundle is the highest version; there is no
mutable pointer.

`openvibes_distribution` may only read `agents`, `certificates`,
`rule_sets`, `rule_bundles`, and `schema_version`; it cannot see trust keys.
`openvibes_ingest` has no rights on the rule tables. A test checks both.

- `add_trust_key(set, issuer, key)` creates the set if needed →
  `Added`, `AlreadyTrusted` (same key), `Conflict` (different key, or the id
  was removed: ids are never re-used), `Retired`. It runs in one transaction
  holding the set row `FOR SHARE`, so a concurrent `retire` waits and no key
  lands on a set retired mid-add.
- `trust_keys(set?)`, `active_trust_keys(set)`, `remove_trust_key(set, issuer)`.
- `publish(&mut client, &NewBundle)` takes a per-set advisory lock, so
  concurrent publishers serialize → `Stored`, `Unchanged` (same version and
  bytes), `VersionConflict`, `NotAboveCurrent(v)`, `Retired`, `UnknownSet`,
  `UntrustedIssuer`. The caller verifies the signature first
  (`openvibes-admin rules publish`); the store then re-checks, under
  `FOR SHARE`, that the issuer is still trusted, so a key removed between
  verification and commit cannot get a bundle stored.
- `list()` (with the current bundle's issuer and whether that key has since
  been removed), `bundles(set)` (newest first), `retire(set)` (bundles are kept).
- `serve(set, current_version?)` → `Unknown` (unknown, retired, or nothing
  published), `UpToDate`, or `Envelope(bytes)`. One primary-key query, read
  backwards; the bytes are fetched only when the agent's version is older.

## Inventories (`inventory::…`, schema 7)

Distinct package versions are stored once for the fleet in
`package_versions` (manager, name, epoch, version, release, arch; unique),
and `host_packages` links each host to the versions it has, so 10,000
Fedora hosts need about 36M two-key rows rather than full package rows.
`agents` gains `os_id`, `os_version`, `inventory_sha256`, and
`inventory_at`. `openvibes_ingest` may add versions and replace a host's
links, never edit or delete versions (a test checks it).

- `replace(&mut client, agent_id, os_id, os_version, running_kernel,
  packages, sha256, now)` locks the agent row; an equal digest is `Unchanged` (nothing written, no
  notification); otherwise it inserts unknown versions, replaces the host's
  links, records OS, running kernel (schema 9) and digest, and sends `NOTIFY inventory_changed` with
  the agent id (delivered at commit) → `Stored`. Several installed versions
  of one package (kernels) are all kept.

## Vulnerabilities (`vulns::…`, schema 8)

`advisories` (id, source, release, severity, title, times, url),
`advisory_cves`, `advisory_packages` (fixed name, arch, EVR),
`vulnerabilities` (host × advisory: affected packages as JSON, first seen,
fixed at — kept after fixing; `reboot_needed` since schema 9), and
`feed_sources` (last check, last change,
content digest, advisories, last error). Role `openvibes_vulns` writes only
these and reads `agents`, `package_versions`, `host_packages`.

- `replace_advisories` upserts in bulk and never deletes advisories.
- `candidates(release, host?)` joins advisories to installed versions of the
  same name with a compatible arch; `openvibes-vulns` decides.
- `apply(scope, found, now)` opens or updates found ones (reopening keeps
  `first_seen_at`) and fixes open ones in scope that were not found.
- `record_feed`, `feeds`, `list(filter)`, `summary` (aggregated in SQL).

Schema 9 adds `agents.running_kernel` (protocol P9) and
`vulnerabilities.reboot_needed`: the fix is installed and only a reboot
is missing. The row stays unfixed (it closes after the reboot), but
`summary` counts it as its own state, not as open.

Schema 10 (VM4) adds `cve_enrichment` (`cve_id`; KEV `kev_added`,
`kev_due`, `kev_ransomware`; EPSS `epss`, `epss_percentile`,
`epss_date`) and `feed_sources.etag`. `enrichment::{replace_kev,
replace_epss}` write it in bulk (KEV clears CVEs no longer listed);
`vulns::list` sorts by priority and returns each advisory's strongest KEV
and EPSS values; `summary` counts open ones on KEV;
`feed_etag`/`set_feed_etag` keep a source's ETag.

Schema 11 (VM5) adds NVD columns (`cvss_score`, `cvss_version`,
`cvss_vector`, `cwe`, `description`, `nvd_modified_at`,
`nvd_checked_at`), EUVD columns (`euvd_id`, `euvd_exploited`,
`euvd_exploited_since`) and `feed_sources.cursor`.
`enrichment::upsert_nvd` keeps only CVEs `advisory_cves` names;
`nvd_pending` lists named CVEs never asked (or unknown for 7 days);
`mark_nvd_checked`, `nvd_known`, `replace_euvd`, `cve_details`;
`feed_cursor`/`set_feed_cursor` hold NVD's sync point. `vulns::summary`
moved to `vulns/summary.rs` (same path).

Schema 12 grants `openvibes_vulns` `MAINTAIN` on the tables it bulk-loads
(PostgreSQL 17 or later), so `replace_advisories` can `ANALYZE` them.
`vulns::list` combines each advisory's CVEs and enrichment once, then
sorts and limits (0.63 s at 244,000 open vulnerabilities).

Schema 13 (other distributions via OSV.dev): `advisory_packages` keeps
each range as whole version strings with its `scheme` (`rpm` or `dpkg`),
`match_on` (`binary`, or `source`), `introduced`, `fixed` (null: no fix
known) and `last_affected`; Fedora's rows were converted. `package_versions`
gains `source` and `source_version` (protocol P10), part of the unique key
so ingest still only inserts. `agents.os_release` (generated) is the
release advisories use: the major version for Rocky and Alma. Candidates
match a source entry against every binary built from it; the installed
version is the binary's, or a dpkg binNMU's source version. `summary`
counts open ones with no fix yet.

## Audit log

`audit::record(&client, actor, action, target, result)` appends one row.
The `detail` column is never given secrets.

## Partitions and retention

- `ensure_partitions(&client, today, days_ahead)`: creates `findings_YYYYMMDD`
  partitions for today and the next `days_ahead` days that are missing;
  returns how many it created. Safe to run repeatedly, and concurrently:
  both this and `drop_partitions_before` hold a session advisory lock
  (always released, errors included), so a second run waits and then finds
  nothing to do.
- `drop_partitions_before(&client, cutoff)`: drops partitions for days before
  `cutoff`, **never today's**, even if `cutoff` is later.
- Partition names come only from dates, never from input.

## Status

`status(&client, now) -> Status`: schema version; active, offline (no
heartbeat for `OFFLINE_AFTER_MINUTES` = 15, well above the 5-minute
`last_seen_at` write throttle), and revoked agents; usable tokens (not
revoked, not expired, uses left); oldest and newest partition. All zeros and
`None` on an empty database.

## Console read models (schema 14)

Migration 7 stores a full latest-observation display snapshot plus the
partition day in `current_findings`. It backfills from retained events and
removes current-state rows whose latest event has already aged out. Future
ingest upserts replace that snapshot only when the observation time advances.
It adds ordering indexes for agents, latest observations, and history pages.

`console_read` is the typed query boundary for the console. It provides
summary counts, bounded keyset pages for agents, certificates, latest findings,
and history, plus exact agent/latest/history lookups. Certificate queries
select metadata only. History queries require a time floor so PostgreSQL can
prune partitions. `PageLimit` enforces the 100-row maximum. Cursor payloads
belong to the console API, which binds them to filters and the current
authorization context. These are global primitives and must only be exposed
through C3 handlers that enforce scope in SQL.

`console_read::schema_is_current` returns true only when the database schema
matches this binary exactly; empty, old, and newer schemas remain unready.

## Console identity and access schema (schema 15)

Migration 15 adds the persistent local identity boundary used by C3: users and
Argon2id credential slots, hash-only pre-auth and session state, bounded login
throttle buckets, idempotency records, role/permission bindings, exact-tag
asset groups, service accounts and hashed tokens, finding-triage state/history,
structured audit columns, and a versioned 365-day audit-retention policy.
`audit::cleanup_expired_events` removes at most 10,000 events older than the
stored policy cutoff per call; repeated maintenance runs drain larger backlogs.
Built-in Viewer, Analyst, Operator, and Admin role permissions are seeded by
the migration. The `openvibes_console` database role can read platform data
and update console-owned state; it cannot update agent/finding source data or
modify/delete audit rows. This migration establishes tables and grants;
bounded transactional store operations follow in C3 work.

## Console enrollment-token administration (schema 16)

Migration 16 grants the console role access to enrollment-token metadata and
use counts. The console stores only the SHA-256 digest of the token's decoded
32-byte secret. Its idempotent creation transaction stores the token,
24-hour request/response replay record, and audit event together; listing
never exposes secret material.

## Console rule verification reads (schema 17)

Migration 17 grants `openvibes_console` `SELECT` on `rule_trust_keys` so the
console can verify uploaded signed envelopes against the active public keys.
It grants no trust-key mutation rights; adding/removing keys remains an audited
local `openvibes-admin` operation.

## Console finding triage history (schema 18)

Migration 18 records assignment, accepted-risk expiry, and rule version in
triage history. `console_triage` reads default Open state for live latest
findings, performs ETag-versioned state changes with history and audit in the
same transaction, and reopens completed triage when a new applicable latest
observation arrives during ingest.

## Test

```sh
eval "$(scripts/test-db.sh)"     # throwaway cluster under target/pg
cargo test --locked -p platform-store
cargo test --locked -p platform-store --test console_read -- --nocapture
```

Each test creates and drops its own database. Tests fail, never skip,
when `OPENVIBES_TEST_DATABASE_URL` is unset.
