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
- `SCHEMA_VERSION` (currently 58; a compile-time check ties it to the last
  migration), `schema_version(&client)` (`None` on an
  empty database), `migrate(&mut client)`.
- `StoreError`: `Unavailable` (connection or pool), `NewerSchema(v)`,
  `Query` (a statement failed), `InvalidUrl` (the configured URL does not
  parse: a configuration error, not an outage). Messages never contain SQL, parameters, or
  connection strings.

## Migrations

Numbered SQL files in `/migrations`, embedded at build time. Migration 4
revokes UPDATE on `findings`, `certificates`, and `token_uses` from
`openvibes-ingest`, which only inserts them; a test checks the role is
refused every write, read, or DDL it does not use. Migration 5 adds `rule_set_id`
to `findings` and `current_findings` (`''` = unknown sender) and keys
current state by agent, rule set, and rule: rule ids are unique only within
a rule set. Migration 6 adds rule distribution (below) and the role
`openvibes-distribution`. `migrate` runs
in one transaction that first takes an advisory lock (before even creating
`schema_version`), so concurrent runs serialize and both succeed;
already-applied migrations are skipped. A database at a
**newer** version is refused with `NewerSchema`, never rolled back.

Schema 1 (`0001_initial.sql`): `agents`, `certificates`,
`enrollment_tokens`, `token_uses`, `findings` (partitioned by
`observed_day`), `current_findings`, `audit_log`, and the least-privilege
role `openvibes-ingest` (which may also read `schema_version`, for its
readiness check). The migrating role needs `CREATEROLE`.

## Tokens, agents, CA certificates (schema 2)

- `tokens::create(&client, &NewToken) -> token_id`, `tokens::list` (never
  returns the token or its hash; includes `uses`, `revoked` and `standing`),
  `tokens::create_standing` / `tokens::live_standing` (the standing token:
  never expires, no use limit, one live at a time; its secret sits in
  `standing_token_secret`, readable by the owner and, from migration 0038,
  the console role, which serves it only in the agent install package),
  `tokens::revoke(&client, id, now) -> bool` (was usable; an unknown id is
  `false`, a malformed id `StoreError::Query`). Ids are UUIDs, passed as
  text.
- `agents::list(&client, Filter::{All, Offline, Revoked}, now)`,
  `agents::show(&client, id)` (with certificate count),
  `agents::revoke(&client, id, now) -> Revoke::{Revoked, AlreadyRevoked,
  Unknown}`.
- `ca::record(&client, role, fingerprint, pem, not_after)` (idempotent on the
  fingerprint), `ca::list`. Migration 2 adds `ca_certificates` (readable by
  `openvibes-ingest`).

## Ingest queries (`ingest::…`)

All run within the `openvibes-ingest` role's grants (the tests use
`SET ROLE "openvibes-ingest"`).

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
  at most every 5 minutes, or at once when the hostname, the capabilities
  or the health report's `rule_sets` change; an absent
  hostname keeps the stored one (migration 3 adds `agents.hostname`,
  indexed). Returns whether it wrote. Every call also upserts the agent's
  row in `agent_presence` (see Live presence below).
- `store_findings(&mut client, agent_id, &[StoredFinding], now) -> new`: one
  transaction, `ON CONFLICT DO NOTHING`, and a `current_findings` upsert
  keeping the newest observation and the first-seen time.
- Certificate chains are stored as a JSON array in `certificates.chain_pem`.

## Agent health (`health::…`, schema 23)

Protocol P12. `agents` gains `health` and `health_previous` (the latest
report and the one before it, JSONB) and `health_at`. `ingest::heartbeat`
takes the report and writes it in its throttled UPDATE (every 5 minutes,
or at once when hostname, capabilities or the report's `rule_sets` change,
so an accepted bundle shows in `agent show` within a minute). The stored report moves
to `health_previous`, and a heartbeat without one keeps it. Schema 50 adds
`hardening_facts_ok_at`: the heartbeat write sets it to the report's time when
`last_scan.collectors.hardening` is `ok` (backfilled from `health_at` for
reports that were `ok` at migration).

`health::health_status(last_seen_at, health_at, health, previous, now)`
gives `Healthy`, `Degraded` (with reasons), `Offline` (no heartbeat for
`OFFLINE_AFTER_MINUTES`) or `Unknown` (no report, or one older than 15
minutes). It is computed when read and never stored.
`AgentInfo::health_status(now)` applies it to active agents only.

**Threat alarms per host** (`alarms_status::alarms_status(reported, alarms)`,
eBPF watcher): from the stored `health -> 'alarms'`, computed when read.
`None` before a health report or when the value does not parse; otherwise
`On { source }` (`ebpf`, or `audit`, which a missing `source` from agents
before the watcher also means) or `Off { reason, text, fix, command, fault }`.
The agent sets `source` and `fallback` once at start; its `collector` is
`not_found` until the first program start and `ok` after; anything else means
the reader is not working.

| `reason` | When | `fix` (words) and `command` | `fault` |
|---|---|---|---|
| `not_enabled` | no `alarms` object (an agent from before alarms were always on, #247) | update the agent; no command | no |
| `no_source` | `source: none` (the audit socket did not open either) | `CAP_AUDIT_READ` in the unit when `permission_denied`, else the agent's log; `sudo systemctl restart openvibes-agent` | yes |
| `reader_failed` | `collector` other than `ok`/`not_found` (the reader stopped, or an older agent's audit socket failed) | the agent's log; the restart command | yes |
| `audit_not_set_up` | `fallback.audit_rule_loaded` false (no keyed audit record seen yet) | auditd installed and running (and, for `capability`, how to get eBPF back); `sudo /usr/libexec/openvibes-agent/audit-fallback` | yes |

`text` names the eBPF failure (`fallback.detail`) in words when eBPF was
tried. `console_read::Agent.alarms` carries it for online (`active`) hosts
only: a stale host's last report no longer says what is true. The console's
agent views and `openvibes-admin agent show` use it, so both say the same
thing. Known: right after a fallback host's agent restarts, the status reads
`audit_not_set_up` until its first program start (seconds on a real host).

Reasons, in this order:
- `queue_dropping`: `dropped_total` rose;
- `delivery_stalled`: oldest pending over `DELIVERY_STALLED_S` (3,600);
- `queue_nearly_full`: over `QUEUE_NEARLY_FULL_PERCENT` (80) of the limit;
- `scan_overdue`: more than twice the interval since the last scan;
- `collector_failing`: an outcome other than `ok`, `unsupported` or
  `not_found` (those mean nothing to read on this host); a code from a
  later version counts as failing;
- `rule_set_expiring`: within `RULE_SET_EXPIRING_DAYS` (7);
- `rule_set_refused`;
- `storage_errors`: rose;
- `clock_jump`: over `CLOCK_JUMP_S` (300).

Since the report is written with the throttle, "rose" compares reports
about 5 minutes apart.

## Rule distribution (`rules::…`, schema 6)

Tables: `rule_sets` (id, `created_at`, `retired_at`), `rule_trust_keys`
(per set and issuer key id: 32-byte Ed25519 key, `added_at`, `removed_at`),
and `rule_bundles` (per set and version: the exact envelope bytes, at most
1 MiB, its SHA-256, issuer, signed creation and expiry, `published_at`,
`published_by`). The current bundle is the highest version; there is no
mutable pointer.

`openvibes-distribution` may only read `agents`, `certificates`,
`rule_sets`, `rule_bundles`, and `schema_version`; it cannot see trust keys.
`openvibes-ingest` has no rights on the rule tables. A test checks both.

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
`inventory_at`. `openvibes-ingest` may add versions and replace a host's
links, never edit or delete versions (a test checks it).

- `replace(&mut client, agent_id, os_id, os_version, running_kernel,
  packages, sha256, now)` locks the agent row; an equal digest is `Unchanged` (nothing written, no
  notification); otherwise it inserts unknown versions, replaces the host's
  links, records OS, running kernel (schema 9) and digest, and sends `NOTIFY inventory_changed` with
  the agent id (delivered at commit) → `Stored`. Several installed versions
  of one package (kernels) are all kept. A changed inventory resets
  `vulnerability_match_version`, leaving it pending until the matcher
  successfully evaluates it.
- `apply_changes(&mut client, agent_id, os, running_kernel, added, removed,
  base, expected, now)` (protocol P11) locks the agent row; unless the
  stored digest is `base`, every removed row is linked, every added row is
  not, and the fingerprint of the result (computed from the host's stored
  rows) is `expected`, it returns `Resync` and writes nothing. Otherwise it
  inserts unknown versions, unlinks the removed rows, links the added ones,
  records OS, kernel and digest and notifies, as `replace` does → `Stored`.
- `PackageRow` is the normalised record of the P11 fingerprint:
  `normalized()` and `From<&NormalizedPackage>`.

## Finding changes (`finding_changes::…`, schema 27, protocol P13)

`current_findings` gains `ended_at` (NULL: the match is open),
`end_approximate` and `source` (`scan` for agents that report every scan,
`changes` for P13), and (schema 49) `end_recorded_at`, the platform's time
when an end was stored (NULL while open; `ended_at` is the agent's clock); `agents` gains `match_sha256`, the digest of the
agent's open P13 matches the platform acknowledged (NULL: none, the empty
set's digest). `finding_changes::apply(client, agent_id, changes, rows,
now)` runs in one transaction under the agent row's lock: it answers
`Outcome::Resync` and stores nothing when the stored digest is not
`base_sha256` (unless `replace`), a `started` match is already open, a
`changed` or `ended` one is not, or the digest of the result (from the open
rows' rule set, rule, version, severity, message and evidence) is not
`sha256`. Otherwise it writes history through `ingest::store_findings_in`
(the idempotent insert and the automatic triage reopen), sets each started,
changed and transient row's content and `source = 'changes'` (open and
current as of `now`, or ended for a transient), ends the `ended` ones (and,
for a `replace`, every open match it omits, as approximate at
`scanned_at`), and records the new digest. A replace ends only P13
rows: when an agent upgrades to P13, its rows from per-scan delivery that
the first replace omits keep `source = 'scan'` and are never ended; they
age out of the console's window like any match no longer observed. `Rows` holds the document's
findings already converted by `wire::finding`.

`finding_changes::heartbeat(client, agent_id, match_sha256, last_scan_at,
now)` handles a P13 heartbeat's digest: `true` (409 `findings_resync`)
when it is not the stored one; otherwise it sets the agent's open P13
matches' `last_observed_at` to now when it is over an hour old (so the
console's window keeps them current; ended matches and offline hosts age
out), and, when `last_scan_at` is given, reopens mitigated or
accepted-risk triage a later scan confirmed (`console_triage::reopen_if_due`,
shared with the reopen on a new observation).

## Wire conversions (`wire::…`)

Shared by online delivery (ingest) and file import (admin), so both refuse
and store alike: `finding(finding, oldest, latest, partitions) ->
Result<StoredFinding, reason>` (`future_observation` beyond
`MAX_FUTURE_MINUTES` = 60, `retention_expired`, `out_of_range`,
`unstorable` without a partition), `inventory(os, running_kernel,
packages) -> (rows, sha256)` (the distinct normalised rows, and the
protocol's inventory fingerprint over OS, kernel and packages, P11) and
`package_rows(packages)` (the rows alone, for change sets). `ingest::store_findings` takes an
`Origin`: `Online` stores `origin = 'online'`, authenticated; `Import`
stores `'import'`, unauthenticated.

## Imported hosts (`imports::…`, schema 15)

Hosts from agent export files (protocol P3b), run as the admin role.
Migration 15 lets `agents.status` be `imported` only with an id
`import.<install_id>` (and `agent.<uuid>` only otherwise), and adds
`claimed_agent_id`, the `agent_id` a file named, kept as a label.

- `upsert_host(&client, &ImportedHost, now) -> id`: creates the row
  (`enrolled_at` = first import) or updates it; `last_seen_at` is the newest
  file time, and hostname, version and claimed id come from the newest file.
  Never matches an enrolled row.
- `replace_inventory(&mut client, id, os_id, os_version, running_kernel,
  rows, sha256, collected_at) -> Stored | Unchanged | Older`: `Older` when
  the stored `inventory_at` is later than `collected_at`; otherwise
  `inventory::replace` with `collected_at` as the time; on `Unchanged` the
  snapshot time still moves forward (content can repeat after a rollback),
  so newest wins whatever order files arrive in.

## Vulnerabilities (`vulns::…`, schema 8)

`advisories` (id, source, release, severity, title, times, url),
`advisory_cves`, `advisory_packages` (fixed name, arch, EVR),
`vulnerabilities` (host × advisory: affected packages as JSON, first seen,
fixed at — kept after fixing; `reboot_needed` since schema 9), and
`feed_sources` (last check, last change,
content digest, advisories, last error). Role `openvibes-vulns` writes only
these and reads `agents`, `package_versions`, `host_packages`. Schema 33 adds
`agents.vulnerability_match_version`: zero means the current inventory still
needs matching; successful host or release matches record the matcher
version. `hosts_needing_match` finds work after a restart, and the service
retries pending hosts every minute. This also marks existing inventories for
one re-match when deploying a new matcher. Host-specific version candidates
start from that host's materialized inventory rows so the query does not
expand the whole release catalog before filtering the host.

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

Schema 39 (CPE matching, `cpe` module) adds `cve_applicability` (NVD's affected
upstream ranges per CVE and product, kept only for products in
`cve_applicability_products`), and `cpe_findings` (an installed package version
in a range, per release, with confidence and basis). They stay apart from
`vulnerabilities`, so no count or host flag includes them; the
`openvibes-vulns` role writes them and the console reads `cpe_findings`.

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

Schema 12 grants `openvibes-vulns` `MAINTAIN` on the tables it bulk-loads
(PostgreSQL 17 or later), so `replace_advisories` can `ANALYZE` them.
`vulns::list` combines each advisory's CVEs and enrichment once, then
sorts and limits (0.63 s at 244,000 open vulnerabilities).

Console reads use `vulns::list_in_scope`, `vulns::summary_in_scope`, and
`vulns::cve_details_in_scope`. Asset-group membership is resolved to agent
IDs and applied in SQL before priority selection, aggregation, or returning
advisory enrichment. An empty scope returns no host rows or summary counts;
advisory details are returned only when a visible host has a matching
vulnerability.
The summary's `feed_last_imported_at` is the newest `feed_sources.last_changed_at`
of an advisory feed (`os_id <> 'cve'`: enrichment feeds alone match
nothing), `None` until one has imported, so an empty summary can say "not
set up" rather than "nothing found". Schema 28 grants the console
`SELECT (os_id, last_changed_at)` on `feed_sources`, and no other column.
`ListFilter.exploited` and `ListFilter.reboot_needed` are applied inside the
ranked/counting SQL before the 10,000-row fleet bound, so filtered fleet reads
do not lose lower-priority matching rows. `hosts_named_in_scope` resolves an
agent ID or hostname only among visible agents; a hidden ID cannot suppress a
visible hostname match.

Schema 25 grants the console role read-only access to the vulnerability and
inventory tables and adds the agent-scoped `vulnerabilities.read` permission
to built-in roles. The role can still change no vulnerability or inventory
rows; each console query must apply the resolved asset scope.

Schema 26 adds `console_dashboards` (a layout per dashboard, owner,
optional shared role, version) and `console_user_home`, and grants the new
global permission `dashboards.share` to Admin.

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

Schema 14 keeps vulnerabilities without a fix per package version
(`version_vulnerabilities`: version, advisory, package, first seen) instead
of per host, and each host's count of them (`host_vulnerability_counts`).
`version_candidates` reads advisory packages against distinct versions on a
release or host; `candidates` selects the (advisory, package) pairs worth
matching per host; `apply_versions` records per-version hits;
`refresh_no_fix_counts` stores counts. Found sets use anti-joins (`NOT
EXISTS`) to keep large match sets bounded.

## Assistant lookups (`assistant::…`)

Read-only queries for the console's assistant (assistant spec §5). Each
takes an `AgentScope` (`All`, or `Only(agent IDs)`, resolved by the console
from the user's asset scope) that applies in SQL to items and counts alike,
a `limit` (1–100), and returns the total so callers can say what was left
out: `finding_groups` (one row per rule set and rule, console decision 18;
text filter on rule, rule set, and latest message with `LIKE` wildcards
escaped; minimum severity), `finding_endpoints` (in-window endpoints and the
count not seen in the window), `agent_summaries` (by agent ID or
case-insensitive host name), `host_vulnerabilities` (open, by priority),
`vulnerable_hosts` (by CVE or advisory; each host carries the open row's
`packages` `{name, installed, fixed}`), and `overview`. A finding with an
unrecognised severity reports `unknown`. Nothing writes.

`assistant_inventory::…` adds the same kind of reads for ports, services
and software (issue #241): `host_listeners` (one host's sockets, optionally
one port) and `host_services` (its running units), `port_listeners` (hosts
on a port, TCP or UDP) and `installed_packages` (package name contains the
text, case-insensitive, optionally on one host), plus `host_report` (status,
`services_at`, owners, truncated). `installed_packages` first picks at most
`limit` matching names installed on a host in scope, then their hosts, so a
short text never sorts every host's packages. The fleet-wide reads skip
revoked hosts (a named host is read even when revoked) and return how many
distinct hosts matched. Each read runs in a transaction with
`SET LOCAL statement_timeout = '5s'`.

`console_read::agent_ids_in_scope` resolves an authorized asset-group scope
to the exact agent IDs used by finding lookups. Global scope stays `All` and
does not materialize the fleet ID list. `agent_matches_in_scope` performs a
bounded exact-ID or hostname lookup for assistant agent summaries without
reading vulnerability tables.

## Audit log

`audit::record(&client, actor, action, target, result)` appends one row.
`audit::record_with_detail` adds a request ID and caller-supplied redacted JSON
metadata for events that need correlation; prompts, answers, and retrieved
records are not valid detail values.
The `detail` column is never given secrets.

## Partitions and retention

- Three tables are partitioned by day and share one retention: `findings`,
  `alarms` and `alarm_triage_history` (schema 29).
- `ensure_partitions(&client, today, days_ahead)`: creates `<table>_YYYYMMDD`
  partitions of each for today and the next `days_ahead` days that are missing;
  returns how many it created. Safe to run repeatedly, and concurrently:
  both this and `drop_partitions_before` hold a session advisory lock
  (always released, errors included), so a second run waits and then finds
  nothing to do.
- `drop_partitions_before(&client, cutoff)`: drops partitions of each for
  days before `cutoff`, **never today's**, even if `cutoff` is later.
- `partition_days(&client)` lists the `findings` days (ingest's "no
  partition" check); `partition_days_of(&client, table)` any of the three.
- Partition names come only from table constants and dates, never from input.

## Alarm hourly starts (schema 60)

`0060_alarm_hourly_starts.sql`: `alarm_hourly_starts (alarm_row_id, hour,
starts)`, PK `(alarm_row_id, hour)`, for the alarm page's "Last 24 hours"
timeline. Not partitioned and no FK (the `alarms` key includes the partition
day). `alarms::insert_batch` adds a new alarm's whole count, or a grown
count's difference, to `date_trunc('hour', now)` in the same transaction; a
repeated or shrinking count adds nothing. `prune_alarm_hourly(client, now)`
(run by `openvibes-admin` maintenance) deletes hours older than 7 days.
Grants: ingest SELECT/INSERT/UPDATE, console SELECT.

**Alarms list** (`alarm_list::alarm_list`, roles 5a): one statement gives the
page, total, per-value counts and the summary line, all inside the
`alarms.read` scope. The summary ("N open", "critical or high", "on hosts with
alarms off") counts OPEN alarms under every filter except state, so choosing
`state=mitigated` never shows "0 open". The assignee user binds as text cast
to uuid; "unassigned" is a separate flag, and text that is not a user id
matches nobody. `limit` and `offset` are clamped (the console rejects values
out of range first).

## Threat alarms (schema 29)

`0029_alarms.sql` (additive; protocol P14, plan
`docs/superpowers/plans/2026-09-30-threat-alarms-3-platform.md`):

- `alarms`: one row per alarm, partitioned by `first_seen_day` (UTC day of
  `first_seen`, checked). `id` is the platform's key for the console;
  `alarm_id` is the agent's and unique only per agent (`(agent_id,
  alarm_id)` is indexed for the lookup before insert). Triage (`state`,
  assignee, note, `accepted_until`, `triage_version`) lives on the row, so
  it leaves with its partition; the CHECKs match findings triage.
- `alarm_triage_history`: partitioned by the alarm's day, same reason.
- `alarm_suppressions`: `host` (agent), `program` (exe) or `command` (exe
  and SHA-256 of the masked args); a CHECK ties the columns to the scope;
  removal sets `removed_at`/`removed_by` and keeps the row.
- `agents.alarms_dropped_total`: the largest `dropped_total` reported.
- Test triggers (`rules::TEST_RULES`: `baseline-alarms/alarm.openvibes.test`
  and `baseline/test.openvibes.running`, spec
  `2026-10-09-test-triggers-design.md`): ingest stores a test alarm as
  `mitigated` with `alarms::TEST_NOTE` and a recurrence never reopens it;
  `rules::last_tests` reads a host's newest test alarm and test finding.
- Permissions `alarms.read`, `alarms.triage`, `alarms.suppress` (agent
  scoped) for the roles in `console-rbac.md`.
- Grants: ingest SELECT/INSERT/UPDATE on `alarms`, INSERT on the history,
  SELECT on suppressions; the console SELECT on `alarms` with UPDATE only
  on the triage columns, SELECT/INSERT on the history, and
  SELECT/INSERT/UPDATE on suppressions.

Code over these tables:

- `alarms` (ingest): `row` checks one alarm (time, skew, retention,
  partition); `insert_batch` upserts with `GREATEST` on count and last
  seen, applies active, unexpired suppressions of the batch's rules on the
  alarm's host, group or all hosts (`suppression_matches`, first by id),
  reopens a mitigated alarm or an
  expired accepted risk on recurrence, and keeps `alarms_dropped_total`.
  `args_sha256` is the `command` suppression hash (SHA-256 of the args'
  JSON array).
- `console_inventory` (console): a host's packages, the fleet's software
  and one package's versions, open advisories and hosts. The software page
  also gets each name's advisory counts, worst severity and exploited flag
  from one extra query over the page's names (`fill_risk`), and one
  package's advisories come from `software_advisories`; no migration.
  Reads are scoped to the caller's agents
  (counts over visible hosts only). The fleet query picks the page's names
  first, in name order, so the scan stops early. It then counts hosts and
  versions by grouping, not `count(DISTINCT)`, which sorted every row
  under the text collation. A global caller skips the visibility join, and
  a scoped caller's hosts are resolved once. `fixable_vulnerable` is an
  open vulnerability with a fix naming the package. An ignored test
  measures it at 1,000 hosts × 2,000 packages.
- `console_alarms` (console): scoped `list` (filters, keyset `(last_seen,
  id)`), `detail`, and `update_triage` with the findings workflow, history
  and audit.
- `alarm_suppressions` (console): see "Suppressions with approval" below.
- `rule_drafts` (schema 42): one row per draft rule of `site` or
  `site-alarms`; `list`, `get`, `put` (upsert) and `delete`. The console
  validates before `put`; the table holds only rules the agent would accept.

## Open ports and running services (`host_services::…`, schema 31, protocol P15)

`0031_host_services.sql` (additive):
- `host_listeners` and `host_services`, replaced per report like
  `host_packages`.
- New `agents` columns: `services_sha256`, `services_at` and
  `services_owners`, plus `services_refused_at` and `services_refused`.

Functions:
- `replace` (ingest): one transaction. A new digest replaces the rows; an
  unchanged one only touches `services_at`. It always clears a refusal.
- `refused` (ingest): records a refused report (`Refusal::TooLarge`,
  `Invalid`, `WrongAgent`) and keeps the stored lists.
- `for_host`, `fleet_ports` and `fleet_services` (console): scoped like
  agents, and the fleet reads leave revoked hosts out.
- `port_hosts` and `unit_hosts` (console): the visible, non-revoked hosts
  with a port or unit, keyset-paged on `(hostname, agent_id[, address])`.
- `agents.services_truncated` holds the report's `truncated`.

Grants: ingest inserts and deletes the two tables, and already updates
`agents`; the console reads.

## Console password change (schema 30)

`0030_console_password_change.sql` (additive): `console_users.password_must_change`
(default false). The console's New user sets it with a one-time password;
`console_auth::session` returns it, and `change_own_password` (a compare-and-swap on the
verified hash, credential row locked first) clears it while replacing the credential, revoking the user's other sessions and
auditing `auth.password.changed`, in one transaction. `create_local_user`
takes the flag and the audit `actor_kind` (`local_admin` from the CLI,
`user` from the console). No new grants: the console already writes
`console_users`, `console_credentials` and `console_sessions`.

## Live presence (schema 40)

`agent_presence(agent_id, seen_at)` is an UNLOGGED table: ingest upserts it on
every heartbeat (`platform_store::presence`, also called by
`ingest::heartbeat`; a narrow row, no WAL), so "online" does not wait for the
throttled `agents.last_seen_at` write. A crash only empties it; readers then
fall back to the saved time until the next heartbeat. The SQL function
`agent_seen_at(agent_id, saved)` returns the later of the two; every read that
decides online or offline or shows a last-seen time (`console_read` agents and
summary, `agents`, `status`, the assistant, host software and services) goes
through it. `OFFLINE_AFTER_MINUTES` is 3. The health report is still saved on
the throttled write, so its own freshness limit is the separate
`health::HEALTH_REPORT_FRESH_MINUTES` (15).
`console_read::online_fingerprint(&client, now) -> (count, id sum)` is a cheap
"did the online set change" check for the console's event stream (not scoped,
carries no agent identity).

## General settings (`console_settings::…`, schema 54)

Table `console_settings (key, value jsonb, changed_at, changed_by)`: one row
per changed key; a key with no row has its default (kept in the console).
`all`, `set` (one transaction: lock the row, upsert, audit `settings.changed`
with `{key, old, new}`; returns the old value), `recent` (newest change
audits), `reset` (delete the row, audit), `values` (every stored value by
key, for a service to apply over its file) and `require_approval(&impl
GenericClient)` (false when the row is absent or not a bool).

Schema 70 adds `service_secrets (key, value, changed_at, changed_by)` for
settings that are secrets (the NVD API key). The console's role may write
it and read only `key`, `changed_at`, `changed_by` (column grants), so no
console query can return a value; `openvibes-vulns` may read it.
`secrets_set` (which are set), `set_secret` (set or remove; an UPDATE or an INSERT under an advisory lock, never an upsert, because `EXCLUDED.value` would need SELECT on the value; the audit line
says `set` or `not set`, never the value) and `secret` (a service reads
one). `console_settings` also grants DELETE to the console and SELECT to
`openvibes-vulns` (and, in schema 71, to `openvibes-ingest` and
`openvibes-distribution`, which read their own keys once at start with
`read_with_prefix`). Schema 72 adds `console_secrets` (same columns) for
secrets the console itself uses, the assistant's API key: the console role
has SELECT, INSERT, UPDATE and DELETE on it, no other role has anything.
`set_secret`, `secret` and `secrets_set` pick the table by key (`assistant.*`
goes to `console_secrets`). Tests: `tests/console_settings.rs`.

## Single sign-on (`console_sso::…`, schema 73)

Tables `console_sso_users` (user id, identity provider issuer and NameID
`subject`, unique together; the link is never by email or username),
`console_saml_requests` (relay token hash, request ID, browser cookie hash,
five-minute expiry, `consumed_at`) and `console_saml_seen` (hash of issuer
and assertion ID, kept until an hour after the assertion ends). The console
role has SELECT, INSERT, UPDATE and DELETE on them. `console_role_bindings`
gains `source` (`manual`, or `sso` for roles the identity provider's groups
gave). `start_request` forgets expired rows, refuses over 2,000 waiting
sign-ins and stores one; `take_request` uses a request up once, only with
the matching browser hash and before it expires; `sign_in` records the
assertion (a repeat is `Replay`), finds or creates the person (username
`sso.` plus 16 hex of the SHA-256 of issuer and subject, `auth_source`
`sso`, no password), and in one transaction sets their `sso` role bindings to
the roles whose display name equals one of the groups, case-insensitively.
Nobody is created without a role; a person left with none gets `NoRole` and
their `sso` bindings revoked; a disabled person gets `Disabled`. `refuse`
writes `auth.saml.refused` with a fixed reason code. `clean` (run by `openvibes-admin maintenance`) deletes expired requests and assertions and removes people with no sign-in for N days: a delete that a foreign key blocks (cases, alarms) instead revokes all their roles (however given) and sessions; the two cases are audited `user.removed` and `user.access_removed`. People are walked in pages by id, and each is re-checked as still idle inside its own transaction. Tests:
`tests/console_sso.rs` (run as the console role).

## Saved views and list columns (`saved_views::…`, schema 56)

Tables `console_saved_views` (name unique per person and page regardless of
case, query at most 1000 characters) and `console_list_columns` (hidden keys
per person and page, at most 32), both `ON DELETE CASCADE` from the person.
`list` (by name), `create` (one transaction under a row lock on the person:
count, then insert; returns `Saved`, `NameTaken` or `TooMany` at 50),
`delete` (own views only; false when none), `hidden_columns` and
`set_hidden_columns`. Page and column keys are validated by the console.
Tests: `tests/saved_views.rs`. See [saved-views.md](saved-views.md).

## The Hosts list (`host_list::hosts`, schema 57)

`hosts(client, &HostQuery, &HostScopes, latest, now) -> HostListPage`: one
statement returns the page rows, the total, the count for every value of
every filter with the other filters applied (status, OS family, group,
label, problems, agent age), and the summary line (online, older agent,
critical), so the numbers always agree (roles spec §10.1, §10.3; plan
rulings 2–7). Search `q` matches the host name (contains, any case), the
start of the agent ID (any case) or of the IP address, or, when it parses
as a CIDR, containment. Each row's `alarms_off` is true when the host is
online and `alarms_status` of its last health report is off by a fault. Each
filter takes one value; `offset` is held to 0–100000 and `limit` to 1–100;
sorts (host, heartbeat, version, problems) break ties by agent ID.

Failing checks are those whose triage is open. Critical is
`host_listed_critical` (migration 58, a derived table; no row is 0),
recounted by `refresh_counts` with the matcher and after each triage change
(one upsert per call that writes 0 rather than deleting, so two recounts of
one host at once never collide): critical
advisories as the Vulnerabilities list and the host page show them by
default, one per advisory, fixable or without a fix, reboot pending or
not, mapped at confidence 80 or more (a known distribution's advisory or a
package without a fix, as `vulns/confidence.rs`) and triage open. The
group pages (`host_groups` list, detail and hosts) count it too. The
older `critical` column (fixable, no reboot pending) still feeds the fleet
summary and its history.

Scope (spec §6): rows, total, counts and summary come only from hosts in
`HostScopes.hosts`. Open alarms, critical vulnerabilities and failing
checks are each counted only where `alarms`, `vulnerabilities` or
`compliance` reaches the host (`None` on the row otherwise, and not counted
in that problem value); "none open" needs at least one kind in reach. A
host in compliance reach whose last contact is older than the 24-hour
window (`check_list_sql::WINDOW`, the base of `host_summary`'s
`compliance_stale`) has `compliance_stale` and no failing count, and is
never "none open". Group
values are groups with a host in scope (plus the chosen one, if it has
one); label values are the 50 most used on hosts in scope (plus the chosen
one, if present there). Group membership is read from the stored table
(`host_list_sql::members` joins `console_host_group_membership`, schema 61).

Migration 57 adds `console_version_parts(v) -> int[]` and
`console_version_older(v, latest) -> boolean` (NULL when either is
unknown; numeric segments, pre-release older than its release, build
ignored, as the web's `olderThan`), with the Rust twin
`version_order::older` checked against the same table; and
`console_condition_holds_prepared` / `console_condition_likes`, an
inlinable form of the group rule check. `console_condition_holds` keeps its
answers and now calls the prepared form. Tests: `tests/host_list.rs`,
`tests/version_order.rs`; the 20,000-host timing (`tests/host_list_timing.rs`) is in console-read.md.

## The Alarms list (`alarm_list::alarm_list`, schema 60)

`alarm_list(client, &AlarmQuery, &AgentScope, hosts_read: Option<&AgentScope>, actor_id, now) -> AlarmListPage`:
one statement returns the page rows, the total, the count for every value
of every filter with the other filters applied, and the summary line, so
the numbers always agree (roles spec §10.3; plan rulings 2–5). Only agent
alarms (`source = 'agent'`) are listed. Filters (one value each, all
combining): state (`None` is every state; the console's default is open),
severity, suppressed (hidden unless `suppressed`), host (agent id), group,
technique, case (in an open case or not) and assignee (`Me` is
`actor_id`, `Unassigned`, or a user id; a value that is not a user id
matches nothing). Search `q` matches the message, rule id, host name,
program and parent program (contains, any case). `offset` is held to
0–100000 and `limit` to 1–100; sorts (last seen, first seen, count,
severity) break ties by alarm id in the same direction.

Each row carries the host's OS family and distribution display name, the
techniques of its rule from `console_rule_meta` (matched on rule set,
set version, rule and rule version; empty when the rule is not indexed, so
the technique filter never matches it), the assignee (id, display name),
the open case holding it (id, number) and `suppressed_by`.

The summary counts, over the alarms matching every filter: open; open and
critical or high; open on hosts that are online with threat alarms off by
a fault (the Hosts list's `alarms_off` rule: the statement returns each
host's `health -> 'alarms'` with its counters zeroed, grouped, and
`alarms_status` decides), counting only hosts also inside `hosts_read`
(none when it is `None`). The console passes its `hosts.read` scope and
shows the last part only with `hosts.read`.

Scope (spec §6): the hosts are `agent_visibility`'s rule read from the
stored group membership (`host_list_sql::members`, schema 61). Group values are groups holding a host with an alarm in
reach (plus the chosen one when the scope reaches it); technique and
person values come from alarms in reach, so no value is named from a host
out of reach. The host filter has no value list. The counts come from a
small `cube` (alarms per combination of state, severity, suppressed, in a
case, assignee and techniques) and a per-host rollup for groups and the
alarms-off part. Tests: `tests/alarm_list.rs`; the 200,000-alarm timing
(`tests/alarm_list_timing.rs`) is in console-read.md.

## The Vulnerabilities list and a vulnerability's page (`vuln_list`, `vuln_summary`, `vuln_hosts`, `vuln_related`, schema 62)

One row and one page per CVE; the queries, their counts and timing are in
[console-vulnerabilities.md](console-vulnerabilities.md#the-store).

## The Compliance list (`check_list::check_list`, `check_area`, schema 63)

`check_list(client, &CheckQuery, &AgentScope, actor_id, now) -> CheckListPage`:
one statement returns one row per check (rule set and rule), the total,
the count for every value of every filter with the other filters applied,
and the summary line (roles spec §10.3; step 5c rulings 2–7, user
decision 1). A row's pairs are the hosts in the `compliance.read` scope
that fail it (a current finding with `ended_at IS NULL` seen within the
last 24 hours, the Compliance groups' default window) or pass it.

A host passes a check when:
- it is active and its heartbeat health (`agents.health`) is at most 24
  hours old;
- the health lists the rule set with a version (the agent reports none
  for a set it never accepted; a version that is not 1–18 digits is
  ignored, so no reported value can fail the statement), neither
  `not_assigned` nor refused;
- the indexed bundle of that version has the rule (`console_rule_meta`;
  a rule no indexed bundle of the set has passes at any version);
- the rule's collectors (`check_area::check_collectors`: `port.*` ports,
  `package.*` packages, `harden.*` hardening, `harden.net.ip_forward`
  hardening and packages, `test.*` processes, from the agent's `scan.rs`)
  ran `ok` in its last scan; a rule ID with no known prefix (a site rule)
  needs at least one collector reported and every one `ok`;
- no finding blocks it: a failing one, or an unended P13 match
  (`source = 'changes'`) however old. A host stuck in a resync keeps fresh
  health while its open matches age; such a pair is neither failing nor
  passing. Legacy `scan` rows never end, so only their age counts.

A failing pair's state is its triage state (no row is open, an accepted
risk past `now` is open). Checks are the rules of each set's newest
indexed version plus every check with a current finding on a host in
reach (a site rule found only out of reach is never named); a row needs
a failing or passing pair in reach. A check without metadata leaves the
list once no host in reach has a finding for it, even when hosts in
reach still pass it. Title: the rule's newest indexed title,
else its ID. Severity: the newest failing finding's in reach, else the
newest other finding's, else the rule's indexed severity
(`console_rule_meta.severity`, schema 63), else `None`. Area: `check_area`
(ruling 3), with the SQL twin `console_check_area(text)`. Since: the
earliest first-seen of the failing pairs. Assignee: as the
Vulnerabilities list (`AssigneeSummary`).

Filters (one value each, all combining): state (`open`, `mitigated`,
`accepted_risk`, `false_positive`, `passing`, `all`; a row matches when
one of its pairs is in it), severity, rule set, area, group and host (they
narrow the pairs) and assignee (state and assignee hold on the same pair;
a passing pair has no assignee and matches only no filter). Search `q`
matches the title, rule ID and rule set. Sorts: severity (then failing
hosts), failing, since and title; nulls last, ties by key in the same
direction. `offset` 0–100000, `limit` 1–100. Rule set and area values are
those of rows in reach, each with its count under the other filters.
Summary, over the rows matching every filter but the state's that have an
open failing pair: how many, on how many hosts, how many critical, how
many with no open pair assigned, and how many per rule set.

`check_list::passing_hosts_sql(hosts, checks, now)` is the same passing
rule as an SQL fragment listing (host, check) pairs, for a check's page;
a test keeps it equal to the list's counts. The list counts passing hosts
per host class instead (hosts alike in group side, mask, set versions and
ok collectors), so the counts per group are exact without listing pairs.

Schema 63 adds:
- `current_findings (rule_set_id, rule_id) WHERE ended_at IS NULL`;
- the extended statistics `current_findings_check` (ndistinct of rule
  set, rule and severity), without which the planner sorted the findings
  on disk;
- `console_rule_meta.severity` and `expression`, written by `rule_meta::upsert_from_bundle`.
  Rows indexed before it have none; `missing_bundles` lists their bundles,
  so the console's start-up backfill re-indexes them;
- `console_check_area`.

Ended findings are not failing anywhere else either (step 5c ruling):
the host page's failing checks (`host_summary`), `finding_summary_in_scope`,
`latest_findings_in_scope` and `finding_groups_in_scope` leave rows with
`ended_at` set out; only the per-rule endpoint list keeps them, for its
"fixed" badge (`tests/ended_findings.rs`).

One failing definition (step 5c ruling): `check_list_sql::failing(now)` (not
ended, seen within `WINDOW`) and `open_failing(now)` (failing, and open by
the pair state: no triage, open, or an expired acceptance) are the only
SQL that says what fails. The list, a check's page, the host page's tile
and top failing (`host_summary`), the Hosts list's failing count
(`host_list_sql`), `finding_summary_in_scope` (the menu count and the
Breakdown tile), the count history's compliance columns (`history.rs`
`host_counts_sql`: metrics and top hosts) and bulk from a check row
(`bulk_triage/compliance.rs`) all use them, so their numbers agree;
`finding_groups_in_scope` takes its triage state from `PAIR_STATE` (an
expired acceptance is open). Passing also needs the host's last scan to
have finished within `WINDOW` (`scan_fresh`, read as 1–18 digits before
the cast), shared by the list and `passing_hosts_sql`
(`tests/check_scan_age.rs`, `tests/finding_summary_failing.rs`). A host whose last
contact is older than `WINDOW` is compliance-stale on the host page and
the Hosts list: no failing count rather than a misleading 0.

Tests: `tests/check_list.rs`, `tests/check_list_filters.rs`,
`tests/check_area.rs`, `tests/rule_meta.rs`; the 500,000-finding timing
(`tests/check_list_timing.rs`) is in console-read.md.

## A check's page (`check_summary`, `check_related`)

`check_summary(client, rule_set_id, rule_id, &AgentScope, now) ->
Lookup<CheckPageSummary>` and `check_hosts(client, rule_set_id, rule_id,
&AgentScope, CheckHostSegment, offset, limit, now) -> Lookup<CheckHostsPage>`
read one check under the list's definitions (`check_list_sql`'s
`failing`, pair state and `passing_hosts_sql`), over the hosts in reach
(`agent_visibility`). The check exists when its set's newest indexed
version has it or a host in reach has a current finding for it, and it
has a failing or passing host in reach; otherwise `Lookup::Missing`.
`days` counts, per UTC day of the last 14, the findings in reach first
seen by the day's end and ended (else, when not failing, last seen) at or
after its start. History merges `console_finding_triage_history` of hosts
in reach, episode starts and ends, and `rule_bundles` publishes, newest
first, 50 at most. The header's `open` counts the failing pairs whose state is open (an
expired acceptance counts); a Hosts row carries the pair's
`accepted_until`, kept after it expires, and the finding's `origin`;
`check_hosts` takes a `CheckHostState` that narrows the Failing segment
and returns the failing pairs per state (`CheckStateCounts`; both in `check_states`, re-exported by `check_summary`). `check_summary::evidence` turns `detection -> 'inputs'`
into evidence, a value only for a complete input. `check_related`
parses the port or unit from the rule's indexed expression
(`member_of`, `rule_port`, `rule_unit`; schema 63 adds
`console_rule_meta.expression`, written with the severity) and counts the
hosts in reach with it (`host_listeners` exposed, `host_services`).
Same area counts the other failing checks in reach whose
`console_check_area` matches, reading every failing finding in reach in
that area; its timing on the ruling 18 fleet is in console-read.md.
Tests: `tests/check_summary.rs`; the overview is
[console-compliance.md](console-compliance.md).

## The host page summary (`host_summary::summary`)

`summary(client, agent_id, &HostScopes, latest, now) -> Option<HostSummary>`:
`None` when `scopes.hosts` does not reach the host (missing and out of
reach look the same). A few small queries on one host: `agent_in_scope`,
one facts row (address, distribution, OS family, status, agent age, and the
package, listening and exposed port, service and certificate counts),
`host_labels::of_host` (groups and labels; a revoked host keeps its labels and is in
no group), the five newest certificates, `rules::last_tests`, and the top
three of each problem kind with its total: open agent alarms and failing
checks (triage open, not ended: an ended finding is fixed, as on the
Compliance list) most severe then newest first, and open vulnerabilities through
`vulns::list_in_scope` with the host as its filter, one item per advisory
(first in priority order). Groups and labels come from
`host_labels::of_host`, which skips the reach check `host_labels` makes. Each problem list is `None` unless its scope
reaches the host. `HostSummary::reaches(scope)` applies the
`agent_visibility` rule from the groups already read; the console uses it
for its `can` flags. Tests: `tests/host_summary.rs`.

## An alarm's page (`alarm_summary::alarm_summary`, roles 5a)

The web page it serves: [console-alarms.md](console-alarms.md).

`alarm_summary(client, id, &alarms_scope, vulnerabilities_scope, now) ->
Option<AlarmPageSummary>`: `None` when the alarm is missing or `alarms_scope`
does not reach its host (`console_alarms::detail`). Otherwise: the alarm as
an `AlarmListRow` (OS, techniques from `console_rule_meta`, assignee, open
case) with its detail and triage; the rule's text from `rule_meta::get`, or
the alarm's message as title and message with no explain, check or
techniques when the rule is not indexed; the commands seen, which are the
alarm and its siblings (agent alarms on the same host with the same rule
set, rule, `process.exe` and `ancestors[0].exe`, user decision 1), most
starts first, then by id, each with its masked `args`, count, first and last
seen, state, suppression and open case; `hourly`, 24 sums of
`alarm_hourly_starts` over those siblings from 23 hours before the current
hour to the current hour, oldest first (hours cut by `date_trunc` as
ingest cuts them); the host's other open agent alarms (five and the total,
`host_summary::top_alarms`); the host's open advisories through
`host_summary::top_vulnerabilities` when `vulnerabilities_scope` reaches
the host, else `None`; and `elsewhere`, the other hosts in `alarms_scope`
with an open, unsuppressed alarm from this rule set and rule, and their
open alarms. The siblings share the host, so the scope that reached the
alarm reaches them. `AlarmPageSummary::reaches(scope)` applies
`agent_visibility`'s rule from the host's groups; the console uses it for
its `can` flags. The sibling key groups NULL with NULL (no parent, or no
exe). Tests: `tests/alarm_summary.rs`.

## Suppressions with approval (`alarm_suppressions::…`, schema 55)

`0055_suppression_approval.sql` (needs a backup) gives `alarm_suppressions`
a `state` (`waiting`, `active`, `rejected`, `withdrawn`, `removed`), a
where (`agent_id` for one host, `host_group_id` for one group, neither for
all hosts), `for_days` (7, 30 or null), `activated_at`, `expires_at`,
`decided_by/at`, `decision_reason` and the source `alarm_id` (no foreign
key: `alarms` is partitioned). Old rows become `active` from `created_at`,
removed ones `removed`; `removed_at` stays in step with `state = 'removed'`.
The console may now UPDATE `alarms.suppressed_by`; ingest may SELECT
`console_host_group_members` (`console_host_in_group` runs with the
caller's rights).

- `request(client, suppress, &Request { alarm_row_id, what, place,
  for_days, reason }, actor, now)`: derived from an alarm within the
  `suppress` scope; all hosts needs a global scope, a group must be in the
  scope. Waiting when `console_settings::require_approval`, else active at
  once: `expires_at = activated_at + for_days`, and the source alarm, if
  open or investigating and covered by the where (its host, or a group
  holding its host), is closed as ingest closes a matched one
  (`false_positive`, `suppressed_by`, triage history).
- `decide(client, approve, id, approve_it, reason, actor, now)`: waiting
  rows in the approver's reach only; never the requester's own
  (`OwnRequest`); rejecting needs a reason. Approving starts the period and
  closes the source alarm (if covered, as above).
- `close_covered(client, suppress, id, alarm_ids, actor, now)`: after bulk
  Suppress made `id` active, closes the other selected alarms it covers
  (same rule, program and where), each within `suppress`, the same way;
  returns the ids of `alarm_ids` now closed by `id`.
- `withdraw(client, id, actor, now)`: the requester's own waiting row;
  another person's is `NotFound`.
- `remove(client, suppress, id, actor, now)`: an active row in reach.
- `list(client, read, &ListFilter { state, alarm_id }, now)`: waiting
  (oldest first), active including expired (`expired` is derived at `now`)
  and rejected rows, at most 500 each. A waiting row carries
  `would_close`: the alarms on hosts the reader reaches, last seen in the
  7 days before `now`, it would have closed, counted with ingest's matcher
  over the newest 10,000 of the same rule and program
  (`would_close_capped` when there were more, so the page says "at
  least"). Args that are not a list of strings never match. Reach (`in_reach`): a host row if
  the host is visible, a group row if the group is in the scope, an
  all-hosts row for every reader but only a global caller for decide and
  remove, a device or signature row for a global caller only. Approving a
  group row whose group is gone is refused (`Invalid("group")`).
- `create_for_device` (`openvibes-admin`): device and signature rows are
  always active.

Every transition is audited: `alarm.suppression.requested`, `.created`,
`.approved`, `.rejected`, `.withdrawn`, `.removed`. Ingest applies only
active rows not past `expires_at` (checked at the batch's `now`; there is
no expiry job), and a group row through `console_host_in_group`, so a host
is covered from the moment it joins. Deleting a host group withdraws its
waiting rows and removes its active ones (plan ruling 4). Tests:
`tests/alarm_suppressions.rs`, `tests/alarm_suppression_states.rs` and
`tests/suppression_upgrade.rs` and `tests/suppression_matching.rs`.

## Status

`status(&client, now) -> Status`: schema version; active, offline (no
heartbeat for `OFFLINE_AFTER_MINUTES` = 3: three missed one-minute
heartbeats, judged on `agent_seen_at`, see Live presence), and revoked agents; usable tokens (not
revoked, not expired, uses left); oldest and newest partition. All zeros and
`None` on an empty database.

## Console read models (schema 15)

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

## Console identity and access schema (schema 16)

Migration 15 adds the persistent local identity boundary used by C3: users and
Argon2id credential slots, hash-only pre-auth and session state, bounded login
throttle buckets, idempotency records, role/permission bindings, asset
groups (exact-tag until schema 53, host groups since), service accounts and hashed tokens, finding-triage state/history,
structured audit columns, and a versioned 365-day audit-retention policy.
`audit::cleanup_expired_events` removes at most 10,000 events older than the
stored policy cutoff per call; repeated maintenance runs drain larger backlogs.
Built-in Viewer, Analyst, Operator, and Admin role permissions are seeded by
the migration. The login role is named `"openvibes-console"` (quoted in SQL
because of the hyphen); it can read platform data
and update console-owned state; it cannot update agent/finding source data or
modify/delete audit rows. This migration establishes tables and grants;
bounded transactional store operations follow in C3 work.

## Console enrollment-token administration (schema 17)

Migration 16 grants the console role access to enrollment-token metadata and
use counts. The console stores only the SHA-256 digest of the token's decoded
32-byte secret. Its idempotent creation transaction stores the token,
24-hour request/response replay record, and audit event together; listing
never exposes secret material.

## Console rule verification reads (schema 18)

Migration 17 grants `openvibes-console` `SELECT` on `rule_trust_keys` so the
console can verify uploaded signed envelopes against the active public keys.
It grants no trust-key mutation rights; adding/removing keys remains an audited
local `openvibes-admin` operation.

## Console finding triage history (schema 19)

Migration 19 records assignment, accepted-risk expiry, and rule version in
triage history. `console_triage` reads default Open state for live latest
findings, performs ETag-versioned state changes with history and audit in the
same transaction, and reopens completed triage when a new applicable latest
observation arrives during ingest.

## Assistant permission (schema 21)

Migration 21 grants the global `assistant.use` permission to the built-in
Analyst and Admin roles. The console only advertises it when the assistant is
enabled; each request also requires the caller's scoped agent and finding read
permissions.

## Console write grants (schema 22)

Migration 22 grants `openvibes-console` DELETE for idempotency and
selector/tag replacement (tables dropped in schema 53) and INSERT for published rule bundles. It grants
column-level UPDATE only for the agent fields used by revoke and one low-impact
column on each table that console code locks (`current_findings`, `rule_sets`,
and `rule_trust_keys`). The role cannot UPDATE those tables as a whole, and a
trigger prevents it from restoring or reclassifying an agent.
`tests/console_role.rs` runs representative console writes after
`SET ROLE "openvibes-console"` and checks forbidden status changes;
`tests/migrate.rs` asserts the exact table and column grants.

## Built-in console permissions (schema 23)

Migration 23 adds agent-scoped `vulnerabilities.read` to all built-in roles.
It removes the older `rules.read` grants from Viewer, Analyst, and Operator;
only Admin receives that global permission by default. The console integration
test compares the complete database role-permission mapping with the canonical
Rust role resolver.

Migration 20 stores the time a finding entered `mitigated` separately from
general `updated_at`, so note or assignment edits do not hide a recurrence
observed after mitigation.

Migration 15 is reserved for imported-host support. Console migrations were
renumbered to 16–21 when import support landed; migration 22 adds the
reviewed console write grants, and migration 23 adds vulnerability reads to
the built-in role inventory.

## Test

```sh
eval "$(scripts/test-db.sh)"     # throwaway cluster under target/pg
cargo test --locked -p platform-store
cargo test --locked -p platform-store --test console_read -- --nocapture
```

Each test creates and drops its own database. Tests fail, never skip,
when `OPENVIBES_TEST_DATABASE_URL` is unset.

## Dashboards (`dashboards::…`, schema 26)

A dashboard is a named layout owned by one console user, `private`, shared
with some of the owner's roles or with `everyone` (`visibility`, schema 68). Only the layout is stored; widgets read their data through the
permission-checked console API, so sharing never exposes data.

- `list_visible(user)`: own dashboards first, then those shared with
  everyone or with a role the user holds through any unrevoked binding, each
  group by name. Shares with roles live in `console_dashboard_roles`; a
  dashboard's `roles` are all of them for its owner and only the viewer's
  own for anyone else. `get_visible(user, id)` returns `None` for unknown,
  invisible and malformed ids (ids are compared as text).
- `create` (at most `MAX_DASHBOARDS_PER_OWNER` = 100 per owner, serialised
  per owner), `update` (owner only, `expected_version` must match),
  `delete` (owner only; homes pointing at it go by cascade),
  `set_sharing(visibility, role_ids)` (owner only; replaces the dashboard's
  roles; `roles` needs at least one role and every one must exist and every
  one being added must be held by the owner (a role already on the dashboard
  may stay or be removed after the owner left it), else `NoRoles`, `UnknownRole` or `RoleNotHeld`; the
  caller checks `dashboards.share` for roles and `dashboards.publish` for
  everyone), `privatise_orphans` (run by `delete_role`: a dashboard left
  shared with roles but with none becomes private, with a `dashboard.share` audit row), `home` (only if still visible) and
  `set_home(id | None)` (must be visible).
- Ids are checked to be UUIDs in Rust (malformed ids are not found without a
  query) and compared as `uuid`, so lookups use the primary key and any case
  works.
- Refusals are values, not errors: `Refusal::{NotFound, NotOwner, Stale,
  TooMany, UnknownRole, RoleNotHeld, NoRoles}`.
- Every change writes its audit row (`dashboard.create`, `.update`,
  `.delete`, `.share`, `.home`; target kind `dashboard`) in the same
  transaction. The row carries the name, never the layout.
- Tested by `tests/console_dashboards.rs` (ownership, sharing through global
  and scoped bindings, revoked binding, versions, limit, home fallback).

## The change log (`change_log::…`, schema 65, step 5e)

Ingest writes what appeared and went away on each host, in the same
transaction as the host's rows; `openvibes-admin maintenance` prunes it
after 90 days. See [change-log.md](change-log.md). Cost on ingest: a
changed services report adds under 1 ms, a 150-package upgrade about 6 ms,
an unchanged report nothing.

## The Ports list and a port's page (`port_list`, `port_summary`, `port_names`, step 5e)

`port_list::port_list` answers `GET /v1/port-list` (filters with counts,
four sorts, offset paging) and `port_summary` the page's summary and Hosts
card, both inside the caller's reach; `port_names` is the built-in map of
about 40 well-known ports. At 10,000 hosts with 20 listeners each (about
300 ports, 500,000 change-log rows) the unfiltered list takes 0.9 s at full
reach and 0.4 s for one group's reach
(`tests/port_list_timing.rs`, ignored; limit 2 s). See
[console-ports.md](console-ports.md).

## The Services list and a service's page (`service_list`, `service_summary`, `service_related`, `service_names`, step 5f)

`service_list::service_list` answers `GET /v1/service-list` (filters with
counts, three sorts, offset paging) and `service_summary` and
`service_related` the page's summary, Hosts card and Related card, all
inside the caller's reach; `service_names` is the built-in map of about 45
well-known units, and a unit is matched to installed packages by name.
At 10,000 hosts running 30 units each the unfiltered list takes 3.3 s at full
reach and 1.8 s for one group's reach (`tests/service_list_timing.rs`, ignored;
target 2 s, met for the scoped reach only; the statement runs with JIT off). See [console-services.md](console-services.md).

## The Software list and a package's page (`software_list`, `software_summary`, `software_version`, step 5g)

`software_list::software_list` answers `GET /v1/software-list` (one row per
package name, filters with counts, five sorts, offset paging) in one
statement (`software_list_sql`), and `software_summary` the page's summary
and Hosts card, all inside the caller's reach. `software_version` holds the
version text and the order that reads digit runs as numbers. On the sizing
fleet (10,000 hosts, 400 packages each) the unfiltered list takes 1.7 s at
full reach and 1.2 s for one group's reach (2.0 s and 2.1 s when a quarter of
the hosts run another OS release, which the no-fix advisories need to know);
a sort by hosts and the heaviest filters 2.2 to 3.1 s
(`tests/software_list_timing.rs`, ignored; target 2 s, met for the default
view). See [console-software.md](console-software.md).

## Cases (`console_cases::…`, schemas 35, 36, 64, 66 and 67)

- `cases`: `case_id`, a `number` from an identity column (unique, never
  reused), `title` (1–120), `status` (`open`, `investigating`, `closed`),
  `resolution`, `resolution_note`, `accepted_until`, `severity`, assignee and
  opener, times and `version`. CHECKs tie a closed case to its note (the
  closing note) and close time, allow a resolution only on a closed case
  (since 64 new closes set none; older ones keep theirs), and tie accepted
  risk to its date.
- `case_items`: a link (`kind`, `ref`, `agent_id` for scope; null for
  software) with `active` (true while the case is not closed), `outcome`
  (`resolved`, `false_positive`, `accepted_risk`, and since 64
  `confirmed_malicious` and `expected`), `outcome_note` (required for all but
  `resolved`) and `outcome_until` (since 64: set exactly for `accepted_risk`,
  partial index for the reopen check; backfilled as in
  [console-cases.md](console-cases.md)). `(case_id, kind, ref)` is unique, and a partial unique index
  on `(kind, ref)` where `active` for alarms, findings and vulnerabilities puts
  each in at most one open case, even under concurrent requests. `seq` orders
  items added in the same instant.
- `case_events`: the append-only timeline; a trigger refuses UPDATE and
  DELETE for every role. `detail` is JSON and never holds a note; item
  entries carry `item_agent_id` so the timeline can be filtered by scope.
- Permission `cases.manage` (agent scoped) for Analyst and Admin.
- Grants: the console role has SELECT, INSERT, UPDATE on `cases`, SELECT,
  INSERT, UPDATE, DELETE on `case_items`, and SELECT, INSERT on `case_events`.

`console_cases` takes the caller's `AgentScope` and user id on every call and
applies `agent_visibility` in SQL: a case is visible through a host-bound
item in scope (`item_in_scope`; a software item never makes a case
visible, user decision 2026-10-25 "hosts decide"), or to its opener or
assignee, and a case with no host-bound item (none, or only software) also
to a global scope; items, counts and timeline entries about hidden
items are left out. Changes return `Result<_, Refusal>` (`NotFound`, `Stale`,
`ItemInCase`, `ItemsUnresolved` and so on) and write the audit row and
timeline entry in the same transaction. `reopen_due` runs the lazy checks that
the console calls before it lists or reads cases: `reopen_expired` reopens
cases closed before 64 whose case-level accepted risk has run out, an item
check reopens closed cases with an item whose `outcome_until` has passed
(clearing only those items; on cases not closed it only clears them), and
`reopen_evidence_returned`
reopens cases closed within the last 30 days whose `resolved` items have
evidence again (migration 36 adds the partial index on `closed_at` it uses).
The module is the folder `src/console_cases/` (see its README). Tested by
`tests/console_cases/` (one module per area), run as the console role. See [console-cases.md](console-cases.md).

### The Cases list (`case_list::case_list`, step 5d)

`case_list(client, &CaseQuery, &AgentScope, actor_id, now) -> CaseListPage`
(step 5d rulings 2, 4, 6–10): one statement (`case_list_sql`) returns the
page, the total, the count for every value of every filter with the
other filters applied, and the summary line. It reuses the cases'
visibility: `vi` holds the items `item_visible` passes (software shows
inside a case already seen), `r` the cases `case_visible_with` passes, its
host-bound-item test read from `vi`'s per-case counts rather than one
lookup per case (1.39 s of a 1.6 s scoped run before). Everything a row shows or counts
comes from visible items only.

- Filters (one value each, ANDed): status (active = not closed, the
  default; open, investigating, closed, all), severity, assignee (me,
  unassigned, a user id; a non-UUID matches nothing), contains (a
  visible alarm, vulnerability or finding), host and group (a visible item
  on that host, or on a host in the group), updated (today = since
  midnight UTC of `now`, the same day for every viewer whatever their
  time zone; week = the last 7
  days; quiet = not for 7 days or more). Search: the title, `C-104`,
  `104`, or the opener's display or user name.
- Counts: every status, severity, contains and updated value; people
  assigned a visible case; groups holding a host the viewer sees, plus the
  chosen one when the scope reaches it. Host and search narrow every count.
- Summary: applies every filter except status (so the status filter never
  empties it), over the cases that are not closed: open, investigating,
  unassigned and ready to close. Ready uses close's own rule
  (`blocking_item`, shared with close): no item, visible or hidden, lacks an
  outcome, is `resolved` with its evidence back, or is `accepted_risk`
  with its date passed (not yet cleared); only that boolean per
  case is revealed.
- Rows: number, title, status, severity, opener, assignee, the newest
  `note` event (first 120 characters and its time), the first five
  distinct visible hosts by name and `host_count` (all of them), visible items per kind, `with_outcome`/`takes_outcome`
  (alarms, findings and vulnerabilities only), `ready` (close's own rule,
  hidden items included, as the summary's "ready to close"), `updated_at`.
- Sorts: updated (default, newest first), severity, number, opened; ties
  by case id in the same direction. Offset 0–100000, limit 1–100.

Tests: `tests/case_list/` (`rows.rs`, including
`case_list_counts_stay_inside_the_scope`; `filters.rs`: filters, search, sorts),
`tests/case_list_scope.rs` (hosts decide, ready to close, the host cap);
`tests/case_list_timing.rs` (ignored; 10,000 hosts, 20,000 cases, 200,000
items, 60,000 events): default list, 2026-10-25, median 458 ms at full
reach and 272 ms scoped to two of ten groups, no index needed.

### A case's page (`case_summary::case_summary`, step 5d)

`case_summary(client, case_id, &HostScopes, user_id, now) ->
Option<CasePageSummary>` (rulings 12–13): `HostScopes.hosts` is the
`cases.read` scope and decides the case (`case_visible`; `None` when
missing or unseen); the other three gate each host's problem counts (open
agent alarms, `host_listed_critical`, `open_failing`, null where that
kind's scope does not reach the host, and the failing count also when the
host is `compliance_stale`: no report in the last day, the Hosts list's
rule). It returns the case with visible
counts (`case_counts`), `ready` (not closed, no `blocking_item` among all
items), `open_for_seconds`, the visible items' hosts by name and who can
see it (`case_people.rs`: enabled live bindings that are Administrator or
hold `cases.read` on all hosts, on a group holding a host-bound item's
host in the viewer's reach, or at any scope for the opener and assignee;
at most 20 names, the total, and `complete` = the viewer's scope is
global). `case_visible_to(client, scope, user_id, case_id)` answers whether a
scope sees the case (the page's `can` flags). Tests:
`tests/case_summary.rs`.

## The rule signer's access (`signer::…`, schema 32, board #107)

Migration 32 creates the `openvibes-signer` role with column grants for a
password and permission check only (see
[openvibes-signer.md](openvibes-signer.md)). `signer_user` reads a
credential (either must-change flag counts), `may_upload_rules` checks
`site_rules.publish` (a platform permission) through an active role binding, and
`record_signer_failure` counts a wrong password in the account's sign-in
bucket without an audit row. Sign-in and the signer share
`console_auth::count_failure` and `account_throttle_bucket`, so a wrong
password counts the same in both.

## Vulnerability match state (schema 33)

Migration 33 adds a pending-match version to `agents`, indexed for the
vulnerability service. Inventory changes reset it to zero. The matcher
records its version only after a successful host or release match; failed
queries therefore remain eligible for retry after the service restarts.

## Detection explanations (schema 41)

Migration 41 stores the optional P17 `Detection` JSON on finding events,
current finding snapshots, and alarms. Ingest validates evidence before it
persists it. Repeated alarm observations update the latest process sample and
explanation in the same transaction. Finding history retains the explanation
from each observation.

`observation_bundles` and `trust_keys` expose bounded historical signed
bundle lookup to the console, including expired or retired bundles, so a
finding or alarm can show the exact rule that produced its evidence. Bundle
signature verification still uses the original signed bytes and recorded
issuer key.

## Triage v2 (schema 45)

Spec `docs/specs/2026-10-10-bulk-triage-design.md`. Migration 45 (marked
`needs-backup`: an upgrade backs up, then migrates, on its own) retires
`investigating`: those alarms and findings become `open`, keeping assignee,
note and case links, with a history row ("investigating retired; cases
replace it", actor `migration`); the CHECKs drop the value. It adds
`vulnerability_triage` (per host × advisory: state, assignee, note,
`accepted_until`, version) and its history, the
`vulnerabilities.triage` permission (roles that have `compliance.triage`),
and a trigger that clears open and mitigated triage, and expired accepted
risk, when the vulnerability is fixed.

- `console_triage` / `console_alarms`: any state to any other.
- `vulnerability_triage`: `get`, `states` (one lookup for a page),
  `update` (version-checked, history, audit, open counts refreshed) and
  `history`. Triaged vulnerabilities leave `host_vulnerability_counts`.
- `bulk_triage`: one state or assignee change on up to 10,000 alarms,
  findings or vulnerabilities (`expand_compliance` and
  `expand_vulnerabilities` turn a rule or advisory into its hosts in
  scope; a reopen skips the hosts already open; an advisory-wide or `open_only` vulnerability close or
  assign expands open pairs only, so closed ones neither count toward the
  cap nor come back, and an item with none open is skipped as "not open";
  the vulnerability half is `bulk_triage/vulns.rs`; a rule-wide or
  `open_only` compliance item does the same over open findings failing as
  the list counts them (`check_list_sql::failing`), `bulk_triage/compliance.rs`;
  `ListRow { open_only, group }` per item, where `group` keeps the item to
  that host group's members, still in scope); each item goes
  through its single-item update, skipped items come back with a reason,
  one audit row per action.
- `triage_history::events`: the newest 200 changes of an alarm, or of a
  rule or advisory across the hosts in scope.
- `console_cases::active_items`: refs of one kind in open cases the
  caller can see, with the case number.
- Tests: `tests/migrate.rs` (`triage_v2_retires_investigating`),
  `tests/vulnerability_triage.rs`, `tests/bulk_triage.rs`, `tests/bulk_triage_cap.rs`, `tests/bulk_triage_compliance.rs`, `tests/bulk_triage_group.rs`.

## Network devices (schema 46)

Spec `docs/specs/2026-10-10-network-device-alarms-design.md`. Additive
migration 46:

- `devices`: name (1–64), kind (`unifi`), address (`inet`, unique among
  active devices), created/removed by and at, `last_seen`, the counters
  `received`, `alarms`, `not_cef`, `unparsed`, `dropped_other`,
  `mismatch`, and `dropped_classes` (jsonb, at most 64 keys). A removed
  device keeps its row because alarms point at it.
- `alarms`: `source` (`agent` default, or `device`), `device_id`,
  `network` (jsonb). `agent_id`, `process` and `ancestors` became
  nullable, and `alarms_source_fields_check` requires each source's own
  fields. `alarms_device_alarm_key` is unique on `(device_id, alarm_id,
  first_seen_day)`.
- `alarm_suppressions`: `device_id`; scopes `device` (one device) and
  `signature` (any device), allowed only for `device-*` rule sets.
- Role `openvibes-netlog`: SELECT on `devices`, UPDATE on its counter
  columns; **column** SELECT, INSERT and UPDATE on `alarms` (never
  `process`, `ancestors`, `note`, `assigned_to`, `agent_id`, `detection`);
  INSERT on `alarm_triage_history`; SELECT on `alarm_suppressions` and
  `schema_version`.

Functions:

- `devices`: `add` (name, kind and duplicate checks), `remove`, `list`,
  `active` (netlog's sender filter), `flush` (adds counters, caps
  `dropped_classes`), `heads_up` (`NO_EVENTS` 10 minutes after adding with
  nothing received, `SILENT` after a day without a packet).
- `device_alarms::insert_batch`: one transaction. A resend raises `count` and
  `last_seen`. A recurrence reopens a mitigated alarm or an expired accepted
  risk. A suppression closes a new alarm as a false positive, with one history
  row by `netlog`. An alarm whose day has no partition is skipped and counted
  (`unstorable`).
- Console reads stay agent-only until the device screens exist: list,
  detail, triage and cases inner-join `agents`, and `HOST_COUNTS_SQL`, case
  item titles and bulk suppressions filter `source = 'agent'`.

## Assistant internet lookups (schema 47)

Spec `docs/specs/2026-10-10-assistant-internet-lookups.md`. Migration 47
adds the one-row `assistant_internet` table (off by default): `level`
(0 off, 1 security references (OSV, Bodhi), 2 those and web search), `searxng_url` (required at
level 2), `internal_domains` (at most 50), `version`, `updated_at`,
`updated_by`. It adds the global `assistant.admin` permission (granted to
`admin`) and the `openvibes-fetch` login role, which has `SELECT` only on
`assistant_internet`, `agents(agent_id, hostname)`, `console_users(username)`
and `schema_version`. `openvibes-console` can `SELECT` the table and
`UPDATE` its editable columns.

- `assistant_internet::get`: reads the setting.
- `assistant_internet::update`: version-checked (`None` when stale), with
  an `assistant.internet.changed` audit row (old and new level, URL and
  domains) in the same transaction. Refused with `StoreError::Query` before
  the transaction: level outside 0-2, level 2 without a URL, over 50
  domains, or a domain that is not lowercase LDH labels joined by dots
  (253 characters at most; a single label such as `intranet` is allowed).
- `assistant_internet::denylist`: lowercase, de-duplicated agent ids,
  hostnames (not empty) and the first label of every dotted one (`web-01`
  for `web-01.corp.example`; only when it has at least three characters, so
  `a.corp.example` adds no `a`), console usernames and the internal domains, for
  the fetch service's outbound filter.
- Tests: `tests/assistant_internet.rs` (including the denylist and the
  console write path under their own roles).

## Rule-set assignment (`rule_assignment::…`, schema 49)

`rule_set_assignment` (default per assignable set) and
`rule_set_group_assignment` (overrides per asset group, cascading with the
group); the console role reads and writes them. Behaviour, grants and tests:
[rule-set-assignment.md](rule-set-assignment.md).
`hardening_facts(agent)` returns the hardening outcome of the latest report and
`hardening_facts_ok_at`, for the host panel's facts warning.

## Custom roles (`console_roles::…`, schema 52)

Migration 51 renames the permissions to the catalogue of 48 (see
console-rbac.md); 51 and 52 both start with the needs-backup marker.
Roles carry a host reach (all hosts, some asset groups in
`console_role_groups`, or none), a description and a version; names are
unique regardless of case. Role bindings lose `asset_group_id`: migration 52
turns each holder's scoped bindings of one role into one role reaching those
groups, keeps held former built-ins (viewer, analyst, operator) as ordinary
roles reaching all hosts, deletes unheld ones, and shows `admin` as
Administrator. (Schema 68 then adds `console_dashboards.visibility`: a
dashboard with shares becomes `roles`, the rest `private`.) Dashboard shares move from `console_dashboards.shared_role_id`
(dropped) to `console_dashboard_roles`, and a share with a role whose scoped
holders moved is copied to their new roles, so nobody loses a dashboard.
The console role may write roles, their permissions and groups, dashboard
shares, and `console_users` `email`, `display_name` and `last_sign_in_at`.
`audit_log_actor_recent_idx` (`actor_id`, `at DESC`) serves a person's recent
activity. People reads and writes and role gifts live in `console_people`.
Schema 69 adds `console_user_pictures` (one row per person: the 256 px and 64 px WebP bytes, a SHA-256 `etag` over both, `animated`, who and when); `console_people` sets, removes and reads them, and the audit rows `user.picture.set` and `user.picture.removed` never hold image bytes. Deleting a person deletes their picture.
Interface and guards: [console-auth-store.md](console-auth-store.md).
Tests: `tests/custom_roles.rs` (upgrade, run to 52 only with
`common::step_to`) and `tests/role_writes.rs`; tests that bind a former
built-in id create it first with `common::seed_role`.

## Host groups and labels (schema 53)

Spec 2026-10-16-roles-permissions-design.md §5, §12 part 4. Migration 53
(needs-backup) gives `console_asset_groups` a `kind` (`automatic`, `rule`,
`manual`), `description` (≤ 500), `auto_key` (`os_family:linux`,
`distribution:debian 12`; set exactly for automatic groups), `version`,
`changed_at`/`changed_by` and `upgraded_from_tags`; names are unique
regardless of case. `agents` gains `last_address inet` and the generated,
indexed `os_family` (`windows` or `linux`) and `distribution`
(`lower(os_id || ' ' || os_version)`, Rocky and AlmaLinux cut to the major
release). New tables: `console_host_group_conditions` (≤ 16 per group,
`field` os_family/distribution/hostname/ip, `negate`, 1–64 `vals`, no NULL
value, `ip` values must parse as `inet`),
`console_host_group_members` (manual groups), `console_host_group_dismissed`
(deleted automatic keys) and `console_host_labels` (1–64 characters).

**Membership is one rule** (stored since schema 61, below): only active hosts; a manual group holds its
members; a rule or automatic group holds hosts satisfying every condition,
a condition holding when any value matches (or none does, when negated). A
fact the host has not reported never satisfies a condition, negated or not;
a group without conditions holds no one; a condition that evaluates to
unknown counts as not holding (fail closed). Hostname patterns are
case-insensitive with `*` the only wildcard (`console_glob_like`); `ip`
values are CIDRs or single addresses, v4 or v6. `console_host_in_group(agent,
group)` answers it; `agent_visibility`, `revoke_agent_in_scope` and rule-set
assignment (`FLEET`, `HOST_STATE`) all use it. `console_os_family_name` and `console_distribution_name` give the
display names of automatic groups (Debian, Ubuntu, Fedora, Rocky Linux,
AlmaLinux, other ids capitalised, plus the release).
`console_free_group_name(display, suffix, keep)` returns a free name of at
most 128 characters: `display`, else `display (suffix)`, `(suffix 2)`, …
(with suffix `''`: ` (2)`, ` (3)`, …), cutting `display` so the suffix fits.
It sees only committed or earlier-statement names, so insert one group per
statement (the migration loops; ingest's automatic groups must too).

**Upgrade:** names that differed only in case (allowed before) are made
unique first: the oldest keeps its name, later ones get ` (2)`, ` (3)`, …,
recorded as `renamed_from`/`renamed_to` in their `host_group.migrated` row.
Each existing asset group becomes a manual group of the active
hosts its selectors matched (a group without selectors holds none), with
`upgraded_from_tags` and a description naming its tags, and one
`host_group.migrated` audit row; each tag `k=v` becomes the label `k:v` (cut to 64 characters; a host whose
tags were cut, or fell together into one label, gets one
`host.labels_migrated` row listing them);
automatic groups are made for the OS families and distributions active hosts
already report (`host_group.created_automatically`; named through
`console_free_group_name(…, 'automatic')`). `console_agent_tags` and `console_asset_group_selectors` are
dropped with their grants. Revoked hosts leave every group, the one access
change. Grants: the console role reads and writes the new tables and may
delete groups; distribution reads conditions, members, `kind` and the agent
facts; ingest may create groups and conditions and read dismissals.

**Stored membership (schema 61).** `console_host_group_membership
(asset_group_id, agent_id)` holds every pair of every kind, indexed by
`agent_id`. Triggers keep it in the changing transaction, never a job:
on `agents` an active insert (enrolment; imports are never active), a
delete, and an update of `status`, `os_id`, `os_version`, `hostname` or
`last_address` only when the host was or becomes active and `status`,
`os_family`, `distribution`, `hostname` or `last_address` really changed (a
heartbeat repeating its facts does nothing); on conditions and picked hosts
(statement-level, each touched group recomputed once); on groups a delete
and a `kind` change (a new group has nothing to hold until its conditions
or picks are inserted). The functions are `SECURITY DEFINER`, so writers
need no grant on the table. Every refresh takes advisory lock 1870032226
until commit and then reads committed state, so a host change and a rule
change racing in two transactions cannot leave a stale or too wide pair.
Lock order (`host_group_facts::MEMBERSHIP_LOCK`): `ACCESS_BINDING_LOCK`
(group writes) and the enrolment token lock come before it, and it comes
before `AUTO_GROUP_LOCK`: `ensure_automatic_groups` takes it first, since an
inventory whose OS changed already holds it from its agents UPDATE. Most
likely first contention: heartbeat `last_address` churn (roaming or NAT).
`console_host_in_group`, `agent_visibility` and `host_list_sql::members`
read the table; console, distribution and ingest may SELECT it. Measured
(release build, 20,000 hosts, 20 groups): 10,000 imports one statement
each 72.1 s before and 70.9 s after (no trigger fires; the time is the
per-statement commit); 10,000 active hosts in one INSERT 0.21 s → 1.35 s;
1,000 hostname changes in one UPDATE 39 ms → 152 ms; one condition edit
6 ms → 85 ms; an UPDATE of 30,000 hosts repeating their facts 1.07 s →
1.16 s.

Tests: `tests/host_groups_membership.rs` (the rule),
`tests/host_group_membership.rs` (the table equals the rule, kept as the
oracle, after every change path; a heartbeat repeating its facts does not
refresh; scoped Hosts, Alarms and Vulnerabilities lists reach the hosts the
rule puts in scope), `tests/host_groups_upgrade.rs` (every role reaches the
same hosts after the upgrade). Fixtures make groups with `common::manual_group` and
`common::rule_group`.

Agent facts: `ingest::heartbeat` takes the peer `address` and stores it as
`last_address` (written at once when it changes, like the hostname).
`host_group_facts::ensure_automatic_groups` (called by `inventory::finish` in
the inventory transaction with the row's generated `os_family`/`distribution`)
makes the missing, undismissed automatic groups, one statement each, under the
transaction advisory lock `AUTO_GROUP_LOCK` (0x4F564847) taken only
when a group is missing; names come from `console_free_group_name`, and the
Rust display map must equal the migration's. Hardening (agents report their own os-release): a distribution gets a group
only when its os id is one of debian, ubuntu, fedora, rocky, almalinux and the
release is a dotted number `[0-9]{1,4}(\.[0-9]{1,4}){0,2}` (`12`, `24.04`;
never a word such as `prod-servers`), and an OS family only when linux or windows
(unknown ids get no group at all, so a hostile agent cannot fill the cap or
squat a name; users make rule groups for them); there are at most 20
automatic distribution groups per os id and 200 automatic groups in all
(OS family groups are made first; at a cap nothing is created, a line goes to
stderr, the agent gets no error); the name functions of an unknown id (not reachable from ingest) return it raw
lowercase, never capitalised. Migration 53's name functions and its backfill
(same ids and pattern, 20 per os id, 200 at most) agree.
Test: `tests/host_group_facts.rs`.

### Host-group store API

- `host_groups::list(scope)` / `detail(id, scope)` return `GroupSummary`
  (kind, description, ordered `conditions`, `picked` (active picked hosts
  inside the scope), version, changed
  at/by, `upgraded_from_tags`). Host counts, `online` (seen within
  `OFFLINE_AFTER_MINUTES`), `open_alarms` (agent alarms in state `open`)
  and `critical` (`host_vulnerability_counts.critical`) count only active
  member hosts inside the caller's `AgentScope` (`agent_visibility`); every
  group is listed whatever the scope. `roles` are those in
  `console_role_groups`; `people` the distinct enabled users bound to them.
- `host_groups::hosts(id, scope, after, limit)` pages member hosts by
  hostname (cursor: the last agent id; an unknown cursor id, or one outside
  the scope, yields an
  empty page; limit 1–100) with display
  distribution, address, labels, last seen, online, problems and `why`
  ("Matches the rule" / "Picked by hand"). `recent_changes(id, scope, limit)`
  reads the group's audit rows (`target_kind = 'host_group'`), newest first;
  for a scoped caller the `picked` and `hosts` details are dropped so no
  host outside its reach is named or counted. `picked_ids(id)` lists the
  active hosts picked by hand (what a rename of a manual group keeps);
  non-active members are left out, so a manual update drops them.
- `host_group_writes::create` / `update` / `delete` run in one transaction
  under the access-binding advisory lock (the one role writes take, so a
  role cannot start using a group being deleted). They check the version
  (`Stale`), refuse a malformed name, description or condition (`Invalid`
  naming the part: `invalid_part` checks the field is one of the four,
  1–64 values, `os_family` linux/windows, `ip` an address or CIDR, at most
  16 conditions), a picked id that is missing or not active
  (`UnknownHost`), and a name taken regardless of case (`NameTaken`, from
  the unique index). `update` takes `expected_roles`: when given (the
  console passes the roles it share-checked a membership change against),
  the write is `Stale` unless exactly those roles reach the group, read
  under the lock. The kind follows the content; updating an automatic
  group clears its `auto_key` and records the key as dismissed, making it
  the person's (the next inventory does not make it again).
  Manual members keep their `added_at` across updates. A delete refuses
  while roles reach the group (`InUse` with their names), remembers an
  automatic key in `console_host_group_dismissed`, cascades rule-set
  switches, and ends the group's suppressions (waiting → `withdrawn`,
  active → `removed`, by the deleter), each with its
  `alarm.suppression.withdrawn` / `.removed` audit line (detail `reason`
  "group deleted") in the same transaction. Audit: `host_group.created` / `updated` (`{name, kind,
  conditions | picked}`), `host_group.deleted` (`{name, kind,
  overrides_removed, suppressions_ended}`).
- `host_group_writes::preview(id, proposed)` (module `host_group_preview`)
  returns `PreviewOutcome::Invalid(part)` for a malformed rule
  (`invalid_content`, the checks writes use) and `NotFound` for a missing
  group; otherwise `Ready(Preview)`. It compares today's membership with the proposed rule (evaluated with
  `console_condition_holds` over active hosts) or picked list; `proposed`
  None previews a delete and counts `overrides_removed` and
  `suppressions_ended`. `gains` / `loses`
  are the enabled people bound to roles reaching the group who get the
  joining / lose the leaving hosts, except those holding a role on all
  hosts (simplified: their other groups are not checked). Lists hold at
  most 50 entries; `joins_total`, `leaves_total`, `people_total` count all.
- `host_labels::labels` / `add_label` / `remove_label`: trimmed, 1–64
  characters, no control characters, not `.` or `..` (they cannot be a URL
  path segment), at most 32 per active host (`TooMany`;
  the agent row lock, `FOR NO KEY UPDATE`, serialises adds), `AlreadyThere` for a repeat,
  `NotFound` for a missing or non-active host, `Invalid` otherwise. Audit
  `host.label_added` / `host.label_removed` (`{label}`). Labels are never a
  membership field.
- `host_labels::reachable(scope, agent_id)`: a non-revoked host inside the
  scope. `host_labels::host_labels(scope, agent_id)`: its labels and the
  groups holding it (id, name, kind), `None` when not reachable.
- `rule_assignment::overview` lists every group with its `kind`, rule
  `conditions` and `picked` count, for the console's membership sentence.

Tests: `tests/host_group_reads.rs`, `tests/host_group_writes.rs`,
`tests/host_labels.rs` (fixtures in `tests/common/groups.rs`).

## Rule metadata (`rule_meta::…`, schema 59)

`console_rule_meta` holds one row per rule of each stored rule bundle
(primary key `rule_set_id, rule_set_version, rule_id`; `rule_version`,
`title`, `message`, optional `explain` and `"check"` of at most 600
characters each, `attack` as `[{tactic, technique}]` and `techniques`, the
distinct technique ids). Rows go with their bundle (`ON DELETE CASCADE`).
The console reads and writes it (SELECT, INSERT, UPDATE); the admin CLI
writes as the owner. `check` is a reserved word: quote it in SQL.

- `upsert_from_bundle(set, version, rows)` indexes one bundle in one
  statement; storing it again rewrites its rows. The caller verifies the
  bundle first (the console's `rules/meta.rs`); this module verifies nothing.
- `get(set, set_version, rule_id, rule_version)` returns `RuleMeta`, or
  `None` for a rule that was never indexed (old data, an unverifiable
  bundle): the caller falls back to resolving the bundle.
- `missing_bundles(limit)` lists stored bundles without a row, for the
  console's start-up backfill. Unverifiable bundles stay listed.

Tests: `tests/rule_meta.rs`.
