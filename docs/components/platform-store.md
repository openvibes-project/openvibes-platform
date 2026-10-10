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
- `SCHEMA_VERSION` (currently 42; a compile-time check ties it to the last
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
to `health_previous`, and a heartbeat without one keeps it.

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
| `not_enabled` | no `alarms` object (no `process_events` in `collectors`) | add it to `agent.toml`, restart; no command | no |
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
`changes` for P13); `agents` gains `match_sha256`, the digest of the
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
`vulnerable_hosts` (by CVE or advisory), and `overview`. A finding with an
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
  seen, applies active suppressions, reopens a mitigated alarm or an
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
- `alarm_suppressions` (console): `list`, `create` (derived from a visible
  alarm; `program`/`command` need global scope) and `remove` (kept as
  history), audited.
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
every heartbeat (a narrow row, no WAL), so "online" does not wait for the
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
throttle buckets, idempotency records, role/permission bindings, exact-tag
asset groups, service accounts and hashed tokens, finding-triage state/history,
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
selector/tag replacement and INSERT for published rule bundles. It grants
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

A dashboard is a named layout owned by one console user, optionally shared
with a role. Only the layout is stored; widgets read their data through the
permission-checked console API, so sharing never exposes data.

- `list_visible(user)`: own dashboards first, then those shared with a role
  the user holds through any unrevoked binding (global or asset-group), each
  group by name. `get_visible(user, id)` returns `None` for unknown,
  invisible and malformed ids (ids are compared as text).
- `create` (at most `MAX_DASHBOARDS_PER_OWNER` = 100 per owner, serialised
  per owner), `update` (owner only, `expected_version` must match),
  `delete` (owner only; homes pointing at it go by cascade),
  `set_sharing(role | None)` (owner only; the caller checks
  `dashboards.share`), `home` (only if still visible) and
  `set_home(id | None)` (must be visible).
- Ids are checked to be UUIDs in Rust (malformed ids are not found without a
  query) and compared as `uuid`, so lookups use the primary key and any case
  works.
- Refusals are values, not errors: `Refusal::{NotFound, NotOwner, Stale,
  TooMany, UnknownRole}`.
- Every change writes its audit row (`dashboard.create`, `.update`,
  `.delete`, `.share`, `.home`; target kind `dashboard`) in the same
  transaction. The row carries the name, never the layout.
- Tested by `tests/console_dashboards.rs` (ownership, sharing through global
  and scoped bindings, revoked binding, versions, limit, home fallback).

## Cases (`console_cases::…`, schemas 35 and 36)

- `cases`: `case_id`, a `number` from an identity column (unique, never
  reused), `title` (1–120), `status` (`open`, `investigating`, `closed`),
  `resolution`, `resolution_note`, `accepted_until`, `severity`, assignee and
  opener, times and `version`. CHECKs tie a closed case to its resolution,
  note and close time, and accepted risk to its date.
- `case_items`: a link (`kind`, `ref`, `agent_id` for scope; null for
  software) with `active` (true while the case is not closed), `outcome` and
  `outcome_note`. `(case_id, kind, ref)` is unique, and a partial unique index
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
applies `agent_visibility` in SQL: a case is visible through a visible item,
or to its opener or assignee; items, counts and timeline entries about hidden
items are left out. Changes return `Result<_, Refusal>` (`NotFound`, `Stale`,
`ItemInCase`, `ItemsUnresolved` and so on) and write the audit row and
timeline entry in the same transaction. `reopen_due` runs two lazy checks that
the console calls before it lists or reads cases: `reopen_expired` reopens
closed cases whose accepted risk has run out, and `reopen_evidence_returned`
reopens cases closed within the last 30 days whose `resolved` items have
evidence again (migration 36 adds the partial index on `closed_at` it uses).
Tested by `tests/console_cases.rs`, run as
the console role. See [console-cases.md](console-cases.md).

## The rule signer's access (`signer::…`, schema 32, board #107)

Migration 32 creates the `openvibes-signer` role with column grants for a
password and permission check only (see
[openvibes-signer.md](openvibes-signer.md)). `signer_user` reads a
credential (either must-change flag counts), `may_upload_rules` checks
`rules.upload` through an active global role binding, and
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
  scope; a close skips expanded hosts already closed, a reopen the ones
  already open); each item goes
  through its single-item update, skipped items come back with a reason,
  one audit row per action.
- `triage_history::events`: the newest 200 changes of an alarm, or of a
  rule or advisory across the hosts in scope.
- `console_cases::active_items`: refs of one kind in open cases the
  caller can see, with the case number.
- Tests: `tests/migrate.rs` (`triage_v2_retires_investigating`),
  `tests/vulnerability_triage.rs`, `tests/bulk_triage.rs`.

## Assistant internet lookups (schema 46)

Spec `docs/specs/2026-10-10-assistant-internet-lookups.md`. Migration 46
adds the one-row `assistant_internet` table (off by default): `level`
(0 off, 1 fetch pages, 2 fetch and search), `searxng_url` (required at
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
  hostnames (not empty), console usernames and the internal domains, for
  the fetch service's outbound filter.
- Tests: `tests/assistant_internet.rs` (including the denylist and the
  console write path under their own roles).
