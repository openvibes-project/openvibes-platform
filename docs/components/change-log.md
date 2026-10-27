# change-log (what appeared and went away on each host)

The shared change log, from roles step 5e (spec §10 and its "Plan rulings,
2026-10-25 (step 5e)", rulings 2 to 6; migration 0065). One table records
what appeared on and went away from each host, for installed packages,
listening ports and running services. The Ports pages read it now (This
week, Recent changes, first seen) and so do the Services pages (5f); the
Software pages (5g) will read the same rows.

## Interfaces

| Part | What | Code |
|---|---|---|
| `change_log` table | `at`, `agent_id` (cascade delete), `kind` (`package`, `listener`, `service`), `key`, `change` (`appeared`, `went_away`, `exposed`, `local`), `detail` | `migrations/0065_change_log.sql` (repository root) |
| `change_log_start` | one row, the time of the upgrade: nothing before it was logged | same migration |
| `listener_diff`, `key_diff`, `package_diff`, `record` | compare a host's stored rows with its new report inside ingest's transaction and insert only the differences | `platform-store/src/change_log.rs`, called from `inventory.rs` and `host_services.rs` |
| `change_log::prune` | delete rows older than 90 days | called by `openvibes-admin maintenance` |

Keys: a listener is `tcp/22` (the API's spelling), a service is its unit, a
package is its name with `detail = {manager, version, arch}`.

## What counts as a change

- **Listener:** per host, the set of `(protocol, port)`. A port that
  appears or goes away writes `appeared` or `went_away`. A port that stays
  but changes exposure writes `exposed` (now bound to a non-loopback
  address) or `local` (now loopback only). A change of address alone
  (`0.0.0.0` to `::`) writes nothing.
- **Service:** the set of units. A change of process count, program or user
  writes nothing.
- **Package:** the set of package versions. An upgrade is `went_away` of
  the old version and `appeared` of the new one at the same `at`.

## Behaviour

- **A host's first report is its baseline and writes nothing.** After the
  upgrade, existing hosts already have stored rows, so their next report
  diffs against them: there is no flood. A full-inventory resync diffs
  against the stored rows.
- **No change, no write.** An unchanged digest returns before any
  change-log work. A changed digest with the same keys computes the diff and
  issues no INSERT.
- **Retention:** 90 days. The nightly `openvibes-admin maintenance` run
  prunes older rows (see [openvibes-admin.md](openvibes-admin.md)).
  Daily partitions are the upgrade path if the volume ever needs them.
- **First seen** on a page is the earliest of the earliest `appeared` in
  reach and, for each host in reach that lists it now and has no `appeared`
  event for it (its port was in the baseline or predates the log), the later
  of its enrolment and the log's floor (`greatest(change_log_start, now - 90
  days)`). When that is the floor the page says "Before {date}", so it never
  claims a date later than the truth.

## Failure behaviour

The log is written in the same transaction as the host's rows, so a
failure leaves both as they were and the agent sends the report again.

## How to test

`cargo test -p platform-store --test change_log` (first report writes
nothing, upgrade writes no flood, unchanged and same-key reports write
nothing, every kind of change, pruning). Cost on ingest, measured with
`cargo test --release -p platform-store --test change_log_ingest_timing --
--ignored --nocapture`: a changed services report adds under 1 ms (7.2 ms
unchanged keys, 7.9 ms with a listener changed) and a 150-package upgrade
adds about 6 ms (9.9 ms against 15.7 ms), against the 5 ms and 50 ms limits.
