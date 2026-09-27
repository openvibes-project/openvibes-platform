# Agent health and the rotating queue (protocol P12) — design

Status: approved by the user in conversation, 2026-09-27; written spec
awaiting review. Implements sub-project 4 of the platform architecture
(`2026-09-23-platform-architecture-design.md` §7 and §9: "Agent health
reporting and rotating queue"), and the decision in the workspace
`decisions.md` ("Planned, with hooks: … rotating agent queue (drop oldest,
count it)").

## 1. Decisions (the user, 2026-09-27)

- **One sub-project for both:** health reporting and the rotating queue,
  delivered as one PR per repository. The queue's dropped count is itself a
  health field, and today a full queue refuses new findings without anyone
  on the platform knowing.
- **Surfaces:** the admin CLI (`agent list`, `agent show`) and the console's
  agent status (Healthy, Degraded, Offline, Unknown, with reasons). This
  sub-project builds the store and the console API; the console UI follows
  as Codex's PR.
- **Quiet by default:** no alerts or notifications in this sub-project.

Out of scope: alerts and notification channels, health history, configurable
thresholds, the console UI itself, platform-specific health beyond what the
agent already observes (Windows and macOS report what they can).

## 2. What the agent reports (`Heartbeat.health`)

Heartbeats (`POST /v1/heartbeat`, every 60 s) gain an optional `health`
object. It stays within schema version 1: `Heartbeat` does not refuse unknown
fields and its schema allows extra properties, so a platform before P12
ignores it, and an agent before P12 simply does not send it. It holds counts
and codes only (never paths, file contents, or finding data) and stays well
under 1 KB.

```json
"health": {
  "queue": {
    "pending": 12,
    "oldest_pending_age_s": 340,
    "bytes": 81920,
    "max_bytes": 268435456,
    "dropped_total": 0,
    "rejected_total": { "retention_expired": 2 }
  },
  "last_scan": {
    "finished_at_unix_ms": 1790000000000,
    "interval_s": 3600,
    "rules_evaluated": 42,
    "rules_unavailable": 1,
    "rules_failed": 0,
    "collectors": { "packages": "ok", "ports": "ok", "processes": "permission_denied" }
  },
  "rule_sets": [
    { "id": "baseline", "version": 7, "expires_at_unix_ms": 1790600000000, "refused": null }
  ],
  "storage_errors": 0,
  "clock_jump_s": null
}
```

- **`queue`:** pending findings, the age of the oldest, bytes used and the
  limit, and two totals kept durably across restarts:
  - `dropped_total`: findings the rotating queue dropped since the queue was created;
  - `rejected_total`: findings the platform refused permanently, by reason.
- **`last_scan`:** absent until the first scan. It carries:
  - when the scan finished, and the configured interval;
  - rule counts (evaluated, unavailable, failed);
  - each enabled collector's outcome: `ok`, or a `CollectorErrorCode`
    (`permission_denied`, `not_found`, `timed_out`, `invalid_data`,
    `unsupported`, `internal`).
- **`rule_sets`:** each configured rule set with:
  - the version in use (`null` before the first accepted bundle) and its expiry;
  - `refused`: `null`, or why the last provisioned bundle was refused
    (`signature`, `expired`, `rolled_back`, `invalid`).
- **`storage_errors`:** local database failures since the agent started.
- **`clock_jump_s`:** the last wall-clock jump the clock guard detected,
  when there was one.

Totals are cumulative, so the platform compares a report with the previous
one; a missed heartbeat loses nothing.

**Bounds:**
- at most 16 collectors, 64 rule sets and 16 rejection reasons;
- identifiers as elsewhere in the protocol;
- counts are non-negative integers;
- a heartbeat with a `health` object over these bounds is refused like any
  other invalid heartbeat (400).

## 3. The rotating queue (agent)

When a new finding would push the queue over `queue_bytes` (256 MiB), the
agent drops the oldest pending findings, in queue order and only as many as
needed to make room, in the same transaction as the insert, and adds them to
`dropped_total`. Today the new finding is refused instead (`not_queued`).
The newest observations are the ones worth keeping, and agent storage stays
bounded. A single finding larger than the whole queue is still refused (it
cannot happen within the document limit).

`dropped_total` and `rejected_total` live in the queue's SQLite database, so
they survive restarts and a queue that is moved aside as corrupt starts them
again at zero (reported as a fresh queue).

## 4. What the platform does with it

**Storage:**
- migration: `agents.health jsonb`, `agents.health_at timestamptz`, and
  `agents.health_previous jsonb` (the report before, so a total that rose can
  be told from one that stayed);
- ingest validates the heartbeat as today, and when `health` is present
  moves the stored report to `health_previous` and stores the new one;
- heartbeats without it leave the stored report as it was, so an agent
  downgraded to a pre-P12 version keeps its last report and turns Unknown by
  age (below);
- no history table.

**Status**, computed when read (never stored) by one function in
`platform-store`, shared by the CLI and the console:

| Status | When |
|---|---|
| **Offline** | no heartbeat for 15 minutes (`last_seen_at`) |
| **Unknown** | online, but no health report, or the last one is older than 15 minutes |
| **Degraded** | online with a current report, and at least one reason below |
| **Healthy** | online with a current report and no reason |

Reasons, each with a stable code for the API:
- `queue_dropping`: `dropped_total` rose since the previous report;
- `delivery_stalled`: the oldest pending finding is over 1 hour old;
- `queue_nearly_full`: over 80% of `max_bytes`;
- `scan_overdue`: the last scan finished more than twice its interval ago;
- `collector_failing`: a collector's outcome is not `ok`;
- `rule_set_expiring`: a rule set expires within 7 days;
- `rule_set_refused`: a rule set's last bundle was refused;
- `storage_errors`: the count rose since the previous report;
- `clock_jump`: the last jump exceeded 5 minutes.

The thresholds are constants in one place, documented in the component page.

**Surfaces:**
- `openvibes-admin agent list`: a status column and
  `--status healthy|degraded|offline|unknown`;
- `openvibes-admin agent show`: prints the report and the reasons;
- the console API's agent list and agent view gain `health_status` and
  `health_reasons`, plus a `health_status` filter, with the OpenAPI snapshot
  and generated client regenerated. Revoked agents keep their existing
  status; health applies to active agents.

## 5. Failure behaviour

- A heartbeat whose `health` is invalid is refused whole (400), as today for
  any invalid heartbeat; the agent logs it and its liveness is not recorded.
  To keep one bad field from hiding an agent, the agent validates its own
  report before sending and drops `health` (sending the rest) if it would be
  invalid.
- A platform before P12 ignores `health`; nothing changes for it.
- A queue database error while dropping keeps the transaction's all-or-nothing
  guarantee: nothing is dropped and the new finding is not queued; the
  storage error counts.

## 6. Testing

- **Protocol:**
  - fixtures: heartbeats with a full `health`, with none, and invalid ones
    (a negative count, an unknown collector outcome, too many rule sets);
  - contract text for `health` and the rotating queue.
- **Agent:**
  - a full queue drops the oldest (by queue order), counts them, and the
    count survives a restart;
  - a finding that fits is never dropped;
  - the report matches the scan, queue, rule store and clock guard state;
  - heartbeats carry it;
  - an invalid report is dropped from the heartbeat, not the heartbeat.
- **Platform:**
  - storage and overwrite;
  - status: one test per reason, plus Offline, Unknown (no report, stale
    report) and Healthy;
  - CLI `agent list --status`, `agent show`;
  - console API fields and filter.
- **End to end (systemd):** the enrolled agent reports Healthy. The e2e then
  makes the RPM database unreadable to the agent and restarts it; the agent
  turns Degraded with `collector_failing`. It then restores access.

## 7. Delivery

Protocol P12 PR → agent PR → platform PR, each merged with the user's
approval; then the console UI (Codex). The platform PR is safe before the
agent PR merges (it only reads an optional field), and agents before P12
show as Unknown.
