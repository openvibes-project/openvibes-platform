# count-history

## Purpose

Daily history of the counts shown on the console Overview (alarms,
vulnerabilities, compliance findings, agent states), so graphs can show how a
number moved. Code: `platform_store::history` and
`crates/openvibes-console/src/metrics.rs`.

## Table

`host_daily_counts` (migration 0044): one row per host per UTC day, primary
key `(day, agent_id)`: `status` (`active`, `stale`, `revoked`, `imported`),
the 5 alarm (critical/high/medium/low/info), 6 vulnerability (critical/high/medium/low, exploited, no fix),
`needs_reboot` and 4 compliance counts. The console role has `SELECT` only.

## Writer and retention

`openvibes-admin maintenance` (the systemd timer) records today's counts for
every host with `history::record` (deleting and re-inserting that day's rows in one
transaction, so a rerun is safe and a failed run leaves the day's previous
rows intact) and then deletes days older than `--history-days` (default 400, range
30 to 3650; see [openvibes-admin.md](openvibes-admin.md)). It prints
`recorded history for N hosts, deleted M old rows`.

The day is the UTC date at the moment the run starts. The timer fires daily
in local time with up to an hour's random delay, so near UTC midnight one
run can land on the same UTC day as the previous one (it replaces that day)
and the next day is then missing: a harmless one-day gap.

Size: measured 76 MB per 1,000 hosts per year in a freshly filled table
(52 MB rows, 24 MB primary key) and about 95 MB with day-to-day churn, so
plan on about 1 GB at 10,000 hosts with the 400-day default.

## Reader: `GET /api/v1/metrics/history`

Query: `metric` (catalogue id) and `days` (7, 30, 90 or 365; default 30).
Response: `{metric, points: [{day, value}]}`, oldest first. The window is
`days` days including today, so at most `days` points.

- Stored days in the window come from `host_daily_counts`; the last point is
  today, computed live. Stored rows dated today or later are not served.
- A day with no stored row (missed maintenance run, or no visible host) is
  absent from `points`: a gap, not a zero.
- Sums cover only the hosts in the caller's scope, filtered in SQL.
- Permissions: every permission listed for the metric is required (403
  otherwise). If a metric needs several permissions and the caller's scopes
  for them differ (for example global alarms, group-scoped vulnerabilities),
  the answer is 403, since no single host set is correct.
- 401 without a session or token; 422 `invalid_metric_query` with field code
  `unknown_metric` or `invalid_days`; 503 when the database is unavailable.

## Reader: `GET /api/v1/metrics/top-hosts`

Query: `limit` (1 to 10, default 6; else 422 `invalid_metric_query` with field
code `invalid_limit`). Response: `{items: [{agent_id, hostname, serious, open}]}`
from the same per-host query (`history::top_hosts`): `serious` is critical plus
high of alarms, vulnerabilities and compliance; `open` adds medium and low
(info alarms excluded). Ordered by `serious`, then `open`, then agent id; hosts
with nothing open are left out. Unrated vulnerabilities are in no count here (the vulnerabilities-only mode of the Most exposed hosts tile does list them). Same permission rule and scoping as the
cross-kind metrics (403 unless alarms, vulnerabilities and compliance reads
share one scope).

| Metric id | Meaning | Permissions |
|---|---|---|
| `all.open.critical` | alarms + vulnerabilities + compliance, critical | alarms.read, vulnerabilities.read, compliance.read |
| `all.open.high` | the same, high | alarms.read, vulnerabilities.read, compliance.read |
| `alarms.active` | open or investigating alarms, all severities (info included, as in the alarm list) | alarms.read |
| `alarms.active.critical` / `.high` / `.medium` / `.low` | active alarms by severity | alarms.read |
| `vulns.open.critical` / `.high` / `.medium` / `.low` | open vulnerabilities by severity (important counts as high, moderate as medium) | vulnerabilities.read |
| `vulns.exploited` | open vulnerabilities known exploited | vulnerabilities.read |
| `vulns.no_fix` | open vulnerabilities without a fix | vulnerabilities.read |
| `vulns.reboot_hosts` | hosts needing a reboot | vulnerabilities.read |
| `compliance.open.critical` / `.high` / `.medium` / `.low` | current compliance findings by severity | compliance.read |
| `agents.active` / `.stale` / `.revoked` | hosts by agent status | agents.read |

## Failure behaviour

A missed maintenance day leaves a gap; history is not backfilled, because the
past state cannot be recomputed. A failed run keeps earlier days and the same day's previous rows. Database
errors on the endpoint answer 503 without partial data. Metrics are a fixed
catalogue; request input never reaches SQL.

## Testing

```
eval "$(scripts/test-db.sh)"
cargo test -p platform-store history
cargo test -p openvibes-console --features openvibes-console/dev-seed metrics
cargo test -p openvibes-console --features openvibes-console/dev-seed api_contract
```
