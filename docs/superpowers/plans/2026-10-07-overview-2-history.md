# Overview clarity 2: daily count history — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The platform records each host's problem counts once a day and serves any catalogue count as a scoped daily series.

**Architecture:** New table `host_daily_counts` (migration 0044, additive). One SQL query (`HOST_COUNTS_SQL`) computes current per-host counts; `openvibes-admin maintenance` inserts its result under today's date and deletes rows past `--history-days`. The console's new `metrics.rs` module holds the count catalogue and `GET /api/v1/metrics/history`, which sums stored rows over the caller's visible hosts and appends today's live value from the same query.

**Tech Stack:** Rust (tokio-postgres, axum, utoipa, clap), PostgreSQL.

**Spec:** `docs/superpowers/specs/2026-10-07-overview-clarity-design.md` §5, §6.1.

## Global Constraints

- Independent of plan 1 (either can merge first). If plan 1 is merged, permission names are `compliance.read`; otherwise `findings.read`. Use the enum variant (`Permission::ComplianceRead` after plan 1, `Permission::FindingsRead` before) — never a string.
- Severity mapping for vulnerabilities: `critical`→critical, `important`→high, `moderate`→medium, `low`→low; `unrated` is not in any severity count.
- Definitions match today's summaries: active alarm = `state IN ('open','investigating')`; open vulnerability = a row counted in `host_vulnerability_counts`; exploited = `summary_for_agents`' exploited query per host; compliance = rows in `current_findings`; host status = `agent_summary_in_scope`'s rule (`revoked`, `imported`, `active` if seen within `OFFLINE_AFTER_MINUTES`, else `stale`).
- `--history-days` default 400, range 30–3650. Periods: 7, 30, 90, 365.
- Days without rows are absent from the series, never zero.
- Gate: `testing.md` §2, and §3 (Fedora job) because maintenance changes.

## Review Focus

1. A scoped analyst sees only their asset groups' hosts in a series (Task 4 test).
2. Maintenance run twice on one day leaves one row per host, the later values (Task 2 test).
3. A host revoked yesterday still contributes yesterday's counts, and today's live point excludes nothing it shouldn't: revoked hosts count only in `agents.revoked` (Task 2 test).
4. An install that has run maintenance once returns one stored point plus today, not 30 zeros (Task 4 test).
5. `metric=all.open.critical` for a role with different scopes for alarms and vulnerabilities is refused with 403, not a mixed-scope number (Task 4 test).

---

### Task 1: Migration 0044 adds `host_daily_counts`

**Files:**
- Create: `migrations/0044_host_daily_counts.sql`
- Modify: `crates/platform-store/src/migrate.rs` (`SCHEMA_VERSION` 44; register 44)

- [ ] **Step 1: Write the migration**

```sql
-- OpenVIBES platform schema version 44: one row of problem counts per host
-- per day, written by maintenance, read by the console's history graphs
-- (spec 2026-10-07-overview-clarity-design §5). Additive.
CREATE TABLE host_daily_counts (
    day date NOT NULL,
    agent_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'stale', 'revoked', 'imported')),
    alarms_critical integer NOT NULL, alarms_high integer NOT NULL,
    alarms_medium integer NOT NULL, alarms_low integer NOT NULL,
    vulns_critical integer NOT NULL, vulns_high integer NOT NULL,
    vulns_medium integer NOT NULL, vulns_low integer NOT NULL,
    vulns_exploited integer NOT NULL, vulns_no_fix integer NOT NULL,
    needs_reboot boolean NOT NULL,
    compliance_critical integer NOT NULL, compliance_high integer NOT NULL,
    compliance_medium integer NOT NULL, compliance_low integer NOT NULL,
    PRIMARY KEY (day, agent_id)
);
GRANT SELECT ON host_daily_counts TO "openvibes-console";
```

- [ ] **Step 2:** Register in `migrate.rs`; run `cargo test -p platform-store --test migrate`. Expected: PASS.
- [ ] **Step 3: Commit** `git commit -am "Store: host_daily_counts table"`

### Task 2: Store snapshot, retention and series

**Files:**
- Create: `crates/platform-store/src/history.rs`; Modify: `crates/platform-store/src/lib.rs` (`pub mod history;`)
- Test: `crates/platform-store/tests/history.rs`

**Interfaces:**
- Produces:
  - `pub const COLUMNS: [&str; 17]` (the 15 count columns in table order, then `status`, `agent_id`)
  - `pub async fn record(client: &Client, day: NaiveDate, now: DateTime<Utc>) -> Result<u64, StoreError>` — rows written
  - `pub async fn delete_before(client: &Client, cutoff: NaiveDate) -> Result<u64, StoreError>`
  - `pub enum Expr { Sum(&'static [&'static str]), HostsWhere(&'static str) }` — how a metric is computed from columns
  - `pub async fn series(client: &Client, expr: &Expr, since: NaiveDate, agents: Option<&[String]>) -> Result<Vec<(NaiveDate, i64)>, StoreError>`
  - `pub async fn current(client: &Client, expr: &Expr, now: DateTime<Utc>, agents: Option<&[String]>) -> Result<i64, StoreError>`

- [ ] **Step 1: Failing tests** `crates/platform-store/tests/history.rs`

```rust
mod common;

use chrono::{NaiveDate, TimeZone, Utc};
use platform_store::history::{self, Expr};

const CRIT: Expr = Expr::Sum(&["alarms_critical", "vulns_critical", "compliance_critical"]);

#[tokio::test]
async fn record_counts_each_host_and_replaces_the_same_day() {
    let (db, client) = common::migrated().await;
    // agent-1: 1 open critical alarm, host_vulnerability_counts critical=2 important=1,
    // 1 critical current finding; agent-2: nothing. Use the seed helpers in
    // tests/common (alarms.rs, inventory.rs and finding tests show the inserts).
    common::seed_agent(&client, "agent-1").await;
    common::seed_agent(&client, "agent-2").await;
    common::seed_alarm(&client, "agent-1", "critical", "open").await;
    common::seed_alarm(&client, "agent-1", "high", "mitigated").await; // not active
    common::seed_host_vuln_counts(&client, "agent-1", 2, 1, 0, 0).await;
    common::seed_current_finding(&client, "agent-1", "critical").await;
    let day = NaiveDate::from_ymd_opt(2026, 10, 7).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    assert_eq!(history::record(&client, day, now).await.unwrap(), 2);
    assert_eq!(history::record(&client, day, now).await.unwrap(), 2, "same day replaced");
    let rows: i64 = client.query_one("SELECT count(*) FROM host_daily_counts", &[]).await.unwrap().get(0);
    assert_eq!(rows, 2);
    let series = history::series(&client, &CRIT, day, None).await.unwrap();
    assert_eq!(series, [(day, 4)]);
    let high = Expr::Sum(&["alarms_high", "vulns_high", "compliance_high"]);
    assert_eq!(history::series(&client, &high, day, None).await.unwrap(), [(day, 1)]);
    assert_eq!(history::current(&client, &CRIT, now, None).await.unwrap(), 4);
    let only_2 = ["agent-2".to_owned()];
    assert_eq!(history::series(&client, &CRIT, day, Some(&only_2)).await.unwrap(), [(day, 0)]);
    db.drop().await;
}

#[tokio::test]
async fn retention_deletes_only_older_days() {
    let (db, client) = common::migrated().await;
    common::seed_agent(&client, "agent-1").await;
    let now = Utc.with_ymd_and_hms(2026, 10, 7, 3, 0, 0).unwrap();
    for d in [1, 5, 7] {
        history::record(&client, NaiveDate::from_ymd_opt(2026, 10, d).unwrap(), now).await.unwrap();
    }
    let deleted = history::delete_before(&client, NaiveDate::from_ymd_opt(2026, 10, 5).unwrap()).await.unwrap();
    assert_eq!(deleted, 1);
    let days = history::series(&client, &Expr::HostsWhere("status = 'active'"),
        NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(), None).await.unwrap();
    assert_eq!(days.iter().map(|(d, _)| d.to_string()).collect::<Vec<_>>(), ["2026-10-05", "2026-10-07"]);
    db.drop().await;
}
```

Add the `seed_*` helpers to `tests/common/mod.rs`, each a single INSERT with the NOT NULL columns of its table (read `0029_alarms.sql`, the `host_vulnerability_counts` and `current_findings` migrations). `seed_agent` sets `status='active'`, `last_seen_at = '2026-10-07T02:59:00Z'`.

- [ ] **Step 2:** `cargo test -p platform-store --test history` — Expected: FAIL (module missing).

- [ ] **Step 3: Implement** `crates/platform-store/src/history.rs`

```rust
//! Daily per-host problem counts for the console's graphs (spec
//! 2026-10-07-overview-clarity-design §5). One query computes the counts;
//! maintenance stores them, the console sums them over visible hosts.

use chrono::{DateTime, Duration, NaiveDate, Utc};
use tokio_postgres::Client;

use crate::{StoreError, console_read::OFFLINE_AFTER_MINUTES};

pub const COLUMNS: [&str; 17] = [
    "alarms_critical", "alarms_high", "alarms_medium", "alarms_low",
    "vulns_critical", "vulns_high", "vulns_medium", "vulns_low",
    "vulns_exploited", "vulns_no_fix", "needs_reboot",
    "compliance_critical", "compliance_high", "compliance_medium", "compliance_low",
    "status", "agent_id",
];

/// Current counts per host; `$1` is the "seen since" threshold.
const HOST_COUNTS_SQL: &str = "
SELECT a.agent_id,
       CASE WHEN a.status IN ('revoked', 'imported') THEN a.status
            WHEN agent_seen_at(a.agent_id, a.last_seen_at) >= $1 THEN 'active'
            ELSE 'stale' END AS status,
       COALESCE(al.c, 0)::int AS alarms_critical, COALESCE(al.h, 0)::int AS alarms_high,
       COALESCE(al.m, 0)::int AS alarms_medium, COALESCE(al.l, 0)::int AS alarms_low,
       COALESCE(v.critical, 0)::int AS vulns_critical, COALESCE(v.important, 0)::int AS vulns_high,
       COALESCE(v.moderate, 0)::int AS vulns_medium, COALESCE(v.low, 0)::int AS vulns_low,
       COALESCE(x.n, 0)::int AS vulns_exploited, COALESCE(v.no_fix, 0)::int AS vulns_no_fix,
       COALESCE(v.reboot, 0) > 0 AS needs_reboot,
       COALESCE(f.c, 0)::int AS compliance_critical, COALESCE(f.h, 0)::int AS compliance_high,
       COALESCE(f.m, 0)::int AS compliance_medium, COALESCE(f.l, 0)::int AS compliance_low
FROM agents a
LEFT JOIN LATERAL (
    SELECT count(*) FILTER (WHERE severity = 'critical') c, count(*) FILTER (WHERE severity = 'high') h,
           count(*) FILTER (WHERE severity = 'medium') m, count(*) FILTER (WHERE severity = 'low') l
    FROM alarms WHERE agent_id = a.agent_id AND state IN ('open', 'investigating')) al ON true
LEFT JOIN host_vulnerability_counts v ON v.agent_id = a.agent_id
LEFT JOIN LATERAL (
    SELECT count(*) n FROM vulnerabilities vv
    WHERE vv.agent_id = a.agent_id AND vv.fixed_at IS NULL AND NOT vv.reboot_needed
      AND vv.advisory_id = ANY(ARRAY(
          SELECT DISTINCT c.advisory_id FROM advisory_cves c
          JOIN cve_enrichment e ON e.cve_id = c.cve_id
          WHERE e.kev_added IS NOT NULL OR e.euvd_exploited))) x ON true
LEFT JOIN LATERAL (
    SELECT count(*) FILTER (WHERE severity = 'critical') c, count(*) FILTER (WHERE severity = 'high') h,
           count(*) FILTER (WHERE severity = 'medium') m, count(*) FILTER (WHERE severity = 'low') l
    FROM current_findings WHERE agent_id = a.agent_id) f ON true";

/// How a metric is computed from one day's rows.
pub enum Expr {
    /// Sum of these count columns.
    Sum(&'static [&'static str]),
    /// Number of hosts matching this condition on the row (fixed strings from the catalogue).
    HostsWhere(&'static str),
}

impl Expr {
    fn select(&self) -> String {
        match self {
            Self::Sum(cols) => format!("COALESCE(sum({}), 0)::bigint", cols.join(" + ")),
            Self::HostsWhere(cond) => format!("count(*) FILTER (WHERE {cond})"),
        }
    }
}

fn threshold(now: DateTime<Utc>) -> DateTime<Utc> {
    now - Duration::minutes(OFFLINE_AFTER_MINUTES)
}

/// Stores every host's current counts under `day`, replacing that day.
pub async fn record(client: &Client, day: NaiveDate, now: DateTime<Utc>) -> Result<u64, StoreError> {
    client.execute("DELETE FROM host_daily_counts WHERE day = $1", &[&day]).await?;
    let cols = COLUMNS[..15].join(", ");
    Ok(client.execute(
        &format!("INSERT INTO host_daily_counts (day, agent_id, status, {cols})
                  SELECT $2, agent_id, status, {cols} FROM ({HOST_COUNTS_SQL}) h"),
        &[&threshold(now), &day],
    ).await?)
}

pub async fn delete_before(client: &Client, cutoff: NaiveDate) -> Result<u64, StoreError> {
    Ok(client.execute("DELETE FROM host_daily_counts WHERE day < $1", &[&cutoff]).await?)
}

/// Stored days from `since`, oldest first, summed over `agents` (all when None).
pub async fn series(client: &Client, expr: &Expr, since: NaiveDate, agents: Option<&[String]>)
    -> Result<Vec<(NaiveDate, i64)>, StoreError> {
    let rows = client.query(
        &format!("SELECT day, {} FROM host_daily_counts
                  WHERE day >= $1 AND ($2::text[] IS NULL OR agent_id = ANY($2))
                  GROUP BY day ORDER BY day", expr.select()),
        &[&since, &agents],
    ).await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}

/// Today's value, live, from the same per-host query.
pub async fn current(client: &Client, expr: &Expr, now: DateTime<Utc>, agents: Option<&[String]>)
    -> Result<i64, StoreError> {
    Ok(client.query_one(
        &format!("SELECT {} FROM ({HOST_COUNTS_SQL}) h WHERE ($2::text[] IS NULL OR agent_id = ANY($2))", expr.select()),
        &[&threshold(now), &agents],
    ).await?.get(0))
}
```

Make `OFFLINE_AFTER_MINUTES` `pub` in `console_read.rs` if it is not. If `series` returns a stored day with no visible host (scoped), it has no row: that is a gap — acceptable and documented.

- [ ] **Step 4:** `cargo test -p platform-store --test history` — Expected: PASS. Also run `EXPLAIN ANALYZE` of `HOST_COUNTS_SQL` once on the dev seed (`cargo run -p openvibes-console --example seeded_server --features dev-seed`) and note the time in the PR.
- [ ] **Step 5: Commit** `git commit -am "Store: per-host daily counts, retention and series"`

### Task 3: Maintenance writes snapshots

**Files:** Modify `crates/openvibes-admin/src/main.rs:62-66, 547-570`; Test `crates/openvibes-admin/tests/maintenance.rs` (create if absent, using `tests/common` `Fixture` like `tests/assistant.rs`).

- [ ] **Step 1: Failing test**

```rust
mod common;
use common::{Fixture, stdout};

#[tokio::test]
async fn maintenance_records_todays_counts_and_reports_them() {
    let fixture = Fixture::create().await;
    stdout(&fixture.run(&["migrate"]));
    let out = stdout(&fixture.run(&["maintenance", "--history-days", "30"]));
    assert!(out.contains("recorded history for 0 hosts, deleted 0 old rows"), "{out}");
    let bad = fixture.run(&["maintenance", "--history-days", "10"]);
    assert!(!bad.status.success(), "below 30 is refused before any change");
    fixture.drop().await;
}
```

- [ ] **Step 2:** `cargo test -p openvibes-admin --test maintenance` — FAIL (unknown flag).
- [ ] **Step 3: Implement**

```rust
    Maintenance {
        /// Keep findings for this many days (1 to 36500).
        #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u32).range(1..=36500))]
        retention_days: u32,
        /// Keep daily count history for this many days (30 to 3650).
        #[arg(long, default_value_t = 400, value_parser = clap::value_parser!(u32).range(30..=3650))]
        history_days: u32,
    },
```

In the handler, after the audit cleanup:

```rust
            let now = Utc::now();
            let recorded = platform_store::history::record(client, today, now).await.map_err(fail)?;
            let history_cutoff = today - Duration::days(i64::from(*history_days));
            let pruned = platform_store::history::delete_before(client, history_cutoff).await.map_err(fail)?;
            Ok(format!(
                "created {created} partitions, dropped {dropped}, deleted {audit_deleted} expired audit events\n\
                 recorded history for {recorded} hosts, deleted {pruned} old rows\n"
            ))
```

Update the `Command::Maintenance { retention_days }` pattern to bind `history_days`. Check `crates/openvibes-admin/src/tui` and Setup for code that parses maintenance output (`grep -rn "expired audit events" crates`) and keep them working.

- [ ] **Step 4:** `cargo test -p openvibes-admin` — PASS.
- [ ] **Step 5:** Docs: `docs/components/openvibes-admin.md` maintenance row: add `--history-days 400` and the new output line. Commit `git commit -am "Admin: maintenance records daily count history"`.

### Task 4: Count catalogue and `GET /api/v1/metrics/history`

**Files:**
- Create: `crates/openvibes-console/src/metrics.rs`; Modify `lib.rs`/`main` module list, `router.rs` (route `.route("/v1/metrics/history", get(crate::metrics::history))`), `openapi.rs` (path + schemas), `api.rs` (DTOs)
- Test: `crates/openvibes-console/tests/metrics_http.rs`

**Interfaces:**
- Consumes: `platform_store::history::{Expr, series, current}`, `console_read::agent_ids_in_scope`, router's `authenticated_agent_scope(&state, &headers, Permission) -> Result<AgentScope, Response>`.
- Produces: `pub struct Metric { id: &'static str, label: &'static str, permissions: &'static [Permission], expr: Expr }`, `pub static CATALOGUE: [Metric; N]`, DTO `MetricHistory { metric: String, points: Vec<MetricPoint> }`, `MetricPoint { day: String /* YYYY-MM-DD */, value: u64 }`.

Catalogue (IDs exact; `R` = the compliance read variant):

| id | permissions | expr |
|---|---|---|
| `all.open.critical` | Alarms, Vulns, R | Sum alarms_critical, vulns_critical, compliance_critical |
| `all.open.high` | Alarms, Vulns, R | Sum alarms_high, vulns_high, compliance_high |
| `alarms.active` | Alarms | Sum the four alarms_* |
| `alarms.active.<sev>` ×4 | Alarms | Sum alarms_<sev> |
| `vulns.open.<sev>` ×4 | Vulns | Sum vulns_<sev> |
| `vulns.exploited` / `vulns.no_fix` | Vulns | Sum vulns_exploited / vulns_no_fix |
| `vulns.reboot_hosts` | Vulns | HostsWhere `needs_reboot` |
| `compliance.open.<sev>` ×4 | R | Sum compliance_<sev> |
| `agents.active` / `.stale` / `.revoked` | Agents | HostsWhere `status = 'active'` etc. |

- [ ] **Step 1: Failing tests** `tests/metrics_http.rs` (use the same server/session helpers as `auth_http.rs`; seed rows directly into `host_daily_counts` for two hosts in different asset groups):

```rust
#[tokio::test]
async fn history_sums_visible_hosts_and_appends_today() {
    // rows: 2026-10-05 and 2026-10-06 for host-a (group A, vulns_critical=1) and host-b (group B, vulns_critical=5)
    let global = admin.get("/api/v1/metrics/history?metric=vulns.open.critical&days=30").await.json::<Value>().await;
    assert_eq!(global["points"][0], json!({"day": "2026-10-05", "value": 6}));
    let scoped = analyst_group_a.get("/api/v1/metrics/history?metric=vulns.open.critical&days=30").await.json::<Value>().await;
    assert_eq!(scoped["points"][0]["value"], 1);
    let last = global["points"].as_array().unwrap().last().unwrap();
    assert_eq!(last["day"], today_utc_string()); // live point
}

#[tokio::test]
async fn history_refuses_bad_input_and_mixed_scopes() {
    assert_eq!(admin.get("/api/v1/metrics/history?metric=nope&days=30").await.status(), 422);
    assert_eq!(admin.get("/api/v1/metrics/history?metric=alarms.active&days=12").await.status(), 422);
    // role with alarms.read on group A but vulnerabilities.read on group B
    assert_eq!(mixed.get("/api/v1/metrics/history?metric=all.open.critical&days=30").await.status(), 403);
    assert_eq!(viewer_without_alarms.get("/api/v1/metrics/history?metric=alarms.active&days=7").await.status(), 403);
}

#[tokio::test]
async fn a_fresh_install_has_only_todays_point() {
    let body = admin.get("/api/v1/metrics/history?metric=alarms.active&days=30").await.json::<Value>().await;
    assert_eq!(body["points"].as_array().unwrap().len(), 1);
}
```

- [ ] **Step 2:** `cargo test -p openvibes-console --test metrics_http` — FAIL (404).
- [ ] **Step 3: Implement** `metrics.rs`: parse `metric` (must be in `CATALOGUE`) and `days` (7|30|90|365) else 422 with `FieldError`s (`code: "unknown_metric"` / `"invalid_days"`); for each permission call `authenticated_agent_scope`; if scopes differ → 403 `permission_denied` "Counts across kinds need the same scope for alarms, vulnerabilities and compliance"; `agents = None` for global else `agent_ids_in_scope`; `since = today - (days - 1)`; `points = series(...)` with stored `today` removed, then push `(today, current(...))`. Add the `#[utoipa::path]` and schemas; regenerate OpenAPI and TS client (plan 1 Task 4 commands).
- [ ] **Step 4:** `cargo test -p openvibes-console --all-features` — PASS.
- [ ] **Step 5: Commit** `git commit -am "Console: count history API"`

### Task 5: Docs and gate

- [ ] `docs/components/openvibes-console.md`: interface row for `/api/v1/metrics/history` (permissions, scope, 422/403, absent days). New `docs/components/count-history.md` (purpose, table, maintenance writer, retention, failure behaviour, how to test) and index it in `docs/components/README.md`.
- [ ] Gate: `testing.md` §2 and §3 (Fedora job: the maintenance unit runs the new code; check `systemctl start openvibes-maintenance` succeeds in the integration job). Open PR 2.
