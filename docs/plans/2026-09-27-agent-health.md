# Agent health and the rotating queue (protocol P12) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (native) or superpowers:subagent-driven-development. Steps use checkboxes.

**Goal:** Agents report their health in every heartbeat, and a full queue drops its oldest findings instead of refusing new ones (counting them). The platform stores the latest report and shows Healthy / Degraded / Offline / Unknown with reasons in `openvibes-admin agent list/show` and the console API.

**Architecture:** Three repositories, one PR each, merged in order: protocol → agent → platform. The console API fields come last, after Codex's #38/#39 merge, because they touch the same console files.
- **Protocol:** an optional `health` object in `Heartbeat`.
- **Agent:**
  - `openvibes-core` gains the `Health` types;
  - `openvibes-storage`'s queue gains durable counters, the rotating drop and `stats()`;
  - the scan reports per-collector and per-rule-set state;
  - the service assembles `health` for each heartbeat.
- **Platform:**
  - a migration adds `agents.health`, `health_at` and `health_previous`;
  - ingest stores the report on the existing 5-minute heartbeat write throttle;
  - a pure `platform-store::health` function computes the status and reasons for the CLI and the console.

**Tech Stack:** Rust (serde, rusqlite, tokio-postgres/JSONB, clap), JSON Schema 2020-12, bash e2e.

**Spec:** `docs/specs/2026-09-27-agent-health-design.md`.

## Global Constraints

- **`Heartbeat.health` is optional and within schema version 1.**
  - `Heartbeat` accepts unknown fields; its schema has no `additionalProperties: false`.
  - A platform before P12 ignores `health`; an agent before P12 does not send it.
- **Contents:** counts and codes only. No paths, file contents or finding data. Well under 1 KB.
- **Bounds:**
  - at most 16 collectors, 64 rule sets and 16 rejection reasons;
  - counts are non-negative integers (`u64`);
  - times are Unix ms as elsewhere;
  - collector outcomes are one of `ok permission_denied not_found timed_out invalid_data unsupported internal`;
  - refusal codes are one of `signature expired rolled_back invalid`.
- **Rotating queue:**
  - a finding that would exceed `queue_bytes` drops the oldest pending findings, by `seq`, only as many as needed, in the insert's transaction, and adds them to the durable `dropped_total`;
  - a finding larger than an empty queue is still refused with `StorageError::Full`.
- **Durable totals:** `dropped_total` and `rejected_total` live in the queue database (upgrade V2, table `counters`). A queue moved aside as corrupt starts them again at zero.
- **Platform status:** Offline after 15 minutes without a heartbeat (`OFFLINE_AFTER_MINUTES`).
  - **Unknown:** online, but no report, or the report is older than 15 minutes.
  - **Degraded:** online with a current report and at least one reason.
  - **Healthy:** otherwise.
  - Status applies to `active` agents only.
- **Reasons (codes):**

  | Code | When |
  |---|---|
  | `queue_dropping` | `dropped_total` > previous report's |
  | `delivery_stalled` | oldest pending > 3,600 s |
  | `queue_nearly_full` | `bytes` > 80% of `max_bytes` |
  | `scan_overdue` | last scan finished more than 2 × `interval_s` ago |
  | `collector_failing` | any outcome is not `ok` |
  | `rule_set_expiring` | expires within 7 days |
  | `rule_set_refused` | `refused` is set |
  | `storage_errors` | `storage_errors` > previous report's |
  | `clock_jump` | `|clock_jump_s|` > 300 |

  The thresholds are constants in `platform-store/src/health.rs`.
- **Write throttle:**
  - Ingest writes `health` in the same UPDATE as the existing throttled heartbeat write (every 5 minutes, or at once when hostname or capabilities change). Writing every minute would mean about 170 writes/s at 10,000 agents.
  - So "since the previous report" compares reports about 5 minutes apart, and a rise stays visible for one interval.
  - `agent show` always prints the totals.
- **Migration number:** the next free one when the task runs; 0023 today. If Codex's #38 (0023) / #39 (0024) merge first, use 0025 (the repository rule: whoever merges second renumbers).
- **Workflow:**
  - One worktree per repository: `../openvibes-protocol-health`, `../openvibes-agent-health`, `../openvibes-platform-health` (exists; branch `agent-health`), each with `git submodule update --init` and the `itismelime` identity.
  - Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - Files stay under 500 lines: `contracts.rs` (873) and `service.rs` (821) are already over, so new code goes in new modules.
  - Component docs are updated in the same task.
  - Every merge needs the user's approval.
- **Gates:** protocol `tools/validate.py`; agent `testing.md` §4; platform `testing.md` §2 plus §3 (systemd e2e changes).

## Review Focus

- A heartbeat whose `health` is invalid (a bug, or a limit crossed) must not make the agent disappear: the agent drops `health` and sends the rest (Task 5 `an_invalid_health_report_is_left_out`).
- A queue already full of maximum-size findings, and one new finding: it drops just enough, and the counter survives a restart (Task 3 `a_full_queue_drops_the_oldest`, `dropped_total_survives_restart`); the reviewer checks that the loop rolls back and drops nothing when even an empty queue cannot hold the finding.
- A platform peer sending a new rejection reason every batch: the reasons map stays bounded at 16 (Task 3 `rejection_reasons_are_bounded`).
- An agent that stops sending health, after a downgrade, or with the report stale: Unknown, not Healthy (Task 6 `a_stale_report_is_unknown`).
- A heartbeat arriving inside the 5-minute throttle: `health` is not written and the previous-report comparison is not disturbed (Task 6 `health_follows_the_heartbeat_throttle`).

---

## Repository 1: openvibes-protocol

### Task 1: `Heartbeat.health` (P12)

**Files:**
- Modify: `schemas/v1/heartbeat.schema.json`, `spec/contracts-v1.md`, `PLAN.md`
- Create: `fixtures/v1/heartbeat/valid-health.json`, `fixtures/v1/heartbeat/invalid-health-negative-count.json`, `fixtures/v1/heartbeat/invalid-health-unknown-outcome.json`, `fixtures/v1/heartbeat/invalid-health-too-many-rule-sets.json`

- [ ] **Step 1: Failing fixtures.**
  - Worktree `../openvibes-protocol-health`, branch `agent-health`.
  - Write `valid-health.json`: an existing valid heartbeat plus the spec §2 example `health`.
  - Each invalid fixture has exactly one defect: `"pending": -1`; `"processes": "exploded"`; 65 entries in `rule_sets` (generate the file with a short Python one-off; keep it checked in).
  - Run: `.venv/bin/python tools/validate.py` (the job venv works: `/home/lime/.claude/jobs/0fd2d966/tmp/venv/bin/python`).
  - Expected: the three invalid fixtures FAIL as valid, because the schema does not know `health` yet.

- [ ] **Step 2: Schema.** Add to `heartbeat.schema.json` `properties`:

```json
"health": {
  "type": "object",
  "description": "Optional (P12): the agent's health, counts and codes only. Totals are cumulative since the queue was created.",
  "required": ["queue", "storage_errors"],
  "properties": {
    "queue": {
      "type": "object",
      "required": ["pending", "bytes", "max_bytes", "dropped_total"],
      "properties": {
        "pending": { "$ref": "#/$defs/count" },
        "oldest_pending_age_s": { "$ref": "#/$defs/count" },
        "bytes": { "$ref": "#/$defs/count" },
        "max_bytes": { "$ref": "#/$defs/count" },
        "dropped_total": { "$ref": "#/$defs/count" },
        "rejected_total": {
          "type": "object", "maxProperties": 16,
          "propertyNames": { "$ref": "common.schema.json#/$defs/identifier" },
          "additionalProperties": { "$ref": "#/$defs/count" }
        }
      }
    },
    "last_scan": {
      "type": "object",
      "required": ["finished_at_unix_ms", "interval_s", "rules_evaluated", "rules_unavailable", "rules_failed", "collectors"],
      "properties": {
        "finished_at_unix_ms": { "$ref": "common.schema.json#/$defs/unixMs" },
        "interval_s": { "$ref": "#/$defs/count" },
        "rules_evaluated": { "$ref": "#/$defs/count" },
        "rules_unavailable": { "$ref": "#/$defs/count" },
        "rules_failed": { "$ref": "#/$defs/count" },
        "collectors": {
          "type": "object", "maxProperties": 16,
          "propertyNames": { "$ref": "common.schema.json#/$defs/identifier" },
          "additionalProperties": { "enum": ["ok", "permission_denied", "not_found", "timed_out", "invalid_data", "unsupported", "internal"] }
        }
      }
    },
    "rule_sets": {
      "type": "array", "maxItems": 64,
      "items": {
        "type": "object", "required": ["id"],
        "properties": {
          "id": { "$ref": "common.schema.json#/$defs/identifier" },
          "version": { "type": ["integer", "null"], "minimum": 1 },
          "expires_at_unix_ms": { "anyOf": [{ "$ref": "common.schema.json#/$defs/unixMs" }, { "type": "null" }] },
          "refused": { "enum": ["signature", "expired", "rolled_back", "invalid", null] }
        }
      }
    },
    "storage_errors": { "$ref": "#/$defs/count" },
    "clock_jump_s": { "type": ["integer", "null"] }
  }
}
```

  and a `$defs` entry `"count": { "type": "integer", "minimum": 0 }`. If the file has no `$defs`, add one; if `common.schema.json` already has a non-negative integer, use that instead.
  - Run the validator. Expected: `… 0 failures`.

- [ ] **Step 3: Contract and PLAN.**
  - In `contracts-v1.md` under `Heartbeat`, add a paragraph on `health`:
    - optional, within version 1; counts and codes only;
    - what each part means (spec §2), and the bounds;
    - an invalid `health` makes the heartbeat invalid (400), so senders validate it and leave it out rather than send it invalid.
  - Add a paragraph on the rotating queue: when full, the oldest pending findings are dropped and counted in `dropped_total`.
  - Replace "(agent health, planned)" at the rejected-reasons paragraph with "reported in `health.queue.rejected_total`".
  - `PLAN.md`: message-table row 3 gains "health (P12)"; add a section `### P12: Agent health and the rotating queue (user, 2026-09-27)` with boxes (spec/schema checked).

- [ ] **Step 4: Run, commit, PR.** Run the validator (expected 0 failures). Commit "Protocol P12: agent health in heartbeats". Push and open the PR. Merge with the user's approval.

---

## Repository 2: openvibes-agent

### Task 2: core `Health` types

**Files:**
- Create: `crates/openvibes-core/src/health.rs`
- Modify: `crates/openvibes-core/src/{lib.rs,contracts.rs}` (`Heartbeat.health` and its validation), `crates/openvibes-core/tests/protocol_fixtures.rs` (no change needed if `heartbeat` is already mapped), every `Heartbeat { … }` literal (`openvibes-agent/src/service.rs`, `openvibes-transport/tests/platform.rs`; add `health: None`), `protocol` submodule → Task 1, `docs/components/openvibes-core.md`

**Interfaces — Produces:**

```rust
// health.rs (re-exported from lib.rs)
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Health {
    pub queue: QueueHealth,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub last_scan: Option<ScanHealth>,
    #[serde(default)] pub rule_sets: Vec<RuleSetHealth>,
    pub storage_errors: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub clock_jump_s: Option<i64>,
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueHealth {
    pub pending: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub oldest_pending_age_s: Option<u64>,
    pub bytes: u64, pub max_bytes: u64, pub dropped_total: u64,
    #[serde(default)] pub rejected_total: BTreeMap<Identifier, u64>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanHealth {
    pub finished_at_unix_ms: i64, pub interval_s: u64,
    pub rules_evaluated: u64, pub rules_unavailable: u64, pub rules_failed: u64,
    pub collectors: BTreeMap<Identifier, CollectorOutcome>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)] #[serde(rename_all = "snake_case")]
pub enum CollectorOutcome { Ok, PermissionDenied, NotFound, TimedOut, InvalidData, Unsupported, Internal }
impl From<CollectorErrorCode> for CollectorOutcome;
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuleSetHealth {
    pub id: Identifier,
    #[serde(default)] pub version: Option<u64>,
    #[serde(default)] pub expires_at_unix_ms: Option<i64>,
    #[serde(default)] pub refused: Option<BundleRefusal>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)] #[serde(rename_all = "snake_case")]
pub enum BundleRefusal { Signature, Expired, RolledBack, Invalid }
pub const HEALTH_MAX_COLLECTORS: usize = 16;
pub const HEALTH_MAX_RULE_SETS: usize = 64;
pub const HEALTH_MAX_REASONS: usize = 16;
impl Validate for Health;
// contracts.rs: Heartbeat gains
#[serde(default, skip_serializing_if = "Option::is_none")] pub health: Option<Health>,
```

- [ ] **Step 1: Failing tests** (bottom of `health.rs`, which otherwise has only its doc comment and `use` lines):

```rust
#[cfg(test)]
mod tests {
    use crate::{Heartbeat, ResourceLimits, Validate};

    fn fixture(name: &str) -> Result<Heartbeat, String> {
        let text = std::fs::read_to_string(format!(
            "{}/../../protocol/fixtures/v1/heartbeat/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let heartbeat: Heartbeat = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        heartbeat.validate(ResourceLimits::V1).map_err(|e| e.to_string())?;
        Ok(heartbeat)
    }

    #[test]
    fn the_protocol_fixtures_agree() {
        let health = fixture("valid-health.json").unwrap().health.unwrap();
        assert_eq!(health.queue.pending, 12);
        for invalid in [
            "invalid-health-negative-count.json",
            "invalid-health-unknown-outcome.json",
            "invalid-health-too-many-rule-sets.json",
        ] {
            assert!(fixture(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_heartbeat_without_health_is_still_valid() {
        let mut heartbeat = fixture("valid-health.json").unwrap();
        heartbeat.health = None;
        let text = serde_json::to_string(&heartbeat).unwrap();
        assert!(!text.contains("health"));
        assert!(heartbeat.validate(ResourceLimits::V1).is_ok());
    }
}
```

  Run: `cargo test -p openvibes-core health` (worktree `../openvibes-agent-health`, protocol submodule at Task 1's commit). Expected: FAIL to compile (`health` missing).

- [ ] **Step 2: Implement** the types above in `health.rs`, then:

```rust
impl From<crate::CollectorErrorCode> for CollectorOutcome {
    fn from(code: crate::CollectorErrorCode) -> Self {
        use crate::CollectorErrorCode as C;
        match code {
            C::PermissionDenied => Self::PermissionDenied,
            C::NotFound => Self::NotFound,
            C::TimedOut => Self::TimedOut,
            C::InvalidData => Self::InvalidData,
            C::Unsupported => Self::Unsupported,
            C::Internal => Self::Internal,
        }
    }
}

impl Validate for Health {
    fn validate(&self, _limits: ResourceLimits) -> Result<(), ValidationError> {
        let too_many = |field, message| Err(ValidationError::new(field, message));
        if self.queue.rejected_total.len() > HEALTH_MAX_REASONS {
            return too_many("health.queue.rejected_total", "more than 16 reasons");
        }
        if self.rule_sets.len() > HEALTH_MAX_RULE_SETS {
            return too_many("health.rule_sets", "more than 64 rule sets");
        }
        if let Some(scan) = &self.last_scan {
            if scan.collectors.len() > HEALTH_MAX_COLLECTORS {
                return too_many("health.last_scan.collectors", "more than 16 collectors");
            }
            crate::contracts::validate_unix_ms("health.last_scan.finished_at_unix_ms", scan.finished_at_unix_ms)?;
        }
        for set in &self.rule_sets {
            if let Some(expires) = set.expires_at_unix_ms {
                crate::contracts::validate_unix_ms("health.rule_sets.expires_at_unix_ms", expires)?;
            }
            if set.version == Some(0) {
                return too_many("health.rule_sets.version", "versions start at 1");
            }
        }
        Ok(())
    }
}
```

  (Make `validate_unix_ms` `pub(crate)` if it is private. `CollectorErrorCode` variant names must match the file; adjust the `match` if they differ, and rule it.)
  - `contracts.rs`: add the `health` field to `Heartbeat`, and in `impl Validate for Heartbeat` add `if let Some(health) = &self.health { health.validate(limits)?; }`.
  - Add `health: None` to the struct literals listed under Files.

- [ ] **Step 3: Run.** `cargo test -p openvibes-core`. Expected: PASS, protocol fixtures included.

- [ ] **Step 4: Docs, commit.** In `openvibes-core.md`, a "Health (P12)" bullet. Commit "Core: P12 health types".

### Task 3: queue: counters, rotating drop, stats

**Files:**
- Modify: `crates/openvibes-storage/src/{queue.rs,lib.rs}`, `crates/openvibes-storage/tests/queue.rs`, `docs/components/openvibes-storage.md`
- If `queue.rs` passes 500 lines, move the counters and stats into `src/queue_stats.rs`.

**Interfaces — Produces:**

```rust
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QueueStats {
    pub pending: u64,
    pub oldest_enqueued_at_ms: Option<i64>,
    pub bytes: u64,
    pub dropped_total: u64,
    pub rejected_total: std::collections::BTreeMap<String, u64>,
}
impl SqliteQueue { pub fn stats(&self) -> Result<QueueStats, StorageError>; }
// enqueue(&mut self, finding, now) keeps its signature; a full queue now drops the oldest.
```

- [ ] **Step 1: Failing tests.**
  - Replace `byte_bound_applies_backpressure_until_delivery_frees_space` with `a_full_queue_drops_the_oldest`:
    - open with `queue_bytes: 64 * 1024` and 4,000-byte findings, enqueueing `f.0`, `f.1`, … until the first time `stats().dropped_total` becomes non-zero, capped at 200 findings;
    - assert that `enqueue` never returned `Err(StorageError::Full)`;
    - assert that the newest finding is pending and `f.0` is not: deliver one batch and check the IDs it offers;
    - assert that `len() + dropped_total` equals the number enqueued.
  - Then add:

```rust
#[test]
fn dropped_total_survives_restart() {
    let path = path("dropped-restart");
    let small = ResourceLimits { queue_bytes: 64 * 1024, ..ResourceLimits::V1 };
    let big = |n: usize| Finding { message: "x".repeat(4_000), ..finding(&format!("f.{n}")) };
    {
        let mut queue = SqliteQueue::open(&path, small).unwrap();
        for n in 0..60 {
            queue.enqueue(&big(n), 0).unwrap();
        }
        assert!(queue.stats().unwrap().dropped_total > 0);
    }
    let queue = SqliteQueue::open(&path, small).unwrap();
    let stats = queue.stats().unwrap();
    assert!(stats.dropped_total > 0);
    assert_eq!(stats.pending + stats.dropped_total, 60);
}

#[test]
fn rejections_are_counted_durably_by_reason() {
    let path = path("rejected");
    let mut queue = SqliteQueue::open(&path, ResourceLimits::V1).unwrap();
    for name in ["f.a", "f.b", "f.c"] {
        queue.enqueue(&finding(name), 0).unwrap();
    }
    queue
        .deliver(0, |batch| {
            Ok::<_, ()>(DeliveryAcknowledgement {
                accepted_finding_ids: batch.iter().map(|f| f.finding_id.clone()).collect(),
                rejected_findings: vec![
                    openvibes_core::RejectedFinding { finding_id: id("f.a"), reason: id("retention_expired") },
                    openvibes_core::RejectedFinding { finding_id: id("f.b"), reason: id("retention_expired") },
                    openvibes_core::RejectedFinding { finding_id: id("f.zzz"), reason: id("not_in_batch") },
                ],
                ..ack(&[])
            })
        })
        .unwrap();
    drop(queue);
    let stats = SqliteQueue::open(&path, ResourceLimits::V1).unwrap().stats().unwrap();
    assert_eq!(stats.rejected_total.get("retention_expired"), Some(&2));
    assert_eq!(stats.rejected_total.get("not_in_batch"), None, "only findings in the batch count");
}

#[test]
fn rejection_reasons_are_bounded() {
    let mut queue = SqliteQueue::open(&path("reasons"), ResourceLimits::V1).unwrap();
    for n in 0..20 {
        let name = format!("f.{n}");
        queue.enqueue(&finding(&name), 0).unwrap();
        queue
            .deliver(0, |batch| {
                Ok::<_, ()>(DeliveryAcknowledgement {
                    accepted_finding_ids: batch.iter().map(|f| f.finding_id.clone()).collect(),
                    rejected_findings: vec![openvibes_core::RejectedFinding {
                        finding_id: id(&name),
                        reason: id(&format!("reason_{n}")),
                    }],
                    ..ack(&[])
                })
            })
            .unwrap();
    }
    let stats = queue.stats().unwrap();
    assert_eq!(stats.rejected_total.len(), 16, "15 named reasons and `other`");
    assert_eq!(stats.rejected_total.get("other"), Some(&5));
}

#[test]
fn stats_report_pending_age_and_bytes() {
    let mut queue = SqliteQueue::open(&path("stats"), ResourceLimits::V1).unwrap();
    assert_eq!(queue.stats().unwrap().oldest_enqueued_at_ms, None);
    queue.enqueue(&finding("f.1"), 1_000).unwrap();
    queue.enqueue(&finding("f.2"), 5_000).unwrap();
    let stats = queue.stats().unwrap();
    assert_eq!((stats.pending, stats.oldest_enqueued_at_ms), (2, Some(1_000)));
    assert!(stats.bytes > 0);
}
```

  There is no test for "a finding larger than the whole queue". Within V1 a finding is at most a few KiB, against the 256 MiB bound, and SQLite's own schema pages make a queue small enough to test it unrealistic. The code path (delete finds nothing, so return `Full`, and the transaction rolls back) is covered by review, as the spec notes.

  Run: `cargo test -p openvibes-storage --test queue`. Expected: FAIL to compile (`stats` missing).

- [ ] **Step 2: Implement.**
  - `const UPGRADE_V2: &str = "CREATE TABLE counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL) STRICT, WITHOUT ROWID; PRAGMA user_version = 2;";` and `open_database(path, APPLICATION_ID, SCHEMA_V1, &[UPGRADE_V2])`.
  - `enqueue`: replace the single `INSERT … DO NOTHING` with a loop over the insert:
    - on success, break;
    - on `rusqlite::Error::SqliteFailure(e, _)` where `e.code == rusqlite::ErrorCode::DiskFull`, run `DELETE FROM pending WHERE seq = (SELECT min(seq) FROM pending)`. If it deleted 0 rows, return `Err(StorageError::Full)` (the transaction rolls back; nothing was dropped). Otherwise `dropped += 1` and retry;
    - any other error goes through `?`.
    - After the insert, if `dropped > 0`: `INSERT INTO counters VALUES ('dropped', ?1) ON CONFLICT(name) DO UPDATE SET value = value + excluded.value`, then commit.
  - `deliver`: inside the existing transaction, after the loop, when `ack_valid`, for each `rejected_findings` entry whose `finding_id` was in the batch, call `count_rejection(&transaction, reason)`:

```rust
/// Adds one rejection under `rejected:<reason>`; after 15 distinct reasons,
/// new ones count under `rejected:other` (at most 16 keys).
fn count_rejection(transaction: &rusqlite::Transaction<'_>, reason: &str) -> Result<(), StorageError> {
    let key = format!("rejected:{reason}");
    let known: bool = transaction
        .query_row("SELECT 1 FROM counters WHERE name = ?1", [&key], |_| Ok(()))
        .optional()?
        .is_some();
    let reasons: i64 = transaction.query_row(
        "SELECT count(*) FROM counters WHERE name LIKE 'rejected:%' AND name <> 'rejected:other'",
        [],
        |row| row.get(0),
    )?;
    let key = if known || reasons < 15 { key } else { "rejected:other".to_owned() };
    transaction.execute(
        "INSERT INTO counters VALUES (?1, 1) ON CONFLICT(name) DO UPDATE SET value = value + 1",
        [&key],
    )?;
    Ok(())
}
```

  - `stats`:
    - `pending` and `min(enqueued_at_ms)` from `pending`;
    - `bytes` = `(page_count - freelist_count) * page_size` from the pragmas;
    - `dropped_total` from `counters`;
    - `rejected_total` from the `rejected:%` rows, with the prefix stripped.

    Export `QueueStats` from `lib.rs`.
  - Scan code that matched `Err(StorageError::Full)` still compiles; it now happens only for a finding that can never fit.

- [ ] **Step 3: Run.** `cargo test -p openvibes-storage`. Expected: PASS (every queue test, the replaced one included).

- [ ] **Step 4: Docs, commit.** `openvibes-storage.md`: the rotating queue, counters, `stats()`. Commit "Storage: a full queue drops its oldest findings and counts them".

### Task 4: scan: collector and rule-set state

**Files:**
- Modify: `crates/openvibes-agent/src/scan.rs` (tests in its `#[cfg(test)]` module and `tests/scan.rs`)

**Interfaces — Produces:** `ScanReport` gains:
- `pub rules_evaluated: usize`;
- `pub collectors: BTreeMap<String, CollectorOutcome>` (each enabled collector that ran: `Ok`, or its error code);
- `pub rule_sets: Vec<RuleSetHealth>` (every configured set: its version and expiry in use, and `refused` from this scan's errors).

- [ ] **Step 1: Failing tests.** In `tests/scan.rs`, or wherever the existing scan tests build a rule set and bundle file (reuse their helpers), add:
  - `a_scan_reports_collectors_and_rule_sets`: after a scan with one valid bundle file, `report.rule_sets` has that id with `version == Some(<its version>)`, `expires_at_unix_ms == Some(<its expiry>)` and `refused == None`. `report.collectors` has an entry for every enabled collector. `report.rules_evaluated` equals the number of rules that matched or did not.
  - `a_refused_bundle_is_named`: a second rule set whose provisioned file has a broken signature (flip one byte of the signature in the test's copy) reports `refused == Some(BundleRefusal::Signature)`, and `version == None` when nothing was accepted before.

  Also add a unit test for the mapping:

```rust
#[test]
fn load_errors_map_to_refusal_codes() {
    use openvibes_core::BundleRefusal as R;
    use openvibes_rules::LoadError as L;
    assert_eq!(super::refusal(&L::InvalidSignature), R::Signature);
    assert_eq!(super::refusal(&L::UntrustedIssuer), R::Signature);
    assert_eq!(super::refusal(&L::DigestMismatch), R::Signature);
    assert_eq!(super::refusal(&L::Expired), R::Expired);
    assert_eq!(super::refusal(&L::NotYetValid), R::Expired);
    assert_eq!(super::refusal(&L::Rollback), R::RolledBack);
    assert_eq!(super::refusal(&L::VersionConflict), R::RolledBack);
    assert_eq!(super::refusal(&L::InvalidRules), R::Invalid);
}
```

  Run: `cargo test -p openvibes-agent scan`. Expected: FAIL to compile.

- [ ] **Step 2: Implement.**
  - `fn refusal(error: &LoadError) -> BundleRefusal` (`InvalidSignature | UntrustedIssuer | InvalidTrustKey | DigestMismatch` → `Signature`; `Expired | NotYetValid` → `Expired`; `Rollback | VersionConflict` → `RolledBack`; anything else → `Invalid`).
  - In the rule-set loop, build `RuleSetHealth` for each set. Take `version`/`expires_at_unix_ms` from the accepted `VerifiedRuleSet` (`accepted_version().version()`, `expires_at_unix_ms()`), and `refused` from the first `AgentError::Rules(e)` in its errors, through `refusal`. Transport and storage errors are not refusals.
  - For the collectors, record `"processes"`, `"ports"` and `"packages"` (the collector `SOURCE` names) when enabled: `Ok` on success, `CollectorOutcome::from(error.code)` on error.
  - Count `rules_evaluated` for `Match` and `NoMatch`.
  - When `verified` is empty (the early return), `collectors` stays empty and `rule_sets` is still filled.

- [ ] **Step 3: Run.** `cargo test -p openvibes-agent`. Expected: PASS.

- [ ] **Step 4: Commit** "Scan: report collector and rule-set state".

### Task 5: service: `health` in heartbeats

**Files:**
- Create: `crates/openvibes-agent/src/health.rs` (assembly)
- Modify: `crates/openvibes-agent/src/{service.rs,lib.rs}`, `crates/openvibes-agent/tests/service.rs`, `docs/components/openvibes-agent.md`

**Interfaces — Consumes:** Task 2 `Health` etc.; Task 3 `QueueStats`; Task 4 `ScanReport` fields.
**Produces:** `pub(crate) fn assemble(stats: &QueueStats, max_bytes: u64, last_scan: Option<&ScanHealth>, rule_sets: &[RuleSetHealth], storage_errors: u64, clock_jump_ms: Option<i64>, now_unix_ms: i64) -> Option<Health>`. It returns `None` when the result fails `Validate`, so the heartbeat goes without it.

- [ ] **Step 1: Failing tests** (`tests/service.rs`):

```rust
#[test]
fn heartbeats_carry_health() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("health");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![issue(&pki, 10_000_000), Box::new(|_: &Seen| status(204))],
    );
    let config = write_config(&dir, &pki, &url, "");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let heartbeat: serde_json::Value = serde_json::from_slice(
        &seen.try_iter().find(|s| s.path == "/v1/heartbeat").unwrap().decoded_body(),
    )
    .unwrap();
    let health = &heartbeat["health"];
    assert_eq!(health["queue"]["pending"], 0);
    assert_eq!(health["queue"]["max_bytes"], ResourceLimits::V1.queue_bytes);
    assert_eq!(health["storage_errors"], 0);
}
```

  Also:
  - `a_scan_shows_up_in_the_next_heartbeat`: configure a provisioned rule set (reuse the existing test helpers that write a signed bundle, as in `first_tick_enrolls_…` or the scan tests). Assert that `health.last_scan.collectors` lists the enabled collectors and `health.rule_sets[0].version` is set.
  - A unit test in `health.rs`, `an_invalid_health_report_is_left_out`: 70 `RuleSetHealth` entries make `assemble` return `None`. Add the same test at service level if it is cheap: 70 rule sets in the config is too heavy, so the unit test is enough; rule it.

  Run: `cargo test -p openvibes-agent`. Expected: FAIL (no `health` in the heartbeat).

- [ ] **Step 2: Implement.**
  - **`health.rs` `assemble`:**
    - `oldest_pending_age_s` = `(now - oldest) / 1000`, clamped at 0;
    - `clock_jump_s` = `jump_ms / 1000`;
    - `rejected_total` keys become `Identifier`s, skipping any that do not parse;
    - `validate` → `None` on failure.
  - **Service fields:**
    - `last_scan: Option<ScanHealth>` (set in `scan_if_due` from the report: `finished_at_unix_ms = now`, `interval_s = interval_ms / 1000`, the counts, `collectors` converted to `Identifier` keys);
    - `rule_sets: Vec<RuleSetHealth>` (from the report);
    - `storage_errors: u64`, incremented where `scan_if_due` returns `Err(AgentError::Storage(_))` and where `exchange` returns `Err(AgentError::Storage(_))`;
    - `last_clock_jump_ms: Option<i64>` (set in `observe_clock` when a jump is seen).
  - **`tick`:** before `exchange`, compute `health` with `self.queue.stats()` (a stats error counts as a storage error and sends `health: None`), and pass it to `exchange`, which puts it in the `Heartbeat`.
  - **Remove the per-tick `rejected` counting in `exchange`,** now durable in the queue, but keep `TickReport.rejected` for the log line: fill it from the difference of `stats().rejected_total` before and after delivery (a few lines). If that is awkward, keep the closure counting as is and rule it.

- [ ] **Step 3: Run.** `cargo test -p openvibes-agent`. Expected: PASS.

- [ ] **Step 4: Docs, gate, PR.**
  - **Docs:** `openvibes-agent.md` gets health contents, the rotating queue, and "no health = platform before P12 ignores nothing".
  - **Gate:** `testing.md` §4.
  - **Commit:** "Agent: report health in heartbeats (P12)".
  - **PR:** push, then open "Agent P12: health reports and the rotating queue". Merge with the user's approval.

---

## Repository 3: openvibes-platform

### Task 6: store: health columns, write, status

**Files:**
- Create: `migrations/00NN_agent_health.sql` (next free number), `crates/platform-store/src/health.rs`
- Modify: `crates/platform-store/src/{migrate.rs,lib.rs,ingest.rs,agents.rs}`, `crates/openvibes-ingest/src/delivery.rs`, `crates/openvibes-ingest/tests/delivery.rs` (literal gains `health: None`), `crates/platform-store/tests/…` (new `health.rs` test file), `Cargo.toml`/`Cargo.lock` (agent pin → Task 5 head), `protocol` submodule → Task 1, `docs/components/platform-store.md`

**Interfaces — Produces:**

```rust
// health.rs
#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum HealthStatus { Healthy, Degraded, Offline, Unknown }
impl HealthStatus { pub fn as_str(self) -> &'static str; pub fn parse(s: &str) -> Option<Self>; }
pub fn health_status(last_seen_at: Option<DateTime<Utc>>, health_at: Option<DateTime<Utc>>,
    health: Option<&openvibes_core::Health>, previous: Option<&openvibes_core::Health>, now: DateTime<Utc>)
    -> (HealthStatus, Vec<&'static str>);
pub const DELIVERY_STALLED_S: u64 = 3_600; pub const QUEUE_NEARLY_FULL_PERCENT: u64 = 80;
pub const RULE_SET_EXPIRING_DAYS: i64 = 7; pub const CLOCK_JUMP_S: i64 = 300;
// ingest::heartbeat gains `health: Option<&serde_json::Value>`
// agents::AgentInfo gains `health: Option<openvibes_core::Health>`, `health_previous: Option<Health>`, `health_at: Option<DateTime<Utc>>`
```

- [ ] **Step 1: Migration.**

```sql
-- Agent health (protocol P12): the latest report from a heartbeat, the one
-- before it (to tell a total that rose), and when it was written.
ALTER TABLE agents
    ADD COLUMN health jsonb,
    ADD COLUMN health_previous jsonb,
    ADD COLUMN health_at timestamptz;
```

  Bump `SCHEMA_VERSION` and add it to `MIGRATIONS`. The ingest and console roles have table-level grants on `agents` (0001, 0017), so no new grants are needed.

- [ ] **Step 2: Failing tests.**
  - In `health.rs` (unit, no database), these cases (the full list):
    - `offline_after_15_minutes`
    - `unknown_without_a_report`
    - `a_stale_report_is_unknown` (health_at 16 min ago, last_seen now)
    - `healthy_with_a_clean_report`
    - one test per reason:
      - `queue_dropping` (previous dropped 3, now 5);
      - `delivery_stalled` (oldest 3,601 s);
      - `queue_nearly_full` (81%);
      - `scan_overdue` (finished 2 × interval + 1 s ago);
      - `collector_failing`;
      - `rule_set_expiring` (6 days);
      - `rule_set_refused`;
      - `storage_errors` (rose);
      - `clock_jump` (301 s).
    - `no_reason_at_the_boundaries`: exactly 80%, exactly 3,600 s, exactly 7 days, exactly 300 s, and an equal previous total are all Healthy.

    Build `Health` values with a `fn clean(now) -> Health` helper and mutate one field per test.
  - In `crates/openvibes-ingest/tests/delivery.rs`, add `health_is_stored_with_the_heartbeat` and `health_follows_the_heartbeat_throttle`:
    - the first heartbeat with `health` (`pending: 1`) stores it, and `health_previous` is NULL;
    - a second heartbeat 1 minute later (same hostname and capabilities; set `observed_at` but the server uses its own now, so call `platform_store::ingest::heartbeat` directly with `now + 1 min`) does not change it;
    - a third at `now + 6 min` with `pending: 2` moves `pending: 1` into `health_previous`.

    Use the store function directly with a `World` database, as the other store-level tests do.

  Run: `cargo test -p platform-store health; cargo test -p openvibes-ingest --test delivery health`. Expected: FAIL to compile.

- [ ] **Step 3: Implement.**
  - Repin the agent (three `rev`s → Task 5 head) and run `cargo update -p openvibes-core -p openvibes-transport -p openvibes-rules`. Move the protocol submodule to Task 1.
  - `health.rs`: `health_status` as the constraints table says. Offline wins over everything; Unknown next; the reasons are collected in the table's order.
  - `ingest::heartbeat`: add `health: Option<&serde_json::Value>` ($7) to the UPDATE:
    - `health_previous = CASE WHEN $7::jsonb IS NULL THEN health_previous ELSE health END`;
    - `health = COALESCE($7, health)`;
    - `health_at = CASE WHEN $7::jsonb IS NULL THEN health_at ELSE $2 END`.

    The WHERE clause is unchanged, so it follows the throttle.
  - `delivery.rs`: pass `heartbeat.health.as_ref().map(serde_json::to_value).transpose().map_err(|_| ApiError::BadRequest)?.as_ref()`.
  - `agents.rs`:
    - `SELECT` adds `a.health, a.health_previous, a.health_at`;
    - `info` parses the JSON with `serde_json::from_value::<Health>`; a report that does not parse counts as absent (a newer agent's field it does not know is ignored by serde, so this only drops real garbage).

- [ ] **Step 4: Run.** `eval "$(scripts/test-db.sh)"; cargo test -p platform-store -p openvibes-ingest`. Expected: PASS.

- [ ] **Step 5: Docs, commit.** `platform-store.md`: columns, `health_status` and its thresholds. Commit "Store: agent health columns and status".

### Task 7: CLI `agent list --health`, `agent show`

**Files:**
- Modify: `crates/openvibes-admin/src/agent.rs`, `crates/platform-store/src/agents.rs` (`Filter::Health(HealthStatus)`, applied in Rust after the query), `crates/openvibes-admin/tests/agent.rs`, `docs/components/openvibes-admin.md`

- [ ] **Step 1: Failing tests** (`tests/agent.rs`, following its existing style of running the binary against a fresh database):
  - `agent_list_shows_health`: seed three active agents:
    - one with `last_seen_at` 20 minutes ago (offline);
    - one without a report (unknown);
    - one with a report whose `last_scan.collectors.packages` is `permission_denied` (degraded).

    Assert that each line shows `health offline` / `health unknown` / `health degraded (collector_failing)`, and that `agent list --health degraded` prints only the third.
  - `agent_show_prints_the_report`: `agent show` prints the queue line (`queue 12 pending, oldest 340 s, 0 dropped`), the collector outcomes and the reasons.

  Run: `cargo test -p openvibes-admin --test agent health`. Expected: FAIL.

- [ ] **Step 2: Implement.**
  - `--health <healthy|degraded|offline|unknown>`, parsed with `HealthStatus::parse` through a clap `value_parser`. It conflicts with `--revoked` and `--imported`.
  - `line()` appends `  health <status>[ (<reason>, …)]` for active agents.
  - `show` appends:
    - `health <status>`;
    - `reasons …`;
    - `queue <pending> pending, oldest <age> s, <dropped> dropped, rejected <reason>=<n> …`;
    - `last scan <time>, <evaluated> rules (<unavailable> unavailable, <failed> failed)`;
    - `collectors <name>=<outcome> …`;
    - one `rule set <id> version <v> expires <time>[ refused <code>]` line per set;
    - `storage errors <n>`;
    - `health report <time>`.

    Leave out the lines with no data.
  - **Ruling to record:** the flag is `--health`, not the spec's `--status`, because `status` already means active/revoked/imported in this command.

- [ ] **Step 3: Run.** `cargo test -p openvibes-admin`. Expected: PASS.

- [ ] **Step 4: Docs, commit.** `openvibes-admin.md` gets the `agent` section. Commit "CLI: agent health in list and show".

### Task 8: e2e, docs, gate, PR

**Files:**
- Modify: `scripts/systemd-e2e.sh`, `docs/components/openvibes-ingest.md`

- [ ] **Step 1: e2e.** After the P11 step, add the following. Health is written with the 5-minute throttle; the restart changes nothing the throttle watches, so wait up to 6 minutes, or restart ingest first to make its next heartbeat write immediately:

```bash
# P12: the agent reports health; an unreadable package database turns it
# Degraded with collector_failing.
wait_for "the agent reports Healthy (protocol P12)" 420 \
    'runuser -u openvibes-admin -- openvibes-admin agent list | grep -q "health healthy"'
in_c 'chmod 000 /var/lib/rpm/rpmdb.sqlite && systemctl restart openvibes-agent' || fail "hide the RPM database"
wait_for "the agent reports collector_failing" 420 \
    'runuser -u openvibes-admin -- openvibes-admin agent list | grep -q "health degraded (collector_failing"'
in_c 'chmod 644 /var/lib/rpm/rpmdb.sqlite && systemctl restart openvibes-agent' || fail "restore the RPM database"
ok "agent health reaches the platform"
```

  (`wait_for` evaluates in the container; check that the helper's expression runs through `in_c`, as the existing `wait_for` calls do, and quote to match. If waiting 7 minutes is too slow for CI, lower `HEARTBEAT_WRITE_MINUTES` for the e2e only through an ingest config value: rule it, and prefer the longer wait over new config.)

- [ ] **Step 2: Gate.** Rebase on `origin/main` and renumber the migration if #38/#39 merged. Then run `testing.md` §2 in order. The systemd e2e runs in CI: say so in the PR body and watch it.

- [ ] **Step 3: PR.**
  - Commit the e2e and `openvibes-ingest.md` ("heartbeats store health on the write throttle").
  - Push and open "Platform P12: agent health and status". Repin the agent to its merge commit before merging.
  - Merge with the user's approval.
  - Then tick P12 in the protocol's `PLAN.md` (follow-up PR).

### Task 9: console API fields (after #38/#39 merge)

**Files:**
- Modify: `crates/openvibes-console/src/{api.rs,router.rs}` (agent list and detail handlers), `crates/platform-store/src/console_read.rs` (select the three columns), `docs/api/console-v1.openapi.json`, `crates/openvibes-console/web/src/api/generated.ts`, `crates/openvibes-console/tests/…` (agent API test), `docs/components/console-read.md`

- [ ] **Step 1: Failing test.** In the console's agent HTTP test file (where `/api/v1/agents` is tested), seed one degraded agent and assert that the agent list item has `"health": {"status": "degraded", "reasons": ["collector_failing"]}`, and `null` for a revoked agent.
- [ ] **Step 2: Implement.**
  - `api.rs`:
    - `pub struct AgentHealthView { pub status: AgentHealthStatus, pub reasons: Vec<String> }`;
    - `AgentHealthStatus` is `healthy degraded offline unknown`;
    - `AgentView.health: Option<AgentHealthView>`, which is `None` unless the agent is active.

    The router fills it through `platform_store::health::health_status`, and `console_read` selects the columns.
  - Regenerate the OpenAPI snapshot and the client (`testing.md` §2 commands).
  - **Ruling to record:** the spec's `health_status` list filter is not added. Status is computed in Rust from JSON, so filtering it under the console's cursor pagination needs its own design. The CLI filter covers operators meanwhile.
- [ ] **Step 3: Run** `bash scripts/build-console.sh && cargo test -p openvibes-console`. Expected: PASS.
- [ ] **Step 4: Commit, PR.**
  - Commit and open "Console API: agent health" as its own PR, after #38/#39 have merged and this branch is rebased.
  - Hand the UI to Codex in the chat: show `health.status` with the reasons on the agent list and the agent page.
