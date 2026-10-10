# Network Device Alarms, Part 1: Store — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The schema and `platform-store` functions that let a new service store UniFi IPS/IDS events as alarms. Agent alarms keep working exactly as they do now.

**Architecture:** One additive migration (0046) adds a `devices` table and lets `alarms` hold `source = 'device'` rows: `device_id` and `network` filled in, no agent/process. Two new store modules: `devices` (CRUD, counters, the "no events" heads-up) and `device_alarms` (batch insert with collapse, suppressions and reopening, mirroring `alarms::insert_batch`). Console paths that could reach a device row are guarded.

**Tech Stack:** Rust 2024, tokio-postgres 0.7 (`IpAddr` ↔ `inet` is built in), deadpool-postgres, chrono. No new dependencies.

**Spec:** `docs/specs/2026-10-10-network-device-alarms-design.md` (platform #266). Parts 2 (`-2-netlog.md`) and 3 (`-3-admin-packaging.md`) build on this one.

## Global Constraints

- Migrations are append-only. This one is `0046_network_devices.sql` with `SCHEMA_VERSION = 46`. If `main` already has a 0046 when this merges, renumber.
- Additive only: no `UPDATE`/`DELETE`/`DROP COLUMN` (the `needs-backup` test at `crates/platform-store/src/migrate.rs:274` must stay quiet).
- `rule_set_id` for device alarms is `device-unifi`; `rule_id` is `ips.<signature_id>`; both versions are 0.
- Severity names: `critical`, `high`, `medium`, `low`, `info` (existing CHECK).
- Device names are 1–64 characters with no control characters. `kind` is `unifi` only.
- A removed device keeps its row (alarms reference it); only `removed_at IS NULL` devices are active, and the address is unique among those.
- The `openvibes-netlog` role gets exactly what spec §4 lists, plus `SELECT ON schema_version` for `/ready`.
- Tests run against `eval "$(scripts/test-db.sh)"`. Grants are checked with `SET ROLE "openvibes-netlog"`.
- Every file stays under 500 lines. Component docs change in the same change (done in Part 3, Task 12).

## Review Focus

1. **An existing agent alarm row after migration.** Ingest inserts without naming `source`, so it must still pass the new CHECK. Test: ingest-style insert after migrating (Task 1).
2. **The same router IP registered twice.** The second add is refused while the first is active and allowed after a remove. Test in Task 2.
3. **A device alarm whose day has no partition** (netlog running long after `maintenance` last ran). It must be skipped and counted, never fail the whole batch. Test in Task 3.
4. **A console bulk action or case that picks a device alarm ID** (`bulk.rs:456` and `console_cases.rs:361-391` don't join `agents`). It must be refused or ignored, never panic on a NULL `process`. Test in Task 4.
5. **Two suppressions match one device alarm** (`device` and `signature`). The first active one wins and exactly one history row is written. Test in Task 3.

---

### Task 1: Migration 0046

**Files:**
- Create: `migrations/0046_network_devices.sql`
- Modify: `crates/platform-store/src/migrate.rs` (`SCHEMA_VERSION` at :6 → 46; add the tuple after the 0045 entry)
- Test: `crates/platform-store/tests/network_devices_schema.rs`

**Interfaces:**
- Produces: tables and columns used by Tasks 2–4 and Part 2. `devices(id bigint, name, kind, address inet, created_by, created_at, removed_by, removed_at, last_seen, received, alarms, not_cef, unparsed, dropped_other, mismatch bigint, dropped_classes jsonb)`. `alarms.source text`, `alarms.device_id bigint`, `alarms.network jsonb`. `alarm_suppressions.device_id bigint` and scopes `device`, `signature`.

- [ ] **Step 1: Write the failing schema test**

```rust
//! Schema 46: devices and device alarms.

mod common;

use chrono::Utc;
use common::TestDb;

async fn migrated() -> TestDb {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive(), 1)
        .await
        .unwrap();
    db
}

#[tokio::test]
async fn device_alarm_rows_need_device_fields_and_agent_rows_keep_theirs() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let device: i64 = c
        .query_one(
            "INSERT INTO devices (name, kind, address, created_by, created_at)
             VALUES ('UCG Max', 'unifi', '192.168.1.1', 'test', now()) RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let insert = |source: &'static str, agent: Option<&'static str>, dev: Option<i64>, net: bool| {
        let c = &c;
        async move {
            c.execute(
                "INSERT INTO alarms (first_seen_day, source, agent_id, device_id, alarm_id,
                    rule_set_id, rule_set_version, rule_id, rule_version, severity, confidence,
                    message, first_seen, last_seen, count, process, ancestors, network, received_at)
                 VALUES ((now() AT TIME ZONE 'UTC')::date, $1, $2, $3, 'a1', 'device-unifi', 0,
                    'ips.1', 0, 'medium', 80, 'm', now(), now(), 1,
                    CASE WHEN $2::text IS NULL THEN NULL ELSE '{}'::jsonb END,
                    CASE WHEN $2::text IS NULL THEN NULL ELSE '[]'::jsonb END,
                    CASE WHEN $4 THEN '{}'::jsonb ELSE NULL END, now())",
                &[&source, &agent, &dev, &net],
            )
            .await
        }
    };
    assert!(insert("device", None, Some(device), true).await.is_ok());
    assert!(insert("device", None, None, true).await.is_err(), "device row without device_id");
    assert!(insert("device", Some("x"), Some(device), true).await.is_err(), "mixed row");
    assert!(insert("agent", None, Some(device), true).await.is_err(), "agent row without agent");
    db.drop().await;
}

#[tokio::test]
async fn an_active_address_is_unique_and_a_removed_one_frees_it() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let add = "INSERT INTO devices (name, kind, address, created_by, created_at)
               VALUES ('r', 'unifi', '192.168.1.1', 't', now())";
    c.execute(add, &[]).await.unwrap();
    assert!(c.execute(add, &[]).await.is_err());
    c.execute("UPDATE devices SET removed_at = now(), removed_by = 't'", &[])
        .await
        .unwrap();
    c.execute(add, &[]).await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn the_netlog_role_reads_devices_and_writes_only_counters() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    c.execute(
        "INSERT INTO devices (name, kind, address, created_by, created_at)
         VALUES ('r', 'unifi', '192.168.1.1', 't', now())",
        &[],
    )
    .await
    .unwrap();
    c.batch_execute("SET ROLE \"openvibes-netlog\"").await.unwrap();
    c.query("SELECT id, address FROM devices WHERE removed_at IS NULL", &[])
        .await
        .unwrap();
    c.execute("UPDATE devices SET received = received + 1, last_seen = now()", &[])
        .await
        .unwrap();
    assert!(c.execute("UPDATE devices SET name = 'x'", &[]).await.is_err());
    assert!(c.execute("DELETE FROM devices", &[]).await.is_err());
    c.query("SELECT 1 FROM schema_version", &[]).await.unwrap();
    db.drop().await;
}

#[tokio::test]
async fn device_and_signature_suppressions_are_device_rule_sets_only() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let device: i64 = c
        .query_one(
            "INSERT INTO devices (name, kind, address, created_by, created_at)
             VALUES ('r', 'unifi', '192.168.1.1', 't', now()) RETURNING id",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let sup = |set: &'static str, scope: &'static str, dev: Option<i64>| {
        let c = &c;
        async move {
            c.execute(
                "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, device_id, note,
                    created_by, created_at) VALUES ($1, 'ips.1', $2, $3, 'n', 't', now())",
                &[&set, &scope, &dev],
            )
            .await
        }
    };
    assert!(sup("device-unifi", "device", Some(device)).await.is_ok());
    assert!(sup("device-unifi", "signature", None).await.is_ok());
    assert!(sup("device-unifi", "device", None).await.is_err());
    assert!(sup("baseline-alarms", "signature", None).await.is_err());
    db.drop().await;
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `eval "$(scripts/test-db.sh)" && cargo test -p platform-store --test network_devices_schema`
Expected: FAIL, `relation "devices" does not exist`.

- [ ] **Step 3: Write the migration**

`migrations/0046_network_devices.sql`:

```sql
-- OpenVIBES platform schema version 46: network device alarms (UniFi
-- IPS/IDS through openvibes-netlog; spec 2026-10-10-network-device-alarms).
-- Additive only: a new table, nullable columns, relaxed NOT NULLs, wider
-- CHECKs, a role and its grants.

-- A router or firewall that sends events. Identity is its address; a
-- removed device keeps its row because alarms point at it.
CREATE TABLE devices (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    kind text NOT NULL CHECK (kind IN ('unifi')),
    address inet NOT NULL CHECK (masklen(address) = CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    removed_by text,
    removed_at timestamptz,
    last_seen timestamptz,
    received bigint NOT NULL DEFAULT 0,
    alarms bigint NOT NULL DEFAULT 0,
    not_cef bigint NOT NULL DEFAULT 0,
    unparsed bigint NOT NULL DEFAULT 0,
    dropped_other bigint NOT NULL DEFAULT 0,
    mismatch bigint NOT NULL DEFAULT 0,
    -- Dropped events per "class:subCategory" (and "risk:<value>"), ≤ 64 keys.
    dropped_classes jsonb NOT NULL DEFAULT '{}',
    CHECK ((removed_at IS NULL) = (removed_by IS NULL))
);
CREATE UNIQUE INDEX devices_active_address_key ON devices (address) WHERE removed_at IS NULL;

-- Alarms from a device: no agent, no process; the network fields instead.
ALTER TABLE alarms
    ADD COLUMN source text NOT NULL DEFAULT 'agent' CHECK (source IN ('agent', 'device')),
    ADD COLUMN device_id bigint REFERENCES devices,
    ADD COLUMN network jsonb,
    ALTER COLUMN agent_id DROP NOT NULL,
    ALTER COLUMN process DROP NOT NULL,
    ALTER COLUMN ancestors DROP NOT NULL,
    ADD CONSTRAINT alarms_source_fields_check CHECK (
        (source = 'agent' AND agent_id IS NOT NULL AND process IS NOT NULL
            AND ancestors IS NOT NULL AND device_id IS NULL AND network IS NULL)
        OR (source = 'device' AND device_id IS NOT NULL AND network IS NOT NULL
            AND agent_id IS NULL AND process IS NULL AND ancestors IS NULL));
-- (agent_id, alarm_id, first_seen_day) is unique for agents; this is the
-- same for devices and serves netlog's lookup before insert.
CREATE UNIQUE INDEX alarms_device_alarm_key ON alarms (device_id, alarm_id, first_seen_day);

-- `device`: one device; `signature`: the rule on any device. Both only for
-- device rule sets.
ALTER TABLE alarm_suppressions
    ADD COLUMN device_id bigint REFERENCES devices,
    DROP CONSTRAINT alarm_suppressions_scope_check,
    DROP CONSTRAINT alarm_suppressions_check,
    ADD CONSTRAINT alarm_suppressions_scope_check
        CHECK (scope IN ('host', 'program', 'command', 'device', 'signature')),
    ADD CONSTRAINT alarm_suppressions_scope_fields_check CHECK (
        (scope = 'host' AND agent_id IS NOT NULL AND exe IS NULL AND args_sha256 IS NULL AND device_id IS NULL)
        OR (scope = 'program' AND agent_id IS NULL AND exe IS NOT NULL AND args_sha256 IS NULL AND device_id IS NULL)
        OR (scope = 'command' AND agent_id IS NULL AND exe IS NOT NULL AND args_sha256 IS NOT NULL AND device_id IS NULL)
        OR (scope = 'device' AND device_id IS NOT NULL AND agent_id IS NULL AND exe IS NULL AND args_sha256 IS NULL
            AND rule_set_id LIKE 'device-%')
        OR (scope = 'signature' AND device_id IS NULL AND agent_id IS NULL AND exe IS NULL AND args_sha256 IS NULL
            AND rule_set_id LIKE 'device-%'));

DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes-netlog') THEN
        CREATE ROLE "openvibes-netlog" LOGIN;
    END IF;
-- Roles are cluster-wide: parallel migrations (tests) can race on creation.
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
GRANT SELECT ON schema_version TO "openvibes-netlog";
GRANT SELECT ON devices TO "openvibes-netlog";
GRANT UPDATE (last_seen, received, alarms, not_cef, unparsed, dropped_other, mismatch, dropped_classes)
    ON devices TO "openvibes-netlog";
GRANT SELECT, INSERT, UPDATE ON alarms TO "openvibes-netlog";
GRANT INSERT ON alarm_triage_history TO "openvibes-netlog";
GRANT SELECT ON alarm_suppressions TO "openvibes-netlog";
```

The two dropped constraint names are Postgres's automatic names for the unnamed CHECKs in `0029_alarms.sql:11` and `:20-22`. If `DROP CONSTRAINT` fails with "does not exist", run `\d alarm_suppressions` on a migrated test database and use the names it shows.

In `migrate.rs`, set `pub const SCHEMA_VERSION: i32 = 46;` and add
`(46, include_str!("../../../migrations/0046_network_devices.sql")),` after the 45 entry.

- [ ] **Step 4: Run the new test and the existing store suite**

Run: `cargo test -p platform-store`
Expected: PASS. That includes `tests/alarms.rs` (ingest inserts without `source`, which is Review Focus 1) and the migrate tests (numbering, needs-backup scan).

- [ ] **Step 5: Commit**

```bash
git add migrations/0046_network_devices.sql crates/platform-store/src/migrate.rs crates/platform-store/tests/network_devices_schema.rs
git commit -m "Store: schema 46, devices and device alarms"
```

---

### Task 2: `platform_store::devices`

**Files:**
- Create: `crates/platform-store/src/devices.rs`
- Modify: `crates/platform-store/src/lib.rs` (add `pub mod devices;` in alphabetical order, after `pub mod dashboards;`)
- Test: `crates/platform-store/tests/devices.rs`

**Interfaces:**
- Consumes: the `devices` table from Task 1.
- Produces:
  - `pub const KINDS: [&str; 1] = ["unifi"]`
  - `pub const NO_EVENTS: &str`, `pub const SILENT: &str`
  - `pub struct Device { pub id: i64, pub name: String, pub kind: String, pub address: IpAddr, pub created_at: DateTime<Utc>, pub last_seen: Option<DateTime<Utc>>, pub received: i64, pub alarms: i64, pub not_cef: i64, pub unparsed: i64, pub dropped_other: i64, pub mismatch: i64, pub dropped_classes: serde_json::Value }`
  - `pub fn check_name(name: &str) -> Result<(), String>`
  - `pub async fn add(client: &Client, name: &str, kind: &str, address: IpAddr, actor: &str, now: DateTime<Utc>) -> Result<Result<i64, String>, StoreError>`
  - `pub async fn remove(client: &Client, id: i64, actor: &str, now: DateTime<Utc>) -> Result<bool, StoreError>`
  - `pub async fn list(client: &Client) -> Result<Vec<Device>, StoreError>`
  - `pub async fn active(client: &Client) -> Result<Vec<(i64, IpAddr)>, StoreError>`
  - `#[derive(Clone, Debug, Default, PartialEq)] pub struct Counters { pub received: i64, pub alarms: i64, pub not_cef: i64, pub unparsed: i64, pub dropped_other: i64, pub mismatch: i64, pub classes: BTreeMap<String, i64>, pub last_seen: Option<DateTime<Utc>> }`
  - `pub async fn flush(client: &mut Client, id: i64, counters: &Counters) -> Result<(), StoreError>`
  - `pub fn heads_up(device: &Device, now: DateTime<Utc>) -> Option<&'static str>`

- [ ] **Step 1: Write the failing tests**

```rust
//! Devices: add, remove, counters, heads-up.

mod common;

use std::net::IpAddr;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::devices::{self, Counters};

async fn migrated() -> TestDb {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    db
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[tokio::test]
async fn add_refuses_a_second_active_address_and_remove_frees_it() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let now = Utc::now();
    let id = devices::add(&c, "UCG Max", "unifi", ip("192.168.1.1"), "t", now)
        .await
        .unwrap()
        .unwrap();
    let again = devices::add(&c, "Other", "unifi", ip("192.168.1.1"), "t", now)
        .await
        .unwrap();
    assert_eq!(again, Err("a device with address 192.168.1.1 already exists".into()));
    assert!(devices::remove(&c, id, "t", now).await.unwrap());
    assert!(!devices::remove(&c, id, "t", now).await.unwrap(), "already removed");
    assert!(devices::add(&c, "UCG Max", "unifi", ip("192.168.1.1"), "t", now)
        .await
        .unwrap()
        .is_ok());
    assert_eq!(devices::active(&c).await.unwrap().len(), 1);
    db.drop().await;
}

#[tokio::test]
async fn add_checks_name_and_kind() {
    let db = migrated().await;
    let c = db.pool.get().await.unwrap();
    let now = Utc::now();
    for (name, kind) in [("", "unifi"), ("a\u{7}b", "unifi"), (&"x".repeat(65)[..], "unifi"), ("ok", "opnsense")] {
        assert!(devices::add(&c, name, kind, ip("10.0.0.1"), "t", now).await.unwrap().is_err());
    }
    db.drop().await;
}

#[tokio::test]
async fn flush_adds_counters_and_caps_dropped_classes_at_64_keys() {
    let db = migrated().await;
    let mut c = db.pool.get().await.unwrap();
    let now = Utc::now();
    let id = devices::add(&c, "r", "unifi", ip("10.0.0.1"), "t", now).await.unwrap().unwrap();
    let mut counters = Counters { received: 3, not_cef: 2, last_seen: Some(now), ..Counters::default() };
    for n in 0..70 {
        counters.classes.insert(format!("c{n:02}"), 1);
    }
    devices::flush(&mut c, id, &counters).await.unwrap();
    devices::flush(&mut c, id, &counters).await.unwrap();
    let device = devices::list(&c).await.unwrap().remove(0);
    assert_eq!((device.received, device.not_cef), (6, 4));
    let classes = device.dropped_classes.as_object().unwrap();
    assert_eq!(classes.len(), 64);
    assert_eq!(classes["c00"], 2);
    db.drop().await;
}

#[tokio::test]
async fn heads_up_only_after_ten_quiet_minutes() {
    let db = migrated().await;
    let mut c = db.pool.get().await.unwrap();
    let now = Utc::now();
    let id = devices::add(&c, "r", "unifi", ip("10.0.0.1"), "t", now).await.unwrap().unwrap();
    let device = devices::list(&c).await.unwrap().remove(0);
    assert_eq!(devices::heads_up(&device, now + Duration::minutes(9)), None);
    assert_eq!(devices::heads_up(&device, now + Duration::minutes(11)), Some(devices::NO_EVENTS));
    let seen = Counters { received: 1, last_seen: Some(now), ..Counters::default() };
    devices::flush(&mut c, id, &seen).await.unwrap();
    let device = devices::list(&c).await.unwrap().remove(0);
    assert_eq!(devices::heads_up(&device, now + Duration::minutes(11)), None);
    // The router's SIEM setting was changed and it went quiet.
    assert_eq!(devices::heads_up(&device, now + Duration::hours(25)), Some(devices::SILENT));
    db.drop().await;
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p platform-store --test devices`
Expected: FAIL to compile, `unresolved import platform_store::devices`.

- [ ] **Step 3: Implement `devices.rs`**

```rust
//! Network devices that send events to `openvibes-netlog` (spec
//! 2026-10-10-network-device-alarms §4). The address is the identity; a
//! removed device keeps its row because alarms point at it.

use std::{collections::BTreeMap, net::IpAddr};

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Client;

use crate::StoreError;

/// Device kinds netlog understands.
pub const KINDS: [&str; 1] = ["unifi"];
/// Shown for a device with no packet 10 minutes after it was added.
pub const NO_EVENTS: &str = "No events received yet: check the router's SIEM server setting \
    (this host, port 514) and that UDP 514 is open in this host's firewall";
/// Shown when a device that did send has been silent for a day (its SIEM
/// setting changed, or the host's firewall did).
pub const SILENT: &str = "No events for a day: check the router's SIEM server setting \
    (this host, port 514) and that UDP 514 is still open in this host's firewall";
const MAX_CLASSES: usize = 64;

/// One active device and its counters.
#[derive(Clone, Debug)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub address: IpAddr,
    pub created_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub received: i64,
    pub alarms: i64,
    pub not_cef: i64,
    pub unparsed: i64,
    pub dropped_other: i64,
    pub mismatch: i64,
    pub dropped_classes: serde_json::Value,
}

/// 1–64 characters, no control characters.
pub fn check_name(name: &str) -> Result<(), String> {
    let n = name.chars().count();
    if n == 0 || n > 64 || name.chars().any(char::is_control) {
        return Err("a device name is 1 to 64 characters without control characters".into());
    }
    Ok(())
}

/// Adds a device; the inner error is for the person adding it.
pub async fn add(
    client: &Client,
    name: &str,
    kind: &str,
    address: IpAddr,
    actor: &str,
    now: DateTime<Utc>,
) -> Result<Result<i64, String>, StoreError> {
    if let Err(error) = check_name(name) {
        return Ok(Err(error));
    }
    if !KINDS.contains(&kind) {
        return Ok(Err(format!("unknown device kind {kind}; known: {}", KINDS.join(", "))));
    }
    // ponytail: check then insert; two concurrent adds of one address end in
    // the unique index refusing the second as a query error.
    let taken = client
        .query_opt(
            "SELECT 1 FROM devices WHERE address = $1 AND removed_at IS NULL",
            &[&address],
        )
        .await?;
    if taken.is_some() {
        return Ok(Err(format!("a device with address {address} already exists")));
    }
    let id = client
        .query_one(
            "INSERT INTO devices (name, kind, address, created_by, created_at)
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
            &[&name, &kind, &address, &actor, &now],
        )
        .await?
        .get(0);
    Ok(Ok(id))
}

/// Marks a device removed; false if there was no active device `id`.
pub async fn remove(client: &Client, id: i64, actor: &str, now: DateTime<Utc>) -> Result<bool, StoreError> {
    let n = client
        .execute(
            "UPDATE devices SET removed_at = $2, removed_by = $3
             WHERE id = $1 AND removed_at IS NULL",
            &[&id, &now, &actor],
        )
        .await?;
    Ok(n == 1)
}

/// Active devices by name.
pub async fn list(client: &Client) -> Result<Vec<Device>, StoreError> {
    let rows = client
        .query(
            "SELECT id, name, kind, address, created_at, last_seen, received, alarms, not_cef,
                unparsed, dropped_other, mismatch, dropped_classes
             FROM devices WHERE removed_at IS NULL ORDER BY name, id",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| Device {
            id: r.get(0),
            name: r.get(1),
            kind: r.get(2),
            address: r.get(3),
            created_at: r.get(4),
            last_seen: r.get(5),
            received: r.get(6),
            alarms: r.get(7),
            not_cef: r.get(8),
            unparsed: r.get(9),
            dropped_other: r.get(10),
            mismatch: r.get(11),
            dropped_classes: r.get(12),
        })
        .collect())
}

/// `(id, address)` of every active device, for netlog's sender filter.
pub async fn active(client: &Client) -> Result<Vec<(i64, IpAddr)>, StoreError> {
    let rows = client
        .query("SELECT id, address FROM devices WHERE removed_at IS NULL", &[])
        .await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}

/// What netlog counted for one device since its last flush.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Counters {
    pub received: i64,
    pub alarms: i64,
    pub not_cef: i64,
    pub unparsed: i64,
    pub dropped_other: i64,
    pub mismatch: i64,
    /// Dropped events per class key.
    pub classes: BTreeMap<String, i64>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Adds `counters` to device `id`; `dropped_classes` keeps at most 64 keys
/// (existing keys grow, new ones in key order until full).
pub async fn flush(client: &mut Client, id: i64, counters: &Counters) -> Result<(), StoreError> {
    let tx = client.transaction().await?;
    let Some(row) = tx
        .query_opt("SELECT dropped_classes FROM devices WHERE id = $1 FOR UPDATE", &[&id])
        .await?
    else {
        return Ok(());
    };
    let mut classes: serde_json::Map<String, serde_json::Value> = match row.get(0) {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    for (key, n) in &counters.classes {
        let old = classes.get(key).and_then(serde_json::Value::as_i64);
        if old.is_some() || classes.len() < MAX_CLASSES {
            classes.insert(key.clone(), (old.unwrap_or(0) + n).into());
        }
    }
    tx.execute(
        "UPDATE devices SET received = received + $2, alarms = alarms + $3,
            not_cef = not_cef + $4, unparsed = unparsed + $5,
            dropped_other = dropped_other + $6, mismatch = mismatch + $7,
            dropped_classes = $8, last_seen = GREATEST(last_seen, $9)
         WHERE id = $1",
        &[
            &id,
            &counters.received,
            &counters.alarms,
            &counters.not_cef,
            &counters.unparsed,
            &counters.dropped_other,
            &counters.mismatch,
            &serde_json::Value::Object(classes),
            &counters.last_seen,
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// [`NO_EVENTS`] when nothing arrived in the 10 minutes after adding,
/// [`SILENT`] when the last packet is more than a day old. Any datagram
/// counts (plain syslog too), so a gateway with only "Security Detections"
/// ticked may trip SILENT on a quiet day; ponytail: one fixed day, a
/// per-device setting if that proves noisy.
#[must_use]
pub fn heads_up(device: &Device, now: DateTime<Utc>) -> Option<&'static str> {
    match device.last_seen {
        None => (now - device.created_at > Duration::minutes(10)).then_some(NO_EVENTS),
        Some(seen) => (now - seen > Duration::days(1)).then_some(SILENT),
    }
}
```

`GREATEST(NULL, x)` is `x` in Postgres, so the first `last_seen` is set correctly.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p platform-store --test devices && cargo clippy -p platform-store --all-targets -- -D warnings`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/platform-store/src/devices.rs crates/platform-store/src/lib.rs crates/platform-store/tests/devices.rs
git commit -m "Store: devices (add, remove, counters, no-events heads-up)"
```

---

### Task 3: `platform_store::device_alarms`

**Files:**
- Create: `crates/platform-store/src/device_alarms.rs`
- Modify: `crates/platform-store/src/alarms.rs`. Make `history` `pub(crate)` and give it a `by: &str` parameter (pass `INGEST` at its three call sites :262, :331 and any other the compiler names).
- Modify: `crates/platform-store/src/lib.rs` (`pub mod device_alarms;` after `pub mod devices;`)
- Test: `crates/platform-store/tests/device_alarms.rs`

**Interfaces:**
- Consumes: `alarms::history(tx, id, day, from, to, note, now, by)` (crate-private), `crate::partition_days_of`, Task 1 schema.
- Produces:
  - `pub const RULE_SET: &str = "device-unifi"`
  - `pub const NETLOG: &str = "netlog"`
  - `#[derive(Clone, Debug, PartialEq)] pub struct DeviceAlarm { pub device_id: i64, pub alarm_id: String, pub rule_id: String, pub severity: String, pub confidence: i16, pub message: String, pub first_seen: DateTime<Utc>, pub last_seen: DateTime<Utc>, pub count: i64, pub network: serde_json::Value }`
  - `#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)] pub struct DeviceStored { pub stored: u32, pub raised: u32, pub suppressed: u32, pub unstorable: u32 }`
  - `pub async fn insert_batch(client: &mut Client, alarms: &[DeviceAlarm], now: DateTime<Utc>) -> Result<DeviceStored, StoreError>`

- [ ] **Step 1: Write the failing tests**

```rust
//! Device alarms: insert, collapse resend, suppressions, reopen, partitions.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use deadpool_postgres::Client;
use platform_store::device_alarms::{self, DeviceAlarm, DeviceStored};

async fn setup() -> (TestDb, i64) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive() - Duration::days(1), 3)
        .await
        .unwrap();
    let id = platform_store::devices::add(&admin, "r", "unifi", "192.168.1.1".parse().unwrap(), "t", Utc::now())
        .await
        .unwrap()
        .unwrap();
    (db, id)
}

async fn as_netlog(db: &TestDb) -> Client {
    let c = db.pool.get().await.unwrap();
    c.batch_execute("SET ROLE \"openvibes-netlog\"").await.unwrap();
    c
}

fn alarm(device: i64, count: i64) -> DeviceAlarm {
    let now = Utc::now();
    DeviceAlarm {
        device_id: device,
        alarm_id: "2402000/81.181.129.172/1".into(),
        rule_id: "ips.2402000".into(),
        severity: "medium".into(),
        confidence: 80,
        message: "ET DROP Dshield: blocked".into(),
        first_seen: now,
        last_seen: now,
        count,
        network: serde_json::json!({"src": "81.181.129.172", "action": "blocked"}),
    }
}

#[tokio::test]
async fn a_resend_with_a_higher_count_raises_it() {
    let (db, device) = setup().await;
    let mut c = as_netlog(&db).await;
    let now = Utc::now();
    let first = device_alarms::insert_batch(&mut c, &[alarm(device, 1)], now).await.unwrap();
    assert_eq!(first, DeviceStored { stored: 1, ..DeviceStored::default() });
    let mut later = alarm(device, 5);
    later.last_seen = now + Duration::seconds(30);
    let second = device_alarms::insert_batch(&mut c, &[later], now).await.unwrap();
    assert_eq!(second.raised, 1);
    let row = c.query_one("SELECT count, source, state FROM alarms", &[]).await.unwrap();
    assert_eq!((row.get::<_, i64>(0), row.get::<_, String>(1), row.get::<_, String>(2)), (5, "device".into(), "open".into()));
    db.drop().await;
}

#[tokio::test]
async fn a_device_suppression_closes_a_new_alarm_once() {
    let (db, device) = setup().await;
    let admin = db.pool.get().await.unwrap();
    for (scope, dev) in [("device", Some(device)), ("signature", None)] {
        admin
            .execute(
                "INSERT INTO alarm_suppressions (rule_set_id, rule_id, scope, device_id, note, created_by, created_at)
                 VALUES ('device-unifi', 'ips.2402000', $1, $2, 'n', 't', now())",
                &[&scope, &dev],
            )
            .await
            .unwrap();
    }
    let mut c = as_netlog(&db).await;
    let done = device_alarms::insert_batch(&mut c, &[alarm(device, 1)], Utc::now()).await.unwrap();
    assert_eq!((done.stored, done.suppressed), (1, 1));
    let state: String = admin.query_one("SELECT state FROM alarms", &[]).await.unwrap().get(0);
    assert_eq!(state, "false_positive");
    let history: i64 = admin.query_one("SELECT count(*) FROM alarm_triage_history", &[]).await.unwrap().get(0);
    assert_eq!(history, 1);
    db.drop().await;
}

#[tokio::test]
async fn a_recurrence_reopens_a_mitigated_alarm() {
    let (db, device) = setup().await;
    let admin = db.pool.get().await.unwrap();
    let mut c = as_netlog(&db).await;
    device_alarms::insert_batch(&mut c, &[alarm(device, 1)], Utc::now()).await.unwrap();
    admin.execute("UPDATE alarms SET state = 'mitigated', note = 'fixed'", &[]).await.unwrap();
    device_alarms::insert_batch(&mut c, &[alarm(device, 2)], Utc::now()).await.unwrap();
    let state: String = admin.query_one("SELECT state FROM alarms", &[]).await.unwrap().get(0);
    assert_eq!(state, "open");
    db.drop().await;
}

#[tokio::test]
async fn a_day_without_a_partition_is_skipped_not_fatal() {
    let (db, device) = setup().await;
    let mut c = as_netlog(&db).await;
    let mut old = alarm(device, 1);
    old.first_seen = Utc::now() - Duration::days(30);
    old.alarm_id = "old".into();
    let done = device_alarms::insert_batch(&mut c, &[old, alarm(device, 1)], Utc::now()).await.unwrap();
    assert_eq!((done.stored, done.unstorable), (1, 1));
    db.drop().await;
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p platform-store --test device_alarms`
Expected: FAIL to compile, `unresolved import platform_store::device_alarms`.

- [ ] **Step 3: Change `alarms::history`**

In `crates/platform-store/src/alarms.rs`, change the signature to

```rust
pub(crate) async fn history(
    transaction: &deadpool_postgres::Transaction<'_>,
    alarm_row_id: i64,
    day: NaiveDate,
    from: Option<&str>,
    to: &str,
    note: &str,
    now: DateTime<Utc>,
    by: &str,
) -> Result<(), StoreError> {
```

and bind `&by` in place of `&INGEST`. Add `INGEST` as the last argument at every existing call (the compiler lists them). If clippy flags `too_many_arguments`, add `#[allow(clippy::too_many_arguments, reason = "one history row's columns")]`.

- [ ] **Step 4: Implement `device_alarms.rs`**

```rust
//! Alarms from network devices (spec 2026-10-10-network-device-alarms §3–4),
//! stored by `openvibes-netlog`. Same rules as agent alarms: a resend
//! raises `count` and `last_seen`, a recurrence reopens a mitigated alarm or
//! an expired accepted risk, and a suppression closes a new alarm as a
//! false positive with one history row.

use chrono::{DateTime, NaiveDate, Utc};
use deadpool_postgres::Client;

use crate::{StoreError, alarms::history};

/// The rule set every UniFi alarm carries.
pub const RULE_SET: &str = "device-unifi";
/// Who netlog writes into triage columns and history.
pub const NETLOG: &str = "netlog";

/// One collapsed device alarm, validated by netlog.
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceAlarm {
    pub device_id: i64,
    /// Netlog's id, unique per device.
    pub alarm_id: String,
    /// `ips.<signature_id>`.
    pub rule_id: String,
    pub severity: String,
    pub confidence: i16,
    pub message: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Total events collapsed into it so far.
    pub count: i64,
    pub network: serde_json::Value,
}

/// What one batch did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceStored {
    pub stored: u32,
    pub raised: u32,
    pub suppressed: u32,
    /// Skipped: no `alarms` partition for its first day.
    pub unstorable: u32,
}

/// Stores `alarms` in one transaction.
pub async fn insert_batch(
    client: &mut Client,
    alarms: &[DeviceAlarm],
    now: DateTime<Utc>,
) -> Result<DeviceStored, StoreError> {
    let partitions = crate::partition_days_of(client, "alarms").await?;
    let tx = client.transaction().await?;
    let suppressions: Vec<(i64, String, Option<i64>)> = tx
        .query(
            "SELECT id, rule_id, device_id FROM alarm_suppressions
             WHERE removed_at IS NULL AND rule_set_id = $1 AND scope IN ('device', 'signature')
             ORDER BY id",
            &[&RULE_SET],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2)))
        .collect();
    let mut done = DeviceStored::default();
    for alarm in alarms {
        let day = alarm.first_seen.date_naive();
        if !partitions.contains(&day) {
            done.unstorable += 1;
            continue;
        }
        let known = tx
            .query_opt(
                "SELECT id, first_seen_day, count, last_seen, state,
                    state = 'accepted_risk' AND accepted_until <= $3
                 FROM alarms WHERE device_id = $1 AND alarm_id = $2 LIMIT 1",
                &[&alarm.device_id, &alarm.alarm_id, &now],
            )
            .await?;
        if let Some(known) = known {
            let (id, day, count, last_seen, state, expired): (i64, NaiveDate, i64, DateTime<Utc>, String, bool) =
                (known.get(0), known.get(1), known.get(2), known.get(3), known.get(4), known.get(5));
            if alarm.count <= count && alarm.last_seen <= last_seen {
                continue;
            }
            tx.execute(
                "UPDATE alarms SET count = GREATEST(count, $3), last_seen = GREATEST(last_seen, $4),
                    network = CASE WHEN $4 > last_seen THEN $5 ELSE network END
                 WHERE id = $1 AND first_seen_day = $2",
                &[&id, &day, &alarm.count, &alarm.last_seen, &alarm.network],
            )
            .await?;
            if alarm.count > count && (state == "mitigated" || expired) {
                tx.execute(
                    "UPDATE alarms SET state = 'open', accepted_until = NULL,
                        triage_version = triage_version + 1,
                        triage_updated_at = $3, triage_updated_by = $4
                     WHERE id = $1 AND first_seen_day = $2",
                    &[&id, &day, &now, &NETLOG],
                )
                .await?;
                history(&tx, id, day, Some(state.as_str()), "open", "recurred", now, NETLOG).await?;
            }
            done.raised += 1;
            continue;
        }
        let suppression = suppressions
            .iter()
            .find(|(_, rule, device)| *rule == alarm.rule_id && device.is_none_or(|d| d == alarm.device_id))
            .map(|(id, ..)| *id);
        let (state, note) = match suppression {
            Some(id) => ("false_positive", Some(format!("suppressed by #{id}"))),
            None => ("open", None),
        };
        let triage_at = suppression.map(|_| now);
        let triage_by = suppression.map(|_| NETLOG);
        let id: i64 = tx
            .query_one(
                "INSERT INTO alarms (first_seen_day, source, device_id, alarm_id, rule_set_id,
                    rule_set_version, rule_id, rule_version, severity, confidence, message,
                    first_seen, last_seen, count, network, received_at, suppressed_by, state,
                    note, triage_updated_at, triage_updated_by)
                 VALUES ($1, 'device', $2, $3, $4, 0, $5, 0, $6, $7, $8, $9, $10, $11, $12,
                    $13, $14, $15, $16, $17, $18)
                 RETURNING id",
                &[
                    &day,
                    &alarm.device_id,
                    &alarm.alarm_id,
                    &RULE_SET,
                    &alarm.rule_id,
                    &alarm.severity,
                    &alarm.confidence,
                    &alarm.message,
                    &alarm.first_seen,
                    &alarm.last_seen,
                    &alarm.count,
                    &alarm.network,
                    &now,
                    &suppression,
                    &state,
                    &note,
                    &triage_at,
                    &triage_by,
                ],
            )
            .await?
            .get(0);
        done.stored += 1;
        if let Some(note) = &note {
            history(&tx, id, day, None, state, note, now, NETLOG).await?;
            done.suppressed += 1;
        }
    }
    tx.commit().await?;
    Ok(done)
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p platform-store && cargo clippy -p platform-store --all-targets -- -D warnings`
Expected: PASS. `tests/alarms.rs` still passes after the `history` change.

- [ ] **Step 6: Commit**

```bash
git add crates/platform-store/src/device_alarms.rs crates/platform-store/src/alarms.rs crates/platform-store/src/lib.rs crates/platform-store/tests/device_alarms.rs
git commit -m "Store: device alarms (collapse, suppressions, reopen, partitions)"
```

---

### Task 4: Keep device alarms out of the console until the mockups land

Spec §6 says console reads see `source = 'agent'` only. Every read that inner-joins `agents` already drops device rows (`agent_id` is NULL). Two paths don't, and this task guards those.

**Files:**
- Modify: `crates/openvibes-console/src/bulk.rs:456`. Add `AND source = 'agent'` to `SELECT DISTINCT ON (rule_set_id, rule_id, process->>'exe') id FROM alarms WHERE id = ANY($1)`.
- Modify: `crates/platform-store/src/console_cases.rs:361`, `:377`, `:391`. Add `AND al.source = 'agent'` to each join condition `al.id = i.ref::bigint`, so a device alarm row shows as gone.
- Modify: `crates/platform-store/src/history.rs:40` (`HOST_COUNTS_SQL`). Add `AND source = 'agent'` to `WHERE state = 'open'`. NULL groups are dropped today, so this only states the intent.
- Test: `crates/platform-store/tests/device_alarms.rs` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/device_alarms.rs`:

```rust
#[tokio::test]
async fn console_alarm_reads_do_not_see_device_alarms() {
    let (db, device) = setup().await;
    let mut c = as_netlog(&db).await;
    device_alarms::insert_batch(&mut c, &[alarm(device, 1)], Utc::now()).await.unwrap();
    let admin = db.pool.get().await.unwrap();
    let id: i64 = admin.query_one("SELECT id FROM alarms", &[]).await.unwrap().get(0);
    // The console's alarm list and detail (inner join on agents).
    use platform_store::{console_alarms, console_read::AgentScope};
    let filters = console_alarms::AlarmFilters { suppressed: true, ..Default::default() };
    let page = console_alarms::list(&admin, &AgentScope::Global, &filters, None, 50)
        .await
        .unwrap();
    assert!(page.is_empty());
    assert!(console_alarms::detail(&admin, &AgentScope::Global, id).await.unwrap().is_none());
    db.drop().await;
}
```

- [ ] **Step 2: Run it**

Run: `cargo test -p platform-store --test device_alarms console_alarm_reads`
Expected: PASS already for list/detail (inner joins). That's the regression guard. Then apply the three edits above and run the console's own tests:

Run: `cargo test -p platform-store -p openvibes-console`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/openvibes-console/src/bulk.rs crates/platform-store/src/console_cases.rs crates/platform-store/src/history.rs crates/platform-store/tests/device_alarms.rs
git commit -m "Console: device alarms stay out of alarm reads until their screens exist"
```

`openvibes-console` is Codex's crate (`AGENTS.md`, parallel work). Keep this edit to the one-line filter in `bulk.rs` and mention it in the PR so Codex sees it.
