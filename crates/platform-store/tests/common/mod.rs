//! A fresh, uniquely named database per test, dropped afterwards.

use std::hash::{BuildHasher, Hasher};

use deadpool_postgres::Pool;

pub struct TestDb {
    pub pool: Pool,
    admin_url: String,
    name: String,
}

fn base_url() -> String {
    std::env::var("OPENVIBES_TEST_DATABASE_URL")
        .expect("set OPENVIBES_TEST_DATABASE_URL, see scripts/test-db.sh")
}

/// `url` with its database name replaced by `name`.
fn with_database(url: &str, name: &str) -> String {
    let (head, query) = url
        .split_once('?')
        .map_or((url, None), |(h, q)| (h, Some(q)));
    let head = &head[..head.rfind('/').expect("database URL has a path")];
    match query {
        Some(query) => format!("{head}/{name}?{query}"),
        None => format!("{head}/{name}"),
    }
}

impl TestDb {
    /// This test database's URL.
    #[allow(dead_code, reason = "used by some test binaries only")]
    pub fn url(&self) -> String {
        with_database(&self.admin_url, &self.name)
    }

    pub async fn create() -> Self {
        let admin_url = base_url();
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_test_{:016x}", hasher.finish());
        let admin = platform_store::connect(&admin_url).await.unwrap();
        let client = admin.get().await.unwrap();
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let pool = platform_store::connect(&with_database(&admin_url, &name))
            .await
            .unwrap();
        Self {
            pool,
            admin_url,
            name,
        }
    }

    pub async fn drop(self) {
        self.pool.close();
        let admin = platform_store::connect(&self.admin_url).await.unwrap();
        let client = admin.get().await.unwrap();
        let drop_client = client;
        // DROP grows with partitions; no statement timeout for it.
        drop_client
            .batch_execute("SET statement_timeout = 0")
            .await
            .unwrap();
        drop_client
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}

/// A database with migrations 1..=VERSION applied from the files.
#[allow(dead_code, reason = "used by some test binaries only")]
pub async fn at_version(db: &TestDb, version: i32) -> deadpool_postgres::Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("CREATE TABLE schema_version (version integer NOT NULL)")
        .await
        .unwrap();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    for file in files.iter().take(version as usize) {
        client
            .batch_execute(&std::fs::read_to_string(file).unwrap())
            .await
            .unwrap();
    }
    client
        .execute("INSERT INTO schema_version VALUES ($1)", &[&version])
        .await
        .unwrap();
    client
}

/// One case with one item of `kind`, owned by user ...0001 (which must exist).
#[allow(dead_code, reason = "used by some test binaries only")]
pub async fn insert_case_with_item(
    client: &deadpool_postgres::Client,
    kind: &str,
    reference: &str,
) {
    client
        .batch_execute(&format!(
            "INSERT INTO cases (case_id, title, status, severity, opened_by_user_id, created_at, updated_at)
             VALUES ('00000000-0000-0000-0000-0000000000c1', 'T', 'open', 'high',
                     '00000000-0000-0000-0000-000000000001', now(), now());
             INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, added_by_user_id, added_at)
             VALUES ('00000000-0000-0000-0000-0000000000e1', '00000000-0000-0000-0000-0000000000c1',
                     '{kind}', '{reference}', 'agent-1', '00000000-0000-0000-0000-000000000001', now());"
        ))
        .await
        .unwrap();
}

/// A migrated database with alarm partitions from yesterday to tomorrow, so
/// a test spanning UTC midnight still finds today's partition.
#[allow(dead_code, reason = "used by some test binaries only")]
pub async fn migrated() -> (TestDb, deadpool_postgres::Client) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let yesterday = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
    platform_store::ensure_partitions(&client, yesterday, 2)
        .await
        .unwrap();
    (db, client)
}

/// An active agent last seen at 2026-10-07T02:59:00Z; `agent_id` must match
/// `agent.<36 hex/dash chars>`.
#[allow(dead_code, reason = "used by some test binaries only")]
pub async fn seed_agent(client: &deadpool_postgres::Client, agent_id: &str) {
    client
        .execute(
            "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at)
             VALUES ($1, 'active', '2026-10-01T00:00:00Z', '2026-10-07T02:59:00Z')",
            &[&agent_id],
        )
        .await
        .unwrap();
}

/// One alarm first seen now, in `state`.
#[allow(dead_code, reason = "used by some test binaries only")]
pub async fn seed_alarm(
    client: &deadpool_postgres::Client,
    agent_id: &str,
    severity: &str,
    state: &str,
) {
    client
        .execute(
            "INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version,
                                 rule_id, rule_version, severity, confidence, message, first_seen,
                                 last_seen, count, process, ancestors, received_at, state, note)
             VALUES ((now() AT TIME ZONE 'UTC')::date, $1, md5(random()::text), 'rs', 1, 'r', 1, $2,
                     50, 'm', now(), now(), 1, '{}', '[]', now(), $3, 'n')",
            &[&agent_id, &severity, &state],
        )
        .await
        .unwrap();
}

/// A host's stored vulnerability counts (no_fix, unrated and reboot zero).
#[allow(dead_code, reason = "used by some test binaries only")]
pub async fn seed_host_vuln_counts(
    client: &deadpool_postgres::Client,
    agent_id: &str,
    critical: i32,
    important: i32,
    moderate: i32,
    low: i32,
) {
    client
        .execute(
            "INSERT INTO host_vulnerability_counts
                 (agent_id, no_fix, critical, important, moderate, low, unrated, reboot, counted_at)
             VALUES ($1, 0, $2, $3, $4, $5, 0, 0, now())",
            &[&agent_id, &critical, &important, &moderate, &low],
        )
        .await
        .unwrap();
}

/// One current compliance finding of `severity`.
#[allow(dead_code, reason = "used by some test binaries only")]
pub async fn seed_current_finding(
    client: &deadpool_postgres::Client,
    agent_id: &str,
    severity: &str,
) {
    client
        .execute(
            "INSERT INTO current_findings (agent_id, rule_id, last_finding_id, rule_version,
                                           severity, first_observed_at, last_observed_at,
                                           last_observed_day, scan_id, confidence, message, evidence,
                                           received_at, origin, authenticated)
             VALUES ($1, 'rule-1', 'f-1', 1, $2, now(), now(), (now() AT TIME ZONE 'UTC')::date,
                     's', 50, 'm', '{}', now(), 'online', false)",
            &[&agent_id, &severity],
        )
        .await
        .unwrap();
}
