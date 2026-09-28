//! Finding changes (protocol P13), run as the `openvibes-ingest` role.

mod common;

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, NaiveDate, Utc};
use common::TestDb;
use openvibes_core::{
    Confidence, EndedMatch, Finding, FindingChanges, Identifier, SchemaVersion, Severity,
    TransientMatch, hex, match_digest,
};
use platform_store::{
    Client,
    finding_changes::{self, Outcome, Rows},
    ingest::{self, Enrolled, IssuedCert},
    tokens::{self, NewToken},
    wire,
};

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

async fn setup() -> (TestDb, String) {
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    platform_store::ensure_partitions(&admin, Utc::now().date_naive() - Duration::days(2), 9)
        .await
        .unwrap();
    let token = tokens::create(
        &admin,
        &NewToken {
            token_sha256: [1; 32],
            label: None,
            created_by: "test".into(),
            expires_at: Utc::now() + Duration::days(1),
            max_uses: 1,
        },
    )
    .await
    .unwrap();
    let mut client = as_ingest(&db).await;
    let Enrolled::New(identity) =
        ingest::enroll(&mut client, &token, [9; 32], Utc::now(), |_: &str| {
            let now = Utc::now();
            Ok(IssuedCert {
                serial: [0x41; 16],
                spki_sha256: [9; 32],
                not_before: now,
                not_after: now + Duration::days(30),
                chain_pem: vec!["LEAF".into()],
            })
        })
        .await
        .unwrap()
    else {
        panic!("expected a new identity");
    };
    (db, identity.agent_id)
}

async fn as_ingest(db: &TestDb) -> Client {
    let client = db.pool.get().await.unwrap();
    client
        .batch_execute("SET ROLE \"openvibes-ingest\"")
        .await
        .unwrap();
    client
}

fn finding(rule: &str, version: u64, at: DateTime<Utc>) -> Finding {
    Finding {
        schema_version: SchemaVersion::V1,
        finding_id: id(&format!(
            "finding.{rule}.{version}.{}",
            at.timestamp_millis()
        )),
        scan_id: id("scan.1"),
        rule_set_id: Some(id("base")),
        rule_id: id(rule),
        rule_version: version,
        observed_at_unix_ms: at.timestamp_millis(),
        severity: Severity::High,
        confidence: Confidence::new(100).unwrap(),
        message: format!("{rule} matched"),
        evidence: vec![id("port.tcp.exposed")],
    }
}

async fn partitions(client: &Client) -> BTreeSet<NaiveDate> {
    platform_store::partition_days(client).await.unwrap()
}

/// The document's rows as the ingest handler prepares them.
async fn rows(client: &Client, changes: &FindingChanges) -> Rows {
    let days = partitions(client).await;
    let now = Utc::now();
    let row = |f: &Finding| {
        wire::finding(f, now - Duration::days(90), now + Duration::hours(1), &days).unwrap()
    };
    Rows {
        started: changes.started.iter().map(row).collect(),
        changed: changes.changed.iter().map(row).collect(),
        transient: changes
            .transient
            .iter()
            .map(|t| {
                (
                    row(&t.finding),
                    DateTime::from_timestamp_millis(t.ended_at_unix_ms).unwrap(),
                )
            })
            .collect(),
    }
}

fn digest(findings: &[Finding]) -> String {
    hex(&match_digest(findings))
}

fn doc(agent: &str, base: &str, open: &[Finding], replace: bool) -> FindingChanges {
    FindingChanges {
        schema_version: SchemaVersion::V1,
        agent_id: id(agent),
        base_sha256: base.to_owned(),
        sha256: digest(open),
        replace,
        scanned_at_unix_ms: Utc::now().timestamp_millis(),
        started: Vec::new(),
        changed: Vec::new(),
        ended: Vec::new(),
        transient: Vec::new(),
        transient_dropped: 0,
    }
}

async fn apply(client: &mut Client, agent: &str, changes: &FindingChanges) -> Outcome {
    let rows = rows(client, changes).await;
    finding_changes::apply(client, agent, changes, &rows, Utc::now())
        .await
        .unwrap()
}

/// (rule, ended, approximate) for each P13 row of the agent.
async fn state(client: &Client, agent: &str) -> Vec<(String, bool, bool)> {
    client
        .query(
            "SELECT rule_id, ended_at IS NOT NULL, end_approximate FROM current_findings
             WHERE agent_id = $1 AND source = 'changes' ORDER BY rule_id",
            &[&agent],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

async fn history(client: &Client, agent: &str) -> i64 {
    client
        .query_one(
            "SELECT count(*) FROM findings WHERE agent_id = $1",
            &[&agent],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn replace_then_diff_then_ended() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let (a, b, c) = (
        finding("a", 1, now),
        finding("b", 1, now),
        finding("c", 1, now),
    );
    let mut first = doc(&agent, &digest(&[]), &[a.clone(), b.clone()], true);
    first.started = vec![a.clone(), b.clone()];
    assert_eq!(apply(&mut client, &agent, &first).await, Outcome::Stored);
    assert_eq!(
        state(&client, &agent).await,
        [("a".into(), false, false), ("b".into(), false, false)]
    );
    let mut second = doc(&agent, &first.sha256, &[a.clone(), c.clone()], false);
    second.started = vec![c.clone()];
    second.ended = vec![EndedMatch {
        rule_set_id: id("base"),
        rule_id: id("b"),
        ended_at_unix_ms: now.timestamp_millis(),
    }];
    assert_eq!(apply(&mut client, &agent, &second).await, Outcome::Stored);
    assert_eq!(
        state(&client, &agent).await,
        [
            ("a".into(), false, false),
            ("b".into(), true, false),
            ("c".into(), false, false)
        ]
    );
    assert_eq!(history(&client, &agent).await, 3);
    db.drop().await;
}

#[tokio::test]
async fn wrong_base_or_result_or_entries_is_resync_and_stores_nothing() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let a = finding("a", 1, now);
    let mut first = doc(&agent, &digest(&[]), std::slice::from_ref(&a), true);
    first.started = vec![a.clone()];
    assert_eq!(apply(&mut client, &agent, &first).await, Outcome::Stored);
    let before = (state(&client, &agent).await, history(&client, &agent).await);
    let b = finding("b", 1, now);

    let mut wrong_base = doc(&agent, &digest(&[]), &[a.clone(), b.clone()], false);
    wrong_base.started = vec![b.clone()];
    assert_eq!(
        apply(&mut client, &agent, &wrong_base).await,
        Outcome::Resync
    );

    let mut wrong_result = doc(&agent, &first.sha256, std::slice::from_ref(&b), false);
    wrong_result.started = vec![b.clone()];
    assert_eq!(
        apply(&mut client, &agent, &wrong_result).await,
        Outcome::Resync
    );

    let mut started_open = doc(&agent, &first.sha256, std::slice::from_ref(&a), false);
    started_open.started = vec![a.clone()];
    assert_eq!(
        apply(&mut client, &agent, &started_open).await,
        Outcome::Resync
    );

    let mut ended_missing = doc(&agent, &first.sha256, std::slice::from_ref(&a), false);
    ended_missing.ended = vec![EndedMatch {
        rule_set_id: id("base"),
        rule_id: id("zz"),
        ended_at_unix_ms: now.timestamp_millis(),
    }];
    assert_eq!(
        apply(&mut client, &agent, &ended_missing).await,
        Outcome::Resync
    );

    assert_eq!(
        (state(&client, &agent).await, history(&client, &agent).await),
        before
    );
    db.drop().await;
}

#[tokio::test]
async fn replace_with_an_empty_set_ends_everything_approximately() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let a = finding("a", 1, now);
    let mut first = doc(&agent, &digest(&[]), std::slice::from_ref(&a), true);
    first.started = vec![a];
    apply(&mut client, &agent, &first).await;
    let empty = doc(&agent, &first.sha256, &[], true);
    assert_eq!(apply(&mut client, &agent, &empty).await, Outcome::Stored);
    assert_eq!(state(&client, &agent).await, [("a".into(), true, true)]);
    let stored: Vec<u8> = client
        .query_one(
            "SELECT match_sha256 FROM agents WHERE agent_id = $1",
            &[&agent],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        hex(&stored.try_into().unwrap()),
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
    );
    db.drop().await;
}

#[tokio::test]
async fn a_transient_is_history_and_an_ended_row_and_is_stored_once() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let mut first = doc(&agent, &digest(&[]), &[], true);
    first.transient = vec![TransientMatch {
        finding: finding("t", 1, now - Duration::minutes(5)),
        ended_at_unix_ms: now.timestamp_millis(),
    }];
    first.transient_dropped = 2;
    assert_eq!(apply(&mut client, &agent, &first).await, Outcome::Stored);
    // A lost 2xx: the same replace again (tester).
    assert_eq!(apply(&mut client, &agent, &first).await, Outcome::Stored);
    assert_eq!(state(&client, &agent).await, [("t".into(), true, false)]);
    assert_eq!(history(&client, &agent).await, 1);
    db.drop().await;
}

#[tokio::test]
async fn a_resent_replace_is_not_an_error() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let a = finding("a", 1, Utc::now());
    let mut first = doc(&agent, &digest(&[]), std::slice::from_ref(&a), true);
    first.started = vec![a];
    assert_eq!(apply(&mut client, &agent, &first).await, Outcome::Stored);
    assert_eq!(apply(&mut client, &agent, &first).await, Outcome::Stored);
    assert_eq!(history(&client, &agent).await, 1);
    db.drop().await;
}

#[tokio::test]
async fn concurrent_change_sets_serialise() {
    let (db, agent) = setup().await;
    let mut one = as_ingest(&db).await;
    let mut two = as_ingest(&db).await;
    let now = Utc::now();
    let a = finding("a", 1, now);
    let mut first = doc(&agent, &digest(&[]), std::slice::from_ref(&a), true);
    first.started = vec![a.clone()];
    apply(&mut one, &agent, &first).await;
    let (b, c) = (finding("b", 1, now), finding("c", 1, now));
    let mut with_b = doc(&agent, &first.sha256, &[a.clone(), b.clone()], false);
    with_b.started = vec![b];
    let mut with_c = doc(&agent, &first.sha256, &[a.clone(), c.clone()], false);
    with_c.started = vec![c];
    let (rows_b, rows_c) = (rows(&one, &with_b).await, rows(&two, &with_c).await);
    let (x, y) = tokio::join!(
        finding_changes::apply(&mut one, &agent, &with_b, &rows_b, now),
        finding_changes::apply(&mut two, &agent, &with_c, &rows_c, now),
    );
    let mut outcomes = [x.unwrap(), y.unwrap()];
    outcomes.sort_by_key(|o| *o == Outcome::Resync);
    assert_eq!(outcomes, [Outcome::Stored, Outcome::Resync]);
    db.drop().await;
}

async fn last_observed(client: &Client, agent: &str, rule: &str) -> DateTime<Utc> {
    client
        .query_one(
            "SELECT last_observed_at FROM current_findings WHERE agent_id = $1 AND rule_id = $2",
            &[&agent, &rule],
        )
        .await
        .unwrap()
        .get(0)
}

/// Every row of the agent last observed `by` ago.
async fn age(client: &Client, agent: &str, by: Duration) {
    client
        .execute(
            "UPDATE current_findings SET last_observed_at = $2 WHERE agent_id = $1",
            &[&agent, &(Utc::now() - by)],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn an_agreeing_heartbeat_keeps_open_matches_current_at_most_hourly() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let (a, b) = (finding("a", 1, now), finding("b", 1, now));
    let mut first = doc(&agent, &digest(&[]), &[a.clone(), b.clone()], true);
    first.started = vec![a.clone(), b.clone()];
    apply(&mut client, &agent, &first).await;
    let mut second = doc(&agent, &first.sha256, std::slice::from_ref(&a), false);
    second.ended = vec![EndedMatch {
        rule_set_id: id("base"),
        rule_id: id("b"),
        ended_at_unix_ms: now.timestamp_millis(),
    }];
    apply(&mut client, &agent, &second).await;
    let digest_now = digest_from_hex(&second.sha256);

    // Within the hour: nothing written.
    let before = last_observed(&client, &agent, "a").await;
    assert!(
        !finding_changes::heartbeat(&mut client, &agent, digest_now, None, now)
            .await
            .unwrap()
    );
    assert_eq!(last_observed(&client, &agent, "a").await, before);

    // Two hours later: the open match is current again, the ended one is not.
    age(&client, &agent, Duration::hours(2)).await;
    let ended_before = last_observed(&client, &agent, "b").await;
    assert!(
        !finding_changes::heartbeat(&mut client, &agent, digest_now, None, now)
            .await
            .unwrap()
    );
    assert!(last_observed(&client, &agent, "a").await >= now - Duration::seconds(1));
    assert_eq!(last_observed(&client, &agent, "b").await, ended_before);

    // Another digest: resync, nothing written.
    age(&client, &agent, Duration::hours(2)).await;
    let aged = last_observed(&client, &agent, "a").await;
    assert!(
        finding_changes::heartbeat(&mut client, &agent, [0; 32], None, now)
            .await
            .unwrap()
    );
    assert_eq!(last_observed(&client, &agent, "a").await, aged);
    db.drop().await;
}

#[tokio::test]
async fn per_scan_rows_are_never_touched_by_a_heartbeat() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let days = partitions(&client).await;
    let row = wire::finding(
        &finding("s", 1, now),
        now - Duration::days(90),
        now + Duration::hours(1),
        &days,
    )
    .unwrap();
    ingest::store_findings(&mut client, &agent, &[row], ingest::Origin::Online, now)
        .await
        .unwrap();
    age(&client, &agent, Duration::hours(2)).await;
    let before = last_observed(&client, &agent, "s").await;
    let empty = match_digest(&[]);
    assert!(
        !finding_changes::heartbeat(&mut client, &agent, empty, None, now)
            .await
            .unwrap()
    );
    assert_eq!(last_observed(&client, &agent, "s").await, before);
    db.drop().await;
}

#[tokio::test]
async fn a_later_confirming_scan_reopens_mitigated_triage() {
    let (db, agent) = setup().await;
    let mut client = as_ingest(&db).await;
    let admin = db.pool.get().await.unwrap();
    let now = Utc::now();
    let a = finding("a", 1, now - Duration::hours(3));
    let mut first = doc(&agent, &digest(&[]), std::slice::from_ref(&a), true);
    first.started = vec![a];
    apply(&mut client, &agent, &first).await;
    let mitigated_at = now - Duration::hours(1);
    admin
        .execute(
            "INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state,
                 rule_version, note, version, updated_at, updated_by, mitigated_at)
             VALUES ($1, 'base', 'a', 'mitigated', 1, 'patched', 1, $2, 'test', $2)",
            &[&agent, &mitigated_at],
        )
        .await
        .unwrap();
    let d = digest_from_hex(&first.sha256);
    // The last scan ran before the mitigation: it proves nothing.
    finding_changes::heartbeat(&mut client, &agent, d, Some(now - Duration::hours(2)), now)
        .await
        .unwrap();
    assert_eq!(triage_state(&admin, &agent).await, "mitigated");
    // A scan after it still has the match open: reopen.
    finding_changes::heartbeat(
        &mut client,
        &agent,
        d,
        Some(now - Duration::minutes(5)),
        now,
    )
    .await
    .unwrap();
    assert_eq!(triage_state(&admin, &agent).await, "open");
    db.drop().await;
}

fn digest_from_hex(text: &str) -> [u8; 32] {
    openvibes_core::digest_from_hex(text).unwrap()
}

async fn triage_state(client: &Client, agent: &str) -> String {
    client
        .query_one(
            "SELECT state FROM console_finding_triage WHERE agent_id = $1 AND rule_id = 'a'",
            &[&agent],
        )
        .await
        .unwrap()
        .get(0)
}

/// Scale check for the hourly refresh (review): 1,000 agents × 500 open P13
/// matches, every match due. Run by hand and record the numbers in
/// docs/sizing.md: `cargo test --release -p platform-store --test
/// finding_changes scale -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "scale measurement, run by hand"]
async fn scale_hourly_refresh_and_console_list() {
    const AGENTS: i32 = 1_000;
    const MATCHES: i32 = 500;
    let db = TestDb::create().await;
    let mut admin = db.pool.get().await.unwrap();
    platform_store::migrate(&mut admin).await.unwrap();
    let today = Utc::now().date_naive();
    platform_store::ensure_partitions(&admin, today - Duration::days(2), 9)
        .await
        .unwrap();
    admin
        .batch_execute(&format!(
            "SET statement_timeout = 0;
             INSERT INTO agents (agent_id, status, enrolled_at, match_sha256)
             SELECT 'agent.' || lpad(a::text, 36, '0'), 'active', now(), '\\x00'
             FROM generate_series(1, {AGENTS}) a;
             INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                 rule_version, severity, first_observed_at, last_observed_at, last_observed_day,
                 scan_id, confidence, message, evidence, received_at, origin, authenticated,
                 source)
             SELECT 'agent.' || lpad(a::text, 36, '0'), 'base', 'rule.' || r,
                 'finding.' || a || '.' || r, 1, 'high', now() - interval '3 hours',
                 now() - interval '2 hours', current_date, 'scan.1', 100, 'matched',
                 ARRAY['port.tcp.exposed'], now(), 'online', true, 'changes'
             FROM generate_series(1, {AGENTS}) a, generate_series(1, {MATCHES}) r;
             ANALYZE current_findings;"
        ))
        .await
        .unwrap();
    let mut client = as_ingest(&db).await;
    let now = Utc::now();
    let started = std::time::Instant::now();
    for a in 1..=AGENTS {
        let agent = format!("agent.{a:036}");
        client
            .execute(
                "UPDATE agents SET match_sha256 = NULL WHERE agent_id = $1",
                &[&agent],
            )
            .await
            .unwrap();
        let resync = finding_changes::heartbeat(&mut client, &agent, match_digest(&[]), None, now)
            .await
            .unwrap();
        assert!(!resync);
    }
    let refresh = started.elapsed();
    let refreshed: i64 = client
        .query_one(
            "SELECT count(*) FROM current_findings WHERE last_observed_at >= $1",
            &[&now],
        )
        .await
        .unwrap()
        .get(0);
    let query = platform_store::console_read::FindingGroupQuery {
        since: now - Duration::hours(24),
        after: None,
        limit: platform_store::console_read::PageLimit::new(50).unwrap(),
    };
    let started = std::time::Instant::now();
    let page = platform_store::console_read::finding_groups_in_scope(
        &admin,
        &query,
        &platform_store::console_read::AgentScope::Global,
    )
    .await
    .unwrap();
    let list = started.elapsed();
    println!(
        "SCALE agents={AGENTS} matches={MATCHES} refreshed_rows={refreshed} refresh_all={refresh:?} \
         per_heartbeat={:?} group_list={list:?} groups={}",
        refresh / u32::try_from(AGENTS).unwrap(),
        page.items.len()
    );
    assert_eq!(refreshed, i64::from(AGENTS * MATCHES));
    db.drop().await;
}
