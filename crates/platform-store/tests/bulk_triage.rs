//! Bulk triage (triage v2): scope, expansion, the note rule and the cap.

mod common;

use chrono::{Duration, Utc};
use common::TestDb;
use platform_store::{
    bulk_triage::{self as bulk, BulkChange, BulkRefusal},
    console_read::AgentScope,
};

const WEB: &str = "agent.00000000-0000-4000-8000-000000000001";
const DB: &str = "agent.00000000-0000-4000-8000-000000000002";
const PROD: &str = "00000000-0000-4000-8000-0000000000aa";

/// Two hosts (web-01 in the prod group, db-01 not), one alarm, one finding
/// and one open vulnerability on each.
async fn setup() -> (TestDb, deadpool_postgres::Client, Vec<i64>) {
    let db = TestDb::create().await;
    let mut client = db.pool.get().await.unwrap();
    platform_store::migrate(&mut client).await.unwrap();
    let now = Utc::now();
    platform_store::ensure_partitions(&client, now.date_naive() - Duration::days(1), 3)
        .await
        .unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at) VALUES
                ('{WEB}', 'active', now(), 'web-01', now()),
                ('{DB}', 'active', now(), 'db-01', now());
             INSERT INTO console_agent_tags VALUES ('{WEB}', 'env', 'prod', now(), 't');
             INSERT INTO console_asset_groups VALUES ('{PROD}', 'prod', now(), 't');
             INSERT INTO console_asset_group_selectors VALUES ('{PROD}', 'env', 'prod', now());
             INSERT INTO alarms (first_seen_day, agent_id, alarm_id, rule_set_id, rule_set_version,
                 rule_id, rule_version, severity, confidence, message, first_seen, last_seen, count,
                 process, ancestors, received_at)
             SELECT (now() AT TIME ZONE 'UTC')::date, g, md5(g), 'baseline-alarms', 1,
                 'alarm.openvibes.test', 1, 'info', 100, 'test', now(), now(), 1, '{{}}', '[]', now()
             FROM unnest(ARRAY['{WEB}', '{DB}']) g;
             INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id,
                rule_version, severity, first_observed_at, last_observed_at, last_observed_day,
                scan_id, confidence, message, evidence, received_at, origin, authenticated)
             SELECT g, 'baseline', 'port.ssh.exposed', 'f-' || g, 1, 'low', now(), now(),
                 current_date, 'scan.1', 90, 'SSH is exposed', '{{}}', now(), 'online', true
             FROM unnest(ARRAY['{WEB}', '{DB}']) g;
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
             VALUES ('FEDORA-1', 'fedora', 'fedora', '44', 'important', 'openssl update', 'https://x');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at,
                fixed_at, last_evaluated_at)
             SELECT g, 'FEDORA-1', '[]', now(), NULL, now() FROM unnest(ARRAY['{WEB}', '{DB}']) g;"
        ))
        .await
        .unwrap();
    let ids: Vec<i64> = client
        .query("SELECT id FROM alarms ORDER BY agent_id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    (db, client, ids)
}

fn mitigate(note: Option<&str>) -> BulkChange<'_> {
    BulkChange::State {
        state: "mitigated",
        note,
        accepted_until: None,
    }
}

#[tokio::test]
async fn alarms_close_in_bulk_with_a_note_and_out_of_scope_ones_are_skipped() {
    let (db, mut client, ids) = setup().await;
    let now = Utc::now();
    let prod = AgentScope::AssetGroups(vec![PROD.into()]);
    assert_eq!(
        bulk::alarms(&mut client, &prod, &ids, mitigate(None), "alice", now)
            .await
            .unwrap(),
        Err(BulkRefusal::Fields),
        "a bulk close needs a note"
    );
    let done = bulk::alarms(
        &mut client,
        &prod,
        &ids,
        mitigate(Some("test alarms")),
        "alice",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(done.changed, 1, "only web-01 is in the prod scope");
    assert_eq!(
        done.skipped,
        [(ids[1].to_string(), "not found or out of scope")]
    );
    let states: Vec<String> = client
        .query("SELECT state FROM alarms ORDER BY agent_id", &[])
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(states, ["mitigated", "open"]);
    let audited: i64 = client
        .query_one(
            "SELECT count(*) FROM audit_log WHERE action = 'alarm.bulk_triage'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audited, 1);
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn a_rule_or_an_advisory_expands_to_every_host_in_scope() {
    let (db, mut client, _) = setup().await;
    let now = Utc::now();
    let all = AgentScope::Global;
    let rule = [("baseline".to_owned(), "port.ssh.exposed".to_owned(), None)];
    let done = bulk::compliance(
        &mut client,
        &all,
        &rule,
        mitigate(Some("firewalled")),
        "alice",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (2, 0));
    // A rule-wide close leaves an already closed host's decision alone; a
    // named host changes as asked.
    let one = [(
        "baseline".to_owned(),
        "port.ssh.exposed".to_owned(),
        Some(DB.to_owned()),
    )];
    let fp = BulkChange::State {
        state: "false_positive",
        note: Some("lab"),
        accepted_until: None,
    };
    assert_eq!(
        bulk::compliance(&mut client, &all, &one, fp, "alice", now)
            .await
            .unwrap()
            .unwrap()
            .changed,
        1
    );
    let again = bulk::compliance(
        &mut client,
        &all,
        &rule,
        mitigate(Some("again")),
        "alice",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(again.changed, 0);
    assert!(
        again
            .skipped
            .iter()
            .all(|(_, why)| *why == "already closed")
    );
    let db_state: String = client
        .query_one(
            "SELECT state FROM console_finding_triage WHERE agent_id = $1",
            &[&DB],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(db_state, "false_positive");
    let advisory = [("FEDORA-1".to_owned(), None)];
    let done = bulk::vulnerabilities(
        &mut client,
        &all,
        &advisory,
        mitigate(Some("WAF")),
        "alice",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (2, 0));
    // Assign keeps the state and note (no assignee user exists: skipped).
    let done = bulk::vulnerabilities(
        &mut client,
        &all,
        &advisory,
        BulkChange::Assign(Some("nobody")),
        "alice",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(done.changed, 0);
    assert!(
        done.skipped
            .iter()
            .all(|(_, why)| *why == "assignee unavailable")
    );
    let unknown = [("FEDORA-9".to_owned(), None)];
    let done = bulk::vulnerabilities(
        &mut client,
        &all,
        &unknown,
        mitigate(Some("x")),
        "alice",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        done.skipped,
        [("FEDORA-9".to_owned(), "not found or out of scope")]
    );
    drop(client);
    db.drop().await;
}

#[tokio::test]
async fn more_than_ten_thousand_items_are_refused() {
    let (db, mut client, _) = setup().await;
    let ids: Vec<i64> = (1..=10_001).collect();
    assert_eq!(
        bulk::alarms(
            &mut client,
            &AgentScope::Global,
            &ids,
            mitigate(Some("x")),
            "a",
            Utc::now()
        )
        .await
        .unwrap(),
        Err(BulkRefusal::Count)
    );
    drop(client);
    db.drop().await;
}
