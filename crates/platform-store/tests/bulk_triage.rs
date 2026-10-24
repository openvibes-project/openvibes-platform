//! Bulk triage (triage v2): scope, expansion, the note rule and the cap.

mod common;

use chrono::{Duration, Utc};
use common::{
    TestDb,
    hosts::id,
    vulns::{every, fixture, row, run},
};
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
             INSERT INTO console_asset_groups VALUES ('{PROD}', 'prod', now(), 't');
             INSERT INTO console_host_group_members VALUES ('{PROD}', '{WEB}', now(), 't');
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
    // A rule-wide close leaves a closed host's decision alone ("not open");
    // a named host changes as asked.
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
    assert_eq!(
        again.skipped,
        [("baseline/port.ssh.exposed".to_owned(), "not open")]
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
    // Reopening the rule reopens its closed hosts and skips none that are open.
    let reopen = BulkChange::State {
        state: "open",
        note: None,
        accepted_until: None,
    };
    let reopened = bulk::compliance(&mut client, &all, &rule, reopen, "alice", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((reopened.changed, reopened.skipped.len()), (2, 0));
    let again = bulk::compliance(&mut client, &all, &rule, reopen, "alice", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(again.changed, 0);
    assert!(again.skipped.iter().all(|(_, why)| *why == "already open"));
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
    // Assign keeps the state and note; an advisory-wide one skips the closed
    // pairs ("not open", whatever the assignee).
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
    assert!(done.skipped.iter().all(|(_, why)| *why == "not open"));
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

async fn triage_of(
    c: &deadpool_postgres::Client,
    agent: &str,
    adv: &str,
) -> (String, Option<String>) {
    c.query_opt(
        "SELECT state, note FROM vulnerability_triage WHERE agent_id = $1 AND advisory_id = $2",
        &[&agent, &adv],
    )
    .await
    .unwrap()
    .map_or(("none".into(), None), |r| (r.get(0), r.get(1)))
}

/// The fixture's ann and bob can be assigned (admins).
async fn make_admins(c: &deadpool_postgres::Client) {
    c.batch_execute(
        "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
         SELECT gen_random_uuid(), user_id, 'admin', now(), 't' FROM console_users;",
    )
    .await
    .unwrap();
}

fn why(done: &bulk::BulkResult, pair: &str) -> Option<&'static str> {
    done.skipped
        .iter()
        .find(|(p, _)| p == pair)
        .map(|(_, w)| *w)
}

/// An advisory-wide state change or assignment (a CVE row) touches only the
/// open pairs in reach.
#[tokio::test]
async fn bulk_on_cve_rows_changes_only_open_pairs() {
    let (db, mut c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    make_admins(&c).await;
    let (h1, h2, h4) = (id(1), id(2), id(4));
    // DEBIAN-A: h1 open, h2 mitigated; an open pair on h4, out of reach.
    c.batch_execute(&format!(
        "INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at,
            last_evaluated_at) VALUES ('{h4}', 'DEBIAN-A', '[]', now(), NULL, now());"
    ))
    .await
    .unwrap();
    let scope = AgentScope::AssetGroups(vec![web]);
    let now = Utc::now();
    let a = [("DEBIAN-A".to_owned(), None)];
    let done = bulk::vulnerabilities(
        &mut c,
        &scope,
        &a,
        BulkChange::Assign(Some("bob")),
        "ann",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    // The mitigated h2 and the out-of-reach h4 are not reached at all.
    assert_eq!((done.changed, done.skipped.len()), (1, 0), "{done:?}");
    let assigned = |agent: &str| {
        let agent = agent.to_owned();
        let c = &c;
        async move {
            c.query_one(
                "SELECT u.username FROM vulnerability_triage t JOIN console_users u ON u.user_id = t.assigned_to
                 WHERE agent_id = $1 AND advisory_id = 'DEBIAN-A'",
                &[&agent],
            )
            .await
            .unwrap()
            .get::<_, String>(0)
        }
    };
    assert_eq!(assigned(h1).await, "bob");
    assert_eq!(
        assigned(h2).await,
        "bob",
        "the mitigated pair keeps its assignee"
    );
    assert_eq!(triage_of(&c, h4, "DEBIAN-A").await.0, "none");
    // Accepted, false-positive and mitigated pairs are all left alone: an
    // advisory with no open pair in reach says "not open".
    for (adv, pair) in [("FEDORA-1", "FEDORA-1"), ("DEBIAN-FP", "DEBIAN-FP")] {
        let one = [(adv.to_owned(), None)];
        for change in [mitigate(Some("x")), BulkChange::Assign(Some("bob"))] {
            let done = bulk::vulnerabilities(&mut c, &scope, &one, change, "ann", now)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(done.changed, 0, "{adv}");
            assert_eq!(why(&done, pair), Some("not open"), "{adv}");
        }
    }
    let before = triage_of(&c, id(3), "FEDORA-1").await;
    assert_eq!(before, ("accepted_risk".into(), Some("n".into())));
    // Close: only h1's open pair changes; the mitigated one keeps its note.
    let done = bulk::vulnerabilities(&mut c, &scope, &a, mitigate(Some("patched")), "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (1, 0), "{done:?}");
    assert_eq!(
        triage_of(&c, h1, "DEBIAN-A").await,
        ("mitigated".into(), Some("patched".into()))
    );
    assert_eq!(
        triage_of(&c, h2, "DEBIAN-A").await,
        ("mitigated".into(), Some("n".into()))
    );
    assert_eq!(triage_of(&c, h4, "DEBIAN-A").await.0, "none");
    // A list row on one host (the Host chip) sends `open_only`: h2's mitigated
    // pair is still left alone, for a close and an assignment alike.
    let on_h2 = [("DEBIAN-A".to_owned(), Some(h2.to_owned()))];
    for change in [mitigate(Some("again")), BulkChange::Assign(Some("ann"))] {
        let done =
            bulk::vulnerabilities_open_only(&mut c, &scope, &on_h2, &[true], change, "ann", now)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(done.changed, 0, "{done:?}");
        assert_eq!(why(&done, &format!("{h2}/DEBIAN-A")), Some("not open"));
    }
    assert_eq!(
        triage_of(&c, h2, "DEBIAN-A").await,
        ("mitigated".into(), Some("n".into()))
    );
    // An expired accepted risk counts as open: DEBIAN-EXP (h1 open, h2 expired)
    // takes an assignee on both, then closes on both.
    let exp = [("DEBIAN-EXP".to_owned(), None)];
    let done = bulk::vulnerabilities(
        &mut c,
        &scope,
        &exp,
        BulkChange::Assign(Some("ann")),
        "ann",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (2, 0), "{done:?}");
    assert_eq!(triage_of(&c, h2, "DEBIAN-EXP").await.0, "open");
    let done = bulk::vulnerabilities(&mut c, &scope, &exp, mitigate(Some("x")), "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (2, 0), "{done:?}");
    // A reopen keeps its rule: it reopens the closed pairs (h1 closed above,
    // h2 mitigated by the fixture; the test depends on the close above).
    let reopen = BulkChange::State {
        state: "open",
        note: None,
        accepted_until: None,
    };
    let done = bulk::vulnerabilities(&mut c, &scope, &a, reopen, "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.changed, 2);
    drop(c);
    db.drop().await;
}

/// The list shows a bulk change on every CVE row the advisory covers.
#[tokio::test]
async fn triage_on_one_cve_shows_on_its_siblings() {
    let (db, mut c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    make_admins(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let now = Utc::now();
    let fed = [("FEDORA-1".to_owned(), None)];
    let open =
        |p: &platform_store::vuln_list::VulnListPage| (row(p, "CVE-A").open, row(p, "CVE-B").open);
    assert_eq!(open(&run(&c, &every(), &scope).await), (1, 0));
    let reopen = BulkChange::State {
        state: "open",
        note: None,
        accepted_until: None,
    };
    let r = bulk::vulnerabilities(&mut c, &scope, &fed, reopen, "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.changed, 1, "{r:?}");
    // Both CVEs of FEDORA-1 now show its host open (CVE-A also has DEBIAN-A's h1).
    assert_eq!(open(&run(&c, &every(), &scope).await), (2, 1));
    let done = bulk::vulnerabilities(&mut c, &scope, &fed, mitigate(Some("patched")), "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.changed, 1);
    assert_eq!(open(&run(&c, &every(), &scope).await), (1, 0));
    drop(c);
    db.drop().await;
}

/// Pairs with no fix (`version_vulnerabilities`) have no triage: they are
/// always open in the list and never expanded, so a bulk item for a no-fix
/// advisory finds nothing and the list does not move.
#[tokio::test]
async fn no_fix_pairs_are_not_reached_by_bulk() {
    let (db, mut c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let nf = [("DEBIAN-NF".to_owned(), None)];
    let done = bulk::vulnerabilities(&mut c, &scope, &nf, mitigate(Some("x")), "ann", Utc::now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.changed, 0);
    assert_eq!(
        done.skipped,
        [("DEBIAN-NF".to_owned(), "not found or out of scope")]
    );
    assert_eq!(row(&run(&c, &every(), &scope).await, "CVE-NF").open, 2);
    drop(c);
    db.drop().await;
}
