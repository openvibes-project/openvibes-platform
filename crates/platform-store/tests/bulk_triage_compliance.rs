//! Bulk triage on a Compliance list row (one check): only its open, failing
//! pairs in reach change, with or without the Host chip.

mod common;

use chrono::Utc;
use common::{hosts::id, vulns::fixture};
use platform_store::{
    bulk_triage::{self as bulk, BulkChange},
    console_read::AgentScope,
};

const R: (&str, &str) = ("baseline", "port.ssh.exposed");

fn row(agent: Option<&str>) -> [(String, String, Option<String>); 1] {
    [(R.0.to_owned(), R.1.to_owned(), agent.map(str::to_owned))]
}

fn close(note: &str) -> BulkChange<'_> {
    BulkChange::State {
        state: "mitigated",
        note: Some(note),
        accepted_until: None,
    }
}

/// h1 open, h2 mitigated, h3 ended, h5 accepted risk expired (all in reach);
/// h4 open out of reach.
async fn setup() -> (common::TestDb, deadpool_postgres::Client, AgentScope) {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    c.batch_execute(&format!(
        "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
         SELECT gen_random_uuid(), user_id, 'admin', now(), 't' FROM console_users;
         INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
         VALUES ('{h5}', 'active', now(), now(), 'web-05');
         INSERT INTO console_host_group_members VALUES ('{web}', '{h5}', now(), 't');
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version,
             severity, first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
             message, evidence, received_at, origin, authenticated, ended_at)
         SELECT h, '{set}', '{rule}', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}',
             now(), 'online', true, CASE WHEN h = '{h3}' THEN now() - interval '1 hour' END
         FROM unnest(ARRAY['{h1}', '{h2}', '{h3}', '{h4}', '{h5}']) h;
         INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, note,
             accepted_until, version, updated_at, updated_by)
         VALUES ('{h2}', '{set}', '{rule}', 'mitigated', 1, 'n', NULL, 1, now(), 't'),
                ('{h5}', '{set}', '{rule}', 'accepted_risk', 1, 'n', now() - interval '2 days', 1, now(), 't');",
        h1 = id(1),
        h2 = id(2),
        h3 = id(3),
        h4 = id(4),
        h5 = id(5),
        set = R.0,
        rule = R.1,
    ))
    .await
    .unwrap();
    (db, c, AgentScope::AssetGroups(vec![web]))
}

async fn state_of(c: &deadpool_postgres::Client, agent: &str) -> (String, Option<String>) {
    c.query_opt(
        "SELECT state, note FROM console_finding_triage WHERE agent_id = $1 AND rule_id = $2",
        &[&agent, &R.1],
    )
    .await
    .unwrap()
    .map_or(("none".into(), None), |r| (r.get(0), r.get(1)))
}

#[tokio::test]
async fn compliance_rows_change_only_open_failing_pairs() {
    let (db, mut c, scope) = setup().await;
    let now = Utc::now();
    // With and without the Host chip on the closed h2, a close and an assign
    // leave it alone ("not open"); the rule-wide one never lists it.
    let on_h2 = row(Some(id(2)));
    for change in [close("x"), BulkChange::Assign(Some("bob"))] {
        let done = bulk::compliance_open_only(&mut c, &scope, &on_h2, &[true], change, "ann", now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(done.changed, 0, "{done:?}");
        assert_eq!(
            done.skipped,
            [(format!("{}/{}/{}", id(2), R.0, R.1), "not open")]
        );
    }
    assert_eq!(
        state_of(&c, id(2)).await,
        ("mitigated".into(), Some("n".into()))
    );
    // Assign: h1 (open) and h5 (expired acceptance, written back open); the
    // mitigated h2, the ended h3 and the unreachable h4 are not reached.
    let done = bulk::compliance(
        &mut c,
        &scope,
        &row(None),
        BulkChange::Assign(Some("bob")),
        "ann",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (2, 0), "{done:?}");
    assert_eq!(state_of(&c, id(5)).await.0, "open");
    let until: Option<chrono::DateTime<Utc>> = c
        .query_one(
            "SELECT accepted_until FROM console_finding_triage WHERE agent_id = $1",
            &[&id(5)],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        until.is_none(),
        "the expired acceptance is written back open"
    );
    // Close: h1 and h5 only, with or without the Host chip.
    let done = bulk::compliance(&mut c, &scope, &row(None), close("fixed"), "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (2, 0), "{done:?}");
    assert_eq!(
        state_of(&c, id(1)).await,
        ("mitigated".into(), Some("fixed".into()))
    );
    assert_eq!(
        state_of(&c, id(2)).await,
        ("mitigated".into(), Some("n".into()))
    );
    // An ended finding and an unreachable one were never touched.
    assert_eq!(state_of(&c, id(3)).await.0, "none");
    assert_eq!(state_of(&c, id(4)).await.0, "none");
    // Nothing open is left: the row says "not open", not "not found".
    let done = bulk::compliance(&mut c, &scope, &row(None), close("again"), "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.skipped, [(format!("{}/{}", R.0, R.1), "not open")]);
    // The ended host named with the chip is not a failing finding at all, so
    // it is "not found or out of scope"; a reopen still reopens the closed
    // pairs (h1, h2, h5) and finds h3 already open.
    let on_h3 = row(Some(id(3)));
    let done = bulk::compliance_open_only(&mut c, &scope, &on_h3, &[true], close("x"), "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.changed, 0, "{done:?}");
    assert_eq!(
        done.skipped,
        [(
            format!("{}/{}/{}", id(3), R.0, R.1),
            "not found or out of scope"
        )]
    );
    assert_eq!(state_of(&c, id(3)).await.0, "none");
    // Add to case from the row takes every failing pair (closed ones too),
    // never the ended one; a named host without the chip keeps its pair.
    let rule_wide = bulk::expand_compliance(&c, &scope, &row(None), &[])
        .await
        .unwrap()
        .unwrap();
    let hosts: Vec<&str> = rule_wide.iter().map(|(a, _, _)| a.as_str()).collect();
    assert_eq!(hosts, [id(1), id(2), id(5)]);
    let named = bulk::expand_compliance(&c, &scope, &row(Some(id(3))), &[false])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(named.len(), 1);
    let chip = bulk::expand_compliance(&c, &scope, &row(Some(id(3))), &[true])
        .await
        .unwrap()
        .unwrap();
    assert!(chip.is_empty());
    let reopen = BulkChange::State {
        state: "open",
        note: None,
        accepted_until: None,
    };
    let done = bulk::compliance(&mut c, &scope, &row(None), reopen, "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.changed, 3, "{done:?}");
    drop(c);
    db.drop().await;
}

#[tokio::test]
async fn a_named_host_without_open_only_still_changes_as_asked() {
    let (db, mut c, scope) = setup().await;
    let done = bulk::compliance(
        &mut c,
        &scope,
        &row(Some(id(2))),
        close("again"),
        "ann",
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (1, 0), "{done:?}");
    assert_eq!(
        state_of(&c, id(2)).await,
        ("mitigated".into(), Some("again".into()))
    );
    drop(c);
    db.drop().await;
}
