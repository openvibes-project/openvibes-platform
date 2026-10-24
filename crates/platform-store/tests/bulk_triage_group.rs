//! Bulk from a list row counted under a Group filter (`ListRow::group`)
//! reaches only that group's hosts, still inside reach, for compliance and
//! vulnerabilities alike (step 5c final fix 2).

mod common;

use chrono::Utc;
use common::{hosts::id, vulns::fixture};
use platform_store::{
    bulk_triage::{self as bulk, BulkChange, ListRow},
    console_read::AgentScope,
};

/// The vulnerability fixture (Web: hosts 1-3, the scope; Alpha: host 1;
/// Other: host 4) plus a failing check on hosts 1, 2 and 4.
async fn setup() -> (
    common::TestDb,
    deadpool_postgres::Client,
    AgentScope,
    String,
    String,
) {
    let (db, c) = common::migrated().await;
    let (web, alpha) = fixture(&c).await;
    c.batch_execute(&format!(
        "INSERT INTO console_role_bindings (binding_id, user_id, role_id, created_at, created_by)
         SELECT gen_random_uuid(), user_id, 'admin', now(), 't' FROM console_users;
         INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version,
             severity, first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
             message, evidence, received_at, origin, authenticated)
         SELECT h, 'baseline', 'port.ssh.exposed', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}',
             now(), 'online', true
         FROM unnest(ARRAY['{}', '{}', '{}']) h;",
        id(1),
        id(2),
        id(4)
    ))
    .await
    .unwrap();
    let other: String = c
        .query_one(
            "SELECT asset_group_id::text FROM console_asset_groups WHERE name = 'Other'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    (db, c, AgentScope::AssetGroups(vec![web]), alpha, other)
}

fn row(group: &str) -> [ListRow; 1] {
    [ListRow {
        open_only: true,
        group: Some(group.to_owned()),
    }]
}

#[tokio::test]
async fn a_group_row_reaches_only_its_group_in_reach() {
    let (db, mut c, scope, alpha, other) = setup().await;
    let now = Utc::now();
    let check = [("baseline".to_owned(), "port.ssh.exposed".to_owned(), None)];
    let unassign = BulkChange::Assign(None);
    // Compliance: Alpha holds host 1 only; Other's host 4 is out of reach.
    let case = bulk::expand_compliance(&c, &scope, &check, &row(&alpha))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        case,
        [(
            id(1).to_owned(),
            "baseline".into(),
            "port.ssh.exposed".into()
        )]
    );
    let all = bulk::expand_compliance(&c, &scope, &check, &[])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(all.len(), 2, "hosts 1 and 2 without a group");
    let close = BulkChange::State {
        state: "mitigated",
        note: Some("x"),
        accepted_until: None,
    };
    let done = bulk::compliance_open_only(&mut c, &scope, &check, &row(&alpha), close, "ann", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (1, 0), "{done:?}");
    let out =
        bulk::compliance_open_only(&mut c, &scope, &check, &row(&other), unassign, "ann", now)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        (out.changed, out.skipped),
        (
            0,
            vec![(
                "baseline/port.ssh.exposed".to_owned(),
                "not found or out of scope"
            )]
        )
    );
    // Vulnerabilities: DEBIAN-EXP is open on hosts 1 and 2.
    let exp = [("DEBIAN-EXP".to_owned(), None)];
    let case = bulk::expand_vulnerabilities(&c, &scope, &exp, &row(&alpha))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(case, [(id(1).to_owned(), "DEBIAN-EXP".into())]);
    let done =
        bulk::vulnerabilities_open_only(&mut c, &scope, &exp, &row(&alpha), close, "ann", now)
            .await
            .unwrap()
            .unwrap();
    assert_eq!((done.changed, done.skipped.len()), (1, 0), "{done:?}");
    let left: String = c
        .query_one(
            "SELECT state FROM vulnerability_triage WHERE agent_id = $1 AND advisory_id = 'DEBIAN-EXP'",
            &[&id(2)],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, "accepted_risk", "host 2 is outside Alpha");
    let out_row = [("DEBIAN-OUT".to_owned(), None)];
    let out = bulk::vulnerabilities_open_only(
        &mut c,
        &scope,
        &out_row,
        &row(&other),
        unassign,
        "ann",
        now,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        (out.changed, out.skipped),
        (
            0,
            vec![("DEBIAN-OUT".to_owned(), "not found or out of scope")]
        )
    );
    drop(c);
    db.drop().await;
}
