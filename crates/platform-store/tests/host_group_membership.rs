//! Stored host-group membership (schema 61; roles plan step 5b, task 2a):
//! `console_host_group_membership` is kept by triggers in the same
//! transaction and always equals the live rule of migration 53, which this
//! file keeps as the oracle.
mod common;

use std::collections::BTreeMap;

use chrono::Utc;
use common::hosts::id;
use platform_store::{
    Client,
    console_read::AgentScope,
    host_group_facts::{MEMBERSHIP_LOCK, ensure_automatic_groups},
    host_list::{HostScopes, hosts},
    vuln_list::VulnQuery,
};

/// Migration 53's `console_host_in_group`, over every (group, host) pair.
const ORACLE: &str = "
SELECT g.asset_group_id::text AS gid, a.agent_id
FROM console_asset_groups g JOIN agents a ON a.status = 'active'
WHERE CASE WHEN g.kind = 'manual' THEN EXISTS (
        SELECT 1 FROM console_host_group_members m
        WHERE m.asset_group_id = g.asset_group_id AND m.agent_id = a.agent_id)
      ELSE EXISTS (SELECT 1 FROM console_host_group_conditions c WHERE c.asset_group_id = g.asset_group_id)
       AND NOT EXISTS (SELECT 1 FROM console_host_group_conditions c
                       WHERE c.asset_group_id = g.asset_group_id
                         AND NOT COALESCE(console_condition_holds(a, c.field, c.negate, c.vals), false))
      END";

async fn pairs(c: &Client, sql: &str) -> Vec<(String, String)> {
    c.query(&format!("SELECT * FROM ({sql}) p ORDER BY 1, 2"), &[])
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
}

/// The table equals the rule; returns the pair count.
async fn same(c: &Client, step: &str) -> usize {
    let stored = pairs(
        c,
        "SELECT asset_group_id::text, agent_id FROM console_host_group_membership",
    )
    .await;
    assert_eq!(stored, pairs(c, ORACLE).await, "after {step}");
    stored.len()
}

async fn run(c: &Client, sql: &str) {
    c.batch_execute(sql).await.unwrap();
}

#[tokio::test]
async fn membership_matches_the_rule_after_every_change() {
    let (db, c) = common::migrated().await;
    let (h1, h2, h3, h4, h5) = (id(1), id(2), id(8), id(4), id(5));
    run(&c, &format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, revoked_at, hostname, os_id, os_version, last_address) VALUES
           ('{h1}', 'active', now(), NULL, 'web-01', 'debian', '12', '10.0.1.5'),
           ('{h2}', 'active', now(), NULL, 'db-01', 'fedora', '44', '10.0.2.7'),
           ('{h3}', 'imported', now(), NULL, 'web-03', 'windows', '11', '10.2.0.8'),
           ('{h4}', 'revoked', now(), now(), 'web-04', 'debian', '12', '10.0.4.4')"
    ))
    .await;
    let debian = common::rule_group(&c, "Debian", &[("distribution", false, &["debian 12"])]).await;
    let web = common::rule_group(
        &c,
        "Web",
        &[
            ("hostname", false, &["web-*"]),
            ("ip", false, &["10.0.0.0/8"]),
        ],
    )
    .await;
    common::rule_group(&c, "Not Windows", &[("os_family", true, &["windows"])]).await;
    let picked = common::manual_group(&c, "Picked", &[h1, h3, h4]).await;
    run(&c, "INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind, auto_key)
              VALUES ('00000000-0000-4000-8000-00000000aaaa', 'Linux', now(), 't', 'automatic', 'os_family:linux');
             INSERT INTO console_host_group_conditions VALUES
               ('00000000-0000-4000-8000-00000000aaaa', 0, 'os_family', false, '{linux}')").await;
    assert!(same(&c, "setup").await >= 5);

    // enrol, then the first facts
    common::seed_agent(&c, h5).await;
    same(&c, "enrol").await;
    run(
        &c,
        &format!(
            "UPDATE agents SET hostname = 'web-05', os_id = 'debian', os_version = '12',
                        last_address = '10.0.5.5' WHERE agent_id = '{h5}'"
        ),
    )
    .await;
    let before = same(&c, "first facts").await;

    // fact changes
    for (step, set, who) in [
        ("hostname", "hostname = 'db-09'", h1),
        ("address", "last_address = '192.168.0.1'", h5),
        ("os", "os_id = 'debian', os_version = '12'", h2),
        ("os family", "os_id = 'windows', os_version = '11'", h5),
        ("revoke", "status = 'revoked', revoked_at = now()", h1),
        ("reactivate", "status = 'active', revoked_at = NULL", h1),
        ("revive", "status = 'active', revoked_at = NULL", h4),
    ] {
        run(
            &c,
            &format!("UPDATE agents SET {set} WHERE agent_id = '{who}'"),
        )
        .await;
        same(&c, step).await;
    }
    run(
        &c,
        "UPDATE agents SET hostname = 'web-' || right(agent_id, 2)",
    )
    .await;
    assert_ne!(same(&c, "every host at once").await, before);

    // conditions
    for (step, sql) in [
        (
            "condition add",
            format!(
                "INSERT INTO console_host_group_conditions VALUES ('{debian}', 1, 'hostname', false, '{{web-0*}}')"
            ),
        ),
        (
            "condition edit",
            format!(
                "UPDATE console_host_group_conditions SET vals = '{{*0}}' WHERE asset_group_id = '{debian}' AND position = 1"
            ),
        ),
        (
            "condition negate",
            format!(
                "UPDATE console_host_group_conditions SET negate = true WHERE asset_group_id = '{web}'"
            ),
        ),
        (
            "condition field",
            format!(
                "UPDATE console_host_group_conditions SET field = 'os_family', vals = '{{linux}}' WHERE asset_group_id = '{debian}' AND position = 1"
            ),
        ),
        (
            "condition remove",
            format!(
                "DELETE FROM console_host_group_conditions WHERE asset_group_id = '{web}' AND position = 0"
            ),
        ),
        (
            "last condition remove",
            format!("DELETE FROM console_host_group_conditions WHERE asset_group_id = '{web}'"),
        ),
    ] {
        run(&c, &sql).await;
        same(&c, step).await;
    }

    // manual members, kinds, groups
    for (step, sql) in [
        (
            "member add",
            format!(
                "INSERT INTO console_host_group_members VALUES ('{picked}', '{h2}', now(), 't')"
            ),
        ),
        (
            "member remove",
            format!(
                "DELETE FROM console_host_group_members WHERE asset_group_id = '{picked}' AND agent_id = '{h1}'"
            ),
        ),
        (
            "rule to manual",
            format!(
                "UPDATE console_asset_groups SET kind = 'manual' WHERE asset_group_id = '{debian}'"
            ),
        ),
        (
            "manual to rule",
            format!(
                "UPDATE console_asset_groups SET kind = 'rule' WHERE asset_group_id = '{picked}'"
            ),
        ),
        (
            "back to manual",
            format!(
                "UPDATE console_asset_groups SET kind = 'manual' WHERE asset_group_id = '{picked}'"
            ),
        ),
        (
            "group delete",
            format!("DELETE FROM console_asset_groups WHERE asset_group_id = '{debian}'"),
        ),
        (
            "manual group delete",
            format!("DELETE FROM console_asset_groups WHERE asset_group_id = '{picked}'"),
        ),
        (
            "agent delete",
            format!("DELETE FROM agents WHERE agent_id = '{h2}'"),
        ),
    ] {
        run(&c, &sql).await;
        same(&c, step).await;
    }
    common::rule_group(&c, "Late", &[("hostname", false, &["web-*"])]).await;
    common::manual_group(&c, "Late picks", &[h3, h5]).await;
    assert!(same(&c, "group create").await > 0);

    // several changes in one transaction
    run(&c, &format!(
        "BEGIN;
         UPDATE agents SET os_id = 'fedora', os_version = '44' WHERE agent_id = '{h5}';
         INSERT INTO console_host_group_conditions VALUES ('00000000-0000-4000-8000-00000000aaaa', 1, 'hostname', true, '{{web-05}}');
         COMMIT"
    ))
    .await;
    same(&c, "one transaction").await;
    db.drop().await;
}

/// Whether this transaction refreshed membership: every refresh, and so
/// every membership write, takes advisory lock 1870032226 until commit.
/// (`pg_stat_xact_user_tables` also counts earlier, unflushed transactions.)
async fn refreshed(c: &impl deadpool_postgres::GenericClient) -> bool {
    c.query_one(
        "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()
                          AND classid = 0 AND objid = $1::bigint::oid)",
        &[&MEMBERSHIP_LOCK],
    )
    .await
    .unwrap()
    .get(0)
}

#[tokio::test]
async fn a_heartbeat_that_changes_nothing_relevant_writes_no_membership_rows() {
    let (db, mut c) = common::migrated().await;
    let h1 = id(1);
    common::seed_agent(&c, h1).await;
    run(
        &c,
        &format!(
            "UPDATE agents SET hostname = 'web-01', last_address = '10.0.1.5', os_id = 'debian',
                        os_version = '12' WHERE agent_id = '{h1}'"
        ),
    )
    .await;
    common::rule_group(&c, "Web", &[("hostname", false, &["web-*"])]).await;
    assert_eq!(same(&c, "setup").await, 1);

    let tx = c.transaction().await.unwrap();
    // ingest's heartbeat, the same facts again (ingest.rs)
    tx.batch_execute(&format!(
        "UPDATE agents SET last_seen_at = now(), scanner_version = '0.5.0', hostname = COALESCE('web-01', hostname),
             last_address = COALESCE('10.0.1.5'::inet, last_address), health = '{{}}', health_at = now()
         WHERE agent_id = '{h1}';
         UPDATE agents SET os_id = 'debian', os_version = '12', inventory_at = now() WHERE agent_id = '{h1}'"
    ))
    .await
    .unwrap();
    assert!(!refreshed(&tx).await);
    tx.batch_execute(&format!(
        "UPDATE agents SET hostname = 'db-01' WHERE agent_id = '{h1}'"
    ))
    .await
    .unwrap();
    assert!(refreshed(&tx).await, "a relevant change refreshes");
    tx.commit().await.unwrap();
    db.drop().await;
}

/// The hosts the oracle puts in `groups`.
async fn in_scope(c: &Client, groups: &[String]) -> Vec<String> {
    c.query(
        &format!("SELECT DISTINCT agent_id FROM ({ORACLE}) o WHERE gid = ANY($1) ORDER BY 1"),
        &[&groups],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

/// The scoped Hosts, Alarms and Vulnerabilities lists reach exactly the
/// hosts the oracle puts in the scope.
async fn lists_match(c: &Client, groups: &[String], step: &str) {
    let want = in_scope(c, groups).await;
    let scope = AgentScope::AssetGroups(groups.to_vec());
    let s = HostScopes {
        hosts: &scope,
        alarms: None,
        vulnerabilities: None,
        compliance: None,
    };
    let page = hosts(c, &common::hosts::query(), &s, None, Utc::now())
        .await
        .unwrap();
    let mut got: Vec<String> = page.rows.iter().map(|r| r.agent_id.clone()).collect();
    got.sort();
    assert_eq!(got, want, "hosts after {step}");

    let page = common::alarms::run(c, &common::alarms::query(), &scope).await;
    let mut got: Vec<String> = page.rows.iter().map(|r| r.agent_id.clone()).collect();
    got.sort();
    got.dedup();
    assert_eq!(got, want, "alarms after {step}");

    let mut expected = BTreeMap::new();
    for host in &want {
        let q = VulnQuery {
            host: Some(host),
            ..common::vulns::every()
        };
        for r in common::vulns::run(c, &q, &AgentScope::Global).await.rows {
            *expected.entry(r.key).or_insert(0) += r.total;
        }
    }
    let got: BTreeMap<String, i64> = common::vulns::run(c, &common::vulns::every(), &scope)
        .await
        .rows
        .into_iter()
        .map(|r| (r.key, r.total))
        .collect();
    assert_eq!(got, expected, "vulnerabilities after {step}");
}

#[tokio::test]
async fn scoped_lists_reach_the_hosts_the_rule_puts_in_scope() {
    let (db, c) = common::migrated().await;
    let (_, alpha) = common::vulns::fixture(&c).await;
    let fedora = common::rule_group(&c, "Fedora", &[("distribution", false, &["fedora 44"])]).await;
    for n in 1..=4 {
        common::seed_alarm(&c, id(n), "high", "open").await;
    }
    let groups = [alpha, fedora];
    lists_match(&c, &groups, "setup").await;
    run(
        &c,
        &format!(
            "UPDATE agents SET os_id = 'fedora', os_version = '44' WHERE agent_id = '{}'",
            id(4)
        ),
    )
    .await;
    assert_eq!(in_scope(&c, &groups).await.len(), 3);
    lists_match(&c, &groups, "a host joins").await;
    run(
        &c,
        &format!(
            "UPDATE agents SET status = 'revoked', revoked_at = now() WHERE agent_id = '{}'",
            id(3)
        ),
    )
    .await;
    lists_match(&c, &groups, "a host is revoked").await;
    db.drop().await;
}

/// Advisory locks on `key` held (`true`) or awaited (`false`) by other
/// backends in this test's database (tests run in parallel).
async fn others_on(c: &Client, key: i64) -> Vec<bool> {
    c.query(
        "SELECT granted FROM pg_locks WHERE locktype = 'advisory' AND pid <> pg_backend_pid()
           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
           AND classid = ($1::bigint >> 32)::oid AND objid = ($1::bigint & 4294967295)::oid",
        &[&key],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

/// An inventory whose OS changed holds the membership lock from its agents
/// UPDATE and then takes AUTO_GROUP_LOCK; one that only makes an automatic
/// group must take them in the same order, or the two deadlock.
#[tokio::test]
async fn making_an_automatic_group_takes_the_membership_lock_first() {
    const AUTO_GROUP_LOCK: i64 = 0x4F56_4847;
    let (db, c) = common::migrated().await;
    c.batch_execute(&format!(
        "BEGIN; SELECT pg_advisory_xact_lock({MEMBERSHIP_LOCK})"
    ))
    .await
    .unwrap();
    let pool = db.pool.clone();
    let maker = tokio::spawn(async move {
        let mut a = pool.get().await.unwrap();
        let tx = a.transaction().await.unwrap();
        ensure_automatic_groups(&tx, "linux", "debian 12", Utc::now())
            .await
            .unwrap();
        tx.commit().await.unwrap();
    });
    let mut waiting = Vec::new();
    for _ in 0..100 {
        waiting = others_on(&c, MEMBERSHIP_LOCK).await;
        if waiting == [false] {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(waiting, [false], "the maker waits for the membership lock");
    assert!(
        others_on(&c, AUTO_GROUP_LOCK).await.is_empty(),
        "without holding AUTO_GROUP_LOCK"
    );
    c.batch_execute("COMMIT").await.unwrap();
    maker.await.unwrap();
    assert_eq!(same(&c, "automatic groups made").await, 0);
    let made: i64 = c
        .query_one(
            "SELECT count(*) FROM console_asset_groups WHERE kind = 'automatic'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(made, 2);
    db.drop().await;
}
