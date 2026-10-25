//! A case's page summary (roles plan 2026-10-25 step 5d, rulings 2, 4,
//! 10, 12, 13; Review Focus 1): tiles, hosts with their problems and who
//! can see it, never counting or naming what is out of the viewer's reach.

mod common;

use chrono::Utc;
use common::groups::{bind, group_role, person};
use platform_store::{
    Client,
    case_summary::{CasePageSummary, case_summary, case_visible_to},
    console_read::AgentScope,
    host_list::HostScopes,
};

const ANN: &str = "00000000-0000-4000-8000-0000000000a1"; // creator
const BOB: &str = "00000000-0000-4000-8000-0000000000b2"; // assignee
const CAT: &str = "00000000-0000-4000-8000-0000000000c3"; // cases.read on Web
const DAN: &str = "00000000-0000-4000-8000-0000000000d4"; // cases.read everywhere
const EVE: &str = "00000000-0000-4000-8000-0000000000e5"; // cases.read on Db
const FAY: &str = "00000000-0000-4000-8000-0000000000f6"; // disabled, everywhere
const GUS: &str = "00000000-0000-4000-8000-0000000000a7"; // revoked, everywhere
const HAL: &str = "00000000-0000-4000-8000-0000000000a8"; // hosts.read only, everywhere
const A1: &str = "agent.00000000-0000-4000-8000-000000000001"; // web-01, in Web
const A2: &str = "agent.00000000-0000-4000-8000-000000000002"; // db-02, in Db
const CASE: &str = "00000000-0000-4000-8000-0000000000e1";
const GLOBAL: AgentScope = AgentScope::Global;

struct Fx {
    web: AgentScope,
    db: AgentScope,
}

/// web-01 (2 open alarms, 3 critical, 1 failing check) in Web, db-02 (1
/// open alarm) in Db. Ann's open case for Bob holds an alarm on web-01
/// (no outcome), a vulnerability on db-02 (no outcome) and software.
async fn fixture(c: &Client) -> Fx {
    for (id, name, enabled) in [
        (ANN, "ann", true),
        (BOB, "bob", true),
        (CAT, "cat", true),
        (DAN, "dan", true),
        (EVE, "eve", true),
        (FAY, "fay", false),
        (GUS, "gus", true),
        (HAL, "hal", true),
    ] {
        person(c, id, name, enabled).await;
    }
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname, os_id, os_version) VALUES
           ('{A1}', 'active', now(), now(), 'web-01', 'debian', '12'),
           ('{A2}', 'active', now(), now(), 'db-02', 'fedora', '44');
         INSERT INTO cases (case_id, title, status, severity, assignee_user_id, opened_by_user_id,
                            created_at, updated_at)
         VALUES ('{CASE}', 'Telnet', 'open', 'high', '{BOB}', '{ANN}', now() - interval '1 hour', now());
         INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, added_by_user_id, added_at)
         VALUES (gen_random_uuid(), '{CASE}', 'alarm', '7', '{A1}', '{ANN}', now()),
                (gen_random_uuid(), '{CASE}', 'vulnerability', '{A2}/CVE-1', '{A2}', '{ANN}', now()),
                (gen_random_uuid(), '{CASE}', 'software', 'rpm/telnet', NULL, '{ANN}', now());"
    ))
    .await
    .unwrap();
    for _ in 0..2 {
        common::seed_alarm(c, A1, "high", "open").await;
    }
    common::seed_alarm(c, A1, "high", "mitigated").await;
    common::seed_alarm(c, A2, "low", "open").await;
    common::seed_host_vuln_counts(c, A1, 3, 0, 0, 0).await;
    common::seed_current_finding(c, A1, "high").await;
    let web = common::manual_group(c, "Web", &[A1]).await;
    let db = common::manual_group(c, "Db", &[A2]).await;
    common::seed_role(c, "everywhere", &["cases.read"]).await;
    common::seed_role(c, "hosts_only", &["hosts.read"]).await;
    group_role(c, "web_cases", &web).await;
    group_role(c, "db_cases", &db).await;
    c.batch_execute(
        "INSERT INTO console_role_permissions (role_id, permission_id)
         VALUES ('web_cases', 'cases.read'), ('db_cases', 'cases.read')",
    )
    .await
    .unwrap();
    for (user, role) in [
        (CAT, "web_cases"),
        (DAN, "everywhere"),
        (EVE, "db_cases"),
        (FAY, "everywhere"),
        (GUS, "everywhere"),
        (HAL, "hosts_only"),
    ] {
        bind(c, user, role).await;
    }
    c.execute(
        "UPDATE console_role_bindings SET revoked_at = now(), revoked_by = 't' WHERE user_id = $1::text::uuid",
        &[&GUS],
    )
    .await
    .unwrap();
    Fx {
        web: AgentScope::AssetGroups(vec![web]),
        db: AgentScope::AssetGroups(vec![db]),
    }
}

fn every_kind(cases: &AgentScope) -> HostScopes<'_> {
    HostScopes {
        hosts: cases,
        alarms: Some(&GLOBAL),
        vulnerabilities: Some(&GLOBAL),
        compliance: Some(&GLOBAL),
    }
}

async fn get(c: &Client, scopes: &HostScopes<'_>, user: &str) -> Option<CasePageSummary> {
    case_summary(c, CASE, scopes, user, Utc::now())
        .await
        .unwrap()
}

fn names(s: &CasePageSummary) -> Vec<&str> {
    s.people.names.iter().map(|u| u.username.as_str()).collect()
}

fn hosts(s: &CasePageSummary) -> Vec<&str> {
    s.hosts.iter().map(|h| h.agent_id.as_str()).collect()
}

#[tokio::test]
async fn case_summary_stays_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let fx = fixture(&c).await;
    // Cat reads cases on Web: db-02's vulnerability is out of reach.
    let s = get(&c, &every_kind(&fx.web), CAT).await.unwrap();
    assert_eq!(s.case.items, 2, "the alarm and the software");
    assert_eq!(
        s.case.pending_items, 1,
        "the hidden vulnerability is not counted"
    );
    assert!(!s.ready, "but it still blocks closing");
    assert_eq!(hosts(&s), [A1]);
    assert_eq!(s.hosts[0].hostname.as_deref(), Some("web-01"));
    assert_eq!(s.hosts[0].os_id.as_deref(), Some("debian"));
    // Eve reaches the case only through db-02, which Cat cannot see.
    assert_eq!(names(&s), ["ann", "bob", "cat", "dan"]);
    assert_eq!(s.people.total, 4);

    let s = get(&c, &every_kind(&GLOBAL), DAN).await.unwrap();
    assert_eq!((s.case.items, s.case.pending_items), (3, 2));
    assert_eq!(hosts(&s), [A2, A1], "by host name");
    assert_eq!(names(&s), ["ann", "bob", "cat", "dan", "eve"]);

    // Outside the case's reach it reads as absent; its people still see it.
    let nowhere = AgentScope::AssetGroups(vec![]);
    assert!(get(&c, &every_kind(&nowhere), CAT).await.is_none());
    assert!(get(&c, &every_kind(&nowhere), BOB).await.is_some());
    assert!(get(&c, &every_kind(&fx.db), EVE).await.is_some());
    assert!(!case_visible_to(&c, &nowhere, CAT, CASE).await.unwrap());
    assert!(case_visible_to(&c, &fx.web, CAT, CASE).await.unwrap());
    assert!(case_visible_to(&c, &nowhere, ANN, CASE).await.unwrap());
    assert!(
        !case_visible_to(&c, &GLOBAL, CAT, "not-a-uuid")
            .await
            .unwrap()
    );
    db.drop().await;
}

#[tokio::test]
async fn host_problems_only_for_kinds_the_viewer_reads() {
    let (db, c) = common::migrated().await;
    let fx = fixture(&c).await;
    let s = get(&c, &every_kind(&GLOBAL), DAN).await.unwrap();
    let web = &s.hosts[1].problems;
    assert_eq!(
        (web.alarms, web.critical_vulns, web.failing_checks),
        (Some(2), Some(3), Some(1))
    );
    let db_host = &s.hosts[0].problems;
    assert_eq!(
        (
            db_host.alarms,
            db_host.critical_vulns,
            db_host.failing_checks
        ),
        (Some(1), Some(0), Some(0))
    );
    // Alarms everywhere, vulnerabilities nowhere, compliance on Web only.
    let partial = HostScopes {
        hosts: &GLOBAL,
        alarms: Some(&GLOBAL),
        vulnerabilities: None,
        compliance: Some(&fx.web),
    };
    let s = get(&c, &partial, DAN).await.unwrap();
    let (db_host, web) = (&s.hosts[0].problems, &s.hosts[1].problems);
    assert_eq!(
        (web.alarms, web.critical_vulns, web.failing_checks),
        (Some(2), None, Some(1))
    );
    assert_eq!(
        (
            db_host.alarms,
            db_host.critical_vulns,
            db_host.failing_checks
        ),
        (Some(1), None, None)
    );
    db.drop().await;
}

#[tokio::test]
async fn people_are_at_most_twenty_with_the_total() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    for n in 0..25u8 {
        let id = format!("00000000-0000-4000-8000-0000000001{n:02}");
        person(&c, &id, &format!("zz{n:02}"), true).await;
        bind(&c, &id, "everywhere").await;
    }
    let s = get(&c, &every_kind(&GLOBAL), DAN).await.unwrap();
    assert_eq!(s.people.names.len(), 20);
    assert_eq!(s.people.total, 30, "ann, bob, cat, dan, eve and 25 more");
    assert_eq!(&names(&s)[..5], ["ann", "bob", "cat", "dan", "eve"]);
    db.drop().await;
}

#[tokio::test]
async fn tiles_open_and_closed() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    let s = get(&c, &every_kind(&GLOBAL), DAN).await.unwrap();
    assert!(s.case.closed_at.is_none());
    assert!(
        (3590..3700).contains(&s.open_for_seconds),
        "{}",
        s.open_for_seconds
    );
    // Every item has its outcome: ready (the vulnerability's evidence is gone).
    c.execute(
        "UPDATE case_items SET outcome = CASE kind WHEN 'alarm' THEN 'false_positive'
                                                  ELSE 'resolved' END,
                               outcome_note = 'n'
         WHERE kind <> 'software'",
        &[],
    )
    .await
    .unwrap();
    let s = get(&c, &every_kind(&GLOBAL), DAN).await.unwrap();
    assert!(s.ready);
    assert_eq!(s.case.pending_items, 0);
    c.execute(
        "UPDATE cases SET status = 'closed', closed_at = created_at + interval '30 minutes',
                          resolution = 'mitigated', resolution_note = 'patched'",
        &[],
    )
    .await
    .unwrap();
    let s = get(&c, &every_kind(&GLOBAL), DAN).await.unwrap();
    assert!(!s.ready, "a closed case is not ready to close");
    assert_eq!(s.open_for_seconds, 1800);
    assert_eq!(s.resolution_note.as_deref(), Some("patched"));
    assert_eq!(s.case.resolution.as_deref(), Some("mitigated"));
    db.drop().await;
}

#[tokio::test]
async fn a_hostless_case_is_seen_by_all_hosts_readers_only() {
    let (db, c) = common::migrated().await;
    let fx = fixture(&c).await;
    c.execute("DELETE FROM case_items WHERE agent_id IS NOT NULL", &[])
        .await
        .unwrap();
    let s = get(&c, &every_kind(&GLOBAL), DAN).await.unwrap();
    assert_eq!(names(&s), ["ann", "bob", "dan"]);
    assert!(s.hosts.is_empty());
    assert!(get(&c, &every_kind(&fx.web), CAT).await.is_none());
    db.drop().await;
}
