//! Hosts decide who sees a case (user decision 2026-10-25): a hostless
//! (software) item never makes a case visible, through the Cases list and
//! every `console_cases` read; "ready to close" follows close's own rule;
//! a row names at most five hosts.

mod common;

use chrono::Utc;
use common::groups::person;
use platform_store::{
    Client,
    case_list::{CaseListPage, CaseQuery, CaseSort, CaseStatus, case_list},
    console_cases,
    console_read::AgentScope,
};

const ANN: &str = "00000000-0000-4000-8000-0000000000a1"; // creator
const BOB: &str = "00000000-0000-4000-8000-0000000000b2"; // assignee
const CAT: &str = "00000000-0000-4000-8000-0000000000c3"; // a reader
const A1: &str = "agent.00000000-0000-4000-8000-000000000001"; // in Web
const A2: &str = "agent.00000000-0000-4000-8000-000000000002"; // not
const CASE: &str = "00000000-0000-4000-8000-0000000000e1";

/// Web holds web-01; db-02 is in no group. One open case by Ann for Bob
/// holding `items` (kind, ref, agent, outcome).
async fn fixture(c: &Client, items: &[(&str, &str, Option<&str>, Option<&str>)]) -> AgentScope {
    for (id, name) in [(ANN, "ann"), (BOB, "bob"), (CAT, "cat")] {
        person(c, id, name, true).await;
    }
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname) VALUES
           ('{A1}', 'active', now(), now(), 'web-01'), ('{A2}', 'active', now(), now(), 'db-02');
         INSERT INTO cases (case_id, title, status, severity, assignee_user_id, opened_by_user_id,
                            created_at, updated_at)
         VALUES ('{CASE}', 'Telnet', 'open', 'high', '{BOB}', '{ANN}', now(), now());"
    ))
    .await
    .unwrap();
    for (kind, reference, agent, outcome) in items {
        c.execute(
            "INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, outcome, added_by_user_id, added_at)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, $3, $4, $5, $6::text::uuid, now())",
            &[&CASE, kind, reference, agent, outcome, &ANN],
        )
        .await
        .unwrap();
    }
    AgentScope::AssetGroups(vec![common::manual_group(c, "Web", &[A1]).await])
}

async fn list(c: &Client, scope: &AgentScope, user: &str) -> CaseListPage {
    let q = CaseQuery {
        q: None,
        status: CaseStatus::All,
        severity: None,
        assignee: None,
        contains: None,
        host: None,
        group: None,
        updated: None,
        sort: CaseSort::Number,
        descending: false,
        offset: 0,
        limit: 50,
    };
    case_list(c, &q, scope, user, Utc::now()).await.unwrap()
}

/// Whether `user` in `scope` sees the case: the list, `get` and `for_item`
/// on its software item agree.
async fn sees(c: &Client, scope: &AgentScope, user: &str) -> bool {
    let listed = list(c, scope, user).await.total == 1;
    let got = console_cases::get(c, scope, user, CASE)
        .await
        .unwrap()
        .is_some();
    let held = !console_cases::for_item(c, scope, user, "software", "rpm/telnet")
        .await
        .unwrap()
        .unwrap()
        .is_empty();
    assert_eq!(
        (listed, got),
        (got, held),
        "list, get and for_item disagree"
    );
    listed
}

const SOFTWARE: (&str, &str, Option<&str>, Option<&str>) = ("software", "rpm/telnet", None, None);

#[tokio::test]
async fn a_software_only_case_is_seen_like_an_empty_one() {
    let (db, c) = common::migrated().await;
    let web = fixture(&c, &[SOFTWARE]).await;
    assert!(
        !sees(&c, &web, CAT).await,
        "software never makes a case visible"
    );
    assert!(sees(&c, &web, ANN).await, "its creator");
    assert!(sees(&c, &web, BOB).await, "its assignee");
    assert!(
        sees(&c, &AgentScope::Global, CAT).await,
        "an all-hosts reader"
    );
    db.drop().await;
}

#[tokio::test]
async fn software_and_a_hidden_alarm_stay_hidden() {
    let (db, c) = common::migrated().await;
    let web = fixture(&c, &[SOFTWARE, ("alarm", "7", Some(A2), None)]).await;
    assert!(!sees(&c, &web, CAT).await);
    assert!(
        sees(&c, &AgentScope::Global, CAT).await,
        "db-02 is in a global scope"
    );
    db.drop().await;
}

/// A port is fleet-wide like software: it never makes a case visible...
#[tokio::test]
async fn a_port_only_case_is_hidden_from_a_scoped_viewer() {
    let (db, c) = common::migrated().await;
    let web = fixture(&c, &[("port", "tcp/22", None, None)]).await;
    assert_eq!(list(&c, &web, CAT).await.total, 0);
    assert!(
        console_cases::get(&c, &web, CAT, CASE)
            .await
            .unwrap()
            .is_none()
    );
    db.drop().await;
}

/// ...but it counts when a visible alarm shows the case.
#[tokio::test]
async fn a_port_counts_beside_a_visible_alarm() {
    let (db, c) = common::migrated().await;
    let web = fixture(
        &c,
        &[
            ("port", "tcp/22", None, None),
            ("alarm", "7", Some(A1), None),
        ],
    )
    .await;
    let page = list(&c, &web, CAT).await;
    assert_eq!(
        (page.rows[0].kinds.ports, page.rows[0].kinds.alarms),
        (1, 1)
    );
    db.drop().await;
}

/// A service is fleet-wide like a port: it never makes a case visible...
#[tokio::test]
async fn a_service_only_case_is_hidden_from_a_scoped_viewer() {
    let (db, c) = common::migrated().await;
    let web = fixture(&c, &[("service", "sshd.service", None, None)]).await;
    assert_eq!(list(&c, &web, CAT).await.total, 0);
    db.drop().await;
}

/// ...but it counts when a visible alarm shows the case.
#[tokio::test]
async fn a_service_counts_beside_a_visible_alarm() {
    let (db, c) = common::migrated().await;
    let web = fixture(
        &c,
        &[
            ("service", "sshd.service", None, None),
            ("alarm", "7", Some(A1), None),
        ],
    )
    .await;
    let page = list(&c, &web, CAT).await;
    assert_eq!(
        (page.rows[0].kinds.services, page.rows[0].kinds.alarms),
        (1, 1)
    );
    db.drop().await;
}

#[tokio::test]
async fn software_and_a_visible_alarm_show_the_software() {
    let (db, c) = common::migrated().await;
    let web = fixture(&c, &[SOFTWARE, ("alarm", "7", Some(A1), None)]).await;
    assert!(sees(&c, &web, CAT).await);
    let page = list(&c, &web, CAT).await;
    assert_eq!(
        (page.rows[0].kinds.software, page.rows[0].kinds.alarms),
        (1, 1)
    );
    let detail = console_cases::get(&c, &web, CAT, CASE)
        .await
        .unwrap()
        .unwrap();
    let kinds: Vec<_> = detail.items.iter().map(|i| i.kind.as_str()).collect();
    assert_eq!(kinds, ["software", "alarm"]);
    db.drop().await;
}

#[tokio::test]
async fn ready_to_close_follows_close() {
    let (db, c) = common::migrated().await;
    let web = fixture(&c, &[]).await;
    common::seed_alarm(&c, A1, "high", "open").await;
    c.execute(
        "INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, outcome, added_by_user_id, added_at)
         SELECT gen_random_uuid(), $1::text::uuid, 'alarm', max(id)::text, $2, 'resolved', $3::text::uuid, now()
         FROM alarms",
        &[&CASE, &A1, &ANN],
    )
    .await
    .unwrap();
    let page = list(&c, &web, CAT).await;
    assert_eq!(
        (page.rows[0].with_outcome, page.rows[0].takes_outcome),
        (1, 1)
    );
    assert_eq!(
        (page.summary.ready_to_close, page.rows[0].ready),
        (0, false),
        "resolved, but the alarm is still open"
    );
    c.execute("UPDATE alarms SET state = 'mitigated'", &[])
        .await
        .unwrap();
    let page = list(&c, &web, CAT).await;
    assert_eq!(
        (page.summary.ready_to_close, page.rows[0].ready),
        (1, true),
        "evidence gone"
    );
    db.drop().await;
}

#[tokio::test]
async fn a_row_names_five_hosts_and_counts_them_all() {
    let (db, c) = common::migrated().await;
    fixture(&c, &[]).await;
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname)
         SELECT 'agent.00000000-0000-4000-8000-0000000001' || lpad(n::text, 2, '0'), 'active', now(), now(),
                'h-' || n FROM generate_series(1, 7) n;
         INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, added_by_user_id, added_at)
         SELECT gen_random_uuid(), '{CASE}', 'host', agent_id, agent_id, '{ANN}', now()
         FROM agents WHERE hostname LIKE 'h-%';"
    ))
    .await
    .unwrap();
    let page = list(&c, &AgentScope::Global, CAT).await;
    let names: Vec<_> = page.rows[0]
        .hosts
        .iter()
        .map(|h| h.1.as_deref().unwrap())
        .collect();
    assert_eq!(names, ["h-1", "h-2", "h-3", "h-4", "h-5"]);
    assert_eq!(page.rows[0].host_count, 7);
    db.drop().await;
}
