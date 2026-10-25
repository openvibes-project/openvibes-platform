//! The Cases list query (roles plan 2026-10-25 step 5d, rulings 2, 4, 6–10):
//! rows, total, per-value counts and the summary line, inside the viewer's
//! scope. The fixture's clock is fixed at 2026-10-25 12:00 UTC.

#[path = "../common/mod.rs"]
mod common;

mod filters;
mod rows;

use chrono::{DateTime, TimeZone, Utc};
use common::groups::person;
use platform_store::{
    Client,
    alarm_list::Assignee,
    case_list::{
        CaseContains, CaseListPage, CaseListRow, CaseQuery, CaseSeverity, CaseSort, CaseStatus,
        CaseSummaryLine, CaseUpdated, case_list,
    },
    console_read::AgentScope,
};

const ANN: &str = "00000000-0000-4000-8000-0000000000a1";
const BOB: &str = "00000000-0000-4000-8000-0000000000b2";
const CAT: &str = "00000000-0000-4000-8000-0000000000c3";
/// web-01 and mail-03 are in Web, db-02 in Db.
const A1: &str = "agent.00000000-0000-4000-8000-000000000001";
const A2: &str = "agent.00000000-0000-4000-8000-000000000002";
const A3: &str = "agent.00000000-0000-4000-8000-000000000003";

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 25, 12, 0, 0).unwrap()
}

fn case_id(n: u8) -> String {
    format!("00000000-0000-4000-8000-0000000000{n:02}")
}

/// Six cases (`case_id(1)`–`case_id(6)`, numbers in that order):
/// 1 "SSH brute force" open high by Ann for Bob: alarm web-01 (resolved),
///   vulnerability db-02, host web-01; two notes; updated an hour ago.
/// 2 "Old openssl" closed medium by Bob: vulnerability web-01 (false
///   positive); 10 days ago.
/// 3 "Beacon on db" investigating critical by Bob: alarm db-02; 13 hours
///   ago (yesterday).
/// 4 "Empty" open low by Bob, no items; 8 days ago.
/// 5 "Mine, hidden" open medium by Bob for Ann: finding db-02; 2 hours ago.
/// 6 "Telnet on mail" investigating high by Cat for Ann: finding mail-03
///   (expected), alarm mail-03, software; 2 days ago.
async fn fixture(c: &Client) -> (String, String) {
    for (id, name) in [(ANN, "ann"), (BOB, "bob"), (CAT, "cat")] {
        person(c, id, name, true).await;
    }
    c.batch_execute(&format!(
        "INSERT INTO agents (agent_id, status, enrolled_at, last_seen_at, hostname) VALUES
           ('{A1}', 'active', now(), now(), 'web-01'), ('{A2}', 'active', now(), now(), 'db-02'),
           ('{A3}', 'active', now(), now(), 'mail-03');"
    ))
    .await
    .unwrap();
    let web = common::manual_group(c, "Web", &[A1, A3]).await;
    let db = common::manual_group(c, "Db", &[A2]).await;
    let at = "'2026-10-25 12:00:00+00'::timestamptz";
    c.batch_execute(&format!(
        "INSERT INTO cases (case_id, title, status, resolution_note, closed_at, severity,
                            assignee_user_id, opened_by_user_id, created_at, updated_at)
         SELECT v.id::uuid, v.title, v.status, CASE WHEN v.status = 'closed' THEN 'done' END,
                CASE WHEN v.status = 'closed' THEN {at} END, v.sev, v.assignee::uuid, v.opener::uuid,
                {at} - make_interval(days => 30 - v.n), {at} - v.ago::interval
         FROM (VALUES
           (1, '{c1}', 'SSH brute force', 'open', 'high', '{BOB}', '{ANN}', '1 hour'),
           (2, '{c2}', 'Old openssl', 'closed', 'medium', NULL, '{BOB}', '10 days'),
           (3, '{c3}', 'Beacon on db', 'investigating', 'critical', NULL, '{BOB}', '13 hours'),
           (4, '{c4}', 'Empty', 'open', 'low', NULL, '{BOB}', '8 days'),
           (5, '{c5}', 'Mine, hidden', 'open', 'medium', '{ANN}', '{BOB}', '2 hours'),
           (6, '{c6}', 'Telnet on mail', 'investigating', 'high', '{ANN}', '{CAT}', '2 days'))
           v(n, id, title, status, sev, assignee, opener, ago)
         ORDER BY v.n;
         INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, outcome, outcome_note,
                                 added_by_user_id, added_at)
         SELECT gen_random_uuid(), v.c::uuid, v.kind, v.ref, v.agent, v.c <> '{c2}', v.outcome,
                CASE WHEN v.outcome NOT IN ('resolved') THEN 'why' END, '{BOB}', {at}
         FROM (VALUES
           ('{c1}', 'alarm', '11', '{A1}', 'resolved'),
           ('{c1}', 'vulnerability', '{A2}/FEDORA-1', '{A2}', NULL),
           ('{c1}', 'host', '{A1}', '{A1}', NULL),
           ('{c2}', 'vulnerability', '{A1}/FEDORA-2', '{A1}', 'false_positive'),
           ('{c3}', 'alarm', '33', '{A2}', NULL),
           ('{c5}', 'compliance_finding', '{A2}/baseline/ssh', '{A2}', NULL),
           ('{c6}', 'compliance_finding', '{A3}/baseline/telnet', '{A3}', 'expected'),
           ('{c6}', 'alarm', '66', '{A3}', NULL),
           ('{c6}', 'software', 'rpm/telnet', NULL, NULL)) v(c, kind, ref, agent, outcome);
         INSERT INTO case_events (case_id, at, actor_user_id, kind, body) VALUES
           ('{c1}', {at} - interval '3 hours', '{ANN}', 'note', 'first note'),
           ('{c1}', {at} - interval '2 hours', '{BOB}', 'note', repeat('x', 118) || 'yz-cut here'),
           ('{c1}', {at} - interval '1 hour', '{BOB}', 'status', NULL);",
        c1 = case_id(1),
        c2 = case_id(2),
        c3 = case_id(3),
        c4 = case_id(4),
        c5 = case_id(5),
        c6 = case_id(6),
    ))
    .await
    .unwrap();
    (web, db)
}

fn query() -> CaseQuery<'static> {
    CaseQuery {
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
    }
}

async fn run(c: &Client, q: &CaseQuery<'_>, scope: &AgentScope) -> CaseListPage {
    case_list(c, q, scope, ANN, now()).await.unwrap()
}

/// The page's case numbers, as fixture positions (case ids end in 01–06).
fn ids(page: &CaseListPage) -> Vec<u8> {
    page.rows
        .iter()
        .map(|r| r.case_id[34..].parse().unwrap())
        .collect()
}

fn row(page: &CaseListPage, n: u8) -> &CaseListRow {
    page.rows.iter().find(|r| r.case_id == case_id(n)).unwrap()
}

fn web_only(web: &str) -> AgentScope {
    AgentScope::AssetGroups(vec![web.to_owned()])
}
