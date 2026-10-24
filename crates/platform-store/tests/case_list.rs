//! The Cases list query (roles plan 2026-10-25 step 5d, rulings 2, 4, 6–10):
//! rows, total, per-value counts and the summary line, inside the viewer's
//! scope. The fixture's clock is fixed at 2026-10-25 12:00 UTC.

mod common;

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

#[tokio::test]
async fn rows_carry_the_ruling_9_fields() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    let page = run(&c, &query(), &AgentScope::Global).await;
    assert_eq!(ids(&page), [1, 2, 3, 4, 5, 6]);
    assert_eq!(page.total, 6);
    let one = row(&page, 1);
    assert_eq!(one.title, "SSH brute force");
    assert_eq!(
        (one.status.as_str(), one.severity.as_str()),
        ("open", "high")
    );
    assert_eq!(one.opened_by.display_name, "Ann");
    assert_eq!(one.assignee.as_ref().unwrap().display_name, "Bob");
    let hosts: Vec<_> = one.hosts.iter().map(|h| h.1.as_deref()).collect();
    assert_eq!(hosts, [Some("db-02"), Some("web-01")], "by host name");
    assert_eq!(
        (one.kinds.alarms, one.kinds.vulnerabilities, one.kinds.hosts),
        (1, 1, 1)
    );
    assert_eq!(one.updated_at, now() - chrono::Duration::hours(1));
    assert!(row(&page, 4).hosts.is_empty());
    assert!(row(&page, 4).assignee.is_none());
    db.drop().await;
}

#[tokio::test]
async fn the_latest_note_previews_120_characters() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    let page = run(&c, &query(), &AgentScope::Global).await;
    let note = row(&page, 1).latest_note.as_ref().unwrap();
    assert_eq!(note.text, format!("{}yz", "x".repeat(118)));
    assert_eq!(
        note.at,
        now() - chrono::Duration::hours(2),
        "not the status event"
    );
    assert!(row(&page, 2).latest_note.is_none());
    db.drop().await;
}

#[tokio::test]
async fn n_of_m_counts_only_outcome_taking_items() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    let page = run(&c, &query(), &AgentScope::Global).await;
    let six = row(&page, 6);
    assert_eq!(
        (six.with_outcome, six.takes_outcome),
        (1, 2),
        "software is context"
    );
    assert_eq!((six.kinds.software, six.kinds.findings), (1, 1));
    assert_eq!(
        (row(&page, 1).with_outcome, row(&page, 1).takes_outcome),
        (1, 2)
    );
    assert_eq!(
        (row(&page, 4).with_outcome, row(&page, 4).takes_outcome),
        (0, 0)
    );
    db.drop().await;
}

#[tokio::test]
async fn case_list_counts_stay_inside_the_scope() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let page = run(&c, &query(), &web_only(&web)).await;
    // 3 (db-02 only) and 4 (empty, not all hosts) are not seen; 5 is Ann's.
    assert_eq!(ids(&page), [1, 2, 5, 6]);
    let one = row(&page, 1);
    let hosts: Vec<_> = one.hosts.iter().map(|h| h.0.as_str()).collect();
    assert_eq!(hosts, [A1], "db-02 is never named");
    assert_eq!((one.with_outcome, one.takes_outcome), (1, 1));
    assert_eq!(one.kinds.vulnerabilities, 0);
    let five = row(&page, 5);
    assert_eq!((five.takes_outcome, five.kinds.findings), (0, 0));
    assert!(five.hosts.is_empty());
    let groups: Vec<_> = page.counts.groups.iter().map(|g| g.1.as_str()).collect();
    assert_eq!(groups, ["Web"], "Db is never named");
    assert_eq!(page.counts.groups[0].3, 3, "1, 2 and 6");
    let contains = &page.counts.contains;
    assert_eq!(
        contains,
        &[
            (CaseContains::Alarms, 2),
            (CaseContains::Vulnerabilities, 1),
            (CaseContains::Findings, 1)
        ]
    );
    assert_eq!(
        page.summary,
        CaseSummaryLine {
            open: 2,
            investigating: 1,
            unassigned: 0,
            ready_to_close: 2
        },
        "1 (its hidden vulnerability aside) and 5 (no visible item) are ready"
    );
    let people: Vec<_> = page
        .counts
        .people
        .iter()
        .map(|p| (p.1.as_str(), p.2))
        .collect();
    assert_eq!(people, [("Ann", 2), ("Bob", 1)]);
    db.drop().await;
}

#[tokio::test]
async fn the_summary_line_counts_active_cases() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    let page = run(
        &c,
        &CaseQuery {
            status: CaseStatus::Closed,
            ..query()
        },
        &AgentScope::Global,
    )
    .await;
    assert_eq!(ids(&page), [2]);
    assert_eq!(
        page.summary,
        CaseSummaryLine {
            open: 3,
            investigating: 2,
            unassigned: 2,
            ready_to_close: 1
        },
        "every status: 4 (empty) is ready"
    );
    db.drop().await;
}

#[tokio::test]
async fn every_filter_counts_with_the_others_applied() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let g = AgentScope::Global;
    let page = run(
        &c,
        &CaseQuery {
            status: CaseStatus::Active,
            ..query()
        },
        &g,
    )
    .await;
    assert_eq!(ids(&page), [1, 3, 4, 5, 6], "active is not closed");
    assert_eq!(
        page.counts.status,
        [
            (CaseStatus::Active, 5),
            (CaseStatus::Open, 3),
            (CaseStatus::Investigating, 2),
            (CaseStatus::Closed, 1),
            (CaseStatus::All, 6)
        ]
    );
    let alarms = CaseQuery {
        contains: Some(CaseContains::Alarms),
        ..query()
    };
    let page = run(&c, &alarms, &g).await;
    assert_eq!(ids(&page), [1, 3, 6]);
    assert_eq!(
        page.counts.severity,
        [
            (CaseSeverity::Critical, 1),
            (CaseSeverity::High, 2),
            (CaseSeverity::Medium, 0),
            (CaseSeverity::Low, 0)
        ]
    );
    let high = CaseQuery {
        severity: Some(CaseSeverity::High),
        ..query()
    };
    assert_eq!(ids(&run(&c, &high, &g).await), [1, 6]);
    let page = run(
        &c,
        &CaseQuery {
            assignee: Some(Assignee::Me),
            ..query()
        },
        &g,
    )
    .await;
    assert_eq!(ids(&page), [5, 6]);
    assert_eq!((page.counts.me, page.counts.unassigned), (2, 3));
    let un = CaseQuery {
        assignee: Some(Assignee::Unassigned),
        ..query()
    };
    assert_eq!(ids(&run(&c, &un, &g).await), [2, 3, 4]);
    let bob = CaseQuery {
        assignee: Some(Assignee::User(BOB)),
        ..query()
    };
    assert_eq!(ids(&run(&c, &bob, &g).await), [1]);
    let junk = CaseQuery {
        assignee: Some(Assignee::User("nope")),
        ..query()
    };
    assert_eq!(ids(&run(&c, &junk, &g).await), Vec::<u8>::new());
    let page = run(
        &c,
        &CaseQuery {
            updated: Some(CaseUpdated::Today),
            ..query()
        },
        &g,
    )
    .await;
    assert_eq!(ids(&page), [1, 5], "3 was yesterday (UTC)");
    assert_eq!(
        page.counts.updated,
        [
            (CaseUpdated::Today, 2),
            (CaseUpdated::Week, 4),
            (CaseUpdated::Quiet, 2)
        ]
    );
    let quiet = CaseQuery {
        updated: Some(CaseUpdated::Quiet),
        ..query()
    };
    assert_eq!(ids(&run(&c, &quiet, &g).await), [2, 4]);
    let on_web = CaseQuery {
        host: Some(A1),
        ..query()
    };
    assert_eq!(ids(&run(&c, &on_web, &g).await), [1, 2]);
    let in_web = CaseQuery {
        group: Some(&web),
        ..query()
    };
    let page = run(&c, &in_web, &g).await;
    assert_eq!(ids(&page), [1, 2, 6]);
    let groups: Vec<_> = page
        .counts
        .groups
        .iter()
        .map(|g| (g.1.as_str(), g.3))
        .collect();
    assert_eq!(
        groups,
        [("Db", 3), ("Web", 3)],
        "the group's own filter left out"
    );
    assert_eq!(
        page.counts.status[0],
        (CaseStatus::Active, 2),
        "1 and 6 in Web"
    );
    let both = CaseQuery {
        group: Some(&web),
        contains: Some(CaseContains::Findings),
        ..query()
    };
    assert_eq!(ids(&run(&c, &both, &g).await), [6]);
    db.drop().await;
}

#[tokio::test]
async fn search_covers_title_number_and_opener() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    let g = AgentScope::Global;
    let number: i64 = c
        .query_one(
            "SELECT number FROM cases WHERE case_id = $1::text::uuid",
            &[&case_id(3)],
        )
        .await
        .unwrap()
        .get(0);
    let search = |q| CaseQuery {
        q: Some(q),
        ..query()
    };
    assert_eq!(ids(&run(&c, &search("brute"), &g).await), [1]);
    let (prefixed, bare) = (format!("C-{number}"), number.to_string());
    assert_eq!(ids(&run(&c, &search(&prefixed), &g).await), [3]);
    assert_eq!(ids(&run(&c, &search(&bare), &g).await), [3]);
    assert_eq!(
        ids(&run(&c, &search("cat"), &g).await),
        [6],
        "the opener's name"
    );
    assert_eq!(
        ids(&run(&c, &search("  "), &g).await).len(),
        6,
        "blank is no search"
    );
    db.drop().await;
}

#[tokio::test]
async fn every_sort_pages_stably() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    let g = AgentScope::Global;
    for (sort, descending, want) in [
        (CaseSort::Updated, true, [1, 5, 3, 6, 4, 2]),
        (CaseSort::Updated, false, [2, 4, 6, 3, 5, 1]),
        (CaseSort::Severity, true, [3, 6, 1, 5, 2, 4]),
        (CaseSort::Severity, false, [4, 2, 5, 1, 6, 3]),
        (CaseSort::Number, true, [6, 5, 4, 3, 2, 1]),
        (CaseSort::Opened, false, [1, 2, 3, 4, 5, 6]),
    ] {
        let q = CaseQuery {
            sort,
            descending,
            ..query()
        };
        assert_eq!(ids(&run(&c, &q, &g).await), want, "{sort:?} {descending}");
        let mut paged = Vec::new();
        for offset in [0, 2, 4] {
            let page = run(
                &c,
                &CaseQuery {
                    offset,
                    limit: 2,
                    ..q.clone()
                },
                &g,
            )
            .await;
            assert_eq!(page.total, 6);
            paged.extend(ids(&page));
        }
        assert_eq!(paged, want, "paged {sort:?} {descending}");
    }
    let past = run(
        &c,
        &CaseQuery {
            offset: 10,
            ..query()
        },
        &g,
    )
    .await;
    assert!(past.rows.is_empty());
    assert_eq!(
        (past.total, past.summary.open),
        (6, 3),
        "the meta without rows"
    );
    db.drop().await;
}
