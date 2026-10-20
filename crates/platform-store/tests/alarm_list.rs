//! The Alarms list query (roles spec §10.3; plan rulings 2–5): filters,
//! per-value counts with the other filters applied, search, the summary
//! line and offset paging, all inside the viewer's scope.

mod common;

use common::alarms::{ANN, BOB, CID, alarm_fleet, names, query, run};
use common::hosts::id;
use platform_store::{
    alarm_list::{AlarmQuery, AlarmSeverity, AlarmSort, AlarmState, Assignee},
    console_read::AgentScope,
};

const ALL: AgentScope = AgentScope::Global;

fn n<K: PartialEq>(values: &[(K, i64)], key: K) -> i64 {
    values
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(0, |(_, n)| *n)
}

#[tokio::test]
async fn each_filter_narrows_and_suppressed_is_hidden_by_default() {
    let (db, mut c) = common::migrated().await;
    let groups = alarm_fleet(&mut c).await;
    let every = AlarmQuery {
        state: None,
        ..query()
    };
    for (q, want) in [
        (query(), vec!["a1", "a4", "a2"]),
        (every.clone(), vec!["a1", "a4", "a2", "a3", "a6"]),
        (
            AlarmQuery {
                state: Some(AlarmState::Mitigated),
                ..query()
            },
            vec!["a3"],
        ),
        (
            AlarmQuery {
                severity: Some(AlarmSeverity::High),
                ..query()
            },
            vec!["a1"],
        ),
        (
            AlarmQuery {
                suppressed: true,
                ..query()
            },
            vec!["a1", "a4", "a2", "a5"],
        ),
        (
            AlarmQuery {
                host: Some(id(4)),
                ..every.clone()
            },
            vec!["a4", "a6"],
        ),
        (
            AlarmQuery {
                group: Some(&groups.web),
                ..query()
            },
            vec!["a1", "a2"],
        ),
        (
            AlarmQuery {
                technique: Some("T1059.004"),
                ..every.clone()
            },
            vec!["a1", "a3"],
        ),
        (
            AlarmQuery {
                technique: Some("T1059.001"),
                ..query()
            },
            vec!["a4"],
        ),
        (
            AlarmQuery {
                case: Some(true),
                ..query()
            },
            vec!["a1", "a4"],
        ),
        (
            AlarmQuery {
                case: Some(false),
                ..query()
            },
            vec!["a2"],
        ),
        (
            AlarmQuery {
                assignee: Some(Assignee::Me),
                ..query()
            },
            vec!["a1"],
        ),
        (
            AlarmQuery {
                assignee: Some(Assignee::Unassigned),
                ..query()
            },
            vec!["a2"],
        ),
        (
            AlarmQuery {
                assignee: Some(Assignee::User(BOB)),
                ..every.clone()
            },
            vec!["a3", "a6"],
        ),
        (
            AlarmQuery {
                assignee: Some(Assignee::User("not-a-uuid")),
                ..query()
            },
            vec![],
        ),
    ] {
        let page = run(&c, &q, &ALL).await;
        assert_eq!(names(&page), want, "{q:?}");
        assert_eq!(page.total, i64::try_from(want.len()).unwrap());
    }
    db.drop().await;
}

#[tokio::test]
async fn counts_apply_the_other_filters() {
    let (db, mut c) = common::migrated().await;
    let groups = alarm_fleet(&mut c).await;
    let page = run(&c, &query(), &ALL).await;
    let k = &page.counts;
    assert_eq!(n(&k.state, AlarmState::Open), 3);
    assert_eq!(n(&k.state, AlarmState::Mitigated), 1);
    assert_eq!(n(&k.state, AlarmState::FalsePositive), 1);
    assert_eq!(n(&k.state, AlarmState::AcceptedRisk), 0);
    assert_eq!(k.state.len(), 4);
    assert_eq!(n(&k.severity, AlarmSeverity::High), 1);
    assert_eq!(n(&k.severity, AlarmSeverity::Medium), 1);
    assert_eq!(n(&k.severity, AlarmSeverity::Low), 1);
    assert_eq!(n(&k.severity, AlarmSeverity::Critical), 0);
    assert_eq!(k.severity.len(), 5);
    assert_eq!((k.suppressed_hidden, k.suppressed_shown), (3, 4));
    assert_eq!((k.in_case, k.not_in_case), (2, 1));
    assert_eq!(
        k.techniques,
        [
            ("T1059.001".to_owned(), 1),
            ("T1059.004".to_owned(), 1),
            ("T1105".to_owned(), 1)
        ]
    );
    assert_eq!((k.me, k.unassigned), (1, 1));
    assert_eq!(
        k.people,
        [
            (ANN.to_owned(), "Ann".to_owned(), 1),
            (BOB.to_owned(), "Bob".to_owned(), 0),
            (CID.to_owned(), "Cid".to_owned(), 1),
        ]
    );
    let g: Vec<_> = k.groups.iter().map(|g| (g.1.as_str(), g.3)).collect();
    assert_eq!(
        g,
        [("Alpha", 2), ("Linux", 2), ("Web", 2), ("Windows box", 1)]
    );

    let q = AlarmQuery {
        severity: Some(AlarmSeverity::High),
        assignee: Some(Assignee::Me),
        group: Some(&groups.web),
        ..query()
    };
    let page = run(&c, &q, &ALL).await;
    assert_eq!(names(&page), ["a1"]);
    let k = &page.counts;
    // severity counts keep "me" and Web; assignee counts keep high and Web
    assert_eq!(n(&k.severity, AlarmSeverity::High), 1);
    assert_eq!(n(&k.severity, AlarmSeverity::Medium), 0);
    assert_eq!((k.me, k.unassigned), (1, 0));
    assert_eq!(n(&k.state, AlarmState::Open), 1);
    let windows = k.groups.iter().find(|g| g.1 == "Windows box").unwrap();
    assert_eq!(windows.3, 0);
    db.drop().await;
}

#[tokio::test]
async fn counts_and_values_stay_inside_the_scope() {
    let (db, mut c) = common::migrated().await;
    let groups = alarm_fleet(&mut c).await;
    let web = AgentScope::AssetGroups(vec![groups.web.clone()]);
    let page = run(&c, &query(), &web).await;
    assert_eq!(names(&page), ["a1", "a2"]);
    let k = &page.counts;
    assert_eq!(n(&k.state, AlarmState::Open), 2);
    assert_eq!(n(&k.state, AlarmState::Mitigated), 1);
    assert_eq!(n(&k.state, AlarmState::FalsePositive), 0);
    assert_eq!((k.suppressed_hidden, k.suppressed_shown), (2, 2));
    assert_eq!((k.in_case, k.not_in_case), (1, 1));
    let g: Vec<_> = k.groups.iter().map(|g| (g.1.as_str(), g.3)).collect();
    assert_eq!(g, [("Alpha", 2), ("Linux", 2), ("Web", 2)]);
    let t: Vec<_> = k.techniques.iter().map(|t| t.0.as_str()).collect();
    assert_eq!(t, ["T1059.004", "T1105"]);
    let p: Vec<_> = k.people.iter().map(|p| p.1.as_str()).collect();
    assert_eq!(p, ["Ann", "Bob"]);
    assert_eq!(page.summary.open, 2);
    assert_eq!(page.summary.on_alarms_off_hosts, 0);

    for q in [
        AlarmQuery {
            group: Some(&groups.windows),
            ..query()
        },
        AlarmQuery {
            host: Some(id(4)),
            ..query()
        },
        AlarmQuery {
            assignee: Some(Assignee::User(CID)),
            ..query()
        },
    ] {
        let page = run(&c, &q, &web).await;
        assert_eq!(page.total, 0, "{q:?}");
        assert!(page.counts.groups.iter().all(|g| g.1 != "Windows box"));
        assert!(page.counts.people.iter().all(|p| p.1 != "Cid"));
    }

    // a rule group's scope: Linux holds web-01, web-02, db-01 (a5 suppressed)
    let linux: String = c
        .query_one(
            "SELECT asset_group_id::text FROM console_asset_groups WHERE name = 'Linux'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let linux = AgentScope::AssetGroups(vec![linux]);
    let page = run(
        &c,
        &AlarmQuery {
            suppressed: true,
            ..query()
        },
        &linux,
    )
    .await;
    assert_eq!(names(&page), ["a1", "a2", "a5"]);
    db.drop().await;
}

#[tokio::test]
async fn search_covers_message_rule_host_and_programs() {
    let (db, mut c) = common::migrated().await;
    alarm_fleet(&mut c).await;
    for (q, want) in [
        ("A2", vec!["a2"]),
        ("ENCODED", vec!["a4"]),
        ("win-01", vec!["a4"]),
        ("nginx", vec!["a1"]),
        ("systemd", vec!["a1"]),
        ("fish", vec!["a2"]),
        ("dev", vec![]),
        ("  ", vec!["a1", "a4", "a2"]),
    ] {
        let page = run(
            &c,
            &AlarmQuery {
                q: Some(q),
                ..query()
            },
            &ALL,
        )
        .await;
        assert_eq!(names(&page), want, "q {q}");
    }
    db.drop().await;
}

#[tokio::test]
async fn every_sort_pages_stably_with_ties_by_id() {
    let (db, mut c) = common::migrated().await;
    alarm_fleet(&mut c).await;
    for (sort, newest_first) in [
        (AlarmSort::LastSeen, ["a1", "a4", "a2", "a3", "a5", "a6"]),
        (AlarmSort::FirstSeen, ["a4", "a5", "a2", "a1", "a3", "a6"]),
        (AlarmSort::Count, ["a3", "a6", "a1", "a4", "a5", "a2"]),
        (AlarmSort::Severity, ["a5", "a3", "a1", "a4", "a2", "a6"]),
    ] {
        for descending in [true, false] {
            let mut want = newest_first.to_vec();
            if !descending {
                want.reverse();
            }
            let mut got = Vec::new();
            for offset in [0, 2, 4, 6] {
                let q = AlarmQuery {
                    state: None,
                    suppressed: true,
                    sort,
                    descending,
                    offset,
                    limit: 2,
                    ..query()
                };
                let page = run(&c, &q, &ALL).await;
                assert_eq!(page.total, 6);
                got.extend(names(&page).into_iter().map(str::to_owned));
            }
            assert_eq!(got, want, "{sort:?} descending {descending}");
        }
    }
    db.drop().await;
}

#[tokio::test]
async fn rows_carry_host_techniques_case_and_assignee() {
    let (db, mut c) = common::migrated().await;
    alarm_fleet(&mut c).await;
    c.batch_execute("SET ROLE \"openvibes-console\"")
        .await
        .unwrap();
    let page = run(
        &c,
        &AlarmQuery {
            state: None,
            suppressed: true,
            ..query()
        },
        &ALL,
    )
    .await;
    let row = |name: &str| page.rows.iter().find(|r| r.message == name).unwrap();
    let a1 = row("a1");
    assert_eq!(a1.agent_id, id(1));
    assert_eq!(a1.hostname.as_deref(), Some("web-01"));
    assert_eq!(a1.os_family.as_deref(), Some("linux"));
    assert_eq!(a1.distribution.as_deref(), Some("Debian 12"));
    assert_eq!((a1.rule_set_id.as_str(), a1.rule_id.as_str()), ("rs", "r"));
    assert_eq!(a1.severity, AlarmSeverity::High);
    assert_eq!(a1.state, AlarmState::Open);
    assert_eq!(a1.exe, "/usr/sbin/nginx");
    assert_eq!(a1.parent_exe.as_deref(), Some("/usr/lib/systemd/systemd"));
    assert_eq!(a1.techniques, ["T1059.004", "T1105"]);
    assert_eq!(a1.count, 3);
    assert!(a1.first_seen < a1.last_seen);
    assert_eq!(a1.assignee, Some((ANN.to_owned(), "Ann".to_owned())));
    let (case_id, number) = a1.case.clone().unwrap();
    assert_eq!(case_id, "00000000-0000-0000-0000-0000000000c1");
    assert!(number > 0);
    assert_eq!(a1.suppressed_by, None);
    let a2 = row("a2");
    assert!(a2.techniques.is_empty(), "unindexed rule");
    assert_eq!((a2.assignee.clone(), a2.case.clone()), (None, None));
    assert!(row("a5").suppressed_by.is_some());
    assert!(page.rows.iter().all(|r| r.message != "dev"));
    assert_eq!(page.total, 6);
    db.drop().await;
}

#[tokio::test]
async fn summary_counts_open_severe_and_alarms_off_hosts() {
    let (db, mut c) = common::migrated().await;
    alarm_fleet(&mut c).await;
    let page = run(&c, &query(), &ALL).await;
    assert_eq!(page.summary.open, 3);
    assert_eq!(page.summary.critical_or_high, 1);
    // a4 on win-01, online with alarms off by a fault
    assert_eq!(page.summary.on_alarms_off_hosts, 1);
    let page = run(
        &c,
        &AlarmQuery {
            state: None,
            suppressed: true,
            ..query()
        },
        &ALL,
    )
    .await;
    assert_eq!(page.summary.open, 4);
    assert_eq!(page.summary.critical_or_high, 2);
    // offline: the host no longer counts
    c.batch_execute(&format!(
        "UPDATE agents SET last_seen_at = now() - interval '1 hour' WHERE agent_id = '{}';
         DELETE FROM agent_presence;",
        id(4)
    ))
    .await
    .unwrap();
    let page = run(&c, &query(), &ALL).await;
    assert_eq!(page.summary.on_alarms_off_hosts, 0);
    // an empty page still carries the meta
    let page = run(
        &c,
        &AlarmQuery {
            offset: 100,
            ..query()
        },
        &ALL,
    )
    .await;
    assert!(page.rows.is_empty());
    assert_eq!(page.total, 3);
    db.drop().await;
}
