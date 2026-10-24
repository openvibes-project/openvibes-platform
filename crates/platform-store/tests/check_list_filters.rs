//! The Compliance list's filters with their counts, sorts and paging,
//! search and the summary line (step 5c rulings 4–7).

mod common;

use common::checks::{
    ASLR, BOB, CUSTOM, REDIS, ROOT, SSH, TELNET, every, fixture, keys, n, query, run,
};
use platform_store::{
    alarm_list::Assignee,
    check_list::{CheckListPage, CheckQuery, CheckSeverity, CheckSort, CheckState},
    console_read::AgentScope,
};

#[tokio::test]
async fn every_filter_with_its_counts() {
    let (db, c) = common::migrated().await;
    let (web, alpha) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web.clone()]);
    for (state, want) in [
        (CheckState::Open, 3),
        (CheckState::Mitigated, 1),
        (CheckState::AcceptedRisk, 1),
        (CheckState::FalsePositive, 1),
        (CheckState::Passing, 6),
        (CheckState::All, 6),
    ] {
        let page = run(&c, &CheckQuery { state, ..query() }, &scope).await;
        assert_eq!(page.total, want, "{state:?}");
        assert_eq!(n(&page.counts.state, state), want, "{state:?}");
    }
    let all = run(&c, &every(), &scope).await;
    assert_eq!(n(&all.counts.severity, CheckSeverity::Critical), 1);
    assert_eq!(
        n(&all.counts.severity, CheckSeverity::High),
        2,
        "redis: indexed"
    );
    assert_eq!(n(&all.counts.severity, CheckSeverity::Medium), 2);
    assert_eq!(n(&all.counts.severity, CheckSeverity::Low), 1);
    assert_eq!(
        all.counts.rule_sets,
        [
            ("baseline".into(), 3),
            ("hardening-linux-l1".into(), 2),
            ("site-x".into(), 1)
        ]
    );
    assert_eq!(n(&all.counts.areas, "Network exposure".to_owned()), 2);
    // Each filter narrows; its own counts keep the other values.
    let crit = run(
        &c,
        &CheckQuery {
            severity: Some(CheckSeverity::Critical),
            ..every()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&crit), [ROOT]);
    assert_eq!(n(&crit.counts.severity, CheckSeverity::High), 2);
    assert_eq!(
        n(&crit.counts.rule_sets, "hardening-linux-l1".to_owned()),
        1
    );
    assert_eq!(
        n(&crit.counts.rule_sets, "baseline".to_owned()),
        0,
        "listed with 0"
    );
    let high = CheckQuery {
        severity: Some(CheckSeverity::High),
        ..every()
    };
    let high = run(&c, &high, &scope).await;
    assert_eq!(
        keys(&high),
        [SSH, REDIS],
        "a passing-only check by its rule"
    );
    let set = run(
        &c,
        &CheckQuery {
            rule_set: Some("baseline"),
            ..every()
        },
        &scope,
    )
    .await;
    assert_eq!(set.total, 3);
    assert_eq!(n(&set.counts.rule_sets, "site-x".to_owned()), 1);
    let area = run(
        &c,
        &CheckQuery {
            area: Some("Network exposure"),
            ..every()
        },
        &scope,
    )
    .await;
    let mut got = keys(&area);
    got.sort();
    assert_eq!(got, [REDIS, SSH]);
    assert_eq!(n(&area.counts.areas, "SSH".to_owned()), 1);
    let group = run(
        &c,
        &CheckQuery {
            group: Some(&alpha),
            ..query()
        },
        &scope,
    )
    .await;
    let mut got = keys(&group);
    got.sort();
    assert_eq!(got, [SSH, CUSTOM], "host 1's open pairs");
    let g = |p: &CheckListPage, name: &str| {
        p.counts
            .groups
            .iter()
            .find(|g| g.1 == name)
            .map_or(0, |g| g.3)
    };
    assert_eq!((g(&group, "Alpha"), g(&group, "Web")), (2, 3));
    let alpha_all = run(
        &c,
        &CheckQuery {
            group: Some(&alpha),
            ..every()
        },
        &scope,
    )
    .await;
    assert_eq!(alpha_all.total, 5, "host 1 fails or passes all but root");
    // Assignee: Me (Ann), Bob, unassigned; the state and assignee hold on one pair.
    let me = run(
        &c,
        &CheckQuery {
            assignee: Some(Assignee::Me),
            ..query()
        },
        &scope,
    )
    .await;
    let mut got = keys(&me);
    got.sort();
    assert_eq!(got, [SSH, CUSTOM]);
    assert_eq!((me.counts.me, me.counts.unassigned), (2, 1));
    assert_eq!(
        n(&me.counts.state, CheckState::FalsePositive),
        1,
        "Ann's on root"
    );
    assert_eq!(
        n(&me.counts.state, CheckState::Passing),
        0,
        "passing has no assignee"
    );
    let bob = run(
        &c,
        &CheckQuery {
            assignee: Some(Assignee::User(BOB)),
            ..query()
        },
        &scope,
    )
    .await;
    let mut got = keys(&bob);
    got.sort();
    assert_eq!(got, [ROOT, CUSTOM]);
    let people: Vec<(&str, i64)> = bob
        .counts
        .people
        .iter()
        .map(|p| (p.1.as_str(), p.2))
        .collect();
    assert_eq!(people, [("Ann", 2), ("Bob", 2)]);
    let un = run(
        &c,
        &CheckQuery {
            assignee: Some(Assignee::Unassigned),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(keys(&un), [SSH], "host 3's expired acceptance");
    let bad = run(
        &c,
        &CheckQuery {
            assignee: Some(Assignee::User("nope")),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(bad.total, 0);
    db.drop().await;
}

#[tokio::test]
async fn every_sort_pages_stably() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    let order = |sort, descending| CheckQuery {
        sort,
        descending,
        ..every()
    };
    let full = run(&c, &order(CheckSort::Severity, true), &scope).await;
    assert_eq!(
        keys(&full),
        [ROOT, SSH, REDIS, ASLR, TELNET, CUSTOM],
        "worst first, then most failing"
    );
    let title = run(&c, &order(CheckSort::Title, false), &scope).await;
    assert_eq!(keys(&title), [ASLR, CUSTOM, REDIS, ROOT, SSH, TELNET]);
    let failing = run(&c, &order(CheckSort::Failing, true), &scope).await;
    assert_eq!(
        keys(&failing),
        [CUSTOM, SSH, ROOT, ASLR, REDIS, TELNET],
        "ties by key"
    );
    let since = run(&c, &order(CheckSort::Since, false), &scope).await;
    assert_eq!(
        &keys(&since)[3..],
        [TELNET, REDIS, ASLR],
        "no failing pair last"
    );
    for sort in CheckSort::ALL {
        for descending in [false, true] {
            let all = keys(&run(&c, &order(*sort, descending), &scope).await);
            let mut paged = Vec::new();
            for offset in (0..6).step_by(2) {
                let q = CheckQuery {
                    offset,
                    limit: 2,
                    ..order(*sort, descending)
                };
                let page = run(&c, &q, &scope).await;
                assert_eq!(page.total, 6);
                paged.extend(keys(&page));
            }
            assert_eq!(paged, all, "{sort:?} {descending}");
        }
    }
    let empty = run(
        &c,
        &CheckQuery {
            offset: 100,
            ..every()
        },
        &scope,
    )
    .await;
    assert!(empty.rows.is_empty());
    assert_eq!(empty.total, 6, "the meta comes with an empty page");
    db.drop().await;
}

#[tokio::test]
async fn search_covers_title_rule_and_set() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    for (q, want) in [
        ("ssh", vec![ROOT, SSH]),
        ("HARDENING", vec![ROOT, ASLR]),
        ("aslr off", vec![ASLR]),
        ("site-x", vec![CUSTOM]),
    ] {
        let page = run(
            &c,
            &CheckQuery {
                q: Some(q),
                ..every()
            },
            &scope,
        )
        .await;
        assert_eq!(keys(&page), want, "{q}");
    }
    db.drop().await;
}

#[tokio::test]
async fn the_summary_line() {
    let (db, c) = common::migrated().await;
    let (web, _) = fixture(&c).await;
    let scope = AgentScope::AssetGroups(vec![web]);
    // The state filter is left out: the same line under Passing.
    for state in [CheckState::Open, CheckState::Passing] {
        let s = run(&c, &CheckQuery { state, ..query() }, &scope)
            .await
            .summary;
        assert_eq!(
            (s.failing_checks, s.hosts, s.critical, s.unassigned),
            (3, 3, 1, 0)
        );
        assert_eq!(
            s.rule_sets,
            [
                ("baseline".into(), 1),
                ("hardening-linux-l1".into(), 1),
                ("site-x".into(), 1)
            ]
        );
    }
    let bob = run(
        &c,
        &CheckQuery {
            assignee: Some(Assignee::User(BOB)),
            ..query()
        },
        &scope,
    )
    .await;
    assert_eq!(
        (bob.summary.failing_checks, bob.summary.hosts),
        (2, 2),
        "hosts 2 and 3"
    );
    db.drop().await;
}
