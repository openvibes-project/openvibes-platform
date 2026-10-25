//! Every filter with the others applied, search, and sorting.

use super::*;

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
