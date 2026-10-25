//! Rows, how old cases ended, the note preview, n/m, the scope and the
//! summary line.

use super::*;

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
async fn an_old_closed_case_keeps_how_it_ended() {
    let (db, c) = common::migrated().await;
    fixture(&c).await;
    // A case closed before step 5d names its resolution; new closes set none.
    c.execute(
        "UPDATE cases SET resolution = 'mitigated' WHERE number = 2",
        &[],
    )
    .await
    .unwrap();
    let page = run(&c, &query(), &AgentScope::Global).await;
    assert_eq!(row(&page, 2).resolution.as_deref(), Some("mitigated"));
    assert_eq!(row(&page, 1).resolution, None);
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
            ready_to_close: 0
        },
        "1 and 5 hold hidden items without an outcome, as close sees them"
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
