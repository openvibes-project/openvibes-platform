//! Listing cases, the cases of an item, and assignees.

use super::*;

#[tokio::test]
async fn for_item_finds_the_open_case_of_an_exclusive_item_and_the_cases_of_a_host() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let alarm_2 = fx.web_alarm_2.clone();
    let first = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "First",
        &[("alarm", &alarm), ("host", WEB)],
    )
    .await;
    let second = open_case(&mut fx.console, &global(), DAVE, "Second", &[("host", WEB)]).await;
    let found = cases::for_item(&fx.console, &global(), DAVE, "alarm", &alarm)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].case.number, first.summary.number);
    assert_eq!(found[0].item_id, item_id(&first, "alarm"));
    let none = cases::for_item(&fx.console, &global(), DAVE, "alarm", &alarm_2)
        .await
        .unwrap()
        .unwrap();
    assert!(none.is_empty());
    let hosts = cases::for_item(&fx.console, &global(), DAVE, "host", WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        hosts.iter().map(|c| c.case.number).collect::<Vec<_>>(),
        [second.summary.number, first.summary.number],
        "newest change first"
    );
    // A case the caller cannot see is not listed, nor is its existence.
    let db_case = open_case(&mut fx.console, &global(), ALICE, "Db", &[("host", DB)]).await;
    let hidden = cases::for_item(&fx.console, &prod(), BOB, "host", DB)
        .await
        .unwrap()
        .unwrap();
    assert!(hidden.is_empty(), "{hidden:?} {db_case:?}");
    // Nor is a visible case listed for an item in it that the caller cannot see.
    open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Both",
        &[("host", WEB), ("host", DB)],
    )
    .await;
    let hidden = cases::for_item(&fx.console, &prod(), BOB, "host", DB)
        .await
        .unwrap()
        .unwrap();
    assert!(hidden.is_empty(), "{hidden:?}");
    let visible = cases::for_item(&fx.console, &prod(), BOB, "host", WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(visible.len(), 3);
    let refused = cases::for_item(&fx.console, &prod(), BOB, "alarm", "nope")
        .await
        .unwrap();
    assert!(matches!(refused.unwrap_err(), Refusal::Invalid("ref", _)));
    // A closed case no longer holds its exclusive items.
    let first_item = item_id(&first, "alarm").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &first,
        &first_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("x"),
            outcome_until: None,
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &first).await.unwrap();
    update(&mut fx, &global(), ALICE, &ready, &closing(&ready, "x"))
        .await
        .unwrap();
    assert!(
        cases::for_item(&fx.console, &global(), DAVE, "alarm", &alarm)
            .await
            .unwrap()
            .unwrap()
            .is_empty()
    );
    let hosts = cases::for_item(&fx.console, &global(), DAVE, "host", WEB)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hosts.len(), 3, "hosts stay listed on closed cases");
    fx.db.drop().await;
}

#[tokio::test]
async fn assignees_are_enabled_users_who_can_read_cases() {
    let mut fx = setup().await;
    let names = |users: Vec<cases::UserRef>| -> Vec<String> {
        users.into_iter().map(|u| u.username).collect()
    };
    assert_eq!(
        names(cases::assignees(&fx.console).await.unwrap()),
        ["alice", "bob", "dave"],
        "the viewer cannot read cases"
    );
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Assign",
        &[("host", WEB)],
    )
    .await;
    let viewer = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            assignee_user_id: Some(CAROL),
            ..same(&case, "open")
        },
    )
    .await;
    assert_eq!(viewer.unwrap_err(), Refusal::AssigneeUnavailable);
    for bad in ["not-a-user", "99999999-9999-4999-8999-999999999999"] {
        let refused = update(
            &mut fx,
            &global(),
            ALICE,
            &case,
            &CaseChange {
                assignee_user_id: Some(bad),
                ..same(&case, "open")
            },
        )
        .await;
        assert_eq!(refused.unwrap_err(), Refusal::AssigneeUnavailable);
    }
    fx.admin
        .execute(
            "UPDATE console_users SET enabled = false, disabled_at = now()
             WHERE user_id = $1::text::uuid",
            &[&DAVE],
        )
        .await
        .unwrap();
    assert_eq!(
        names(cases::assignees(&fx.console).await.unwrap()),
        ["alice", "bob"]
    );
    let disabled = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            assignee_user_id: Some(DAVE),
            ..same(&case, "open")
        },
    )
    .await;
    assert_eq!(disabled.unwrap_err(), Refusal::AssigneeUnavailable);
    let assigned = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            assignee_user_id: Some(BOB),
            ..same(&case, "open")
        },
    )
    .await
    .unwrap();
    let event = assigned.events.last().unwrap();
    assert_eq!(event.kind, "assigned");
    assert_eq!(
        (event.detail["from"].is_null(), event.detail["to"].as_str()),
        (true, Some("bob"))
    );
    let unassigned = update(
        &mut fx,
        &global(),
        ALICE,
        &assigned,
        &CaseChange {
            assignee_user_id: None,
            ..same(&assigned, "open")
        },
    )
    .await
    .unwrap();
    assert!(unassigned.summary.assignee.is_none());
    fx.db.drop().await;
}

#[tokio::test]
async fn the_list_filters_by_status_severity_assignee_and_text_and_pages() {
    let mut fx = setup().await;
    let mut made = Vec::new();
    for (title, severity) in [
        ("SSH on web", "high"),
        ("Disk full", "low"),
        ("Old news", "high"),
    ] {
        let case = cases::create(
            &mut fx.console,
            &global(),
            ALICE,
            &NewCase {
                title,
                severity: Some(severity),
                assignee_user_id: None,
                items: &[("host", WEB)],
            },
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
        made.push(case);
    }
    let investigating = update(
        &mut fx,
        &global(),
        ALICE,
        &made[1],
        &same(&made[1], "investigating"),
    )
    .await
    .unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &made[2],
        &closing(&made[2], "ok"),
    )
    .await
    .unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &made[0],
        &CaseChange {
            assignee_user_id: Some(BOB),
            ..same(&made[0], "open")
        },
    )
    .await
    .unwrap();
    let titles = |filters: CaseFilters| {
        let client = &fx.console;
        async move {
            cases::list(client, &global(), ALICE, &filters, None, 50)
                .await
                .unwrap()
                .into_iter()
                .map(|c| c.title)
                .collect::<Vec<_>>()
        }
    };
    let all = CaseFilters {
        status: Some("all".into()),
        ..CaseFilters::default()
    };
    assert_eq!(
        titles(CaseFilters::default()).await,
        ["SSH on web", "Disk full"],
        "open and investigating, newest change first"
    );
    assert_eq!(titles(all.clone()).await.len(), 3);
    for (status, expected) in [
        ("open", "SSH on web"),
        ("investigating", "Disk full"),
        ("closed", "Old news"),
    ] {
        assert_eq!(
            titles(CaseFilters {
                status: Some(status.into()),
                ..CaseFilters::default()
            })
            .await,
            [expected],
            "{status}"
        );
    }
    assert_eq!(
        titles(CaseFilters {
            severity: Some("high".into()),
            ..all.clone()
        })
        .await,
        ["SSH on web", "Old news"]
    );
    assert_eq!(
        titles(CaseFilters {
            assignee: AssigneeFilter::User(BOB.into()),
            ..all.clone()
        })
        .await,
        ["SSH on web"]
    );
    assert_eq!(
        titles(CaseFilters {
            assignee: AssigneeFilter::Nobody,
            ..all.clone()
        })
        .await
        .len(),
        2
    );
    assert_eq!(
        titles(CaseFilters {
            q: Some("DISK".into()),
            ..all.clone()
        })
        .await,
        ["Disk full"]
    );
    assert_eq!(
        titles(CaseFilters {
            q: Some(format!("c-{}", made[2].summary.number)),
            ..all.clone()
        })
        .await,
        ["Old news"]
    );
    // % and _ are text, not patterns.
    assert!(
        titles(CaseFilters {
            q: Some("%".into()),
            ..all.clone()
        })
        .await
        .is_empty()
    );
    // Pages by the last row's (updated_at, case_id).
    let first = cases::list(&fx.console, &global(), ALICE, &all, None, 2)
        .await
        .unwrap();
    assert_eq!(first.len(), 2);
    let cursor = first
        .last()
        .map(|c| (c.updated_at, c.case_id.clone()))
        .unwrap();
    let second = cases::list(&fx.console, &global(), ALICE, &all, Some(&cursor), 2)
        .await
        .unwrap();
    assert_eq!(second.len(), 1);
    let mut numbers: Vec<_> = first.iter().chain(&second).map(|c| c.number).collect();
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(numbers.len(), 3, "no row twice, none missing");
    assert_eq!(investigating.summary.status, "investigating");
    fx.db.drop().await;
}
