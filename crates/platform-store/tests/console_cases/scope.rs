//! A scoped caller sees only the cases and items in reach; items out of reach cannot be added.

use super::*;

#[tokio::test]
async fn a_scoped_user_sees_only_cases_and_items_in_scope() {
    let mut fx = setup().await;
    let both = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Both hosts",
        &[("host", WEB), ("host", DB), ("software", "rpm/bash")],
    )
    .await;
    let only_db = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Only db-01",
        &[("host", DB), ("alarm", &fx.db_alarm.clone())],
    )
    .await;
    let empty = open_case(&mut fx.console, &global(), ALICE, "Nothing yet", &[]).await;

    // Bob sees the first case without the db-01 host: not in the items,
    // the counts or the timeline. Software is visible to every reader.
    let seen = fetch(&fx, &prod(), BOB, &both).await.unwrap();
    assert_eq!(
        seen.items
            .iter()
            .map(|i| i.reference.as_str())
            .collect::<Vec<_>>(),
        [WEB, "rpm/bash"]
    );
    assert_eq!(seen.summary.items, 2);
    let rendered = format!("{seen:?}");
    assert!(!rendered.contains(DB), "{rendered}");
    assert_eq!(
        seen.events
            .iter()
            .filter(|e| e.kind == "item_added")
            .count(),
        2
    );
    // Alice sees everything.
    let all = fetch(&fx, &global(), ALICE, &both).await.unwrap();
    assert_eq!((all.items.len(), all.summary.items), (3, 3));

    // The second case reads as absent, in `get` and in the list.
    assert!(fetch(&fx, &prod(), BOB, &only_db).await.is_none());
    assert!(fetch(&fx, &prod(), BOB, &empty).await.is_none());
    let listed = cases::list(
        &fx.console,
        &prod(),
        BOB,
        &CaseFilters {
            status: Some("all".into()),
            ..CaseFilters::default()
        },
        None,
        50,
    )
    .await
    .unwrap();
    assert_eq!(
        listed.iter().map(|c| c.number).collect::<Vec<_>>(),
        [both.summary.number]
    );
    let searched = cases::list(
        &fx.console,
        &prod(),
        BOB,
        &CaseFilters {
            q: Some(format!("C-{}", only_db.summary.number)),
            ..CaseFilters::default()
        },
        None,
        50,
    )
    .await
    .unwrap();
    assert!(searched.is_empty(), "search never finds a hidden case");
    let hidden_id = cases::get(&fx.console, &prod(), BOB, "not-a-uuid")
        .await
        .unwrap();
    assert!(hidden_id.is_none());

    // Someone who opened a case, or to whom it is assigned, sees it.
    let bobs = open_case(&mut fx.console, &prod(), BOB, "Bob's own", &[]).await;
    assert!(fetch(&fx, &prod(), BOB, &bobs).await.is_some());
    assert!(
        fetch(&fx, &global(), DAVE, &bobs).await.is_some(),
        "an empty case is seen by readers of all hosts too (step 5d ruling 4)"
    );
    let assigned = update(
        &mut fx,
        &global(),
        ALICE,
        &only_db,
        &CaseChange {
            assignee_user_id: Some(BOB),
            ..same(&only_db, "open")
        },
    )
    .await
    .unwrap();
    let as_assignee = fetch(&fx, &prod(), BOB, &assigned).await.unwrap();
    assert!(
        as_assignee.items.is_empty(),
        "assigned, but no item in scope"
    );
    assert_eq!(as_assignee.summary.assignee.unwrap().username, "bob");
    fx.db.drop().await;
}

#[tokio::test]
async fn an_item_out_of_scope_cannot_be_added_and_does_not_say_whether_it_exists() {
    let mut fx = setup().await;
    let case = open_case(
        &mut fx.console,
        &prod(),
        BOB,
        "Bob's case",
        &[("host", WEB)],
    )
    .await;
    let db_finding = finding(DB);
    let db_vuln = vuln(DB);
    let web_alarm = fx.web_alarm.clone();
    let db_alarm = fx.db_alarm.clone();
    let missing = format!("{DB}0");
    let hidden_and_missing: [(&str, &str); 9] = [
        ("host", DB),
        ("alarm", &db_alarm),
        ("compliance_finding", &db_finding),
        ("vulnerability", &db_vuln),
        ("software", "rpm/bash"),
        ("port", "tcp/5432"),
        ("port", "tcp/9"),
        ("host", &missing),
        ("alarm", "999999"),
    ];
    for (kind, reference) in hidden_and_missing {
        let refused = cases::add_item(
            &mut fx.console,
            &prod(),
            BOB,
            &case.summary.case_id,
            kind,
            reference,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(
            refused.unwrap_err(),
            Refusal::ItemNotFound,
            "{kind} {reference}"
        );
    }
    // Creating a case with one is refused the same way, and writes nothing.
    assert_eq!(
        refused_create(
            &mut fx.console,
            &prod(),
            BOB,
            &[("host", WEB), ("host", DB)]
        )
        .await,
        Refusal::ItemNotFound
    );
    // The same items are fine for a global user, and in scope for Bob.
    for (kind, reference) in [
        ("alarm", web_alarm.as_str()),
        ("software", "rpm/openssl"),
        ("port", "tcp/22"),
    ] {
        cases::add_item(
            &mut fx.console,
            &prod(),
            BOB,
            &case.summary.case_id,
            kind,
            reference,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap();
    }
    let added = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "host",
        DB,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(added.unwrap().hostname.as_deref(), Some("db-01"));
    let count: i64 = fx
        .admin
        .query_one("SELECT count(*) FROM cases", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "the refused create left no case behind");
    fx.db.drop().await;
}

#[tokio::test]
async fn malformed_items_are_invalid_not_missing() {
    let mut fx = setup().await;
    let case = open_case(&mut fx.console, &global(), ALICE, "Shapes", &[]).await;
    for (kind, reference, field) in [
        ("service", "sshd.service", "kind"),
        ("alarm", "042", "ref"),
        ("alarm", "abc", "ref"),
        ("compliance_finding", WEB, "ref"),
        ("vulnerability", WEB, "ref"),
        ("host", "web 01", "ref"),
        ("software", "rpm", "ref"),
        ("port", "tcp/0", "ref"),
        ("port", "icmp/22", "ref"),
        ("port", "tcp/022", "ref"),
    ] {
        let refused = cases::add_item(
            &mut fx.console,
            &global(),
            ALICE,
            &case.summary.case_id,
            kind,
            reference,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(
            matches!(refused, Refusal::Invalid(f, _) if f == field),
            "{kind} {reference}: {refused:?}"
        );
    }
    fx.db.drop().await;
}

/// The ids of every case `user` lists.
async fn listed(fx: &Fx, scope: AgentScope, user: &str) -> Vec<String> {
    let all = CaseFilters {
        status: Some("all".into()),
        ..CaseFilters::default()
    };
    cases::list(&fx.console, &scope, user, &all, None, 50)
        .await
        .unwrap()
        .iter()
        .map(|c| c.case_id.clone())
        .collect()
}

#[tokio::test]
async fn an_empty_case_is_visible_to_all_hosts_readers() {
    let mut fx = setup().await;
    // Opened by Bob (production only), assigned to nobody, no items.
    let empty = open_case(&mut fx.console, &prod(), BOB, "Empty", &[]).await;
    let id = empty.summary.case_id.as_str();
    // Its creator, and a reader of all hosts, see it.
    assert!(fetch(&fx, &prod(), BOB, &empty).await.is_some());
    assert!(fetch(&fx, &global(), DAVE, &empty).await.is_some());
    assert_eq!(listed(&fx, global(), DAVE).await, [id]);
    // A reader of some groups who neither opened it nor has it does not.
    let other = open_case(&mut fx.console, &global(), ALICE, "Alice's", &[]).await;
    assert!(fetch(&fx, &prod(), BOB, &other).await.is_none());
    assert_eq!(listed(&fx, prod(), BOB).await, [id]);
    // Assigned to them, they see it.
    let assigned = update(
        &mut fx,
        &global(),
        ALICE,
        &other,
        &CaseChange {
            assignee_user_id: Some(BOB),
            ..same(&other, "open")
        },
    )
    .await
    .unwrap();
    assert!(fetch(&fx, &prod(), BOB, &assigned).await.is_some());
    // Once a case holds items, only its items decide (with opener and
    // assignee): a db-01 item keeps it from Bob, a reader of all hosts
    // still sees it.
    let db_only = open_case(&mut fx.console, &global(), ALICE, "db", &[("host", DB)]).await;
    assert!(fetch(&fx, &prod(), BOB, &db_only).await.is_none());
    assert!(fetch(&fx, &global(), DAVE, &db_only).await.is_some());
    fx.db.drop().await;
}
