//! An alarm, finding or vulnerability is in at most one open case.

use super::*;

#[tokio::test]
async fn an_alarm_finding_or_vulnerability_is_in_one_open_case_and_is_freed_on_close() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let web_finding = finding(WEB);
    let web_vuln = vuln(WEB);
    let exclusive: [(&str, &str); 3] = [
        ("alarm", &alarm),
        ("compliance_finding", &web_finding),
        ("vulnerability", &web_vuln),
    ];
    let first = open_case(&mut fx.console, &global(), ALICE, "First", &exclusive).await;
    let number = first.summary.number;

    // Neither a new case nor an existing one takes them, and the refusal
    // names the first case for someone who can see it.
    for (kind, reference) in exclusive {
        assert_eq!(
            refused_create(&mut fx.console, &global(), DAVE, &[(kind, reference)]).await,
            Refusal::ItemInCase(Some(number)),
            "{kind}"
        );
    }
    let second = open_case(&mut fx.console, &global(), DAVE, "Second", &[]).await;
    let refused = cases::add_item(
        &mut fx.console,
        &prod(),
        DAVE,
        &second.summary.case_id,
        "alarm",
        &alarm,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::ItemInCase(Some(number)));
    // The same item twice in one case is its own refusal.
    let twice = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &first.summary.case_id,
        "alarm",
        &alarm,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(twice.unwrap_err(), Refusal::AlreadyInCase);
    // Hosts and software are not exclusive; the advisory alone is not an item.
    for (case, user) in [(&first, ALICE), (&second, DAVE)] {
        for (kind, reference) in [("host", WEB), ("software", "rpm/openssl")] {
            cases::add_item(
                &mut fx.console,
                &global(),
                user,
                &case.summary.case_id,
                kind,
                reference,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
        }
    }
    // The vulnerability on another host is another item.
    cases::add_item(
        &mut fx.console,
        &global(),
        DAVE,
        &second.summary.case_id,
        "vulnerability",
        &vuln(DB),
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();

    // Closing frees them: mark each, close, and take them again.
    let mut current = first.clone();
    for item in first
        .items
        .iter()
        .filter(|i| i.kind != "host" && i.kind != "software")
    {
        outcome(
            &mut fx,
            &global(),
            ALICE,
            &current,
            &item.item_id,
            Some(OutcomeChange {
                outcome: "false_positive",
                note: Some("expected"),
                outcome_until: None,
            }),
        )
        .await
        .unwrap();
        current = fetch(&fx, &global(), ALICE, &first).await.unwrap();
    }
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &current,
        &closing(&current, "Known"),
    )
    .await
    .unwrap();
    assert_eq!(closed.summary.status, "closed");
    assert!(closed.items.iter().all(|item| !item.active));
    for (kind, reference) in exclusive {
        cases::add_item(
            &mut fx.console,
            &global(),
            DAVE,
            &second.summary.case_id,
            kind,
            reference,
            Utc::now(),
        )
        .await
        .unwrap()
        .unwrap_or_else(|refusal| panic!("{kind} should be free: {refusal:?}"));
    }
    // A closed case takes no new items.
    let refused = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &closed.summary.case_id,
        "host",
        DB,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    // Reopening needs them to be free: they are not.
    let reopen = update(&mut fx, &global(), ALICE, &closed, &same(&closed, "open")).await;
    assert_eq!(
        reopen.unwrap_err(),
        Refusal::ItemInCase(Some(second.summary.number))
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_reopen_conflict_names_the_other_case_only_to_someone_who_can_see_it() {
    let mut fx = setup().await;
    let db_alarm = fx.db_alarm.clone();
    let first = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "First",
        &[("host", WEB), ("alarm", &db_alarm)],
    )
    .await;
    let db_item = item_id(&first, "alarm").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &first,
        &db_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("test"),
            outcome_until: None,
        }),
    )
    .await
    .unwrap();
    let first = fetch(&fx, &global(), ALICE, &first).await.unwrap();
    let closed = update(&mut fx, &global(), ALICE, &first, &closing(&first, "Done"))
        .await
        .unwrap();
    // Someone takes the db-01 alarm in a case Bob cannot see.
    let other = open_case(
        &mut fx.console,
        &global(),
        DAVE,
        "Other",
        &[("alarm", &db_alarm)],
    )
    .await;
    let by_bob = update(&mut fx, &prod(), BOB, &closed, &same(&closed, "open")).await;
    assert_eq!(by_bob.unwrap_err(), Refusal::ItemInCase(None));
    let by_alice = update(&mut fx, &global(), ALICE, &closed, &same(&closed, "open")).await;
    assert_eq!(
        by_alice.unwrap_err(),
        Refusal::ItemInCase(Some(other.summary.number))
    );
    fx.db.drop().await;
}
