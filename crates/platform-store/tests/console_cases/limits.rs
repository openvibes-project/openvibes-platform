//! Limits, removing items, and what the database itself refuses.

use super::*;

#[tokio::test]
async fn limits_on_items_on_creation_and_on_the_timeline_hold() {
    let mut fx = setup().await;
    let many: Vec<String> = (0..51).map(|n| format!("rpm/pkg{n}")).collect();
    let items: Vec<(&str, &str)> = many.iter().map(|r| ("software", r.as_str())).collect();
    assert_eq!(
        refused_create(&mut fx.console, &global(), ALICE, &items).await,
        Refusal::Invalid("items", "too_many_items")
    );
    let case = open_case(&mut fx.console, &global(), ALICE, "Full", &[]).await;
    fx.admin
        .execute(
            "INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, added_by_user_id, added_at)
             SELECT gen_random_uuid(), $1::text::uuid, 'software', 'rpm/pkg' || n, NULL, true,
                    $2::text::uuid, now()
             FROM generate_series(1, $3::int) n",
            &[&case.summary.case_id, &ALICE, &(cases::MAX_ITEMS_PER_CASE as i32)],
        )
        .await
        .unwrap();
    let refused = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "host",
        WEB,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::TooManyItems);
    fx.admin
        .execute(
            "INSERT INTO case_events (case_id, at, actor_user_id, kind, body)
             SELECT $1::text::uuid, now(), $2::text::uuid, 'note', 'n'
             FROM generate_series(1, $3::int)",
            &[
                &case.summary.case_id,
                &ALICE,
                &(cases::MAX_EVENTS_PER_CASE as i32),
            ],
        )
        .await
        .unwrap();
    let refused = cases::add_note(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "one more",
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::TimelineFull);
    fx.db.drop().await;
}

#[tokio::test]
async fn items_can_be_removed_from_an_open_case_only() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Remove",
        &[("alarm", &alarm), ("host", WEB)],
    )
    .await;
    let alarm_item = item_id(&case, "alarm").to_owned();
    cases::remove_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        &alarm_item,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let after = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(after.items.len(), 1);
    let removed = after
        .events
        .iter()
        .find(|e| e.kind == "item_removed")
        .unwrap();
    assert_eq!(removed.detail["item_ref"], alarm.as_str());
    // The alarm is free again, and the second removal finds nothing.
    open_case(
        &mut fx.console,
        &global(),
        DAVE,
        "Elsewhere",
        &[("alarm", &alarm)],
    )
    .await;
    for bad in [alarm_item.as_str(), "not-a-uuid"] {
        let refused = cases::remove_item(
            &mut fx.console,
            &global(),
            ALICE,
            &case.summary.case_id,
            bad,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(refused.unwrap_err(), Refusal::ItemNotFound);
    }
    let host_item = item_id(&after, "host").to_owned();
    let closed = update(&mut fx, &global(), ALICE, &after, &closing(&after, "ok"))
        .await
        .unwrap();
    let refused = cases::remove_item(
        &mut fx.console,
        &global(),
        ALICE,
        &closed.summary.case_id,
        &host_item,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    fx.db.drop().await;
}

#[tokio::test]
async fn the_database_refuses_what_the_rules_forbid() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let first = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "One",
        &[("alarm", &alarm)],
    )
    .await;
    let second = open_case(&mut fx.console, &global(), ALICE, "Two", &[]).await;
    // Even a direct insert cannot put an exclusive item in two open cases.
    let result = fx
        .admin
        .execute(
            "INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active,
                 added_by_user_id, added_at)
             VALUES (gen_random_uuid(), $1::text::uuid, 'alarm', $2, $3, true,
                 $4::text::uuid, now())",
            &[&second.summary.case_id, &alarm, &WEB, &ALICE],
        )
        .await;
    assert!(result.is_err());
    // A closed case needs its note and close time, only a closed case has a
    // resolution (pre-5d closes), and an accepted risk its date.
    for set in [
        "status = 'closed'",
        "resolution = 'mitigated'",
        "status = 'closed', resolution_note = 'x'",
        "status = 'closed', resolution = 'accepted_risk', resolution_note = 'x', closed_at = now()",
        "title = ''",
        "severity = 'urgent'",
    ] {
        let result = fx
            .admin
            .execute(
                &format!("UPDATE cases SET {set} WHERE case_id = $1::text::uuid"),
                &[&first.summary.case_id],
            )
            .await;
        assert!(result.is_err(), "{set}");
    }
    // Accepted risk on an item needs its date, and only it has one.
    for set in [
        "outcome = 'accepted_risk', outcome_note = 'x'",
        "outcome_until = now() + interval '1 day'",
        "outcome = 'expected', outcome_note = 'x', outcome_until = now() + interval '1 day'",
        "outcome = 'expected'",
    ] {
        let result = fx
            .admin
            .execute(
                &format!("UPDATE case_items SET {set} WHERE case_id = $1::text::uuid"),
                &[&first.summary.case_id],
            )
            .await;
        assert!(result.is_err(), "{set}");
    }
    // Case numbers are not reused or chosen.
    let result = fx
        .admin
        .execute(
            "UPDATE cases SET number = 1 WHERE case_id = $1::text::uuid",
            &[&second.summary.case_id],
        )
        .await;
    assert!(result.is_err());
    fx.db.drop().await;
}
