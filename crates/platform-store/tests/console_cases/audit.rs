//! The append-only timeline and the audit rows.

use super::*;

#[tokio::test]
async fn the_timeline_is_append_only_and_audit_rows_never_hold_note_text() {
    let mut fx = setup().await;
    let case = open_case(&mut fx.console, &global(), ALICE, "Notes", &[("host", WEB)]).await;
    let secret = "the password is hunter2";
    let note = cases::add_note(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        secret,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(note.kind, "note");
    assert_eq!(note.body.as_deref(), Some(secret));
    assert_eq!(note.actor.as_ref().unwrap().username, "alice");
    for bad in ["", "   ", "bell\u{7}", &"n".repeat(4001)] {
        let refused = cases::add_note(
            &mut fx.console,
            &global(),
            ALICE,
            &case.summary.case_id,
            bad,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(
            refused.unwrap_err(),
            Refusal::Invalid("body", "invalid_note")
        );
    }
    let hidden = cases::add_note(
        &mut fx.console,
        &prod(),
        BOB,
        "00000000-0000-4000-8000-000000000000",
        "x",
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(hidden.unwrap_err(), Refusal::NotFound);

    // A note moves the case to the top of the list.
    let listed = cases::list(
        &fx.console,
        &global(),
        ALICE,
        &CaseFilters::default(),
        None,
        10,
    )
    .await
    .unwrap();
    assert!(listed[0].updated_at >= case.summary.updated_at);

    // Nobody can edit or delete a timeline entry, not even the owner.
    let update = fx
        .admin
        .execute("UPDATE case_events SET body = 'edited'", &[])
        .await;
    assert!(update.is_err());
    let delete = fx.admin.execute("DELETE FROM case_events", &[]).await;
    assert!(delete.is_err());
    let console = fx.console.execute("DELETE FROM case_events", &[]).await;
    assert!(console.is_err(), "the console role has no DELETE either");
    let events = fetch(&fx, &global(), ALICE, &case).await.unwrap().events;
    let ids: Vec<_> = events.iter().map(|e| e.event_id).collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "oldest first");
    assert_eq!(events.last().unwrap().body.as_deref(), Some(secret));

    let audit: Vec<(String, String)> = fx
        .admin
        .query(
            "SELECT action, detail::text FROM audit_log WHERE action LIKE 'case.%'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert!(audit.iter().any(|(action, _)| action == "case.note"));
    assert!(
        audit.iter().all(|(_, detail)| !detail.contains("hunter2")),
        "{audit:?}"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn every_change_writes_its_audit_row_in_the_same_transaction() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Audit",
        &[("alarm", &alarm)],
    )
    .await;
    let alarm_item = item_id(&case, "alarm").to_owned();
    cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "host",
        WEB,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    cases::add_note(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        "n",
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("fp"),
            outcome_until: None,
        }),
    )
    .await
    .unwrap();
    let host_item = fetch(&fx, &global(), ALICE, &case)
        .await
        .unwrap()
        .items
        .iter()
        .find(|i| i.kind == "host")
        .unwrap()
        .item_id
        .clone();
    cases::remove_item(
        &mut fx.console,
        &global(),
        ALICE,
        &case.summary.case_id,
        &host_item,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let current = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(current.items.len(), 1, "the host is gone");
    let renamed = update(
        &mut fx,
        &global(),
        ALICE,
        &current,
        &CaseChange {
            title: "Audit 2",
            ..same(&current, "investigating")
        },
    )
    .await
    .unwrap();
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &renamed,
        &closing(&renamed, "fp"),
    )
    .await
    .unwrap();
    update(&mut fx, &global(), ALICE, &closed, &same(&closed, "open"))
        .await
        .unwrap();
    let actions = audit_actions(&fx).await;
    assert_eq!(
        actions,
        [
            "case.create",
            "case.item.add",
            "case.item.add",
            "case.note",
            "case.item.outcome",
            "case.item.remove",
            "case.update",
            "case.close",
            "case.reopen",
        ]
    );
    let row = fx
        .admin
        .query_one(
            "SELECT actor, actor_kind, actor_display, target_kind, target_id
             FROM audit_log WHERE action = 'case.close'",
            &[],
        )
        .await
        .unwrap();
    let fields: Vec<String> = (0..5).map(|i| row.get(i)).collect();
    assert_eq!(
        fields,
        [ALICE, "user", "alice", "case", &case.summary.case_id]
    );
    let timeline: Vec<_> = fetch(&fx, &global(), ALICE, &case)
        .await
        .unwrap()
        .events
        .iter()
        .map(|e| e.kind.clone())
        .collect();
    assert_eq!(
        timeline,
        [
            "created",
            "item_added",
            "item_added",
            "note",
            "item_outcome",
            "item_removed",
            "status",
            "resolved",
            "reopened",
        ]
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_refused_change_leaves_no_trace() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let first = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "First",
        &[("alarm", &alarm)],
    )
    .await;
    let before = audit_actions(&fx).await;
    let second = open_case(&mut fx.console, &global(), ALICE, "Second", &[]).await;
    let events_before = fetch(&fx, &global(), ALICE, &second)
        .await
        .unwrap()
        .events
        .len();
    let refused = cases::add_item(
        &mut fx.console,
        &global(),
        ALICE,
        &second.summary.case_id,
        "alarm",
        &alarm,
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(refused.is_err());
    assert_eq!(
        fetch(&fx, &global(), ALICE, &second)
            .await
            .unwrap()
            .events
            .len(),
        events_before
    );
    assert_eq!(
        audit_actions(&fx).await.len(),
        before.len() + 1,
        "only the create"
    );
    assert_eq!(
        fetch(&fx, &global(), ALICE, &first)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    fx.db.drop().await;
}
