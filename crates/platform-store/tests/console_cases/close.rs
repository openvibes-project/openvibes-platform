//! Closing: what it needs, hidden items, versions and invalid fields.

use super::*;

#[tokio::test]
async fn closing_takes_a_closing_note_and_every_outcome() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let web_finding = finding(WEB);
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "To close",
        &[
            ("host", WEB),
            ("alarm", &alarm),
            ("compliance_finding", &web_finding),
        ],
    )
    .await;
    let invalid = |refusal: Refusal, field: &'static str, code: &'static str| {
        assert_eq!(refusal, Refusal::Invalid(field, code));
    };
    // No note, a blank one, and a note on a case that stays open.
    let refused = update(&mut fx, &global(), ALICE, &case, &same(&case, "closed")).await;
    invalid(
        refused.unwrap_err(),
        "closing_note",
        "closing_note_required",
    );
    let refused = update(&mut fx, &global(), ALICE, &case, &closing(&case, "  ")).await;
    invalid(refused.unwrap_err(), "closing_note", "invalid_note");
    let stray = CaseChange {
        closing_note: Some("x"),
        ..same(&case, "investigating")
    };
    let refused = update(&mut fx, &global(), ALICE, &case, &stray).await;
    invalid(
        refused.unwrap_err(),
        "closing_note",
        "closing_note_not_allowed",
    );

    // With a note, the alarm and the finding still need outcomes; the host
    // takes none.
    let refused = update(&mut fx, &global(), ALICE, &case, &closing(&case, "Fixed")).await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(2));
    let alarm_item = item_id(&case, "alarm").to_owned();
    let finding_item = item_id(&case, "compliance_finding").to_owned();
    for (item, decision) in [
        (&alarm_item, "confirmed_malicious"),
        (&finding_item, "expected"),
    ] {
        outcome(
            &mut fx,
            &global(),
            ALICE,
            &case,
            item,
            Some(OutcomeChange {
                outcome: decision,
                note: Some("Checked with the owner"),
                outcome_until: None,
            }),
        )
        .await
        .unwrap();
    }
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(ready.summary.pending_items, 0);
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "Shell was the backup job"),
    )
    .await
    .unwrap();
    let summary = &closed.summary;
    assert_eq!(summary.status, "closed");
    assert_eq!(summary.resolution, None, "new closes set no resolution");
    assert_eq!(summary.accepted_until, None);
    assert!(summary.closed_at.is_some());
    assert_eq!(summary.version, ready.summary.version + 1);
    assert_eq!(
        closed.resolution_note.as_deref(),
        Some("Shell was the backup job")
    );
    let last = closed.events.last().unwrap();
    assert_eq!(last.kind, "resolved");
    assert_eq!(last.body.as_deref(), Some("Shell was the backup job"));
    // Closed means the outcomes and the note stay as they are.
    let refused = outcome(&mut fx, &global(), ALICE, &closed, &alarm_item, None).await;
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &closed,
        &closing(&closed, "Changed my mind"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    // Title, severity and assignee can still be edited, and notes added.
    let renamed = update(
        &mut fx,
        &global(),
        ALICE,
        &closed,
        &CaseChange {
            title: "Renamed",
            ..closing(&closed, "Shell was the backup job")
        },
    )
    .await
    .unwrap();
    assert_eq!(renamed.summary.title, "Renamed");
    cases::add_note(
        &mut fx.console,
        &global(),
        ALICE,
        &closed.summary.case_id,
        "Follow-up after closing",
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    let actions = audit_actions(&fx).await;
    assert!(actions.contains(&"case.close".to_owned()), "{actions:?}");
    fx.db.drop().await;
}

#[tokio::test]
async fn an_old_closed_case_keeps_its_resolution() {
    let mut fx = setup().await;
    let case = open_case(&mut fx.console, &global(), ALICE, "Old", &[("host", WEB)]).await;
    // Closed before step 5d, with a case-level resolution.
    fx.admin
        .execute(
            "UPDATE cases SET status = 'closed', resolution = 'mitigated',
                resolution_note = 'Patched', closed_at = now()
             WHERE case_id = $1::text::uuid",
            &[&case.summary.case_id],
        )
        .await
        .unwrap();
    let old = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(old.summary.resolution.as_deref(), Some("mitigated"));
    // Editing it while it stays closed keeps the resolution.
    let renamed = update(
        &mut fx,
        &global(),
        ALICE,
        &old,
        &CaseChange {
            title: "Old, renamed",
            ..closing(&old, "Patched")
        },
    )
    .await
    .unwrap();
    assert_eq!(renamed.summary.resolution.as_deref(), Some("mitigated"));
    assert_eq!(renamed.resolution_note.as_deref(), Some("Patched"));
    // Reopening clears it and the timeline says what it was.
    let reopened = update(&mut fx, &global(), ALICE, &renamed, &same(&renamed, "open"))
        .await
        .unwrap();
    assert_eq!(reopened.summary.resolution, None);
    let last = reopened.events.last().unwrap();
    assert_eq!(last.kind, "reopened");
    assert_eq!(last.detail["previous_resolution"], "mitigated");
    fx.db.drop().await;
}

#[tokio::test]
async fn close_needs_every_outcome_even_hidden() {
    let mut fx = setup().await;
    let (web_alarm, db_finding) = (fx.web_alarm.clone(), finding(DB));
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Partly hidden",
        &[
            ("host", WEB),
            ("alarm", &web_alarm),
            ("compliance_finding", &db_finding),
        ],
    )
    .await;
    let seen_by_bob = fetch(&fx, &prod(), BOB, &case).await.unwrap();
    assert_eq!(seen_by_bob.items.len(), 2, "the db-01 finding is hidden");
    outcome(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        item_id(&seen_by_bob, "alarm"),
        Some(OutcomeChange {
            outcome: "confirmed_malicious",
            note: Some("Reverse shell"),
            outcome_until: None,
        }),
    )
    .await
    .unwrap();
    let seen_by_bob = fetch(&fx, &prod(), BOB, &case).await.unwrap();
    assert_eq!(seen_by_bob.summary.pending_items, 0, "nothing Bob can see");
    let refused = update(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &closing(&seen_by_bob, "Contained"),
    )
    .await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::HiddenItemsUnresolved,
        "no count and no host"
    );
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        item_id(&case, "compliance_finding"),
        Some(OutcomeChange {
            outcome: "expected",
            note: Some("Lab host"),
            outcome_until: None,
        }),
    )
    .await
    .unwrap();
    let seen_by_bob = fetch(&fx, &prod(), BOB, &case).await.unwrap();
    let closed = update(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &closing(&seen_by_bob, "Contained"),
    )
    .await
    .unwrap();
    assert_eq!(closed.summary.status, "closed");
    fx.db.drop().await;
}

#[tokio::test]
async fn closing_is_refused_for_items_the_closer_cannot_see() {
    let mut fx = setup().await;
    let db_alarm = fx.db_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Mixed",
        &[("host", WEB), ("alarm", &db_alarm)],
    )
    .await;
    let seen_by_bob = fetch(&fx, &prod(), BOB, &case).await.unwrap();
    let refused = update(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &closing(&seen_by_bob, "Done"),
    )
    .await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::HiddenItemsUnresolved,
        "no count, no name of the hidden item"
    );
    // Bob cannot reach the hidden item's outcome either.
    let hidden_item = item_id(&case, "alarm").to_owned();
    let refused = outcome(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &hidden_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("x"),
            outcome_until: None,
        }),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemNotFound);
    let removed = cases::remove_item(
        &mut fx.console,
        &prod(),
        BOB,
        &case.summary.case_id,
        &hidden_item,
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(removed.unwrap_err(), Refusal::ItemNotFound);
    // Someone with the scope clears it, and then Bob can close.
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &hidden_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("Checked"),
            outcome_until: None,
        }),
    )
    .await
    .unwrap();
    let closed = update(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &closing(&seen_by_bob, "Done"),
    )
    .await;
    assert_eq!(closed.unwrap().summary.status, "closed");
    fx.db.drop().await;
}

#[tokio::test]
async fn a_stale_version_is_refused_and_an_unchanged_update_writes_nothing() {
    let mut fx = setup().await;
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Versions",
        &[("host", WEB)],
    )
    .await;
    let renamed = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            title: "Renamed",
            ..same(&case, "open")
        },
    )
    .await
    .unwrap();
    assert_eq!(renamed.summary.version, case.summary.version + 1);
    // The old version again.
    let stale = update(
        &mut fx,
        &global(),
        DAVE,
        &case,
        &CaseChange {
            title: "Mine",
            ..same(&case, "open")
        },
    )
    .await;
    assert_eq!(stale.unwrap_err(), Refusal::Stale);
    // The current values change nothing: same version, no new audit row.
    let before = audit_actions(&fx).await.len();
    let noop = update(&mut fx, &global(), ALICE, &renamed, &same(&renamed, "open"))
        .await
        .unwrap();
    assert_eq!(noop.summary.version, renamed.summary.version);
    assert_eq!(audit_actions(&fx).await.len(), before);
    // A case nobody can see is absent, not stale.
    let db_only = open_case(&mut fx.console, &global(), ALICE, "Hidden", &[("host", DB)]).await;
    let absent = update(
        &mut fx,
        &prod(),
        BOB,
        &db_only,
        &same(&db_only, "investigating"),
    )
    .await;
    assert_eq!(absent.unwrap_err(), Refusal::NotFound);
    // Status moves between open and investigating and is on the timeline.
    let investigating = update(
        &mut fx,
        &global(),
        ALICE,
        &renamed,
        &same(&renamed, "investigating"),
    )
    .await
    .unwrap();
    assert_eq!(investigating.summary.status, "investigating");
    let status = investigating.events.last().unwrap();
    assert_eq!(status.kind, "status");
    assert_eq!(status.detail["from"], "open");
    assert_eq!(status.detail["to"], "investigating");
    fx.db.drop().await;
}

#[tokio::test]
async fn invalid_titles_severities_and_statuses_are_refused() {
    let mut fx = setup().await;
    for title in ["", " padded ", &"t".repeat(121), "tab\there"] {
        let refused = cases::create(
            &mut fx.console,
            &global(),
            ALICE,
            &NewCase {
                title,
                severity: None,
                assignee_user_id: None,
                items: &[],
            },
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(
            refused.unwrap_err(),
            Refusal::Invalid("title", "invalid_title")
        );
    }
    let refused = cases::create(
        &mut fx.console,
        &global(),
        ALICE,
        &NewCase {
            title: "ok",
            severity: Some("urgent"),
            assignee_user_id: None,
            items: &[],
        },
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(
        refused.unwrap_err(),
        Refusal::Invalid("severity", "invalid_severity")
    );
    let case = open_case(&mut fx.console, &global(), ALICE, "ok", &[]).await;
    let refused = update(&mut fx, &global(), ALICE, &case, &same(&case, "done")).await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::Invalid("status", "invalid_status")
    );
    fx.db.drop().await;
}
