//! Closing: what it needs, hidden items, versions and invalid fields.

use super::*;

#[tokio::test]
async fn closing_needs_a_resolution_a_note_a_date_for_accepted_risk_and_every_outcome() {
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
    // No resolution, no note.
    let refused = update(&mut fx, &global(), ALICE, &case, &same(&case, "closed")).await;
    invalid(refused.unwrap_err(), "resolution", "resolution_required");
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            resolution: Some("mitigated"),
            ..same(&case, "closed")
        },
    )
    .await;
    invalid(
        refused.unwrap_err(),
        "resolution_note",
        "resolution_note_required",
    );
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &closing(&case, "wontfix", "x"),
    )
    .await;
    invalid(refused.unwrap_err(), "resolution", "invalid_resolution");
    // Accepted risk needs a future date; other resolutions take none.
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &closing(&case, "accepted_risk", "ok"),
    )
    .await;
    invalid(
        refused.unwrap_err(),
        "accepted_until",
        "accepted_until_required",
    );
    let past = CaseChange {
        accepted_until: Some(Utc::now() - Duration::minutes(1)),
        ..closing(&case, "accepted_risk", "ok")
    };
    let refused = update(&mut fx, &global(), ALICE, &case, &past).await;
    invalid(
        refused.unwrap_err(),
        "accepted_until",
        "accepted_until_past",
    );
    let stray = CaseChange {
        accepted_until: Some(Utc::now() + Duration::days(1)),
        ..closing(&case, "mitigated", "ok")
    };
    let refused = update(&mut fx, &global(), ALICE, &case, &stray).await;
    invalid(
        refused.unwrap_err(),
        "accepted_until",
        "accepted_until_not_allowed",
    );
    // An open case carries no resolution fields.
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &CaseChange {
            resolution: Some("mitigated"),
            ..same(&case, "investigating")
        },
    )
    .await;
    assert!(matches!(
        refused.unwrap_err(),
        Refusal::Invalid("resolution", _)
    ));

    // With the fields right, the alarm and the finding still need outcomes.
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &closing(&case, "mitigated", "Fixed"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(2));
    let alarm_item = item_id(&case, "alarm").to_owned();
    let finding_item = item_id(&case, "compliance_finding").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("Accepted by the owner"),
        }),
    )
    .await
    .unwrap();
    let after_one = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(after_one.summary.pending_items, 1);
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &after_one,
        &closing(&after_one, "mitigated", "Fixed"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &finding_item,
        Some(OutcomeChange {
            outcome: "false_positive",
            note: Some("Scanner noise"),
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(ready.summary.pending_items, 0);
    let until = Utc::now() + Duration::days(30);
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &CaseChange {
            accepted_until: Some(until),
            ..closing(&ready, "accepted_risk", "Risk accepted until the rebuild")
        },
    )
    .await
    .unwrap();
    let summary = &closed.summary;
    assert_eq!(summary.status, "closed");
    assert_eq!(summary.resolution.as_deref(), Some("accepted_risk"));
    assert!(summary.closed_at.is_some() && summary.accepted_until.is_some());
    assert_eq!(summary.version, ready.summary.version + 1);
    assert_eq!(
        closed.resolution_note.as_deref(),
        Some("Risk accepted until the rebuild")
    );
    let last = closed.events.last().unwrap();
    assert_eq!(last.kind, "resolved");
    assert_eq!(last.detail["resolution"], "accepted_risk");
    // Closed means the outcomes and the resolution stay as they are.
    let refused = outcome(&mut fx, &global(), ALICE, &closed, &alarm_item, None).await;
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    let other_way = CaseChange {
        resolution: Some("mitigated"),
        accepted_until: None,
        ..closing(&closed, "mitigated", "Changed my mind")
    };
    let refused = update(&mut fx, &global(), ALICE, &closed, &other_way).await;
    assert_eq!(refused.unwrap_err(), Refusal::Closed);
    // Title, severity and assignee can still be edited, and notes added.
    let renamed = update(
        &mut fx,
        &global(),
        ALICE,
        &closed,
        &CaseChange {
            title: "Renamed",
            resolution: closed.summary.resolution.as_deref(),
            resolution_note: closed.resolution_note.as_deref(),
            accepted_until: closed.summary.accepted_until,
            ..same(&closed, "closed")
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
        &closing(&seen_by_bob, "mitigated", "Done"),
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
        }),
    )
    .await
    .unwrap();
    let closed = update(
        &mut fx,
        &prod(),
        BOB,
        &seen_by_bob,
        &closing(&seen_by_bob, "mitigated", "Done"),
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
