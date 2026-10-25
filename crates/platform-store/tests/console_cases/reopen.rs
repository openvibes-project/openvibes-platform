//! Reopening when accepted risk runs out: an item's date, or the case's
//! date on a case closed before step 5d.

use super::*;

/// Gives a closed case the case-level acceptance a pre-5d close set.
async fn accepted_until(fx: &Fx, case: &CaseDetail, until: DateTime<Utc>) {
    fx.admin
        .execute(
            "UPDATE cases SET resolution = 'accepted_risk', accepted_until = $2
             WHERE case_id = $1::text::uuid",
            &[&case.summary.case_id, &until],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn accepted_risk_that_runs_out_reopens_the_case() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Accept",
        &[("alarm", &alarm), ("host", WEB)],
    )
    .await;
    let alarm_item = item_id(&case, "alarm").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("Until the rebuild"),
            outcome_until: Some(Utc::now() + Duration::days(30)),
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    let until = Utc::now() + Duration::hours(1);
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "Rebuild next week"),
    )
    .await
    .unwrap();
    accepted_until(&fx, &closed, until).await;
    // Not yet.
    let now = Utc::now();
    assert_eq!(
        cases::reopen_expired(&mut fx.console, now).await.unwrap(),
        0
    );
    // After it runs out.
    let later: DateTime<Utc> = until + Duration::minutes(1);
    assert_eq!(
        cases::reopen_expired(&mut fx.console, later).await.unwrap(),
        1
    );
    assert_eq!(
        cases::reopen_expired(&mut fx.console, later).await.unwrap(),
        0
    );
    let reopened = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    let summary = &reopened.summary;
    assert_eq!(summary.status, "open");
    assert!(
        summary.resolution.is_none()
            && summary.accepted_until.is_none()
            && summary.closed_at.is_none()
    );
    assert_eq!(summary.version, closed.summary.version + 1);
    assert_eq!(reopened.resolution_note, None);
    let alarm = reopened.items.iter().find(|i| i.kind == "alarm").unwrap();
    assert!(
        alarm.active && alarm.outcome.is_none(),
        "the acceptance ran out with it"
    );
    let last = reopened.events.last().unwrap();
    assert_eq!(last.kind, "reopened");
    assert!(last.actor.is_none(), "the platform did it");
    assert_eq!(last.detail["reason"], "accepted_risk_expired");
    let who: String = fx
        .admin
        .query_one(
            "SELECT actor FROM audit_log WHERE action = 'case.reopen'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(who, "system");

    // A case whose item has joined another open case since stays closed.
    let again = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Again",
        &[("alarm", &fx.web_alarm_2.clone())],
    )
    .await;
    let item = item_id(&again, "alarm").to_owned();
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &again,
        &item,
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("n"),
            outcome_until: Some(Utc::now() + Duration::days(30)),
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &again).await.unwrap();
    let closed = update(&mut fx, &global(), ALICE, &ready, &closing(&ready, "n"))
        .await
        .unwrap();
    accepted_until(&fx, &closed, Utc::now() + Duration::hours(1)).await;
    open_case(
        &mut fx.console,
        &global(),
        DAVE,
        "Took it",
        &[("alarm", &fx.web_alarm_2.clone())],
    )
    .await;
    let reopened = cases::reopen_expired(&mut fx.console, Utc::now() + Duration::hours(2))
        .await
        .unwrap();
    assert_eq!(reopened, 0);
    assert_eq!(
        fetch(&fx, &global(), ALICE, &again)
            .await
            .unwrap()
            .summary
            .status,
        "closed"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn an_expired_item_acceptance_reopens_the_case() {
    let mut fx = setup().await;
    let (alarm, db_finding, web_vuln) = (fx.web_alarm.clone(), finding(DB), vuln(WEB));
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Per item",
        &[
            ("alarm", &alarm),
            ("compliance_finding", &db_finding),
            ("vulnerability", &web_vuln),
        ],
    )
    .await;
    let now = Utc::now();
    let soon = now + Duration::days(1);
    for (kind, decision, until) in [
        ("alarm", "accepted_risk", Some(soon)),
        (
            "compliance_finding",
            "accepted_risk",
            Some(now + Duration::days(60)),
        ),
        ("vulnerability", "false_positive", None),
    ] {
        outcome(
            &mut fx,
            &global(),
            ALICE,
            &case,
            item_id(&case, kind),
            Some(OutcomeChange {
                outcome: decision,
                note: Some("decided"),
                outcome_until: until,
            }),
        )
        .await
        .unwrap();
    }
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "Accepted"),
    )
    .await
    .unwrap();
    assert_eq!(cases::reopen_due(&mut fx.console, now).await.unwrap(), 0);
    let later = soon + Duration::minutes(1);
    assert_eq!(cases::reopen_due(&mut fx.console, later).await.unwrap(), 1);
    assert_eq!(cases::reopen_due(&mut fx.console, later).await.unwrap(), 0);
    let reopened = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(reopened.summary.status, "open");
    assert!(reopened.summary.closed_at.is_none() && reopened.resolution_note.is_none());
    assert_eq!(reopened.summary.version, closed.summary.version + 1);
    let of = |kind: &str| reopened.items.iter().find(|i| i.kind == kind).unwrap();
    assert!(of("alarm").active);
    assert_eq!(
        (of("alarm").outcome.as_deref(), of("alarm").outcome_until),
        (None, None),
        "only the expired acceptance clears"
    );
    assert_eq!(
        of("compliance_finding").outcome.as_deref(),
        Some("accepted_risk")
    );
    assert!(of("compliance_finding").outcome_until.is_some());
    assert_eq!(
        of("vulnerability").outcome.as_deref(),
        Some("false_positive")
    );
    assert_eq!(reopened.summary.pending_items, 1);
    let kinds: Vec<_> = reopened.events.iter().rev().take(2).collect();
    assert_eq!(kinds[0].kind, "item_outcome");
    assert_eq!(kinds[0].detail["from"], "accepted_risk");
    assert_eq!(kinds[0].detail["item_kind"], "alarm");
    assert_eq!(kinds[1].kind, "reopened");
    assert_eq!(kinds[1].detail["reason"], "accepted_risk_expired");
    assert!(kinds[1].actor.is_none(), "the platform did it");
    fx.db.drop().await;
}

#[tokio::test]
async fn an_expired_acceptance_on_an_open_case_needs_a_decision_again() {
    let mut fx = setup().await;
    let (alarm, web_finding) = (fx.web_alarm.clone(), finding(WEB));
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Still open",
        &[("alarm", &alarm), ("compliance_finding", &web_finding)],
    )
    .await;
    let soon = Utc::now() + Duration::days(1);
    for (kind, decision, until) in [
        ("alarm", "accepted_risk", Some(soon)),
        ("compliance_finding", "false_positive", None),
    ] {
        outcome(
            &mut fx,
            &global(),
            ALICE,
            &case,
            item_id(&case, kind),
            Some(OutcomeChange {
                outcome: decision,
                note: Some("decided"),
                outcome_until: until,
            }),
        )
        .await
        .unwrap();
    }
    let later = soon + Duration::minutes(1);
    assert_eq!(
        cases::reopen_due(&mut fx.console, later).await.unwrap(),
        0,
        "nothing to reopen"
    );
    let now_open = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(now_open.summary.status, "open", "the status stays");
    let alarm_item = now_open.items.iter().find(|i| i.kind == "alarm").unwrap();
    assert_eq!(
        (alarm_item.outcome.as_deref(), alarm_item.outcome_until),
        (None, None)
    );
    assert_eq!(now_open.summary.pending_items, 1);
    let last = now_open.events.last().unwrap();
    assert_eq!(last.kind, "item_outcome");
    assert!(last.actor.is_none());
    assert_eq!(last.detail["reason"], "accepted_risk_expired");
    assert_eq!(last.detail["from"], "accepted_risk");
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &now_open,
        &closing(&now_open, "Done"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    fx.db.drop().await;
}

#[tokio::test]
async fn close_refuses_an_acceptance_that_ran_out_before_it_was_cleared() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Ran out",
        &[("alarm", &alarm)],
    )
    .await;
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        item_id(&case, "alarm"),
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("for now"),
            outcome_until: Some(Utc::now() + Duration::days(1)),
        }),
    )
    .await
    .unwrap();
    // The date passes, and no read has run reopen_due since.
    fx.admin
        .execute(
            "UPDATE case_items SET outcome_until = now() - interval '1 minute'
             WHERE case_id = $1::text::uuid",
            &[&case.summary.case_id],
        )
        .await
        .unwrap();
    let loaded = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &loaded,
        &closing(&loaded, "Done"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    fx.db.drop().await;
}

#[tokio::test]
async fn cases_that_cannot_reopen_do_not_fill_the_batch() {
    let mut fx = setup().await;
    // 100 closed cases, closed last, each with an expired acceptance on an
    // alarm another open case now holds: they stay closed.
    fx.admin
        .batch_execute(&format!(
            "INSERT INTO cases (case_id, title, status, resolution_note, severity,
                 opened_by_user_id, created_at, updated_at, closed_at)
             SELECT ('00000000-0000-4000-8000-' || lpad(n::text, 12, '0'))::uuid, 'Stuck',
                 'closed', 'n', 'low', '{ALICE}', now(), now(), now()
             FROM generate_series(1, 100) n;
             INSERT INTO cases (case_id, title, status, severity, opened_by_user_id,
                 created_at, updated_at)
             VALUES ('00000000-0000-4000-8000-100000000000', 'Holder', 'open', 'low',
                 '{ALICE}', now(), now());
             INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active, outcome,
                 outcome_note, outcome_until, added_by_user_id, added_at)
             SELECT gen_random_uuid(), ('00000000-0000-4000-8000-' || lpad(n::text, 12, '0'))::uuid,
                 'alarm', (1000 + n)::text, '{WEB}', false, 'accepted_risk', 'n',
                 now() - interval '1 day', '{ALICE}', now()
             FROM generate_series(1, 100) n;
             INSERT INTO case_items (item_id, case_id, kind, ref, agent_id, active,
                 added_by_user_id, added_at)
             SELECT gen_random_uuid(), '00000000-0000-4000-8000-100000000000', 'alarm',
                 (1000 + n)::text, '{WEB}', true, '{ALICE}', now()
             FROM generate_series(1, 100) n;"
        ))
        .await
        .unwrap();
    // One case that can reopen, closed earlier than all of them.
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Free",
        &[("alarm", &alarm)],
    )
    .await;
    outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        item_id(&case, "alarm"),
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("n"),
            outcome_until: Some(Utc::now() + Duration::days(1)),
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    update(&mut fx, &global(), ALICE, &ready, &closing(&ready, "n"))
        .await
        .unwrap();
    fx.admin
        .execute(
            "UPDATE cases SET closed_at = now() - interval '1 day' WHERE case_id = $1::text::uuid",
            &[&case.summary.case_id],
        )
        .await
        .unwrap();
    let later = Utc::now() + Duration::days(2);
    assert_eq!(cases::reopen_due(&mut fx.console, later).await.unwrap(), 1);
    let reopened = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(reopened.summary.status, "open");
    fx.db.drop().await;
}
