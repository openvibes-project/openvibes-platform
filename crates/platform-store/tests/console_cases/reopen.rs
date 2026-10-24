//! Reopening when accepted risk runs out.

use super::*;

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
        &CaseChange {
            accepted_until: Some(until),
            ..closing(&ready, "accepted_risk", "Rebuild next week")
        },
    )
    .await
    .unwrap();
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
        }),
    )
    .await
    .unwrap();
    let ready = fetch(&fx, &global(), ALICE, &again).await.unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &CaseChange {
            accepted_until: Some(Utc::now() + Duration::hours(1)),
            ..closing(&ready, "accepted_risk", "n")
        },
    )
    .await
    .unwrap();
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
