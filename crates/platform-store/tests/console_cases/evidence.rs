//! Reopening when the evidence of a resolved item returns.

use super::*;

/// Opens a case with a finding on each host (db-01's is hidden from a
/// production-only caller) and a host, ends both findings, marks each
/// finding `resolved` and closes the case.
async fn closed_on_resolved_findings(fx: &mut Fx, title: &str) -> CaseDetail {
    let web_finding = finding(WEB);
    let db_finding = finding(DB);
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        title,
        &[
            ("host", WEB),
            ("compliance_finding", &web_finding),
            ("compliance_finding", &db_finding),
        ],
    )
    .await;
    fx.admin
        .batch_execute("UPDATE current_findings SET ended_at = now()")
        .await
        .unwrap();
    for item in case.items.iter().filter(|i| i.kind == "compliance_finding") {
        outcome(
            fx,
            &global(),
            ALICE,
            &case,
            &item.item_id,
            Some(OutcomeChange {
                outcome: "resolved",
                note: None,
                outcome_until: None,
            }),
        )
        .await
        .unwrap();
    }
    let ready = fetch(fx, &global(), ALICE, &case).await.unwrap();
    update(fx, &global(), ALICE, &ready, &closing(&ready, "Fixed"))
        .await
        .unwrap()
}

#[tokio::test]
async fn evidence_that_returns_reopens_a_recently_closed_case() {
    let mut fx = setup().await;
    let closed = closed_on_resolved_findings(&mut fx, "Resolved").await;
    // Nothing has come back: nothing to do.
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        0
    );
    // The agent reports web-01's finding again.
    fx.admin
        .execute(
            "UPDATE current_findings SET ended_at = NULL WHERE agent_id = $1",
            &[&WEB],
        )
        .await
        .unwrap();
    assert_eq!(
        cases::reopen_due(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        0,
        "once"
    );
    let reopened = fetch(&fx, &global(), ALICE, &closed).await.unwrap();
    let summary = &reopened.summary;
    assert_eq!(summary.status, "open");
    assert!(summary.resolution.is_none() && summary.closed_at.is_none());
    assert_eq!(summary.version, closed.summary.version + 1);
    assert_eq!(reopened.resolution_note, None);
    assert!(reopened.items.iter().all(|item| item.active));
    let back = reopened
        .items
        .iter()
        .find(|i| i.reference == finding(WEB))
        .unwrap();
    assert!(
        back.outcome.is_none() && !back.evidence_gone,
        "needs a new decision"
    );
    let still_gone = reopened
        .items
        .iter()
        .find(|i| i.reference == finding(DB))
        .unwrap();
    assert_eq!(still_gone.outcome.as_deref(), Some("resolved"));
    assert_eq!(summary.pending_items, 1);
    let tail: Vec<_> = reopened.events.iter().rev().take(2).collect();
    assert_eq!(tail[1].kind, "reopened");
    assert!(tail[1].actor.is_none());
    assert_eq!(tail[1].detail["reason"], "evidence_returned");
    assert!(
        tail[1].detail["previous_resolution"].is_null(),
        "closed with a note only"
    );
    assert!(tail[1].detail.get("item_ref").is_none(), "names no item");
    assert_eq!(tail[0].kind, "item_outcome");
    assert_eq!(tail[0].detail["item_ref"], finding(WEB));
    assert_eq!(tail[0].detail["reason"], "evidence_returned");
    let row = fx
        .admin
        .query_one(
            "SELECT actor, detail::text FROM audit_log WHERE action = 'case.reopen'",
            &[],
        )
        .await
        .unwrap();
    let (actor, detail): (String, String) = (row.get(0), row.get(1));
    assert_eq!(actor, "system");
    assert!(
        detail.contains("evidence_returned") && detail.contains("ssh-root"),
        "{detail}"
    );
    // It must be decided and closed again before it is done.
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &reopened,
        &closing(&reopened, "x"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    fx.db.drop().await;
}

#[tokio::test]
async fn false_positive_and_accepted_risk_do_not_reopen_on_evidence() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let web_finding = finding(WEB);
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Decisions",
        &[("alarm", &alarm), ("compliance_finding", &web_finding)],
    )
    .await;
    for (kind, decision) in [
        ("alarm", "false_positive"),
        ("compliance_finding", "accepted_risk"),
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
                outcome_until: (decision == "accepted_risk")
                    .then(|| Utc::now() + Duration::days(90)),
            }),
        )
        .await
        .unwrap();
    }
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "Accepted"),
    )
    .await
    .unwrap();
    // The alarm and the finding are plainly still there.
    assert_eq!(
        cases::reopen_due(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        fetch(&fx, &global(), ALICE, &case)
            .await
            .unwrap()
            .summary
            .status,
        "closed"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_case_is_watched_for_returning_evidence_for_a_limited_time() {
    let mut fx = setup().await;
    let closed = closed_on_resolved_findings(&mut fx, "Watched").await;
    fx.admin
        .batch_execute("UPDATE current_findings SET ended_at = NULL")
        .await
        .unwrap();
    let after = |days: i64| Utc::now() + Duration::days(days);
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, after(cases::EVIDENCE_WATCH_DAYS + 1))
            .await
            .unwrap(),
        0,
        "closed too long ago"
    );
    assert_eq!(
        fetch(&fx, &global(), ALICE, &closed)
            .await
            .unwrap()
            .summary
            .status,
        "closed"
    );
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, after(cases::EVIDENCE_WATCH_DAYS - 1))
            .await
            .unwrap(),
        1
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_case_stays_closed_when_a_returning_item_joined_another_open_case() {
    let mut fx = setup().await;
    let closed = closed_on_resolved_findings(&mut fx, "Taken").await;
    // Closing freed web-01's finding; someone else takes it, and it returns.
    let web_finding = finding(WEB);
    let other = open_case(
        &mut fx.console,
        &global(),
        DAVE,
        "Other",
        &[("compliance_finding", &web_finding)],
    )
    .await;
    fx.admin
        .batch_execute("UPDATE current_findings SET ended_at = NULL")
        .await
        .unwrap();
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        0
    );
    let unchanged = fetch(&fx, &global(), ALICE, &closed).await.unwrap();
    assert_eq!(unchanged.summary.status, "closed");
    assert!(unchanged.items.iter().all(|i| !i.active));
    assert_eq!(
        fetch(&fx, &global(), DAVE, &other)
            .await
            .unwrap()
            .summary
            .status,
        "open"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn reopening_on_evidence_names_no_item_the_viewer_cannot_see() {
    let mut fx = setup().await;
    let closed = closed_on_resolved_findings(&mut fx, "Hidden").await;
    fx.admin
        .execute(
            "UPDATE current_findings SET ended_at = NULL WHERE agent_id = $1",
            &[&DB],
        )
        .await
        .unwrap();
    assert_eq!(
        cases::reopen_evidence_returned(&mut fx.console, Utc::now())
            .await
            .unwrap(),
        1
    );
    let seen = fetch(&fx, &prod(), BOB, &closed).await.unwrap();
    assert_eq!(seen.summary.status, "open");
    let kinds: Vec<_> = seen.events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds.last(), Some(&"reopened"), "{kinds:?}");
    assert!(
        !kinds.iter().rev().take(2).any(|k| *k == "item_outcome"),
        "the db-01 item's entry is not his to see"
    );
    let rendered = format!("{seen:?}");
    assert!(!rendered.contains(DB), "{rendered}");
    // Someone who sees it all gets the item's entry.
    let all = fetch(&fx, &global(), ALICE, &closed).await.unwrap();
    assert!(
        all.events
            .iter()
            .any(|e| e.kind == "item_outcome" && e.detail["to"].is_null())
    );
    fx.db.drop().await;
}
