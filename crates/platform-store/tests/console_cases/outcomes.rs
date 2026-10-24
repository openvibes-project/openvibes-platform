//! Items' outcomes and the evidence behind `resolved`.

use super::*;

#[tokio::test]
async fn resolved_needs_the_evidence_to_be_gone() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let web_finding = finding(WEB);
    let web_vuln = vuln(WEB);
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Evidence",
        &[
            ("alarm", &alarm),
            ("compliance_finding", &web_finding),
            ("vulnerability", &web_vuln),
            ("host", WEB),
            ("software", "rpm/openssl"),
        ],
    )
    .await;
    let resolved = || {
        Some(OutcomeChange {
            outcome: "resolved",
            note: None,
            outcome_until: None,
        })
    };
    let alarm_item = item_id(&case, "alarm").to_owned();
    let finding_item = item_id(&case, "compliance_finding").to_owned();
    let vuln_item = item_id(&case, "vulnerability").to_owned();
    // Everything is still there: nothing can be resolved.
    for item in [&alarm_item, &finding_item, &vuln_item] {
        let refused = outcome(&mut fx, &global(), ALICE, &case, item, resolved()).await;
        assert_eq!(refused.unwrap_err(), Refusal::EvidencePresent);
    }
    // Hosts and software take no outcome at all.
    for kind in ["host", "software"] {
        let refused = outcome(
            &mut fx,
            &global(),
            ALICE,
            &case,
            item_id(&case, kind),
            resolved(),
        )
        .await;
        assert_eq!(
            refused.unwrap_err(),
            Refusal::Invalid("outcome", "outcome_not_applicable")
        );
    }
    // False positive and accepted risk need a note, and a known outcome.
    for note in [None, Some("   ")] {
        let refused = outcome(
            &mut fx,
            &global(),
            ALICE,
            &case,
            &alarm_item,
            Some(OutcomeChange {
                outcome: "false_positive",
                note,
                outcome_until: None,
            }),
        )
        .await;
        assert!(matches!(refused.unwrap_err(), Refusal::Invalid("note", _)));
    }
    let refused = outcome(
        &mut fx,
        &global(),
        ALICE,
        &case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: "fixed",
            note: Some("x"),
            outcome_until: None,
        }),
    )
    .await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::Invalid("outcome", "invalid_outcome")
    );

    // The alarm is closed as mitigated, the finding is no longer reported,
    // and the advisory no longer matches: each is now evidence.
    fx.admin
        .batch_execute(&format!(
            "UPDATE alarms SET state = 'mitigated', note = 'done' WHERE id = {alarm};
             UPDATE current_findings SET ended_at = now() WHERE agent_id = '{WEB}';
             UPDATE vulnerabilities SET fixed_at = now() WHERE agent_id = '{WEB}';"
        ))
        .await
        .unwrap();
    let fresh = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    for item in &fresh.items {
        let expected = matches!(
            item.kind.as_str(),
            "alarm" | "compliance_finding" | "vulnerability"
        );
        assert_eq!(item.evidence_gone, expected, "{}", item.kind);
    }
    for item in [&alarm_item, &finding_item, &vuln_item] {
        let saved = outcome(&mut fx, &global(), ALICE, &case, item, resolved())
            .await
            .unwrap();
        assert_eq!(saved.outcome.as_deref(), Some("resolved"));
    }
    // With all resolved the case closes...
    let ready = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    assert_eq!(ready.summary.pending_items, 0);
    // ...unless the evidence came back in the meantime.
    fx.admin
        .batch_execute(&format!(
            "UPDATE current_findings SET ended_at = NULL WHERE agent_id = '{WEB}';"
        ))
        .await
        .unwrap();
    let refused = update(&mut fx, &global(), ALICE, &ready, &closing(&ready, "Fixed")).await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    fx.admin
        .batch_execute(&format!(
            "UPDATE current_findings SET ended_at = now() WHERE agent_id = '{WEB}';"
        ))
        .await
        .unwrap();
    let closed = update(&mut fx, &global(), ALICE, &ready, &closing(&ready, "Fixed")).await;
    assert_eq!(closed.unwrap().summary.status, "closed");

    // An outcome can be cleared on an open case; a vulnerability that is
    // only the no-fix kind (by package version) counts as present too.
    let bash = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "No fix",
        &[("vulnerability", &format!("{DB}/FEDORA-2"))],
    )
    .await;
    let bash_item = item_id(&bash, "vulnerability").to_owned();
    assert!(!bash.items[0].evidence_gone);
    assert_eq!(bash.items[0].severity.as_deref(), Some("low"));
    let marked = outcome(
        &mut fx,
        &global(),
        ALICE,
        &bash,
        &bash_item,
        Some(OutcomeChange {
            outcome: "accepted_risk",
            note: Some("No fix exists"),
            outcome_until: Some(Utc::now() + Duration::days(30)),
        }),
    )
    .await
    .unwrap();
    assert_eq!(marked.outcome_note.as_deref(), Some("No fix exists"));
    let cleared = outcome(&mut fx, &global(), ALICE, &bash, &bash_item, None)
        .await
        .unwrap();
    assert_eq!((cleared.outcome, cleared.outcome_note), (None, None));
    fx.db.drop().await;
}

/// Sets `outcome` with `note` and `until` on the case's alarm.
async fn on_alarm(
    fx: &mut Fx,
    case: &CaseDetail,
    outcome_value: &str,
    note: Option<&str>,
    until: Option<DateTime<Utc>>,
) -> Result<cases::CaseItem, Refusal> {
    let alarm_item = item_id(case, "alarm").to_owned();
    outcome(
        fx,
        &global(),
        ALICE,
        case,
        &alarm_item,
        Some(OutcomeChange {
            outcome: outcome_value,
            note,
            outcome_until: until,
        }),
    )
    .await
}

#[tokio::test]
async fn confirmed_malicious_and_expected_need_a_note() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "New",
        &[("alarm", &alarm)],
    )
    .await;
    for value in ["confirmed_malicious", "expected"] {
        let refused = on_alarm(&mut fx, &case, value, None, None).await;
        assert_eq!(
            refused.unwrap_err(),
            Refusal::Invalid("note", "note_required"),
            "{value}"
        );
        let saved = on_alarm(&mut fx, &case, value, Some("Why"), None)
            .await
            .unwrap();
        assert_eq!(saved.outcome.as_deref(), Some(value));
        assert_eq!(saved.outcome_note.as_deref(), Some("Why"));
        assert_eq!(saved.outcome_until, None);
    }
    // No date for anything but accepted risk.
    let refused = on_alarm(
        &mut fx,
        &case,
        "expected",
        Some("Why"),
        Some(Utc::now() + Duration::days(1)),
    )
    .await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::Invalid("outcome_until", "outcome_until_not_allowed")
    );
    // The database holds the same rule.
    let result = fx
        .admin
        .execute(
            "UPDATE case_items SET outcome = 'confirmed_malicious', outcome_note = NULL
             WHERE case_id = $1::text::uuid",
            &[&case.summary.case_id],
        )
        .await;
    assert!(result.is_err());
    fx.db.drop().await;
}

#[tokio::test]
async fn accepted_risk_needs_a_future_date_within_a_year() {
    let mut fx = setup().await;
    let alarm = fx.web_alarm.clone();
    let case = open_case(
        &mut fx.console,
        &global(),
        ALICE,
        "Risk",
        &[("alarm", &alarm)],
    )
    .await;
    let now = Utc::now();
    for (until, code) in [
        (None, "outcome_until_required"),
        (Some(now - Duration::minutes(1)), "outcome_until_past"),
        (Some(now + Duration::days(366)), "outcome_until_too_far"),
    ] {
        let refused = on_alarm(&mut fx, &case, "accepted_risk", Some("ok"), until).await;
        assert_eq!(
            refused.unwrap_err(),
            Refusal::Invalid("outcome_until", code)
        );
    }
    let refused = on_alarm(
        &mut fx,
        &case,
        "accepted_risk",
        None,
        Some(now + Duration::days(30)),
    )
    .await;
    assert_eq!(
        refused.unwrap_err(),
        Refusal::Invalid("note", "note_required")
    );
    let until = now + Duration::days(365) - Duration::minutes(1);
    let saved = on_alarm(
        &mut fx,
        &case,
        "accepted_risk",
        Some("Rebuild"),
        Some(until),
    )
    .await
    .unwrap();
    assert_eq!(
        saved.outcome_until.map(|at| at.timestamp()),
        Some(until.timestamp())
    );
    // Another outcome, or none, drops the date.
    let changed = on_alarm(&mut fx, &case, "expected", Some("Fine"), None)
        .await
        .unwrap();
    assert_eq!(changed.outcome_until, None);
    let detail = fetch(&fx, &global(), ALICE, &case).await.unwrap();
    let event = detail.events.last().unwrap();
    assert_eq!(
        (event.detail["from"].as_str(), event.detail["to"].as_str()),
        (Some("accepted_risk"), Some("expected"))
    );
    fx.db.drop().await;
}
