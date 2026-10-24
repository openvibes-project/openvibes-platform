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
    let refused = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "mitigated", "Fixed"),
    )
    .await;
    assert_eq!(refused.unwrap_err(), Refusal::ItemsUnresolved(1));
    fx.admin
        .batch_execute(&format!(
            "UPDATE current_findings SET ended_at = now() WHERE agent_id = '{WEB}';"
        ))
        .await
        .unwrap();
    let closed = update(
        &mut fx,
        &global(),
        ALICE,
        &ready,
        &closing(&ready, "mitigated", "Fixed"),
    )
    .await;
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
