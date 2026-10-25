//! Cases over HTTP, Fixed and lazy reopening: resolved needs the evidence
//! gone, and accepted risk or evidence that returns reopens the case.
//! Shared harness: `common/cases.rs`.

mod common;
use common::cases::*;

#[tokio::test]
async fn resolved_needs_the_evidence_to_be_gone() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let finding = format!("{WEB}/baseline/ssh-root");
    let case = fx
        .open(
            &alice,
            "Evidence",
            json!([{"kind": "compliance_finding", "ref": finding}, {"kind": "host", "ref": WEB}]),
        )
        .await;
    let uri = case_uri(&case);
    let item = item_of(&case, "compliance_finding")["item_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let outcome_uri = format!("{uri}/items/{item}/outcome");
    let (status, problem, _) = fx
        .send(
            &alice,
            "PUT",
            &outcome_uri,
            Some(json!({"outcome": "resolved"})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("evidence_present"))
    );
    // The agent stops reporting it.
    fx.sql(&format!(
        "UPDATE current_findings SET ended_at = now() WHERE agent_id = '{WEB}'"
    ))
    .await;
    let (_, now_gone) = fx.get(&alice, &uri).await;
    assert_eq!(
        item_of(&now_gone, "compliance_finding")["evidence_gone"],
        true
    );
    let (status, set, _) = fx
        .send(
            &alice,
            "PUT",
            &outcome_uri,
            Some(json!({"outcome": "resolved"})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    assert_eq!(set["outcome"], "resolved");
    // Marking needs a note; hosts take no outcome; unknown outcomes are refused.
    for (item, body, field, code) in [
        (
            item.clone(),
            json!({"outcome": "false_positive"}),
            "note",
            "note_required",
        ),
        (
            item.clone(),
            json!({"outcome": "accepted_risk", "note": " "}),
            "note",
            "note_required",
        ),
        (
            item.clone(),
            json!({"outcome": "fixed"}),
            "outcome",
            "invalid_outcome",
        ),
        (
            item_of(&case, "host")["item_id"]
                .as_str()
                .unwrap()
                .to_owned(),
            json!({"outcome": "resolved"}),
            "outcome",
            "outcome_not_applicable",
        ),
    ] {
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &format!("{uri}/items/{item}/outcome"),
                Some(body.clone()),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body}: {problem}"
        );
        assert_eq!(
            field_errors(&problem),
            [(field.to_owned(), code.to_owned())]
        );
    }
    // Clearing sets it back to pending.
    let (status, cleared, _) = fx
        .send(
            &alice,
            "PUT",
            &outcome_uri,
            Some(json!({"outcome": null})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    assert_eq!(cleared["outcome"], Value::Null);
    // An unknown or foreign item id is a plain 404.
    for bad in ["00000000-0000-4000-8000-000000000000", "nope"] {
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &format!("{uri}/items/{bad}/outcome"),
                Some(json!({"outcome": null})),
                None,
            )
            .await;
        assert_eq!(
            (status, problem["code"].clone()),
            (StatusCode::NOT_FOUND, json!("item_not_found"))
        );
    }
    fx.db.drop().await;
}

#[tokio::test]
async fn accepted_risk_that_runs_out_reopens_the_case_when_it_is_next_read() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let case = fx
        .open(&alice, "Accept", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let uri = case_uri(&case);
    let until = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (status, closed, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(
                &case,
                json!({"status": "closed", "closing_note": "Until Friday"}),
            )),
            Some("\"1\""),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    // A case closed as accepted risk before step 5d.
    fx.sql(&format!(
        "UPDATE cases SET resolution = 'accepted_risk', accepted_until = '{until}'"
    ))
    .await;
    let (_, still_closed) = fx.get(&alice, &uri).await;
    assert_eq!(still_closed["status"], "closed");
    // Time passes.
    fx.sql("UPDATE cases SET accepted_until = now() - interval '1 minute'")
        .await;
    let (_, page) = fx.get(&alice, "/api/v1/cases").await;
    assert_eq!(
        page["items"][0]["status"], "open",
        "the default list shows it again"
    );
    let (_, reopened) = fx.get(&alice, &uri).await;
    assert_eq!(
        (
            reopened["status"].clone(),
            reopened["resolution"].clone(),
            reopened["accepted_until"].clone()
        ),
        (json!("open"), Value::Null, Value::Null)
    );
    assert_eq!(reopened["version"], 3);
    let last = reopened["events"].as_array().unwrap().last().unwrap();
    assert_eq!(
        (
            last["kind"].clone(),
            last["actor"].clone(),
            last["detail"]["reason"].clone()
        ),
        (
            json!("reopened"),
            Value::Null,
            json!("accepted_risk_expired")
        )
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn resolved_evidence_that_returns_reopens_the_case_when_it_is_next_read() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let finding = format!("{WEB}/baseline/ssh-root");
    let case = fx
        .open(
            &alice,
            "Resolved",
            json!([{"kind": "compliance_finding", "ref": finding}, {"kind": "host", "ref": WEB}]),
        )
        .await;
    let uri = case_uri(&case);
    fx.sql("UPDATE current_findings SET ended_at = now()").await;
    let item = item_of(&case, "compliance_finding")["item_id"]
        .as_str()
        .unwrap();
    let (status, set, _) = fx
        .send(
            &alice,
            "PUT",
            &format!("{uri}/items/{item}/outcome"),
            Some(json!({"outcome": "resolved"})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{set}");
    let (status, closed, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(
                &case,
                json!({"status": "closed", "closing_note": "Fixed"}),
            )),
            Some("\"1\""),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    let (_, still_closed) = fx.get(&alice, &uri).await;
    assert_eq!(still_closed["status"], "closed");
    // The agent reports it again.
    fx.sql("UPDATE current_findings SET ended_at = NULL").await;
    let (_, page) = fx.get(&alice, "/api/v1/cases").await;
    assert_eq!(
        page["items"][0]["status"], "open",
        "back in the default list"
    );
    let (status, reopened, etag) = fx.send(&alice, "GET", &uri, None, None).await;
    assert_eq!((status, etag.as_deref()), (StatusCode::OK, Some("\"3\"")));
    assert_eq!(
        (
            reopened["resolution"].clone(),
            reopened["resolution_note"].clone()
        ),
        (Value::Null, Value::Null)
    );
    let item = item_of(&reopened, "compliance_finding");
    assert_eq!(
        (item["outcome"].clone(), item["active"].clone()),
        (Value::Null, json!(true))
    );
    assert_eq!(reopened["pending_item_count"], 1);
    let events = reopened["events"].as_array().unwrap();
    let last = &events[events.len() - 2];
    assert_eq!(last["kind"], "reopened");
    assert_eq!(
        (last["actor"].clone(), last["detail"]["reason"].clone()),
        (Value::Null, json!("evidence_returned"))
    );
    assert_eq!(events[events.len() - 1]["kind"], "item_outcome");
    assert_eq!(events[events.len() - 1]["detail"]["item_ref"], finding);
    let reopen_audits = fx
        .audit()
        .await
        .iter()
        .filter(|(a, _)| a == "case.reopen")
        .count();
    assert_eq!(reopen_audits, 1);
    fx.db.drop().await;
}
