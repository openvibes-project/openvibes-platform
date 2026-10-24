//! Item outcomes and closing over HTTP since step 5d: the five outcomes,
//! accepted risk's per-item `outcome_until`, its lazy clearing, and the
//! closing note.

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::{Value, json};

mod common;
use common::http::call_with;
use common::people::Fx;

const W1: &str = "agent.00000000-0000-4000-8000-0000000000a1";

/// A case holding a vulnerability and an alarm on W1; returns its detail.
async fn seed(fx: &Fx) -> Value {
    let client = fx.db.pool.get().await.unwrap();
    client
        .batch_execute(&format!(
            "INSERT INTO agents (agent_id, status, enrolled_at, hostname, last_seen_at)
                VALUES ('{W1}', 'active', now(), 'web-01', now());
             INSERT INTO advisories (advisory_id, source, os_id, os_version, severity, title, url)
                VALUES ('FEDORA-1', 'fedora', 'fedora', '44', 'important', 'openssl update', 'https://x');
             INSERT INTO vulnerabilities (agent_id, advisory_id, packages, first_seen_at, fixed_at, last_evaluated_at)
                VALUES ('{W1}', 'FEDORA-1', '[]', now(), NULL, now());"
        ))
        .await
        .unwrap();
    let (status, case) = fx
        .call(
            &fx.admin,
            "POST",
            "/api/v1/cases",
            Some(json!({"title": "Openssl",
                        "items": [{"kind": "vulnerability", "ref": format!("{W1}/FEDORA-1")}]})),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{case}");
    case
}

fn outcome_uri(case: &Value) -> String {
    format!(
        "/api/v1/cases/{}/items/{}/outcome",
        case["case_id"].as_str().unwrap(),
        case["items"][0]["item_id"].as_str().unwrap()
    )
}

fn field_error(problem: &Value) -> (Value, Value) {
    (
        problem["field_errors"][0]["field"].clone(),
        problem["field_errors"][0]["code"].clone(),
    )
}

#[tokio::test]
async fn every_outcome_is_accepted_and_accepted_risk_takes_a_date() {
    let Some(fx) = Fx::new().await else { return };
    let case = seed(&fx).await;
    let uri = outcome_uri(&case);
    for outcome in ["false_positive", "confirmed_malicious", "expected"] {
        let (status, item) = fx
            .call(
                &fx.admin,
                "PUT",
                &uri,
                Some(json!({"outcome": outcome, "note": "why"})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{outcome}: {item}");
        assert_eq!(item["outcome"], outcome);
        assert_eq!(item["outcome_until"], Value::Null);
    }
    let soon = Utc::now() + Duration::days(30);
    let (status, item) = fx
        .call(
            &fx.admin,
            "PUT",
            &uri,
            Some(
                json!({"outcome": "accepted_risk", "note": "until the rebuild",
                        "outcome_until": soon.to_rfc3339()}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{item}");
    assert_eq!(item["outcome"], "accepted_risk");
    let until = chrono::DateTime::parse_from_rfc3339(item["outcome_until"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert!((until - soon).num_seconds().abs() < 1, "{until} vs {soon}");
    let case_uri = format!("/api/v1/cases/{}", case["case_id"].as_str().unwrap());
    let (_, detail) = fx.call(&fx.admin, "GET", &case_uri, None).await;
    assert_eq!(
        detail["items"][0]["outcome_until"], item["outcome_until"],
        "the detail shows the date too"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn a_bad_date_is_named_as_the_field_the_client_sent() {
    let Some(fx) = Fx::new().await else { return };
    let case = seed(&fx).await;
    let uri = outcome_uri(&case);
    let far = (Utc::now() + Duration::days(366)).to_rfc3339();
    let past = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let soon = (Utc::now() + Duration::days(1)).to_rfc3339();
    for (body, code) in [
        (
            json!({"outcome": "accepted_risk", "note": "n"}),
            "outcome_until_required",
        ),
        (
            json!({"outcome": "accepted_risk", "note": "n", "outcome_until": "Friday"}),
            "invalid_timestamp",
        ),
        (
            json!({"outcome": "accepted_risk", "note": "n", "outcome_until": past}),
            "outcome_until_past",
        ),
        (
            json!({"outcome": "accepted_risk", "note": "n", "outcome_until": far}),
            "outcome_until_too_far",
        ),
        (
            json!({"outcome": "expected", "note": "n", "outcome_until": soon}),
            "outcome_until_not_allowed",
        ),
    ] {
        let (status, problem) = fx.call(&fx.admin, "PUT", &uri, Some(body.clone())).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body}: {problem}"
        );
        assert_eq!(
            field_error(&problem),
            (json!("outcome_until"), json!(code)),
            "{body}"
        );
        assert_ne!(
            problem["field_errors"][0]["message"],
            "The value is not valid"
        );
    }
    let (status, problem) = fx
        .call(
            &fx.admin,
            "PUT",
            &uri,
            Some(json!({"outcome": "mitigated", "note": "n"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        problem["field_errors"][0]["message"],
        "Use resolved, false_positive, accepted_risk, confirmed_malicious or expected"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn an_expired_acceptance_on_an_open_case_clears() {
    let Some(fx) = Fx::new().await else { return };
    let case = seed(&fx).await;
    let soon = (Utc::now() + Duration::days(1)).to_rfc3339();
    let (status, _) = fx
        .call(
            &fx.admin,
            "PUT",
            &outcome_uri(&case),
            Some(json!({"outcome": "accepted_risk", "note": "n", "outcome_until": soon})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, list) = fx.call(&fx.admin, "GET", "/api/v1/case-list", None).await;
    assert_eq!(list["summary"]["ready_to_close"], 1);
    fx.db
        .pool
        .get()
        .await
        .unwrap()
        .batch_execute("UPDATE case_items SET outcome_until = now() - interval '1 minute'")
        .await
        .unwrap();
    let (_, list) = fx.call(&fx.admin, "GET", "/api/v1/case-list", None).await;
    assert_eq!(list["summary"]["ready_to_close"], 0, "{list}");
    assert_eq!(list["items"][0]["with_outcome"], 0);
    let case_uri = format!("/api/v1/cases/{}", case["case_id"].as_str().unwrap());
    let (_, detail) = fx.call(&fx.admin, "GET", &case_uri, None).await;
    assert_eq!(detail["status"], "open");
    assert_eq!(detail["items"][0]["outcome"], Value::Null);
    fx.db.drop().await;
}

#[tokio::test]
async fn closing_takes_a_closing_note_and_keeps_no_resolution() {
    let Some(fx) = Fx::new().await else { return };
    let case = seed(&fx).await;
    let (status, _) = fx
        .call(
            &fx.admin,
            "PUT",
            &outcome_uri(&case),
            Some(json!({"outcome": "confirmed_malicious", "note": "it was"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let case_uri = format!("/api/v1/cases/{}", case["case_id"].as_str().unwrap());
    let body = |extra: Value| {
        let mut b = json!({"title": "Openssl", "severity": case["severity"], "status": "closed",
                           "assignee_user_id": null});
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        b
    };
    let (_, current) = fx.call(&fx.admin, "GET", &case_uri, None).await;
    let version = format!("\"{}\"", current["version"]);
    for (extra, status, field) in [
        (json!({}), StatusCode::UNPROCESSABLE_ENTITY, "closing_note"),
        (
            json!({"closing_note": "x".repeat(4001)}),
            StatusCode::UNPROCESSABLE_ENTITY,
            "closing_note",
        ),
        (
            json!({"closing_note": "ok", "resolution": "mitigated"}),
            StatusCode::BAD_REQUEST,
            "resolution",
        ),
        (
            json!({"closing_note": "ok", "resolution_note": "old name"}),
            StatusCode::BAD_REQUEST,
            "",
        ),
    ] {
        let (got, problem) = call_with(
            &fx.router,
            "PUT",
            &case_uri,
            &fx.admin,
            Some(body(extra.clone())),
            &[("if-match", &version)],
        )
        .await;
        assert_eq!(got, status, "{extra}: {problem}");
        if !field.is_empty() {
            assert_eq!(problem["field_errors"][0]["field"], field, "{extra}");
        }
    }
    let (status, closed) = call_with(
        &fx.router,
        "PUT",
        &case_uri,
        &fx.admin,
        Some(body(json!({"closing_note": "Contained and rebuilt"}))),
        &[("if-match", &version)],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(
        (
            closed["status"].clone(),
            closed["resolution"].clone(),
            closed["resolution_note"].clone()
        ),
        (json!("closed"), Value::Null, json!("Contained and rebuilt"))
    );
    fx.db.drop().await;
}
