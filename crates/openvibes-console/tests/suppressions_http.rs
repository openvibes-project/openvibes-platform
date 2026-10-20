//! Alarm suppressions with approval over HTTP (roles spec §8): who may
//! request, approve, reject, withdraw and remove, the refusals, the
//! per-row flags and the suppress form's options.

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;
use common::{
    http::sign_in,
    suppressions::{LIST, setup},
};

#[tokio::test]
async fn options_follow_the_suppress_reach() {
    let Some(s) = setup().await else { return };
    let options = "/api/v1/alarm-suppressions/options";
    let (status, body) = s.call(&s.analyst, "GET", options, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["all_hosts"], false);
    assert_eq!(body["require_approval"], false);
    assert_eq!(body["groups"], json!([{"id": s.linux, "name": "linux"}]));
    s.approval(true).await;
    let (_, body) = s.call(&s.fx.admin, "GET", options, None).await;
    assert_eq!(body["all_hosts"], true);
    assert_eq!(body["require_approval"], true);
    let names: Vec<&str> = body["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"linux") && names.contains(&"windows") && names.contains(&"win"),
        "{body}"
    );
    s.done().await;
}

#[tokio::test]
async fn analyst_request_waits_when_approval_is_on() {
    let Some(s) = setup().await else { return };
    let id = s.waiting().await;
    let row = s.row(&s.analyst, &id).await.unwrap();
    assert_eq!(row["can_withdraw"], true);
    assert_eq!(row["can_decide"], false);
    assert_eq!(row["requested_by"], "ana");
    assert_eq!(row["where"]["group_name"], "linux");
    assert_eq!(row["alarm_id"], s.linux_alarm);
    assert_eq!(s.alarm_state(&s.linux_alarm).await, "open");
    s.done().await;
}

#[tokio::test]
async fn lead_approves_and_it_becomes_active() {
    let Some(s) = setup().await else { return };
    let id = s.waiting().await;
    let (status, body) = s.act(&s.lead, &id, "approve", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "active");
    assert_eq!(body["decided_by"], "lead");
    let expires: DateTime<Utc> = body["expires_at"].as_str().unwrap().parse().unwrap();
    assert!(
        (expires - (Utc::now() + Duration::days(7)))
            .num_seconds()
            .abs()
            < 60
    );
    assert_eq!(s.alarm_state(&s.linux_alarm).await, "false_positive");
    s.done().await;
}

#[tokio::test]
async fn requester_cannot_approve_even_holding_approve_everywhere() {
    let Some(s) = setup().await else { return };
    s.approval(true).await;
    let (status, made) = s
        .ask(&s.fx.admin, &s.linux_alarm, json!({"kind": "all"}))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    assert_eq!(made["can_decide"], false);
    let id = made["id"].as_str().unwrap();
    let (status, body) = s.act(&s.fx.admin, id, "approve", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "own_request");
    let (status, body) = s
        .act(&s.fx.admin, id, "reject", Some(json!({"reason": "x"})))
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("own_request"))
    );
    s.done().await;
}

#[tokio::test]
async fn approving_outside_reach_is_not_found() {
    let Some(s) = setup().await else { return };
    let id = s.waiting().await;
    let (status, outside) = s.act(&s.win_lead, &id, "approve", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(outside["code"], "suppression_not_found");
    let (status, missing) = s.act(&s.win_lead, "999999", "approve", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        (&outside["code"], &outside["title"]),
        (&missing["code"], &missing["title"])
    );
    assert_eq!(s.row(&s.analyst, &id).await.unwrap()["status"], "waiting");
    s.done().await;
}

#[tokio::test]
async fn reject_needs_reason() {
    let Some(s) = setup().await else { return };
    let id = s.waiting().await;
    let (status, body) = s.act(&s.lead, &id, "reject", Some(json!({}))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "invalid_suppression");
    assert_eq!(body["field_errors"][0]["field"], "reason");
    let (status, body) = s
        .act(&s.lead, &id, "reject", Some(json!({"reason": "no"})))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "rejected");
    let row = s.row(&s.analyst, &id).await.unwrap();
    assert_eq!(row["decision_reason"], "no");
    let (status, body) = s.act(&s.lead2, &id, "approve", None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::CONFLICT, Some("suppression_not_waiting"))
    );
    s.done().await;
}

#[tokio::test]
async fn withdraw_only_own() {
    let Some(s) = setup().await else { return };
    let id = s.waiting().await;
    let (status, body) = s.act(&s.lead, &id, "withdraw", None).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("suppression_not_found"))
    );
    let (status, body) = s.act(&s.analyst, &id, "withdraw", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(s.row(&s.analyst, &id).await.is_none());
    s.done().await;
}

#[tokio::test]
async fn all_hosts_needs_global() {
    let Some(s) = setup().await else { return };
    let (status, body) = s
        .ask(&s.analyst, &s.linux_alarm, json!({"kind": "all"}))
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("global_scope_required"))
    );
    s.done().await;
}

#[tokio::test]
async fn group_outside_reach() {
    let Some(s) = setup().await else { return };
    let (status, body) = s.ask(&s.analyst, &s.linux_alarm, s.group(&s.windows)).await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("permission_denied"))
    );
    let (status, body) = s
        .ask(&s.analyst, &s.win_alarm, json!({"kind": "host"}))
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("alarm_not_found"))
    );
    let mut bad = json!({"alarm_id": s.linux_alarm, "what": "program", "where": {"kind": "host"},
        "for_days": 5, "reason": "x"});
    let (status, body) = s.call(&s.analyst, "POST", LIST, Some(bad.clone())).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["field_errors"][0]["field"], "for");
    bad["extra"] = json!(1);
    let (status, _) = s.call(&s.analyst, "POST", LIST, Some(bad)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    s.done().await;
}

#[tokio::test]
async fn list_visibility() {
    let Some(s) = setup().await else { return };
    let (_, all) = s
        .ask(&s.fx.admin, &s.linux_alarm, json!({"kind": "all"}))
        .await;
    let (_, win) = s.ask(&s.fx.admin, &s.win_alarm, s.group(&s.windows)).await;
    let (_, lin) = s.ask(&s.fx.admin, &s.linux_alarm, s.group(&s.linux)).await;
    let (_, host) = s
        .ask(&s.fx.admin, &s.win_alarm, json!({"kind": "host"}))
        .await;
    assert_eq!(host["where"]["hostname"], "win-01");
    let seen: Vec<Value> = s
        .rows(&s.win_lead)
        .await
        .into_iter()
        .map(|row| row["id"].clone())
        .collect();
    assert!(seen.contains(&all["id"]) && seen.contains(&win["id"]) && seen.contains(&host["id"]));
    assert!(!seen.contains(&lin["id"]), "{seen:?}");
    s.done().await;
}

#[tokio::test]
async fn can_decide_flags() {
    let Some(s) = setup().await else { return };
    let theirs = s.waiting().await;
    let (_, own) = s.ask(&s.lead, &s.linux_alarm, s.group(&s.linux)).await;
    let own = own["id"].as_str().unwrap();
    assert_eq!(s.row(&s.lead, &theirs).await.unwrap()["can_decide"], true);
    assert_eq!(s.row(&s.lead, own).await.unwrap()["can_decide"], false);
    assert_eq!(s.row(&s.lead2, own).await.unwrap()["can_decide"], true);
    assert_eq!(
        s.row(&s.analyst, &theirs).await.unwrap()["can_decide"],
        false
    );
    s.done().await;
}

#[tokio::test]
async fn bearer_token_cannot_approve() {
    use sha2::{Digest, Sha256};
    let Some(s) = setup().await else { return };
    let id = s.waiting().await;
    let secret = "ovst_0123456789abcdef0123456789abcdef0123456789a";
    let mut client = s.fx.db.pool.get().await.unwrap();
    let admin = common::people::uid(1);
    let account = platform_store::console_auth::create_service_account(
        &mut client,
        "ci",
        &["admin".to_owned()],
        &admin,
        Utc::now(),
    )
    .await
    .unwrap()
    .unwrap();
    client
        .execute(
            "INSERT INTO console_service_tokens (token_id, service_account_id, token_sha256, label,
                created_at, expires_at, created_by)
             VALUES (gen_random_uuid(), $1::text::uuid, $2, 'test', now(), now() + interval '1 day', 'test')",
            &[&account, &Sha256::digest(secret.as_bytes()).as_slice()],
        )
        .await
        .unwrap();
    drop(client);
    let request = |method: &str, uri: String| {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {secret}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{\"reason\":\"x\"}"))
            .unwrap()
    };
    for verb in ["approve", "reject"] {
        let uri = format!("{LIST}/{id}/{verb}");
        let response =
            s.fx.router
                .clone()
                .oneshot(request("POST", uri))
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{verb}");
    }
    let response =
        s.fx.router
            .clone()
            .oneshot(request("GET", LIST.into()))
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "a token may read");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let list: Value = serde_json::from_slice(&bytes).unwrap();
    let row = &list["items"][0];
    assert_eq!(row["status"], "waiting", "{list}");
    for flag in ["can_decide", "can_withdraw", "can_remove"] {
        assert_eq!(row[flag], false, "a token reads no {flag}");
    }
    assert_eq!(s.row(&s.analyst, &id).await.unwrap()["status"], "waiting");
    s.done().await;
}

#[tokio::test]
async fn remove_active() {
    let Some(s) = setup().await else { return };
    let (status, lin) = s.ask(&s.lead, &s.linux_alarm, s.group(&s.linux)).await;
    assert_eq!(
        (status, lin["status"].as_str()),
        (StatusCode::CREATED, Some("active")),
        "{lin}"
    );
    let (_, all) = s
        .ask(&s.fx.admin, &s.linux_alarm, json!({"kind": "all"}))
        .await;
    let all = all["id"].as_str().unwrap();
    assert_eq!(s.row(&s.analyst, all).await.unwrap()["can_remove"], false);
    let lin = lin["id"].as_str().unwrap();
    assert_eq!(s.row(&s.analyst, lin).await.unwrap()["can_remove"], true);
    let (status, _) = s
        .call(&s.analyst, "DELETE", &format!("{LIST}/{lin}"), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body) = s
        .call(&s.analyst, "DELETE", &format!("{LIST}/{all}"), None)
        .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("suppression_not_found"))
    );
    let viewer = sign_in(&s.fx.router, "lead").await;
    assert!(
        s.row(&viewer, lin).await.is_none(),
        "removed rows leave the list"
    );
    s.done().await;
}

#[tokio::test]
async fn bulk_suppress_waits_and_says_requested() {
    let Some(s) = setup().await else { return };
    s.approval(true).await;
    let body = json!({"action": "suppress", "note": "noise", "items": [{"id": s.linux_alarm}]});
    let (status, answer) = s
        .call(&s.fx.admin, "POST", "/api/v1/alarms/bulk", Some(body))
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["changed"], 0);
    assert_eq!(
        answer["skipped"][0]["reason"],
        "Suppression requested, waiting for approval"
    );
    assert_eq!(s.rows(&s.fx.admin).await[0]["status"], "waiting");
    s.done().await;
}

#[tokio::test]
async fn waiting_row_of_a_deleted_group_cannot_be_decided() {
    let Some(s) = setup().await else { return };
    let id = s.waiting().await;
    assert_eq!(s.row(&s.fx.admin, &id).await.unwrap()["can_decide"], true);
    let client = s.fx.db.pool.get().await.unwrap();
    // As a race with the group's delete would leave it (a delete through
    // the API withdraws it).
    for table in ["console_role_groups", "console_asset_groups"] {
        let sql = format!("DELETE FROM {table} WHERE asset_group_id::text = $1");
        client.execute(&sql, &[&s.linux]).await.unwrap();
    }
    drop(client);
    let row = s.row(&s.fx.admin, &id).await.unwrap();
    assert_eq!(row["can_decide"], false, "approve would answer 422 group");
    let (status, body) = s.act(&s.fx.admin, &id, "approve", None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    s.done().await;
}

#[tokio::test]
async fn bulk_suppress_names_an_invalid_note() {
    let Some(s) = setup().await else { return };
    let note = "x".repeat(4001);
    let body = json!({"action": "suppress", "note": note, "items": [{"id": s.linux_alarm}]});
    let (status, answer) = s
        .call(&s.fx.admin, "POST", "/api/v1/alarms/bulk", Some(body))
        .await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer["skipped"][0]["reason"],
        "the note must be 1 to 4,000 characters"
    );
    s.done().await;
}
