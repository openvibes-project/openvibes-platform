//! Bulk triage over HTTP (triage v2): permissions, the note rule and fitting items.

use axum::http::StatusCode;
use serde_json::json;

mod common;
use common::bulk::*;

#[tokio::test]
async fn bulk_triage_needs_the_permission_a_note_to_close_and_fitting_items() {
    let (db, router, ids) = setup().await;
    let items = json!(
        ids.iter()
            .map(|id| json!({"id": id.to_string()}))
            .collect::<Vec<_>>()
    );
    let close = |note: Option<&str>| json!({"action": "state", "state": "mitigated", "note": note, "items": items});
    let (cookie, csrf) = login(&router, "vera").await;
    let (status, _, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(close(Some("x"))),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a viewer cannot triage");
    let (cookie, csrf) = login(&router, "alice").await;
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(close(None)),
        None,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_triage"))
    );
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(close(Some("test alarms"))),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (
            body["changed"].as_u64(),
            body["skipped"].as_array().map(Vec::len)
        ),
        (Some(2), Some(0))
    );
    // The History tab: one event per alarm, with the note.
    let (status, history, _) = call(
        &router,
        "GET",
        &format!("/api/v1/triage-history?kind=alarm&id={}", ids[0]),
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert_eq!(history["items"][0]["to_state"], "mitigated");
    assert_eq!(history["items"][0]["note"], "test alarms");
    // An item that does not fit the list is refused, nothing done.
    let wrong = json!({"action": "state", "state": "open", "items": [{"advisory_id": "FEDORA-1"}]});
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(wrong),
        None,
    )
    .await;
    assert_eq!(
        (status, body["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_items"))
    );
    // Without CSRF.
    let (status, _, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        "",
        Some(close(Some("x"))),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    db.drop().await;
}
