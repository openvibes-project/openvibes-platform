//! The demo's audit events and their CSV export.

use axum::{
    Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
};

use super::{
    persona::{Persona, context, read_error},
    repository::GENERATED_AT,
};
use crate::Permission;

pub(super) async fn audit_events(headers: HeaderMap) -> Response {
    let (persona, mode) = match context(&headers, Permission::AuditRead) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    let events = if matches!(persona, Persona::Admin) {
        vec![serde_json::json!({
            "id": "1", "at": GENERATED_AT, "actor": "admin@example.test",
            "action": "user.login", "target": "console", "result": "success",
            "request_id": null, "actor_kind": "user", "actor_id": "admin",
            "authentication_method": "local_password", "target_kind": null,
            "target_id": null, "reason_code": null
        })]
    } else {
        Vec::new()
    };
    Json(serde_json::json!({ "items": events, "next_cursor": null })).into_response()
}

pub(super) async fn audit_export(headers: HeaderMap) -> Response {
    let (_, mode) = match context(&headers, Permission::AuditExport) {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if let Some(response) = read_error(mode) {
        return response;
    }
    let mut response = (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/csv; charset=utf-8",
        )],
        "event_id,at,actor,action,target,result\r\n1,2026-09-24T12:00:00Z,admin@example.test,user.login,console,success\r\n",
    )
        .into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_static("attachment; filename=\"openvibes-audit.csv\""),
    );
    response
}
