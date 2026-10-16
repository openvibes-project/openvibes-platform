//! The audit event CSV export.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};

use super::{events::invalid_query, query::AuditEventExportParams};
use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

static AUDIT_EXPORT_SPOOL_ID: AtomicU64 = AtomicU64::new(1);

#[utoipa::path(
    get,
    path = "/api/v1/audit-export.csv",
    tag = "audit",
    params(
        ("since" = String, Query, description = "Inclusive RFC3339 lower bound"),
        ("until" = Option<String>, Query, description = "Exclusive RFC3339 upper bound"),
        ("actor" = Option<String>, Query), ("action" = Option<String>, Query),
        ("result" = Option<String>, Query)
    ),
    responses(
        (status = 200, description = "Filtered audit events as CSV", content_type = "text/csv"),
        (status = 413, description = "Export exceeds the row or byte limit", body = ProblemDetails)
    )
)]
pub(crate) async fn authenticated_audit_export(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<AuditEventExportParams>, QueryRejection>,
) -> Response {
    use chrono::DateTime;
    use platform_store::audit::{AuditExportQuery, MAX_EXPORT_BYTES, export_events, record_export};
    let (scope, user_id) =
        match authenticated_permission(&state, &headers, crate::Permission::AuditExport, false)
            .await
        {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_query(),
    };
    let since = match DateTime::parse_from_rfc3339(&params.since) {
        Ok(v) => v.with_timezone(&Utc),
        Err(_) => return invalid_query(),
    };
    let until = match params
        .until
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
    {
        Ok(v) => v.map(|v| v.with_timezone(&Utc)),
        Err(_) => return invalid_query(),
    };
    let now = Utc::now();
    if since > now
        || until.is_some_and(|v| v <= since || v > now)
        || [
            params.actor.as_deref(),
            params.action.as_deref(),
            params.result.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
    {
        return invalid_query();
    }
    let query = AuditExportQuery {
        since,
        until,
        actor: params.actor,
        action: params.action,
        result: params.result,
    };
    let client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let export = match export_events(&client, &query).await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    if export.too_large {
        return export_too_large();
    }
    let mut csv = Vec::new();
    csv.extend_from_slice(b"event_id,at,actor,action,target,result,request_id,actor_kind,actor_id,authentication_method,target_kind,target_id,reason_code\r\n");
    for event in &export.items {
        let fields = [
            event.id.to_string(),
            event.at.to_rfc3339(),
            event.actor.clone(),
            event.action.clone(),
            event.target.clone().unwrap_or_default(),
            event.result.clone(),
            event.request_id.clone().unwrap_or_default(),
            event.actor_kind.clone().unwrap_or_default(),
            event.actor_id.clone().unwrap_or_default(),
            event.authentication_method.clone().unwrap_or_default(),
            event.target_kind.clone().unwrap_or_default(),
            event.target_id.clone().unwrap_or_default(),
            event.reason_code.clone().unwrap_or_default(),
        ];
        let row = fields
            .iter()
            .map(|value| csv_field(value))
            .collect::<Vec<_>>()
            .join(",")
            + "\r\n";
        if csv.len().saturating_add(row.len()) > MAX_EXPORT_BYTES {
            return export_too_large();
        }
        csv.extend_from_slice(row.as_bytes());
    }
    let spool = match PrivateAuditSpool::create(&csv) {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let bytes = match spool.read() {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let sha256 = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if record_export(&client, &user_id, &query, export.items.len(), &sha256)
        .await
        .is_err()
    {
        return unavailable_auth();
    }
    let body = futures_util::stream::unfold((spool, Some(bytes)), |(spool, bytes)| async move {
        bytes.map(|bytes| (Ok::<_, std::io::Error>(bytes), (spool, None)))
    });
    let mut response = axum::body::Body::from_stream(body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"openvibes-audit.csv\""),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn csv_field(value: &str) -> String {
    let mut safe = value.to_owned();
    let first = value.trim_start_matches(char::is_whitespace).chars().next();
    if matches!(first, Some('=' | '+' | '-' | '@' | '\t' | '\r')) {
        safe.insert(0, '\'');
    }
    format!("\"{}\"", safe.replace('"', "\"\""))
}

struct PrivateAuditSpool(PathBuf);

impl PrivateAuditSpool {
    fn create(bytes: &[u8]) -> std::io::Result<Self> {
        for _ in 0..16 {
            let id = AUDIT_EXPORT_SPOOL_ID.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("openvibes-audit-{}-{id}.csv", std::process::id()));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate private export spool",
        ))
    }

    fn read(&self) -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::open(&self.0)?.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

impl Drop for PrivateAuditSpool {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn export_too_large() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "export_too_large",
        "The filtered audit export exceeds the download limits",
    ))
}
