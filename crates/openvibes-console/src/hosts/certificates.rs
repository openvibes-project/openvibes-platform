//! An agent's certificates.

use axum::{
    extract::{Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;

use super::agents::invalid_agent_query;
use crate::{
    access::guard::{authenticated_agent_scope, unavailable_auth},
    http::AuthHttpState,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CertificateListParams {
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct CertificateCursorToken {
    agent_id: String,
    scope: platform_store::console_read::AgentScope,
    issued_at: String,
    serial: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/agents/{agent_id}/certificates",
    tag = "agents",
    params(
        ("agent_id" = String, Path, description = "Stable agent identifier"),
        ("cursor" = Option<String>, Query, description = "Opaque continuation cursor"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 to 100")
    ),
    responses(
        (status = 200, description = "Visible certificate metadata page", body = crate::CertificatePage),
        (status = 400, description = "Invalid query or cursor", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn authenticated_agent_certificates(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    query: Result<Query<CertificateListParams>, QueryRejection>,
) -> Response {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use platform_store::console_read::{CertificateCursor, PageLimit, certificates_in_scope};

    let scope =
        match authenticated_agent_scope(&state, &headers, crate::Permission::HostsRead).await {
            Ok(scope) => scope,
            Err(response) => return response,
        };
    let Query(params) = match query {
        Ok(query) => query,
        Err(_) => return invalid_agent_query(),
    };
    let Some(limit) = PageLimit::new(params.limit.unwrap_or(crate::DEFAULT_PAGE_SIZE)) else {
        return invalid_agent_query();
    };
    let after = match params.cursor.as_deref() {
        None => None,
        Some(encoded) if encoded.len() <= crate::MAX_CURSOR_LENGTH => {
            let decoded = match URL_SAFE_NO_PAD.decode(encoded) {
                Ok(decoded) => decoded,
                Err(_) => return invalid_agent_query(),
            };
            let token = match serde_json::from_slice::<CertificateCursorToken>(&decoded) {
                Ok(token) if token.agent_id == agent_id && token.scope == scope => token,
                _ => return invalid_agent_query(),
            };
            let issued_at = match chrono::DateTime::parse_from_rfc3339(&token.issued_at) {
                Ok(value) => value.with_timezone(&Utc),
                Err(_) => return invalid_agent_query(),
            };
            let Some(serial) = decode_hex(&token.serial) else {
                return invalid_agent_query();
            };
            Some(CertificateCursor { issued_at, serial })
        }
        Some(_) => return invalid_agent_query(),
    };
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let page = match certificates_in_scope(&client, &agent_id, after.as_ref(), limit, &scope).await
    {
        Ok(page) => page,
        Err(_) => return unavailable_auth(),
    };
    let next_cursor = match page.next {
        None => None,
        Some(cursor) => {
            let token = CertificateCursorToken {
                agent_id,
                scope,
                issued_at: cursor
                    .issued_at
                    .to_rfc3339_opts(SecondsFormat::Micros, true),
                serial: encode_hex(&cursor.serial),
            };
            match serde_json::to_vec(&token) {
                Ok(token) => Some(URL_SAFE_NO_PAD.encode(token)),
                Err(_) => return unavailable_auth(),
            }
        }
    };
    (
        StatusCode::OK,
        axum::Json(crate::CertificatePage {
            items: page.items.into_iter().map(certificate_view).collect(),
            next_cursor,
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }),
    )
        .into_response()
}

pub(super) fn certificate_view(
    certificate: platform_store::console_read::Certificate,
) -> crate::CertificateView {
    crate::CertificateView {
        serial: encode_hex(&certificate.serial),
        not_before: certificate
            .not_before
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        not_after: certificate
            .not_after
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        issued_at: certificate
            .issued_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}
