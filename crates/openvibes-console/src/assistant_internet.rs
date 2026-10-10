//! `/api/v1/assistant-internet`: the administrator's switch for the
//! assistant's internet lookups (off, fetch pages, fetch pages and search).

use std::net::IpAddr;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use platform_store::{Pool, assistant_internet as store};

use crate::{
    AssistantInternet, AssistantInternetTest, Permission, ProblemDetails,
    UpdateAssistantInternetRequest,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, parse_if_match_version, unavailable_auth},
};

/// The level in force (0 off, 1 pages, 2 pages and search). Any error reads
/// as 0 so the assistant never breaks because of this setting.
pub(crate) async fn current_level(pool: &Pool) -> u8 {
    let Ok(client) = pool.get().await else {
        return 0;
    };
    match store::get(&client).await {
        Ok(setting) => u8::try_from(setting.level).unwrap_or(0).min(2),
        Err(_) => 0,
    }
}

/// `https://` to any host; `http://` only to loopback or a private address.
/// No user info, query, fragment, whitespace or control characters.
fn valid_searxng_url(url: &str) -> bool {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return false;
    };
    if url.contains(['?', '#', '@']) || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((host, after)) => (host, after.strip_prefix(':')),
            None => return false,
        },
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() || port.is_some_and(|p| p.parse::<u16>().map_or(true, |p| p == 0)) {
        return false;
    }
    https
        || host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| match ip {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
            IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
        })
}

fn invalid(title: &'static str) -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_setting",
        title,
    ))
}

fn forbidden() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        "Access is not available",
    ))
}

fn setting_response(state: &AuthHttpState, setting: store::Setting) -> Response {
    let platform_domain = state
        .public_origin
        .parse::<axum::http::Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    let etag = format!("\"{}\"", setting.version);
    let mut response = (
        StatusCode::OK,
        Json(AssistantInternet {
            level: u8::try_from(setting.level).unwrap_or(0),
            searxng_url: setting.searxng_url,
            internal_domains: setting.internal_domains,
            platform_domain,
            version: u64::try_from(setting.version).unwrap_or_default(),
            updated_at: setting
                .updated_at
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            updated_by: setting.updated_by,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

#[utoipa::path(
    get,
    path = "/api/v1/assistant-internet",
    tag = "assistant",
    responses(
        (status = 200, description = "The assistant internet setting", body = crate::AssistantInternet, headers(("ETag" = String, description = "Setting version"))),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Permission denied", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Read unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn get_assistant_internet(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    match authenticated_permission(&state, &headers, Permission::AssistantAdmin, false).await {
        Ok((platform_store::console_read::AgentScope::Global, _)) => {}
        Ok(_) => return forbidden(),
        Err(response) => return response,
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::get(&client).await {
        Ok(setting) => setting_response(&state, setting),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/assistant-internet",
    tag = "assistant",
    request_body = crate::UpdateAssistantInternetRequest,
    params(
        ("If-Match" = String, Header, description = "Quoted setting version from ETag"),
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")
    ),
    responses(
        (status = 200, description = "Updated setting", body = crate::AssistantInternet, headers(("ETag" = String, description = "New setting version"))),
        (status = 400, description = "Invalid setting or request", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 412, description = "Setting version is stale", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 428, description = "If-Match is required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Update unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn update_assistant_internet(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<UpdateAssistantInternetRequest>, JsonRejection>,
) -> Response {
    let user_id =
        match authenticated_permission(&state, &headers, Permission::AssistantAdmin, true).await {
            Ok((platform_store::console_read::AgentScope::Global, user_id)) => user_id,
            Ok(_) => return forbidden(),
            Err(response) => return response,
        };
    let expected_version = match parse_if_match_version(&headers) {
        Ok(Some(version)) => version,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "If-Match is required",
            ));
        }
        Err(()) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_precondition",
                "If-Match must contain one quoted setting version",
            ));
        }
    };
    let Ok(Json(payload)) = payload else {
        return invalid("Setting request is invalid");
    };
    if payload.level > 2 {
        return invalid("Level must be 0, 1 or 2");
    }
    if payload.level == 2 && payload.searxng_url.is_none() {
        return invalid("Level 2 needs a SearXNG URL");
    }
    if payload
        .searxng_url
        .as_deref()
        .is_some_and(|url| !valid_searxng_url(url))
    {
        return invalid("SearXNG URL must be https, or http on a local or private address");
    }
    let update = store::Update {
        level: i16::from(payload.level),
        searxng_url: payload.searxng_url,
        internal_domains: payload.internal_domains,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::update(&mut client, &update, expected_version, &user_id, Utc::now()).await {
        Ok(Some(setting)) => setting_response(&state, setting),
        Ok(None) => problem_response(ProblemDetails::new(
            StatusCode::PRECONDITION_FAILED,
            "stale_setting",
            "The setting changed; reload before saving",
        )),
        // The store refuses what the checks above let through (domain names).
        Err(platform_store::StoreError::Query) => {
            invalid("Internal domains must be lowercase names, at most 50")
        }
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/assistant-internet/test",
    tag = "assistant",
    params(
        ("Origin" = String, Header, description = "Must exactly match configured origin"),
        ("X-CSRF-Token" = String, Header, description = "Session synchronizer token")
    ),
    responses(
        (status = 200, description = "A search for a fixed word ran (or why not)", body = crate::AssistantInternetTest),
        (status = 401, description = "Authentication required", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Origin, CSRF, or permission check failed", body = crate::ProblemDetails, content_type = "application/problem+json"),
        (status = 503, description = "Audit unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn test_assistant_internet(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let user =
        match authenticated_permission(&state, &headers, Permission::AssistantAdmin, true).await {
            Ok((platform_store::console_read::AgentScope::Global, user_id)) => user_id,
            Ok(_) => return forbidden(),
            Err(response) => return response,
        };
    match crate::fetch_client::test_search(
        &state.pool,
        &state.fetch_socket,
        &state.internet_limits,
        user,
    )
    .await
    {
        Ok((ok, detail)) => Json(AssistantInternetTest { ok, detail }).into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[cfg(test)]
mod tests {
    use super::valid_searxng_url as ok;

    #[test]
    fn http_only_on_local_or_private_hosts() {
        assert!(ok("https://search.example.com"));
        assert!(ok("http://localhost:8080"));
        assert!(ok("http://127.0.0.1:8888/x"));
        assert!(ok("http://10.1.2.3"));
        assert!(ok("http://[::1]:8080"));
        assert!(ok("http://[fd00::1]"));
        assert!(!ok("http://search.example.com"));
        assert!(!ok("http://8.8.8.8"));
        assert!(!ok("ftp://x"));
        assert!(!ok("https://u@x"));
        assert!(!ok("https://"));
    }
}
