//! The browser session read.

use axum::{
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{Duration, SecondsFormat, Utc};
use platform_store::{console_auth, console_people};
use subtle::ConstantTimeEq;

use crate::{
    access::guard::background_request,
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

#[utoipa::path(
    get,
    path = "/api/v1/session",
    tag = "session",
    responses(
        (status = 200, description = "Current authenticated browser session", body = crate::SessionResponse),
        (status = 503, description = "Authentication store is unavailable", body = crate::ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(crate) async fn session() -> Response {
    problem_response(ProblemDetails::authentication_unavailable())
}

pub(crate) async fn authenticated_session(
    State(state): State<AuthHttpState>,
    request: axum::extract::Request,
) -> Response {
    use crate::access::auth::{
        PresentedCredentials, presented_credentials, session_csrf, session_digest,
    };

    let secret = match presented_credentials(request.headers()) {
        Ok(PresentedCredentials::Session(secret)) => secret,
        _ => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "Authentication required",
            ));
        }
    };
    let digest = session_digest(secret.expose_secret());
    let csrf = session_csrf(secret.expose_secret()).0;
    let now = Utc::now();
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
                "Authentication is temporarily unavailable",
            ));
        }
    };
    let active = match console_auth::session(&client, &digest, now).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNAUTHORIZED,
                "authentication_required",
                "Authentication required",
            ));
        }
        Err(_) => {
            return problem_response(ProblemDetails::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
                "Authentication is temporarily unavailable",
            ));
        }
    };
    let expected_csrf_hash = crate::access::auth::session_digest(&csrf);
    if active.csrf_sha256.len() != expected_csrf_hash.len()
        || !bool::from(
            active
                .csrf_sha256
                .as_slice()
                .ct_eq(expected_csrf_hash.as_slice()),
        )
    {
        return problem_response(ProblemDetails::new(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "Authentication required",
        ));
    }
    if !background_request(request.headers())
        && !console_auth::touch_session(&client, &digest, now, Duration::minutes(30))
            .await
            .unwrap_or(false)
    {
        return problem_response(ProblemDetails::new(
            StatusCode::UNAUTHORIZED,
            "authentication_required",
            "Authentication required",
        ));
    }
    let idle_expiry = (now + Duration::minutes(30)).min(active.absolute_expires_at);
    let mut capabilities = if active.password_must_change {
        Vec::new() // nothing but setting the password until then (#85)
    } else {
        match crate::access::rbac::principal_capabilities(
            &client,
            platform_store::console_roles::Principal::User(&active.user_id),
        )
        .await
        {
            Ok(capabilities) => capabilities,
            Err(_) => {
                return problem_response(ProblemDetails::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                    "Authentication is temporarily unavailable",
                ));
            }
        }
    };
    if state.assistant.is_none() {
        capabilities.retain(|capability| capability.permission != crate::Permission::AssistantUse);
    }
    let picture = console_people::picture_etag(&client, &active.user_id)
        .await
        .unwrap_or(None);
    let response = crate::SessionResponse {
        principal: crate::SessionPrincipal {
            picture,
            id: active.user_id,
            display_name: active.display_name,
            username: Some(active.username),
        },
        authentication_method: if active.auth_source == "sso" {
            crate::AuthenticationMethod::Saml
        } else {
            crate::AuthenticationMethod::LocalPassword
        },
        authentication_level: crate::AuthenticationLevel::SingleFactor,
        capabilities,
        csrf_token: csrf,
        idle_expires_at: idle_expiry.to_rfc3339_opts(SecondsFormat::Secs, true),
        absolute_expires_at: active
            .absolute_expires_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        password_must_change: active.password_must_change,
    };
    let mut response = (StatusCode::OK, axum::Json(response)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
