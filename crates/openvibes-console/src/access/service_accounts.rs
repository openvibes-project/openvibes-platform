//! Service accounts: list, create and disable.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::console_auth;

use crate::router::no_store;
use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

/// Lists service accounts without secret material.
#[utoipa::path(get,path="/api/v1/service-accounts",tag="service_accounts",responses((status=200,description="Service-account metadata",body=crate::ServiceAccountPage)))]
pub(crate) async fn authenticated_service_accounts(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    use chrono::SecondsFormat;
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::ServiceAccountsRead,
        false,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let accounts = match console_auth::list_service_accounts(&client).await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &actor,
        "service_accounts.viewed",
        Some("service_accounts"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    no_store(
        Json(crate::ServiceAccountPage {
            items: accounts
                .into_iter()
                .map(|account| crate::ServiceAccountView {
                    service_account_id: account.service_account_id,
                    name: account.name,
                    enabled: account.enabled,
                    created_at: account
                        .created_at
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    active_tokens: account.active_tokens,
                    role_ids: account.role_ids,
                })
                .collect(),
        })
        .into_response(),
    )
}

/// Creates a named service identity with one initial global built-in role.
#[utoipa::path(post,path="/api/v1/service-accounts",tag="service_accounts",request_body=crate::CreateServiceAccountRequest,responses((status=201,description="Service account created",body=crate::ServiceAccountView),(status=409,description="Name already exists",body=ProblemDetails)))]
pub(crate) async fn create_authenticated_service_account(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(request): Json<crate::CreateServiceAccountRequest>,
) -> Response {
    let name = request.name.trim();
    if name.is_empty()
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
        || crate::BuiltInRole::from_id(&request.role_id).is_none()
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_service_account",
            "Provide a valid name and built-in global role",
        ));
    }
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::ServiceAccountsManage,
        true,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let mut client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    let id = match console_auth::create_service_account(
        &mut client,
        name,
        &request.role_id,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(Some(id)) => id,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "service_account_conflict",
                "A service account with this name already exists",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    let response = Json(crate::ServiceAccountView {
        service_account_id: id,
        name: name.to_owned(),
        enabled: true,
        created_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        active_tokens: 0,
        role_ids: vec![request.role_id],
    })
    .into_response();
    let mut response = response;
    *response.status_mut() = StatusCode::CREATED;
    no_store(response)
}

/// Disables an account and revokes its issued tokens.
#[utoipa::path(post,path="/api/v1/service-accounts/{service_account_id}/disable",tag="service_accounts",params(("service_account_id"=String,Path)),responses((status=204,description="Service account disabled"),(status=404,description="Unknown or already disabled",body=ProblemDetails)))]
pub(crate) async fn disable_authenticated_service_account(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(service_account_id): Path<String>,
) -> Response {
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::ServiceAccountsManage,
        true,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    if !matches!(scope, platform_store::console_read::AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let mut client = match state.pool.get().await {
        Ok(value) => value,
        Err(_) => return unavailable_auth(),
    };
    match console_auth::disable_service_account(
        &mut client,
        &service_account_id,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem_response(ProblemDetails::new(
            StatusCode::NOT_FOUND,
            "service_account_not_found",
            "Service account not found or already disabled",
        )),
        Err(_) => unavailable_auth(),
    }
}
