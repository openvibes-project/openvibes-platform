//! Role bindings: grant and revoke a local user's role.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;

use crate::http::validate::valid_uuid;
use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

/// Adds one active local-user role binding.
#[utoipa::path(
    post,
    path = "/api/v1/access-control/bindings",
    tag = "access control",
    request_body = crate::CreateAccessBindingRequest,
    responses((status = 201, description = "Role binding created", body = crate::AccessBinding), (status = 400, description = "Invalid binding request", body = ProblemDetails), (status = 409, description = "Binding conflict", body = ProblemDetails))
)]
pub(crate) async fn create_authenticated_access_binding(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(request): Json<crate::CreateAccessBindingRequest>,
) -> Response {
    use chrono::SecondsFormat;
    use platform_store::console_read::AgentScope;
    if !valid_uuid(&request.user_id)
        || request
            .asset_group_id
            .as_deref()
            .is_some_and(|id| !valid_uuid(id))
        || request.role_id.is_empty()
        || request.role_id.len() > 64
        || !request
            .role_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return invalid_access_binding();
    }
    let (scope, user_id) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AccessGrant,
        true,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let mut client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    let binding = match platform_store::console_auth::create_user_role_binding(
        &mut client,
        &request.user_id,
        &request.role_id,
        request.asset_group_id.as_deref(),
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(Some(binding)) => binding,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "binding_conflict",
                "The role binding could not be created",
            ));
        }
        Err(_) => return unavailable_auth(),
    };
    (
        StatusCode::CREATED,
        Json(crate::AccessBinding {
            binding_id: binding.binding_id,
            user_id: binding.user_id,
            username: binding.username,
            display_name: binding.display_name,
            role_id: binding.role_id,
            asset_group_id: binding.asset_group_id,
            asset_group_name: binding.asset_group_name,
            created_at: binding
                .created_at
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            created_by: binding.created_by,
        }),
    )
        .into_response()
}

#[utoipa::path(
    delete,
    path = "/api/v1/access-control/bindings/{binding_id}",
    tag = "access control",
    params(("binding_id" = String, Path, description = "Role binding UUID")),
    responses((status = 204, description = "Role binding revoked"), (status = 404, description = "Binding not found", body = ProblemDetails))
)]
pub(crate) async fn revoke_authenticated_access_binding(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(binding_id): Path<String>,
) -> Response {
    use platform_store::console_read::AgentScope;
    if !valid_uuid(&binding_id) {
        return invalid_access_binding();
    }
    let (scope, user_id) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AccessGrant,
        true,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return response,
    };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let mut client = match state.pool.get().await {
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_auth::revoke_user_role_binding(
        &mut client,
        &binding_id,
        &user_id,
        Utc::now(),
    )
    .await
    {
        Ok(platform_store::console_auth::BindingRevocation::Revoked) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(platform_store::console_auth::BindingRevocation::NotFound) => {
            problem_response(ProblemDetails::new(
                StatusCode::NOT_FOUND,
                "binding_not_found",
                "Access is not available",
            ))
        }
        Ok(platform_store::console_auth::BindingRevocation::LastGlobalAdmin) => {
            problem_response(ProblemDetails::new(
                StatusCode::CONFLICT,
                "last_global_admin",
                "The final global Admin binding cannot be revoked",
            ))
        }
        Err(_) => unavailable_auth(),
    }
}

fn invalid_access_binding() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_binding",
        "Role binding parameters are invalid",
    ))
}
