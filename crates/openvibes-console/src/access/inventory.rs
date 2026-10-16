//! The access inventory: users, roles, bindings and asset groups.

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

#[utoipa::path(
    get,
    path = "/api/v1/access-control",
    tag = "access control",
    responses((status = 200, description = "Roles, active bindings, and asset groups", body = crate::AccessInventory))
)]
pub(crate) async fn authenticated_access_inventory(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    use chrono::SecondsFormat;
    use platform_store::console_read::AgentScope;
    let (scope, user_id) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AccessRead,
        false,
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
    let client = match state.pool.get().await {
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    let inventory = match platform_store::console_auth::access_inventory(&client).await {
        Ok(inventory) => inventory,
        Err(_) => return unavailable_auth(),
    };
    if platform_store::audit::record(
        &client,
        &user_id,
        "access_control.viewed",
        Some("access_control"),
        "success",
    )
    .await
    .is_err()
    {
        return unavailable_auth();
    }
    Json(crate::AccessInventory {
        roles: inventory
            .roles
            .into_iter()
            .map(|role| crate::AccessRole {
                role_id: role.role_id,
                display_name: role.display_name,
                builtin: role.builtin,
                permissions: role.permissions,
            })
            .collect(),
        bindings: inventory
            .bindings
            .into_iter()
            .map(|binding| crate::AccessBinding {
                binding_id: binding.binding_id,
                user_id: binding.user_id,
                username: binding.username,
                display_name: binding.display_name,
                role_id: binding.role_id,
                asset_group_id: None,
                asset_group_name: None,
                created_at: binding
                    .created_at
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
                created_by: binding.created_by,
            })
            .collect(),
        asset_groups: inventory
            .asset_groups
            .into_iter()
            .map(|group| crate::AccessAssetGroup {
                asset_group_id: group.asset_group_id,
                name: group.name,
                selectors: group.selectors,
            })
            .collect(),
        users: inventory
            .users
            .into_iter()
            .map(|user| crate::AccessUser {
                user_id: user.user_id,
                username: user.username,
                display_name: user.display_name,
            })
            .collect(),
    })
    .into_response()
}
