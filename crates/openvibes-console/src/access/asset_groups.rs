//! Host (asset) groups: named agent selections a role can reach.

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

pub(super) fn validated_agent_tags(
    tags: Vec<crate::AgentTagInput>,
) -> Option<Vec<platform_store::console_auth::AgentTag>> {
    if tags.len() > 64 {
        return None;
    }
    let mut tags = tags
        .into_iter()
        .map(|tag| platform_store::console_auth::AgentTag {
            key: tag.key,
            value: tag.value,
        })
        .collect::<Vec<_>>();
    if tags.iter().any(|tag| {
        tag.key.is_empty()
            || tag.key.len() > 64
            || tag.value.is_empty()
            || tag.value.len() > 256
            || tag.key.chars().any(char::is_control)
            || tag.value.chars().any(char::is_control)
    }) {
        return None;
    }
    tags.sort_by(|a, b| a.key.cmp(&b.key));
    if tags.windows(2).any(|pair| pair[0].key == pair[1].key) {
        return None;
    }
    Some(tags)
}

fn validated_group_request(
    request: crate::SaveAssetGroupRequest,
) -> Option<(String, Vec<platform_store::console_auth::AgentTag>)> {
    let name = request.name.trim().to_owned();
    if name.is_empty()
        || name.chars().count() > 128
        || name.chars().any(char::is_control)
        || request.selectors.is_empty()
        || request.selectors.len() > 32
    {
        return None;
    }
    let mut selectors = request
        .selectors
        .into_iter()
        .map(|s| platform_store::console_auth::AgentTag {
            key: s.key,
            value: s.value,
        })
        .collect::<Vec<_>>();
    if selectors.iter().any(|s| {
        s.key.is_empty()
            || s.key.chars().count() > 64
            || s.value.is_empty()
            || s.value.chars().count() > 256
            || s.key.chars().any(char::is_control)
            || s.value.chars().any(char::is_control)
    }) {
        return None;
    }
    selectors.sort_by(|a, b| a.key.cmp(&b.key));
    if selectors.windows(2).any(|w| w[0].key == w[1].key) {
        return None;
    }
    Some((name, selectors))
}

async fn save_authenticated_asset_group(
    state: AuthHttpState,
    headers: HeaderMap,
    group_id: Option<String>,
    request: crate::SaveAssetGroupRequest,
) -> Response {
    use platform_store::console_read::AgentScope;
    if group_id.as_deref().is_some_and(|id| !valid_uuid(id)) {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_asset_group",
            "The asset group id is invalid",
        ));
    }
    let Some((name, selectors)) = validated_group_request(request) else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_asset_group",
            "Provide a name and 1 to 32 unique exact selectors within the documented lengths",
        ));
    };
    let (scope, actor) =
        match authenticated_permission(&state, &headers, crate::Permission::HostGroupsManage, true)
            .await
        {
            Ok(value) => value,
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
        Ok(client) => client,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_auth::save_asset_group(
        &mut client,
        group_id.as_deref(),
        &name,
        &selectors,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(Some(group)) => {
            let created = group_id.is_none();
            (
                if created {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                Json(crate::AccessAssetGroup {
                    asset_group_id: group.asset_group_id,
                    name: group.name,
                    selectors: group.selectors,
                }),
            )
                .into_response()
        }
        Ok(None) => problem_response(ProblemDetails::not_found(
            "asset_group_not_found",
            "Asset group not found",
        )),
        Err(platform_store::StoreError::Query) => problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "asset_group_conflict",
            "The asset group name is already in use or the change could not be saved",
        )),
        Err(_) => unavailable_auth(),
    }
}

/// Creates an asset group from a bounded conjunction of exact tag selectors.
#[utoipa::path(post,path="/api/v1/access-control/asset-groups",tag="access control",request_body=crate::SaveAssetGroupRequest,responses((status=201,description="Asset group created",body=crate::AccessAssetGroup),(status=400,description="Invalid selector set",body=ProblemDetails),(status=409,description="Name conflict",body=ProblemDetails)))]
pub(crate) async fn create_authenticated_asset_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Json(request): Json<crate::SaveAssetGroupRequest>,
) -> Response {
    save_authenticated_asset_group(state, headers, None, request).await
}

/// Replaces an asset group's name and complete selector conjunction.
#[utoipa::path(put,path="/api/v1/access-control/asset-groups/{group_id}",tag="access control",params(("group_id"=String,Path)),request_body=crate::SaveAssetGroupRequest,responses((status=200,description="Asset group updated",body=crate::AccessAssetGroup),(status=400,description="Invalid selector set",body=ProblemDetails),(status=404,description="Asset group not found",body=ProblemDetails),(status=409,description="Name conflict",body=ProblemDetails)))]
pub(crate) async fn update_authenticated_asset_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    Json(request): Json<crate::SaveAssetGroupRequest>,
) -> Response {
    save_authenticated_asset_group(state, headers, Some(group_id), request).await
}

/// Every host group with its selectors and how many roles reach it, for
/// the Host groups tab and the role reach picker.
#[utoipa::path(get, path = "/api/v1/host-groups", tag = "access control",
    responses((status = 200, description = "Host groups", body = [crate::access::people_types::HostGroupView]),
        (status = 403, description = "Needs access.read or host_groups.manage", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn host_groups(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let editor = match crate::access::editor::caller(&state, &headers, false).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if !editor.holds(crate::Permission::HostGroupsManage)
        && let Some(response) = editor.denied(crate::Permission::AccessRead)
    {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match platform_store::console_roles::host_groups(&client).await {
        Ok(groups) => Json(
            groups
                .into_iter()
                .map(|g| crate::access::people_types::HostGroupView {
                    asset_group_id: g.asset_group_id,
                    name: g.name,
                    selectors: g.selectors,
                    roles: g.roles,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}
