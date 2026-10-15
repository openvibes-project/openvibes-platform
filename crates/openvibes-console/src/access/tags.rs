//! Host tags: preview and apply a tag change on one agent.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;

use super::asset_groups::validated_agent_tags;
use crate::router::valid_agent_id;
use crate::{
    access::guard::{authenticated_permission, unavailable_auth},
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

fn agent_tag_preview_response(
    preview: platform_store::console_auth::AgentTagPreview,
) -> crate::AgentTagPreviewResponse {
    let tags = |items: Vec<platform_store::console_auth::AgentTag>| {
        items
            .into_iter()
            .map(|tag| crate::AgentTagInput {
                key: tag.key,
                value: tag.value,
            })
            .collect()
    };
    let groups = |items: Vec<(String, String)>| {
        items
            .into_iter()
            .map(|(asset_group_id, name)| crate::AgentTagGroupImpact {
                asset_group_id,
                name,
            })
            .collect()
    };
    let bindings = |items: Vec<platform_store::console_auth::TagBindingImpact>| {
        items
            .into_iter()
            .map(|binding| crate::AgentTagBindingImpact {
                binding_id: binding.binding_id,
                username: binding.username,
                role_id: binding.role_id,
                asset_group_name: binding.asset_group_name,
            })
            .collect()
    };
    crate::AgentTagPreviewResponse {
        current: tags(preview.current),
        proposed: tags(preview.proposed),
        gained_groups: groups(preview.gained_groups),
        lost_groups: groups(preview.lost_groups),
        gained_bindings: bindings(preview.gained_bindings),
        lost_bindings: bindings(preview.lost_bindings),
        preview_token: preview.token,
    }
}

/// Previews asset group membership changes for an agent's complete tag set.
#[utoipa::path(post, path="/api/v1/agents/{agent_id}/tags/preview", tag="agents", params(("agent_id"=String,Path)), request_body=crate::AgentTagChangeRequest, responses((status=200,description="Membership impact preview",body=crate::AgentTagPreviewResponse),(status=400,description="Invalid tag set",body=ProblemDetails),(status=404,description="Agent not found",body=ProblemDetails)))]
pub(crate) async fn preview_authenticated_agent_tags(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Json(request): Json<crate::AgentTagChangeRequest>,
) -> Response {
    use platform_store::console_read::AgentScope;
    if !valid_agent_id(&agent_id) {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_agent_id",
            "The agent id is invalid",
        ));
    }
    let Some(tags) = validated_agent_tags(request.tags) else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_tags",
            "Provide at most 64 unique, non-empty tags within key and value limits",
        ));
    };
    let (scope, _) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AssetGroupsManage,
        true,
    )
    .await
    {
        Ok(v) => v,
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
        Ok(v) => v,
        Err(_) => return unavailable_auth(),
    };
    match platform_store::console_auth::preview_agent_tags(&client, &agent_id, &tags).await {
        Ok(Some(preview)) => {
            (StatusCode::OK, Json(agent_tag_preview_response(preview))).into_response()
        }
        Ok(None) => problem_response(ProblemDetails::not_found(
            "agent_not_found",
            "Agent not found",
        )),
        Err(_) => unavailable_auth(),
    }
}

/// Applies an agent tag set only while its membership preview remains current.
#[utoipa::path(put, path="/api/v1/agents/{agent_id}/tags", tag="agents", params(("agent_id"=String,Path)), request_body=crate::ApplyAgentTagsRequest, responses((status=204,description="Tags changed and impact audited"),(status=409,description="Preview is stale",body=crate::AgentTagPreviewResponse),(status=400,description="Invalid tag set",body=ProblemDetails)))]
pub(crate) async fn apply_authenticated_agent_tags(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
    Json(request): Json<crate::ApplyAgentTagsRequest>,
) -> Response {
    use platform_store::console_read::AgentScope;
    if !valid_agent_id(&agent_id)
        || request.preview_token.len() != 64
        || !request.preview_token.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_tag_change",
            "The tag change request is invalid",
        ));
    }
    let Some(tags) = validated_agent_tags(request.tags) else {
        return problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_tags",
            "Provide at most 64 unique, non-empty tags within key and value limits",
        ));
    };
    let (scope, actor) = match authenticated_permission(
        &state,
        &headers,
        crate::Permission::AssetGroupsManage,
        true,
    )
    .await
    {
        Ok(v) => v,
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
    match platform_store::console_auth::apply_agent_tags(
        &mut client,
        &agent_id,
        &tags,
        &request.preview_token,
        &actor,
        Utc::now(),
    )
    .await
    {
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Ok(Some(preview)) => (
            StatusCode::CONFLICT,
            Json(agent_tag_preview_response(preview)),
        )
            .into_response(),
        Err(_) => unavailable_auth(),
    }
}
