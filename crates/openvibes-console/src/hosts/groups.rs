//! Host groups (spec §5.1, §13): the list, a group's page and hosts, and
//! create, edit, preview and delete. Anyone with `access.read` or
//! `host_groups.manage` may read groups, with hosts counted inside their
//! `hosts.read` reach; changing a group changes access for everyone whose
//! role reaches it, so writes and previews also need `hosts.read` on all
//! hosts.

use axum::{
    extract::{
        Json, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::console_read::AgentScope;
use platform_store::host_group_writes::{self as writes, GroupInput, GroupWrite, PreviewOutcome};
use platform_store::host_groups::{self as store, GroupKind};
use serde::Deserialize;

use super::group_checks::{
    Content, answer, group_not_found, invalid, invalid_condition, people_in_share,
    reaching_roles_fit,
};
use super::groups_types::{
    CreateHostGroup, GroupChangeView, GroupHostView, HostGroupDetail, HostGroupKind,
    HostGroupPreview, HostGroupView, PreviewHostGroup, UpdateHostGroup,
};
use crate::access::editor::{Editor, caller};
use crate::access::guard::{scope_of, unavailable_auth};
use crate::http::{
    AuthHttpState,
    problem::{ProblemDetails, problem_response},
};
use crate::{Permission, PermissionScope};

/// Every host group, by name, counted inside the caller's reach.
#[utoipa::path(get, path = "/api/v1/host-groups", tag = "access control",
    responses((status = 200, description = "Host groups", body = [HostGroupView]),
        (status = 403, description = "Needs access.read or host_groups.manage", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_groups(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let scope = match reader(&state, &headers).await {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::list(&client, &scope).await {
        Ok(groups) => Json(
            groups
                .into_iter()
                .map(HostGroupView::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// A group's page: the group counted inside the caller's reach, and its
/// newest 10 changes.
#[utoipa::path(get, path = "/api/v1/host-groups/{group_id}", tag = "access control",
    params(("group_id" = String, Path)),
    responses((status = 200, description = "The group", body = HostGroupDetail),
        (status = 403, description = "Needs access.read or host_groups.manage", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "group_not_found", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
) -> Response {
    let scope = match reader(&state, &headers).await {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let group = match store::detail(&client, &group_id, &scope).await {
        Ok(Some(group)) => group,
        Ok(None) => return group_not_found(),
        Err(_) => return unavailable_auth(),
    };
    let Ok(recent) = store::recent_changes(&client, &group_id, &scope, 10).await else {
        return unavailable_auth();
    };
    Json(HostGroupDetail {
        group: group.into(),
        recent: recent
            .into_iter()
            .map(|line| GroupChangeView {
                action: line.action,
                actor: line.actor,
                at: line.at.to_rfc3339(),
                detail: line.detail,
            })
            .collect(),
    })
    .into_response()
}

#[derive(Deserialize)]
pub(crate) struct HostsQuery {
    after: Option<String>,
    limit: Option<i64>,
}

/// A page of the group's member hosts inside the caller's reach, by
/// hostname, after the host `after`.
#[utoipa::path(get, path = "/api/v1/host-groups/{group_id}/hosts", tag = "access control",
    params(("group_id" = String, Path),
        ("after" = Option<String>, Query, description = "The last agent id of the previous page"),
        ("limit" = Option<i64>, Query, description = "1 to 100; 50 when left out")),
    responses((status = 200, description = "Member hosts", body = [GroupHostView]),
        (status = 403, description = "Needs access.read or host_groups.manage", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "group_not_found", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn group_hosts(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    query: Result<Query<HostsQuery>, QueryRejection>,
) -> Response {
    let scope = match reader(&state, &headers).await {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    let Ok(Query(query)) = query else {
        return problem_response(invalid("query", "Use after and limit (1 to 100)"));
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::detail(&client, &group_id, &scope).await {
        Ok(Some(_)) => {}
        Ok(None) => return group_not_found(),
        Err(_) => return unavailable_auth(),
    }
    let limit = query.limit.unwrap_or(50);
    match store::hosts(&client, &group_id, &scope, query.after.as_deref(), limit).await {
        Ok(hosts) => Json(
            hosts
                .into_iter()
                .map(GroupHostView::from)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// Creates a rule or manual group.
#[utoipa::path(post, path = "/api/v1/host-groups", tag = "access control",
    request_body = CreateHostGroup,
    responses((status = 201, description = "Created", body = HostGroupView),
        (status = 400, description = "invalid_group: name, description or body", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs host_groups.manage and hosts.read on all hosts", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "group_name_taken", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "invalid_condition (naming the field) or unknown_host", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<CreateHostGroup>, JsonRejection>,
) -> Response {
    let editor = match writer(&state, &headers).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return problem_response(invalid("body", "The request body is invalid"));
    };
    let content = match (request.kind, request.conditions, request.agent_ids) {
        (HostGroupKind::Rule, conditions, None) => Content::rule(conditions.unwrap_or_default()),
        (HostGroupKind::Manual, None, picked) => Content::Manual(picked.unwrap_or_default()),
        _ => {
            return problem_response(invalid(
                "kind",
                "A rule group takes conditions, a manual group agent_ids",
            ));
        }
    };
    let content = match content.checked() {
        Ok(content) => content,
        Err(problem) => return problem_response(problem),
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let input = GroupInput {
        name: request.name.trim(),
        description: &request.description,
        content: content.as_ref(),
    };
    let written = writes::create(&mut client, &input, &editor.actor, Utc::now()).await;
    answer(StatusCode::CREATED, written)
}

/// Edits a group when `version` is still current. An automatic group
/// edited becomes a rule group.
#[utoipa::path(patch, path = "/api/v1/host-groups/{group_id}", tag = "access control",
    params(("group_id" = String, Path)), request_body = UpdateHostGroup,
    responses((status = 200, description = "Saved", body = HostGroupView),
        (status = 400, description = "invalid_group", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs host_groups.manage and hosts.read on all hosts", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "group_not_found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "stale_group or group_name_taken", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "invalid_condition or unknown_host", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    payload: Result<Json<UpdateHostGroup>, JsonRejection>,
) -> Response {
    let editor = match writer(&state, &headers).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return problem_response(invalid("body", "The request body is invalid"));
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let current = match store::detail(&client, &group_id, &AgentScope::Global).await {
        Ok(Some(group)) => group,
        Ok(None) => return group_not_found(),
        Err(_) => return unavailable_auth(),
    };
    let membership_changes = request.conditions.is_some() || request.agent_ids.is_some();
    if membership_changes
        && let Err(response) = reaching_roles_fit(&client, &editor, &current.roles).await
    {
        return response;
    }
    // the roles just checked; the store refuses the write as stale if others
    // reach the group by then
    let checked_roles: Vec<String> = current.roles.iter().map(|(id, _)| id.clone()).collect();
    // stored content (None, None) is kept unchecked so a rename never trips a limit
    let content = match (request.conditions, request.agent_ids) {
        (Some(conditions), None) => Content::rule(conditions).checked(),
        (None, Some(picked)) => Content::Manual(picked).checked(),
        (None, None) if current.kind == GroupKind::Manual => {
            match store::picked_ids(&client, &group_id).await {
                Ok(picked) => Ok(Content::Manual(picked)),
                Err(_) => return unavailable_auth(),
            }
        }
        (None, None) => Ok(Content::Rule(current.conditions)),
        (Some(_), Some(_)) => {
            return problem_response(invalid(
                "agent_ids",
                "Send conditions or agent_ids, not both",
            ));
        }
    };
    let content = match content {
        Ok(content) => content,
        Err(problem) => return problem_response(problem),
    };
    let name = request
        .name
        .as_deref()
        .map_or(current.name.as_str(), str::trim);
    let input = GroupInput {
        name,
        description: request
            .description
            .as_deref()
            .unwrap_or(&current.description),
        content: content.as_ref(),
    };
    let written = writes::update(
        &mut client,
        &group_id,
        request.version,
        membership_changes.then_some(checked_roles.as_slice()),
        &input,
        &editor.actor,
        Utc::now(),
    )
    .await;
    answer(StatusCode::OK, written)
}

#[derive(Deserialize)]
pub(crate) struct DeleteQuery {
    version: i32,
}

/// Deletes a group no role reaches, with its rule-set switches.
#[utoipa::path(delete, path = "/api/v1/host-groups/{group_id}", tag = "access control",
    params(("group_id" = String, Path), ("version" = i32, Query, description = "The version you read")),
    responses((status = 204, description = "Deleted"),
        (status = 400, description = "invalid_group: no version", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs host_groups.manage and hosts.read on all hosts", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "group_not_found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "stale_group, or group_in_use with the roles' names", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn delete_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    query: Result<Query<DeleteQuery>, QueryRejection>,
) -> Response {
    let editor = match writer(&state, &headers).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    let Ok(Query(query)) = query else {
        return problem_response(invalid("version", "Send the version you read"));
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match writes::delete(
        &mut client,
        &group_id,
        query.version,
        &editor.actor,
        Utc::now(),
    )
    .await
    {
        Ok(GroupWrite::Saved(_)) => StatusCode::NO_CONTENT.into_response(),
        written => answer(StatusCode::NO_CONTENT, written),
    }
}

/// What saving `conditions` or `agent_ids` into the group would change, or
/// with `{}`, what deleting it would.
#[utoipa::path(post, path = "/api/v1/host-groups/{group_id}/preview", tag = "access control",
    params(("group_id" = String, Path)), request_body = PreviewHostGroup,
    responses((status = 200, description = "What would change", body = HostGroupPreview),
        (status = 403, description = "Needs host_groups.manage and hosts.read on all hosts", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "group_not_found", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "invalid_condition", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn preview_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    payload: Result<Json<PreviewHostGroup>, JsonRejection>,
) -> Response {
    preview(&state, &headers, Some(&group_id), payload).await
}

/// The hosts a new group with `conditions` or `agent_ids` would hold.
#[utoipa::path(post, path = "/api/v1/host-groups/preview", tag = "access control",
    request_body = PreviewHostGroup,
    responses((status = 200, description = "The joining hosts", body = HostGroupPreview),
        (status = 400, description = "invalid_group: neither conditions nor agent_ids", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs host_groups.manage and hosts.read on all hosts", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "invalid_condition", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn preview_new_group(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<PreviewHostGroup>, JsonRejection>,
) -> Response {
    preview(&state, &headers, None, payload).await
}

async fn preview(
    state: &AuthHttpState,
    headers: &HeaderMap,
    group_id: Option<&str>,
    payload: Result<Json<PreviewHostGroup>, JsonRejection>,
) -> Response {
    let editor = match writer(state, headers).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return problem_response(invalid("body", "The request body is invalid"));
    };
    let content = match (request.conditions, request.agent_ids) {
        (Some(conditions), None) => Some(Content::rule(conditions)),
        (None, Some(picked)) => Some(Content::Manual(picked)),
        (None, None) if group_id.is_some() => None,
        _ => return problem_response(invalid("body", "Send conditions or agent_ids")),
    };
    let content = match content.map(Content::checked).transpose() {
        Ok(content) => content,
        Err(problem) => return problem_response(problem),
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let proposed = content.as_ref().map(Content::as_ref);
    match writes::preview(&client, group_id, proposed.as_ref()).await {
        Ok(PreviewOutcome::Ready(mut preview)) => {
            if !editor.admin {
                let visible = match people_in_share(&client, &editor).await {
                    Ok(visible) => visible,
                    Err(response) => return response,
                };
                preview.gains.retain(|p| visible.contains(&p.user_id));
                preview.loses.retain(|p| visible.contains(&p.user_id));
            }
            Json(HostGroupPreview::from(preview)).into_response()
        }
        Ok(PreviewOutcome::NotFound) => group_not_found(),
        Ok(PreviewOutcome::Invalid(part)) => invalid_condition(&part),
        Err(_) => unavailable_auth(),
    }
}

/// The caller's scope for reading groups: their `hosts.read` reach, or no
/// hosts at all without it.
async fn reader(state: &AuthHttpState, headers: &HeaderMap) -> Result<AgentScope, Response> {
    let editor = caller(state, headers, false).await?;
    if !editor.holds(Permission::HostGroupsManage)
        && let Some(response) = editor.denied(Permission::AccessRead)
    {
        return Err(response);
    }
    Ok(scope_of(&editor.capabilities, Permission::HostsRead)
        .unwrap_or_else(|| AgentScope::AssetGroups(Vec::new())))
}

/// The caller (CSRF checked), holding `host_groups.manage` and `hosts.read`
/// on all hosts.
async fn writer(state: &AuthHttpState, headers: &HeaderMap) -> Result<Editor, Response> {
    let editor = caller(state, headers, true).await?;
    if let Some(response) = editor.denied(Permission::HostGroupsManage) {
        return Err(response);
    }
    let every_host = editor.capabilities.iter().any(|c| {
        c.permission == Permission::HostsRead && matches!(c.scope, PermissionScope::Global)
    });
    if !every_host {
        return Err(problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Changing host groups needs access to every host",
        )));
    }
    Ok(editor)
}
