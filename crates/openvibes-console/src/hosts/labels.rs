//! Host labels (spec §5.2): read with `hosts.read` on the host, changed
//! with `hosts.label` on it. A host outside the caller's reach answers 404,
//! the same as a missing one.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::host_labels::{self as store, LabelWrite};

use super::groups_types::{HostGroupRef, HostLabelsView};
use crate::Permission;
use crate::access::guard::{authenticated_permission, unavailable_auth};
use crate::http::{
    AuthHttpState,
    problem::{ProblemDetails, problem_response},
};

/// A host's labels and the groups it is in.
#[utoipa::path(get, path = "/api/v1/hosts/{agent_id}/labels", tag = "agents",
    params(("agent_id" = String, Path)),
    responses((status = 200, description = "Labels and groups", body = HostLabelsView),
        (status = 403, description = "Needs hosts.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "host_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn host_labels(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(agent_id): Path<String>,
) -> Response {
    let scope = match authenticated_permission(&state, &headers, Permission::HostsRead, false).await
    {
        Ok((scope, _)) => scope,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::host_labels(&client, &scope, &agent_id).await {
        Ok(Some(found)) => Json(HostLabelsView {
            labels: found.labels,
            groups: found
                .groups
                .into_iter()
                .map(|(asset_group_id, name, kind)| HostGroupRef {
                    asset_group_id,
                    name,
                    kind: kind.into(),
                })
                .collect(),
        })
        .into_response(),
        Ok(None) => host_not_found(),
        Err(_) => unavailable_auth(),
    }
}

/// Adds a label (1–64 characters, at most 32 per host); adding one already
/// there is fine.
#[utoipa::path(put, path = "/api/v1/hosts/{agent_id}/labels/{label}", tag = "agents",
    params(("agent_id" = String, Path), ("label" = String, Path)),
    responses((status = 204, description = "Added, or already there"),
        (status = 400, description = "invalid_label", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs hosts.label", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "host_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "too_many_labels", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn add_label(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent_id, label)): Path<(String, String)>,
) -> Response {
    let (actor, mut client) = match labeler(&state, &headers, &agent_id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    match store::add_label(&mut client, &agent_id, &label, &actor, Utc::now()).await {
        Ok(LabelWrite::Added | LabelWrite::AlreadyThere) => StatusCode::NO_CONTENT.into_response(),
        Ok(LabelWrite::TooMany) => problem_response(ProblemDetails::new(
            StatusCode::CONFLICT,
            "too_many_labels",
            "A host has at most 32 labels",
        )),
        Ok(LabelWrite::NotFound) => host_not_found(),
        Ok(LabelWrite::Invalid) => problem_response(ProblemDetails::new(
            StatusCode::BAD_REQUEST,
            "invalid_label",
            "Use 1 to 64 characters, without control characters",
        )),
        Err(_) => unavailable_auth(),
    }
}

/// Removes a label; removing one that is not there is fine.
#[utoipa::path(delete, path = "/api/v1/hosts/{agent_id}/labels/{label}", tag = "agents",
    params(("agent_id" = String, Path), ("label" = String, Path)),
    responses((status = 204, description = "Removed, or not there"),
        (status = 403, description = "Needs hosts.label", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "host_not_found: missing or outside reach", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn remove_label(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((agent_id, label)): Path<(String, String)>,
) -> Response {
    let (actor, mut client) = match labeler(&state, &headers, &agent_id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    match store::remove_label(&mut client, &agent_id, &label, &actor, Utc::now()).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// The caller (CSRF checked) holding `hosts.label` on `agent_id`, and a
/// connection.
async fn labeler(
    state: &AuthHttpState,
    headers: &HeaderMap,
    agent_id: &str,
) -> Result<(String, platform_store::Client), Response> {
    let (scope, actor) =
        authenticated_permission(state, headers, Permission::HostsLabel, true).await?;
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    match store::reachable(&client, &scope, agent_id).await {
        Ok(true) => Ok((actor, client)),
        Ok(false) => Err(host_not_found()),
        Err(_) => Err(unavailable_auth()),
    }
}

fn host_not_found() -> Response {
    problem_response(ProblemDetails::not_found("host_not_found", "No such host"))
}
