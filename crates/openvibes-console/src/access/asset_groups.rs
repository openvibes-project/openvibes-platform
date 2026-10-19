//! Host groups: the list for the Host groups tab and the role reach picker.
//! The tag-selector writes are gone with schema 53 and answer 410 until the
//! host-group routes arrive.

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    access::guard::unavailable_auth,
    http::{
        AuthHttpState,
        problem::{ProblemDetails, problem_response},
    },
};

pub(super) fn moved() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::GONE,
        "moved",
        "Tags and tag-based asset groups were replaced by labels and host groups",
    ))
}

/// Creates an asset group from a bounded conjunction of exact tag selectors.
#[utoipa::path(post,path="/api/v1/access-control/asset-groups",tag="access control",request_body=crate::SaveAssetGroupRequest,responses((status=201,description="Asset group created",body=crate::AccessAssetGroup),(status=400,description="Invalid selector set",body=ProblemDetails),(status=409,description="Name conflict",body=ProblemDetails)))]
pub(crate) async fn create_authenticated_asset_group() -> Response {
    moved()
}

/// Replaces an asset group's name and complete selector conjunction.
#[utoipa::path(put,path="/api/v1/access-control/asset-groups/{group_id}",tag="access control",params(("group_id"=String,Path)),request_body=crate::SaveAssetGroupRequest,responses((status=200,description="Asset group updated",body=crate::AccessAssetGroup),(status=400,description="Invalid selector set",body=ProblemDetails),(status=404,description="Asset group not found",body=ProblemDetails),(status=409,description="Name conflict",body=ProblemDetails)))]
pub(crate) async fn update_authenticated_asset_group() -> Response {
    moved()
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
