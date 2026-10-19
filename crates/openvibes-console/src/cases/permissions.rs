use axum::{http::HeaderMap, response::Response};
use platform_store::console_read::AgentScope;

use crate::{Permission, PermissionScope, access::guard::session_user, http::AuthHttpState};

use super::responses::permission_denied;

/// A signed-in browser user holding `permissions`: their scope for the
/// first, and their id. Bearer tokens are refused. For changes, CSRF and
/// origin are checked first; the scope is that of the first permission.
pub(crate) async fn authorize(
    state: &AuthHttpState,
    headers: &HeaderMap,
    permissions: &[Permission],
    csrf_required: bool,
) -> Result<(AgentScope, String), Response> {
    let user = session_user(state, headers, csrf_required).await?;
    let mut scope = None;
    for permission in permissions {
        let Some(capability) = user
            .capabilities
            .iter()
            .find(|capability| capability.permission == *permission)
        else {
            return Err(permission_denied());
        };
        scope.get_or_insert_with(|| match &capability.scope {
            PermissionScope::Global => AgentScope::Global,
            PermissionScope::AssetGroups { asset_group_ids } => {
                AgentScope::AssetGroups(asset_group_ids.clone())
            }
        });
    }
    scope
        .map(|scope| (scope, user.user_id.to_ascii_lowercase()))
        .ok_or_else(permission_denied)
}

/// Reading: `cases.read`.
pub(super) async fn reader(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<(AgentScope, String), Response> {
    authorize(state, headers, &[Permission::CasesRead], false).await
}

/// Changing: `cases.write` (with `cases.read`, which it needs); items are
/// checked against its scope.
pub(super) async fn manager(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<(AgentScope, String), Response> {
    authorize(
        state,
        headers,
        &[Permission::CasesWrite, Permission::CasesRead],
        true,
    )
    .await
}

/// Whether the caller may also set or change a case's assignee
/// (`cases.assign`); asked after [`manager`] has let them in.
pub(super) async fn may_assign(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<bool, Response> {
    let user = session_user(state, headers, false).await?;
    Ok(user
        .capabilities
        .iter()
        .any(|capability| capability.permission == Permission::CasesAssign))
}
