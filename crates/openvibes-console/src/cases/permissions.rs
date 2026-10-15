use axum::{http::HeaderMap, response::Response};
use platform_store::console_read::AgentScope;

use crate::{Permission, PermissionScope, access::guard::session_user, http::AuthHttpState};

use super::answers::permission_denied;

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

/// Changing: `cases.manage` (with `cases.read`, which the built-in roles
/// grant together); items are checked against its scope.
pub(super) async fn manager(
    state: &AuthHttpState,
    headers: &HeaderMap,
) -> Result<(AgentScope, String), Response> {
    authorize(
        state,
        headers,
        &[Permission::CasesManage, Permission::CasesRead],
        true,
    )
    .await
}
