//! Who is changing access, and the share checks (spec §4.4) on whole
//! stored roles: the roles, people and service-account handlers use them.

use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use platform_store::console_roles::{self, Principal, Reach, StoredRole};

use crate::access::guard::{session_user, unavailable_auth};
use crate::access::rbac::{ADMIN_ROLE, resolve_capabilities};
use crate::access::share::{RoleReach, all_fit, fits, refusal_message};
use crate::http::{
    AuthHttpState,
    problem::{ProblemDetails, problem_response},
};
use crate::{EffectiveCapability, Permission};

/// Does the whole stored role fit inside the editor's share (§4.4)? A
/// stored permission id the catalogue does not know is refused, not
/// ignored, except to an Administrator, who holds everything and must be
/// able to clean such a role up.
pub(crate) fn role_fits(editor: &Editor, role: &StoredRole) -> Result<(), ProblemDetails> {
    let mut permissions = Vec::with_capacity(role.permissions.len());
    for id in &role.permissions {
        let Some(permission) = Permission::from_id(id) else {
            if editor.admin {
                continue;
            }
            let mut problem = ProblemDetails::new(StatusCode::FORBIDDEN, "permission_denied", "");
            problem.title =
                format!("The role holds a permission this console does not know ({id})");
            return Err(problem);
        };
        permissions.push(permission);
    }
    within_share(&editor.capabilities, &permissions, &role.reach)
}

/// Do all these roles fit inside the editor's share? People and service
/// accounts are shown to, and changed by, an editor only when they do.
pub(crate) fn roles_fit(editor: &Editor, roles: &[&StoredRole]) -> bool {
    if editor.admin {
        return true;
    }
    let typed: Option<Vec<Vec<Permission>>> = roles
        .iter()
        .map(|role| {
            role.permissions
                .iter()
                .map(|id| Permission::from_id(id))
                .collect()
        })
        .collect();
    let Some(typed) = typed else { return false };
    all_fit(
        &editor.capabilities,
        typed
            .iter()
            .zip(roles)
            .map(|(permissions, role)| (permissions.as_slice(), role_reach(&role.reach))),
    )
}

/// Who is calling: their id, everything they hold, and whether they hold
/// Administrator.
pub(crate) struct Editor {
    pub(crate) actor: String,
    pub(crate) capabilities: Vec<EffectiveCapability>,
    pub(crate) admin: bool,
}

impl Editor {
    pub(crate) fn holds(&self, permission: Permission) -> bool {
        self.capabilities.iter().any(|c| c.permission == permission)
    }

    /// The 403 to answer when the caller does not hold `permission`.
    pub(crate) fn denied(&self, permission: Permission) -> Option<Response> {
        (!self.holds(permission)).then(|| {
            problem_response(ProblemDetails::new(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "Access is not available",
            ))
        })
    }
}

/// The signed-in person (CSRF checked when `csrf`) and everything they
/// hold: the share every access write is checked against. Browser
/// sessions only.
pub(crate) async fn caller(
    state: &AuthHttpState,
    headers: &HeaderMap,
    csrf: bool,
) -> Result<Editor, Response> {
    let user = session_user(state, headers, csrf).await?;
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    principal_editor(&client, Principal::User(&user.user_id))
        .await
        .map_err(|_| unavailable_auth())
}

/// The [`Editor`] of a caller `authenticated_permission` already let in as
/// `actor`: their session's user, or the bearer token's service account.
pub(crate) async fn authenticated_editor(
    client: &platform_store::Client,
    headers: &HeaderMap,
    actor: &str,
) -> Result<Editor, platform_store::StoreError> {
    use crate::access::auth::{PresentedCredentials, presented_credentials};
    let principal = match presented_credentials(headers) {
        Ok(PresentedCredentials::Bearer(_)) => Principal::ServiceAccount(actor),
        _ => Principal::User(actor),
    };
    principal_editor(client, principal).await
}

/// What `principal` holds, as an [`Editor`] (its id is the actor).
pub(crate) async fn principal_editor(
    client: &platform_store::Client,
    principal: Principal<'_>,
) -> Result<Editor, platform_store::StoreError> {
    let grants = console_roles::grants(client, principal).await?;
    let (Principal::User(id) | Principal::ServiceAccount(id)) = principal;
    Ok(Editor {
        admin: grants.iter().any(|grant| grant.role_id == ADMIN_ROLE),
        capabilities: resolve_capabilities(&grants),
        actor: id.to_owned(),
    })
}

fn role_reach(reach: &Reach) -> RoleReach<'_> {
    match reach {
        Reach::None => RoleReach::None,
        Reach::All => RoleReach::All,
        Reach::Groups(groups) => RoleReach::Groups(groups),
    }
}

/// 403 with the share message when the role does not fit (§4.4).
pub(crate) fn within_share(
    editor: &[EffectiveCapability],
    permissions: &[Permission],
    reach: &Reach,
) -> Result<(), ProblemDetails> {
    fits(editor, permissions, role_reach(reach)).map_err(|refusal| {
        tracing::info!(
            permission = refusal.permission.id(),
            reason = refusal.reason,
            "role write outside the editor's share"
        );
        let mut problem = ProblemDetails::new(StatusCode::FORBIDDEN, "permission_denied", "");
        problem.title = refusal_message(&refusal);
        problem
    })
}
