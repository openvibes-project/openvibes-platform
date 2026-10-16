//! The roles API (spec §4.1–4.4, §13): the permission catalogue, the
//! templates, and creating, editing and deleting roles. Every write is
//! checked against the editor's share (`share::fits`).

use std::collections::BTreeSet;

use axum::{
    extract::{Json, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::console_roles::{self, Principal, Reach, RoleInput, RoleWrite};

use crate::access::auth::{PresentedCredentials, presented_credentials};
use crate::access::catalogue::{catalogue_json, def};
use crate::access::guard::{authenticated_permission, session_user, unavailable_auth};
use crate::access::rbac::{ADMIN_ROLE, resolve_capabilities};
use crate::access::roles_types::{ReachInput, RoleView, SaveRole};
use crate::access::share::{RoleReach, fits, refusal_message};
use crate::access::templates::templates_json;
use crate::http::{
    AuthHttpState,
    problem::{FieldError, ProblemDetails, problem_response},
    validate::valid_uuid,
};
use crate::{EffectiveCapability, Permission};

/// The permission catalogue: area, column, scope and needs of each.
#[utoipa::path(get, path = "/api/v1/permissions", tag = "access control",
    responses((status = 200, description = "The permission catalogue", body = [Object]),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn permissions(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    static_json(&state, &headers, catalogue_json()).await
}

/// The role templates; picking one only fills the form.
#[utoipa::path(get, path = "/api/v1/role-templates", tag = "access control",
    responses((status = 200, description = "Role templates", body = [Object]),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn role_templates(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    static_json(&state, &headers, templates_json()).await
}

async fn static_json(state: &AuthHttpState, headers: &HeaderMap, json: String) -> Response {
    if let Err(response) = session_user(state, headers, false).await {
        return response;
    }
    ([(header::CONTENT_TYPE, "application/json")], json).into_response()
}

/// Every role, Administrator first, then by name.
#[utoipa::path(get, path = "/api/v1/roles", tag = "access control",
    responses((status = 200, description = "Roles", body = [RoleView]),
        (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs access.read", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_roles(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    if let Err(response) =
        authenticated_permission(&state, &headers, Permission::AccessRead, false).await
    {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match console_roles::list_roles(&client).await {
        Ok(roles) => {
            Json(roles.into_iter().map(RoleView::from).collect::<Vec<_>>()).into_response()
        }
        Err(_) => unavailable_auth(),
    }
}

/// One role.
#[utoipa::path(get, path = "/api/v1/roles/{role_id}", tag = "access control",
    params(("role_id" = String, Path)),
    responses((status = 200, description = "The role", body = RoleView),
        (status = 404, description = "No such role", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs access.read", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_role(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(role_id): Path<String>,
) -> Response {
    if let Err(response) =
        authenticated_permission(&state, &headers, Permission::AccessRead, false).await
    {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match console_roles::role(&client, &role_id).await {
        Ok(Some(role)) => Json(RoleView::from(role)).into_response(),
        Ok(None) => role_not_found(),
        Err(_) => unavailable_auth(),
    }
}

/// Creates a role that fits inside the editor's own access.
#[utoipa::path(post, path = "/api/v1/roles", tag = "access control", request_body = SaveRole,
    responses((status = 201, description = "Created", body = RoleView),
        (status = 400, description = "Invalid name, description or reach", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs access.roles, or outside the editor's access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "role_name_taken", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "missing_needs or unknown_group", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_role(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<SaveRole>, JsonRejection>,
) -> Response {
    let editor = match editor(&state, &headers).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return problem_response(invalid("body", "The request body is invalid"));
    };
    let role = match Checked::new(&request) {
        Ok(role) => role,
        Err(problem) => return problem_response(problem),
    };
    if let Err(response) = within_share(&editor.capabilities, &role.ids, &role.reach) {
        return problem_response(response);
    }
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let written =
        console_roles::create_role(&mut client, &role.input(), &editor.actor, Utc::now()).await;
    answer(StatusCode::CREATED, written)
}

/// Replaces a role's contents when `version` is still current; the
/// result must fit inside the editor's own access.
#[utoipa::path(patch, path = "/api/v1/roles/{role_id}", tag = "access control",
    params(("role_id" = String, Path)), request_body = SaveRole,
    responses((status = 200, description = "Saved", body = RoleView),
        (status = 400, description = "Invalid fields or no version", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "protected_role, or outside the editor's access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such role", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "stale_role or role_name_taken", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "missing_needs or unknown_group", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_role(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(role_id): Path<String>,
    payload: Result<Json<SaveRole>, JsonRejection>,
) -> Response {
    let editor = match editor(&state, &headers).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if role_id == ADMIN_ROLE {
        return protected_role();
    }
    let Ok(Json(request)) = payload else {
        return problem_response(invalid("body", "The request body is invalid"));
    };
    let Some(version) = request.version else {
        return problem_response(invalid("version", "Send the version you read"));
    };
    let role = match Checked::new(&request) {
        Ok(role) => role,
        Err(problem) => return problem_response(problem),
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    // The stored role must fit too, at the version the caller read: a
    // stale version is refused before the share check, and the store's
    // locked version check closes the race between this read and the write.
    if let Err(response) = stored_role_fits(&client, &editor, &role_id, Some(version)).await {
        return response;
    }
    if let Err(response) = within_share(&editor.capabilities, &role.ids, &role.reach) {
        return problem_response(response);
    }
    let written = console_roles::update_role(
        &mut client,
        &role_id,
        version,
        &role.input(),
        &editor.actor,
        Utc::now(),
    )
    .await;
    answer(StatusCode::OK, written)
}

/// Deletes a role nobody holds, when it fits inside the editor's access.
#[utoipa::path(delete, path = "/api/v1/roles/{role_id}", tag = "access control",
    params(("role_id" = String, Path)),
    responses((status = 204, description = "Deleted"),
        (status = 403, description = "protected_role, or outside the editor's access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such role", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "role_in_use, with holders", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn delete_role(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(role_id): Path<String>,
) -> Response {
    let editor = match editor(&state, &headers).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if role_id == ADMIN_ROLE {
        return protected_role();
    }
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    // ponytail: checked outside the delete's transaction (a delete carries
    // no version); a concurrent widening edit in between is still deleted,
    // and the role has no holders anyway.
    if let Err(response) = stored_role_fits(&client, &editor, &role_id, None).await {
        return response;
    }
    match console_roles::delete_role(&mut client, &role_id, &editor.actor, Utc::now()).await {
        Ok(RoleWrite::Saved(_)) => StatusCode::NO_CONTENT.into_response(),
        written => answer(StatusCode::NO_CONTENT, written),
    }
}

/// Edit and delete both need the role as stored to fit inside the
/// editor's share (§4.4), at `version` when one is given (else 409
/// `stale_role`). A stored permission id the catalogue does not know is
/// refused, not ignored, except to an Administrator, who holds everything
/// and must be able to clean such a role up.
async fn stored_role_fits(
    client: &platform_store::Client,
    editor: &Editor,
    role_id: &str,
    version: Option<i32>,
) -> Result<(), Response> {
    let stored = match console_roles::role(client, role_id).await {
        Ok(Some(role)) => role,
        Ok(None) => return Err(role_not_found()),
        Err(_) => return Err(unavailable_auth()),
    };
    if version.is_some_and(|version| version != stored.version) {
        return Err(conflict("stale_role", "The role changed since you read it"));
    }
    let mut permissions = Vec::with_capacity(stored.permissions.len());
    for id in &stored.permissions {
        let Some(permission) = Permission::from_id(id) else {
            if editor.admin {
                continue;
            }
            let mut problem = ProblemDetails::new(StatusCode::FORBIDDEN, "permission_denied", "");
            problem.title =
                format!("The role holds a permission this console does not know ({id})");
            return Err(problem_response(problem));
        };
        permissions.push(permission);
    }
    within_share(&editor.capabilities, &permissions, &stored.reach).map_err(problem_response)
}

/// Who is editing: their id, everything they hold, and whether they hold
/// Administrator.
struct Editor {
    actor: String,
    capabilities: Vec<EffectiveCapability>,
    admin: bool,
}

/// The caller, holding `access.roles` (CSRF checked), and everything they
/// hold: the share every write is checked against.
async fn editor(state: &AuthHttpState, headers: &HeaderMap) -> Result<Editor, Response> {
    let (_scope, actor) =
        authenticated_permission(state, headers, Permission::AccessRoles, true).await?;
    let principal = match presented_credentials(headers) {
        Ok(PresentedCredentials::Bearer(_)) => Principal::ServiceAccount(&actor),
        _ => Principal::User(&actor),
    };
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    // The same grants and test as `rbac::principal_capabilities`.
    let grants = console_roles::grants(&client, principal)
        .await
        .map_err(|_| unavailable_auth())?;
    Ok(Editor {
        admin: grants.iter().any(|grant| grant.role_id == ADMIN_ROLE),
        capabilities: resolve_capabilities(&grants),
        actor,
    })
}

/// A `SaveRole` that passed validation, ready for the store.
struct Checked {
    name: String,
    description: String,
    ids: Vec<Permission>,
    permissions: Vec<String>,
    reach: Reach,
}

impl Checked {
    fn new(request: &SaveRole) -> Result<Self, ProblemDetails> {
        let name = request.name.trim();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err(invalid(
                "name",
                "Use 1 to 64 characters, without control characters",
            ));
        }
        if request.description.chars().count() > 500 {
            return Err(invalid("description", "Use at most 500 characters"));
        }
        let set: BTreeSet<Permission> = request.permissions.iter().copied().collect();
        for &p in &set {
            if let Some(&need) = def(p).needs.iter().find(|n| !set.contains(n)) {
                let mut problem = ProblemDetails::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "missing_needs",
                    "A permission is missing what it needs",
                );
                problem.extra.permission = Some(p.id().to_owned());
                problem.extra.needs = Some(need.id().to_owned());
                return Err(problem);
            }
        }
        let reach = match &request.reach {
            ReachInput::None => Reach::None,
            ReachInput::All => Reach::All,
            ReachInput::Groups { asset_group_ids } => {
                let ids: BTreeSet<String> = asset_group_ids
                    .iter()
                    .map(|id| id.to_ascii_lowercase())
                    .collect();
                if ids.is_empty() || ids.len() > 64 || ids.len() != asset_group_ids.len() {
                    return Err(invalid(
                        "reach.asset_group_ids",
                        "Choose 1 to 64 host groups, each once",
                    ));
                }
                if !ids.iter().all(|id| valid_uuid(id)) {
                    return Err(unknown_group());
                }
                Reach::Groups(ids.into_iter().collect())
            }
        };
        Ok(Self {
            name: name.to_owned(),
            description: request.description.clone(),
            permissions: set.iter().map(|p| p.id().to_owned()).collect(),
            ids: set.into_iter().collect(),
            reach,
        })
    }

    fn input(&self) -> RoleInput<'_> {
        RoleInput {
            name: &self.name,
            description: &self.description,
            permissions: &self.permissions,
            reach: &self.reach,
        }
    }
}

/// 403 with the share message when the role does not fit (§4.4).
fn within_share(
    editor: &[EffectiveCapability],
    permissions: &[Permission],
    reach: &Reach,
) -> Result<(), ProblemDetails> {
    let reach = match reach {
        Reach::None => RoleReach::None,
        Reach::All => RoleReach::All,
        Reach::Groups(groups) => RoleReach::Groups(groups),
    };
    fits(editor, permissions, reach).map_err(|refusal| {
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

fn answer(status: StatusCode, written: Result<RoleWrite, platform_store::StoreError>) -> Response {
    match written {
        Ok(RoleWrite::Saved(role)) => (status, Json(RoleView::from(role))).into_response(),
        Ok(RoleWrite::NameTaken) => conflict("role_name_taken", "Another role has this name"),
        Ok(RoleWrite::Stale) => conflict("stale_role", "The role changed since you read it"),
        Ok(RoleWrite::NotFound) => role_not_found(),
        Ok(RoleWrite::Protected) => protected_role(),
        Ok(RoleWrite::InUse(holders)) => {
            let mut problem = ProblemDetails::new(
                StatusCode::CONFLICT,
                "role_in_use",
                "Take the role away from everyone who holds it first",
            );
            problem.extra.holders = Some(holders);
            problem_response(problem)
        }
        // Permissions are typed, so an unknown reference is a group (or
        // one deleted during the write).
        Ok(RoleWrite::UnknownReference) => problem_response(unknown_group()),
        Err(_) => unavailable_auth(),
    }
}

fn invalid(field: &str, message: &str) -> ProblemDetails {
    let mut problem = ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_role",
        "The role is invalid",
    );
    problem.field_errors = Some(vec![FieldError {
        field: field.to_owned(),
        code: "invalid".to_owned(),
        message: message.to_owned(),
    }]);
    problem
}

fn unknown_group() -> ProblemDetails {
    ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown_group",
        "A host group does not exist",
    )
}

fn conflict(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::CONFLICT, code, title))
}

fn role_not_found() -> Response {
    problem_response(ProblemDetails::not_found("role_not_found", "No such role"))
}

fn protected_role() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "protected_role",
        "Administrator cannot be changed or deleted",
    ))
}
