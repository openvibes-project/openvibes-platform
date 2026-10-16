//! Giving and removing roles (spec §4.3–4.5, §13): `access.grant`, the
//! whole role inside the editor's share, a holder the editor may see, and
//! nobody changing their own roles. The store keeps the last enabled
//! Administrator.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    Client, console_auth,
    console_people::{self, BindingRevocation, RoleGift},
    console_roles::{self, Principal},
};

use crate::Permission;
use crate::access::editor::{Editor, authenticated_editor, caller, role_fits, roles_fit};
use crate::access::guard::unavailable_auth;
use crate::access::people::{
    all_roles, forbidden, held, last_administrator, user_not_found, visible_person,
};
use crate::http::{
    AuthHttpState,
    problem::{ProblemDetails, problem_response},
    validate::valid_uuid,
};

enum Holder {
    User(String),
    Account(String),
}

/// Gives a person a role (idempotent).
#[utoipa::path(put, path = "/api/v1/users/{user_id}/roles/{role_id}", tag = "access control",
    params(("user_id" = String, Path), ("role_id" = String, Path)),
    responses((status = 204, description = "Held"),
        (status = 403, description = "Needs access.grant; the role is outside your access; or yourself", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access, or no such role", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn give_user_role(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((user_id, role_id)): Path<(String, String)>,
) -> Response {
    change(&state, &headers, Holder::User(user_id), &role_id, true).await
}

/// Takes a role from a person (idempotent); never the last Administrator.
#[utoipa::path(delete, path = "/api/v1/users/{user_id}/roles/{role_id}", tag = "access control",
    params(("user_id" = String, Path), ("role_id" = String, Path)),
    responses((status = 204, description = "Not held"),
        (status = 403, description = "Needs access.grant; the role is outside your access; or yourself", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access, or no such role", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "last_administrator", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn remove_user_role(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((user_id, role_id)): Path<(String, String)>,
) -> Response {
    change(&state, &headers, Holder::User(user_id), &role_id, false).await
}

/// Gives a service account a role (idempotent).
#[utoipa::path(put, path = "/api/v1/service-accounts/{service_account_id}/roles/{role_id}", tag = "service_accounts",
    params(("service_account_id" = String, Path), ("role_id" = String, Path)),
    responses((status = 204, description = "Held"),
        (status = 403, description = "Needs access.grant, or the role is outside your access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such service account inside your access, or no such role", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn give_account_role(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((account_id, role_id)): Path<(String, String)>,
) -> Response {
    change(
        &state,
        &headers,
        Holder::Account(account_id),
        &role_id,
        true,
    )
    .await
}

/// Takes a role from a service account (idempotent).
#[utoipa::path(delete, path = "/api/v1/service-accounts/{service_account_id}/roles/{role_id}", tag = "service_accounts",
    params(("service_account_id" = String, Path), ("role_id" = String, Path)),
    responses((status = 204, description = "Not held"),
        (status = 403, description = "Needs access.grant, or the role is outside your access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such service account inside your access, or no such role", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn remove_account_role(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path((account_id, role_id)): Path<(String, String)>,
) -> Response {
    change(
        &state,
        &headers,
        Holder::Account(account_id),
        &role_id,
        false,
    )
    .await
}

async fn change(
    state: &AuthHttpState,
    headers: &HeaderMap,
    holder: Holder,
    role_id: &str,
    give: bool,
) -> Response {
    let editor = match caller(state, headers, true).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if let Some(response) = editor.denied(Permission::AccessGrant) {
        return response;
    }
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let id = match &holder {
        Holder::User(id) => match visible_person(&client, &editor, id).await {
            Ok((person, _)) if person.user_id == editor.actor => {
                return forbidden("Nobody can change their own roles");
            }
            Ok((person, _)) => person.user_id,
            Err(response) => return response,
        },
        Holder::Account(id) => match visible_account(&client, &editor, id).await {
            Ok(id) => id,
            Err(response) => return response,
        },
    };
    let role = match console_roles::role(&client, role_id).await {
        Ok(Some(role)) => role,
        Ok(None) => {
            return problem_response(ProblemDetails::not_found("role_not_found", "No such role"));
        }
        Err(_) => return unavailable_auth(),
    };
    // ponytail: the share is decided before, not inside, the store's
    // transaction; a concurrent role edit in between is not seen (the last
    // Administrator is still guarded inside it).
    if let Err(problem) = role_fits(&editor, &role) {
        return problem_response(problem);
    }
    let principal = match holder {
        Holder::User(_) => Principal::User(&id),
        Holder::Account(_) => Principal::ServiceAccount(&id),
    };
    let now = Utc::now();
    if give {
        match console_people::give_role(&mut client, principal, role_id, &editor.actor, now).await {
            Ok(RoleGift::Given | RoleGift::AlreadyHeld) => StatusCode::NO_CONTENT.into_response(),
            Ok(RoleGift::NotFound) => user_not_found(),
            Err(_) => unavailable_auth(),
        }
    } else {
        match console_people::remove_role(&mut client, principal, role_id, &editor.actor, now).await
        {
            Ok(BindingRevocation::Revoked | BindingRevocation::NotFound) => {
                StatusCode::NO_CONTENT.into_response()
            }
            Ok(BindingRevocation::LastAdministrator) => last_administrator(),
            Err(_) => unavailable_auth(),
        }
    }
}

/// The service account's id when it exists and all its roles fit inside
/// the editor's share; otherwise 404 `service_account_not_found`, the same
/// for an account outside the share as for one that does not exist.
// ponytail: reads the whole (small) account list; add a one-account read
// if there are ever thousands.
pub(crate) async fn visible_account(
    client: &Client,
    editor: &Editor,
    id: &str,
) -> Result<String, Response> {
    let not_found = || {
        problem_response(ProblemDetails::not_found(
            "service_account_not_found",
            "No such service account",
        ))
    };
    if !valid_uuid(id) {
        return Err(not_found());
    }
    let accounts = console_auth::list_service_accounts(client)
        .await
        .map_err(|_| unavailable_auth())?;
    let account = accounts
        .into_iter()
        .find(|a| a.service_account_id.eq_ignore_ascii_case(id))
        .ok_or_else(not_found)?;
    let roles = all_roles(client).await?;
    if !roles_fit(editor, &held(&account.role_ids, &roles)) {
        return Err(not_found());
    }
    Ok(account.service_account_id)
}

/// For the token and disable routes: the account `id` when it is inside the
/// share of the caller `authenticated_permission` let in as `actor`.
// ponytail: the share is decided before, not inside, the store's
// transaction; a concurrent role change in between is not seen.
pub(crate) async fn account_in_share(
    state: &AuthHttpState,
    headers: &HeaderMap,
    actor: &str,
    id: &str,
) -> Result<String, Response> {
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    let editor = authenticated_editor(&client, headers, actor)
        .await
        .map_err(|_| unavailable_auth())?;
    visible_account(&client, &editor, id).await
}
