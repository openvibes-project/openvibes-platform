//! The People API (spec §4.4, §9.1, §13): the list, a person's page,
//! adding a person, editing details, disable and enable, and reset
//! password. An editor without Administrator sees and changes only people
//! whose roles all fit inside their own share; anyone else is answered as
//! absent (404).

use std::collections::HashMap;

use axum::{
    extract::{Json, Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use platform_store::{
    Client,
    console_auth::{self, NewLocalUser},
    console_people::{self, Person},
    console_roles::{self, Reach, StoredRole},
};

use crate::access::catalogue::{Scope, def};
use crate::access::editor::{Editor, caller, role_fits, roles_fit};
use crate::access::guard::unavailable_auth;
use crate::access::people_types::{
    AccessLine, ActivityLine, Applies, PersonRow, PersonView, UpdatePerson,
};
use crate::access::rbac::ADMIN_ROLE;
use crate::access::roles_types::{GroupRef, RoleView};
use crate::access::users::{canonical_username, one_time_credentials, random_uuid};
use crate::http::{
    AuthHttpState,
    headers::no_store,
    problem::{ProblemDetails, problem_response},
    validate::valid_uuid,
};
use crate::{CreateUserRequest, CreatedUser, Permission};

/// Every role by id: people carry role ids.
pub(crate) type Roles = HashMap<String, StoredRole>;

pub(crate) async fn all_roles(client: &Client) -> Result<Roles, Response> {
    let roles = console_roles::list_roles(client)
        .await
        .map_err(|_| unavailable_auth())?;
    Ok(roles.into_iter().map(|r| (r.role_id.clone(), r)).collect())
}

pub(crate) fn held<'a>(role_ids: &[String], roles: &'a Roles) -> Vec<&'a StoredRole> {
    role_ids.iter().filter_map(|id| roles.get(id)).collect()
}

/// The person `user_id` when the editor may see them: they exist, and are
/// the editor or have roles that all fit inside the editor's share.
pub(crate) async fn visible_person(
    client: &Client,
    editor: &Editor,
    user_id: &str,
) -> Result<(Person, Roles), Response> {
    if !valid_uuid(user_id) {
        return Err(user_not_found());
    }
    let person = console_people::person(client, user_id)
        .await
        .map_err(|_| unavailable_auth())?
        .ok_or_else(user_not_found)?;
    let roles = all_roles(client).await?;
    if person.user_id != editor.actor && !roles_fit(editor, &held(&person.role_ids, &roles)) {
        return Err(user_not_found());
    }
    Ok((person, roles))
}

/// People, filtered to the caller's share.
#[utoipa::path(get, path = "/api/v1/users", tag = "access control",
    responses((status = 200, description = "People", body = [PersonRow]),
        (status = 403, description = "Needs access.read", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_people(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let editor = match caller(&state, &headers, false).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if let Some(response) = editor.denied(Permission::AccessRead) {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let roles = match all_roles(&client).await {
        Ok(roles) => roles,
        Err(response) => return response,
    };
    let Ok(people) = console_people::people(&client).await else {
        return unavailable_auth();
    };
    let Ok(mut pictures) = console_people::picture_etags(&client).await else {
        return unavailable_auth();
    };
    let rows: Vec<PersonRow> = people
        .into_iter()
        .filter_map(|person| {
            let mine = held(&person.role_ids, &roles);
            roles_fit(&editor, &mine).then(|| PersonRow {
                roles: views(&mine),
                picture: pictures.remove(&person.user_id),
                last_sign_in_at: person.last_sign_in_at.map(rfc3339),
                user_id: person.user_id,
                username: person.username,
                display_name: person.display_name,
                email: person.email,
                enabled: person.enabled,
                auth_source: person.auth_source,
            })
        })
        .collect();
    Json(rows).into_response()
}

/// A person's page: details, roles, access and recent activity. Anyone may
/// read their own; others need `access.read` and the share.
#[utoipa::path(get, path = "/api/v1/users/{user_id}", tag = "access control",
    params(("user_id" = String, Path)),
    responses((status = 200, description = "The person", body = PersonView),
        (status = 403, description = "Needs access.read", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_person(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let editor = match caller(&state, &headers, false).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if !user_id.eq_ignore_ascii_case(&editor.actor)
        && let Some(response) = editor.denied(Permission::AccessRead)
    {
        return response;
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let (person, roles) = match visible_person(&client, &editor, &user_id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let Ok(recent) = console_people::recent_activity(&client, &person.user_id, 10).await else {
        return unavailable_auth();
    };
    let Ok(picture) = console_people::picture_etag(&client, &person.user_id).await else {
        return unavailable_auth();
    };
    let mine = held(&person.role_ids, &roles);
    Json(PersonView {
        picture,
        roles: views(&mine),
        access: access_lines(&mine),
        recent: recent
            .into_iter()
            .map(|a| ActivityLine {
                action: a.action,
                target: a.target,
                at: rfc3339(a.at),
            })
            .collect(),
        last_sign_in_at: person.last_sign_in_at.map(rfc3339),
        created_at: rfc3339(person.created_at),
        user_id: person.user_id,
        username: person.username,
        display_name: person.display_name,
        email: person.email,
        enabled: person.enabled,
        auth_source: person.auth_source,
    })
    .into_response()
}

/// Adds a person with a one-time password, holding roles that all fit
/// inside the creator's own access.
#[utoipa::path(post, path = "/api/v1/users", tag = "access control",
    request_body = CreateUserRequest,
    responses((status = 201, description = "Created; the one-time password is shown only here", body = CreatedUser),
        (status = 400, description = "Invalid username, display name or roles", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "Needs access.users, or a role outside your access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "The username is taken", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "invalid_email", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_person(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<CreateUserRequest>, JsonRejection>,
) -> Response {
    // Authentication, CSRF and permission first: nothing about the body is
    // answered to a caller who may not make the request.
    let editor = match caller(&state, &headers, true).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if let Some(response) = editor.denied(Permission::AccessUsers) {
        return response;
    }
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_user", "Provide a username, display name and roles");
    };
    let (Some(username), Some(display_name)) = (
        canonical_username(&request.username),
        display_name(&request.display_name),
    ) else {
        return bad_request(
            "invalid_user",
            "Use 1 to 64 letters, digits or ._@+- for the username and 1 to 160 characters for the name",
        );
    };
    let email = match request.email.as_deref().map(email) {
        None | Some(Ok(None)) => None,
        Some(Ok(Some(email))) => Some(email),
        Some(Err(problem)) => return problem_response(problem),
    };
    let mut role_ids = request.role_ids.clone();
    role_ids.sort();
    role_ids.dedup();
    if role_ids.is_empty() || role_ids.len() > 64 {
        return bad_request("invalid_user", "Give the person 1 to 64 roles");
    }
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let roles = match all_roles(&client).await {
        Ok(roles) => roles,
        Err(response) => return response,
    };
    for id in &role_ids {
        let Some(role) = roles.get(id) else {
            return bad_request("unknown_role", "Choose an existing role");
        };
        if let Err(problem) = role_fits(&editor, role) {
            return problem_response(problem);
        }
    }
    match console_auth::username_taken(&client, &username).await {
        Ok(false) => {}
        Ok(true) => return user_conflict(),
        Err(_) => return unavailable_auth(),
    }
    let (password, phc) = match one_time_credentials(&state).await {
        Ok(credentials) => credentials,
        Err(response) => return response,
    };
    let (Some(user_id), Some(binding_id)) = (random_uuid(), random_uuid()) else {
        return unavailable_auth();
    };
    let created = console_people::create_user(
        &mut client,
        &NewLocalUser {
            user_id: &user_id,
            binding_id: &binding_id,
            username: &username,
            display_name,
            password_phc: &phc,
            role_id: &role_ids[0],
            actor_id: &editor.actor,
            actor_kind: "user",
            password_must_change: true,
            now: Utc::now(),
        },
        email,
        &role_ids[1..],
    )
    .await;
    if created.is_err() {
        // Lost a race with another create of the same name: a conflict.
        return match console_auth::username_taken(&client, &username).await {
            Ok(true) => user_conflict(),
            _ => unavailable_auth(),
        };
    }
    let mut response = Json(CreatedUser {
        user_id,
        username,
        display_name: display_name.to_owned(),
        role_ids,
        one_time_password: password,
    })
    .into_response();
    *response.status_mut() = StatusCode::CREATED;
    no_store(response)
}

/// Changes a person's display name or email: anyone their own, others
/// with `access.users` inside the share.
#[utoipa::path(patch, path = "/api/v1/users/{user_id}", tag = "access control",
    params(("user_id" = String, Path)), request_body = UpdatePerson,
    responses((status = 204, description = "Saved"),
        (status = 403, description = "Needs access.users", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "managed_by_sso", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "invalid_user or invalid_email", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_person(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    payload: Result<Json<UpdatePerson>, JsonRejection>,
) -> Response {
    let editor = match caller(&state, &headers, true).await {
        Ok(editor) => editor,
        Err(response) => return response,
    };
    if !user_id.eq_ignore_ascii_case(&editor.actor)
        && let Some(response) = editor.denied(Permission::AccessUsers)
    {
        return response;
    }
    let Ok(Json(request)) = payload else {
        return bad_request("invalid_user", "Send a display name or an email");
    };
    let name = match request.display_name.as_deref().map(display_name) {
        None => None,
        Some(Some(name)) => Some(name),
        Some(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_user",
                "Use 1 to 160 characters for the name",
            ));
        }
    };
    let email = match request.email.as_deref().map(email) {
        None => None,
        Some(Ok(email)) => Some(email),
        Some(Err(problem)) => return problem_response(problem),
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let person = match visible_person(&client, &editor, &user_id).await {
        Ok((person, _)) => person,
        Err(response) => return response,
    };
    if person.auth_source == "sso" {
        return crate::sso::managed_by_sso();
    }
    let saved = console_people::set_details(
        &mut client,
        &person.user_id,
        name,
        email,
        &editor.actor,
        Utc::now(),
    )
    .await;
    match saved {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => user_not_found(),
        Err(_) => unavailable_auth(),
    }
}

fn views(roles: &[&StoredRole]) -> Vec<RoleView> {
    roles
        .iter()
        .map(|&role| RoleView::from(role.clone()))
        .collect()
}

/// Each permission the roles give, in catalogue order: where it applies
/// and which role gives it. A host permission on a role reaching no host
/// applies nowhere and is left out.
fn access_lines(roles: &[&StoredRole]) -> Vec<AccessLine> {
    let mut lines = Vec::new();
    for permission in Permission::ALL {
        let def = def(permission);
        for role in roles {
            let holds = role.role_id == ADMIN_ROLE
                || role.permissions.iter().any(|id| id == permission.id());
            if !holds {
                continue;
            }
            let (applies, groups) = match (def.scope, &role.reach) {
                (Scope::Platform, _) => (Applies::Platform, Vec::new()),
                (Scope::Host, Reach::All) => (Applies::All, Vec::new()),
                (Scope::Host, Reach::Groups(_)) => (Applies::Groups, group_refs(role)),
                (Scope::Host, Reach::None) => continue,
            };
            lines.push(AccessLine {
                permission,
                label: def.label.to_owned(),
                area: def.area.to_owned(),
                applies,
                groups,
                from_role: role.name.clone(),
            });
        }
    }
    lines
}

fn group_refs(role: &StoredRole) -> Vec<GroupRef> {
    role.group_names
        .iter()
        .map(|(asset_group_id, name)| GroupRef {
            asset_group_id: asset_group_id.clone(),
            name: name.clone(),
        })
        .collect()
}

fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn display_name(name: &str) -> Option<&str> {
    let name = name.trim();
    (!name.is_empty() && name.chars().count() <= 160 && !name.chars().any(char::is_control))
        .then_some(name)
}

/// An email as sent: empty clears it (`None`); otherwise the database's
/// rule (at most 254 characters, one `@` with text either side, no space).
fn email(email: &str) -> Result<Option<&str>, ProblemDetails> {
    let email = email.trim();
    if email.is_empty() {
        return Ok(None);
    }
    let valid = email.chars().count() <= 254
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && !domain.contains('@')
        });
    if valid {
        Ok(Some(email))
    } else {
        Err(ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_email",
            "Enter an email address such as name@example.com",
        ))
    }
}

fn bad_request(code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(StatusCode::BAD_REQUEST, code, title))
}

pub(crate) fn forbidden(title: &'static str) -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::FORBIDDEN,
        "permission_denied",
        title,
    ))
}

pub(crate) fn last_administrator() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::CONFLICT,
        "last_administrator",
        "Someone else must hold Administrator first",
    ))
}

pub(crate) fn user_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "user_not_found",
        "No such person",
    ))
}

fn user_conflict() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::CONFLICT,
        "user_conflict",
        "A user with this username already exists",
    ))
}
