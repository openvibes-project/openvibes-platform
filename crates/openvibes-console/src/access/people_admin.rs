//! People administration (spec §4.3, §4.4, §9.1): disable, enable and
//! reset password, each needing `access.users` and the person inside the
//! editor's share; nobody disables themself, and the store keeps the last
//! enabled Administrator.

use axum::{
    extract::{Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::{
    console_auth::{self, AuditContext, DisableOutcome},
    console_people::{self, Person},
};

use crate::Permission;
use crate::access::editor::{Editor, caller};
use crate::access::guard::unavailable_auth;
use crate::access::people::{forbidden, last_administrator, user_not_found, visible_person};
use crate::access::people_types::OneTimePassword;
use crate::access::users::one_time_credentials;
use crate::http::{AuthHttpState, headers::no_store, problem::ProblemDetails};

/// Disables a person and ends their sessions; never yourself, never the
/// last Administrator.
#[utoipa::path(post, path = "/api/v1/users/{user_id}/disable", tag = "access control",
    params(("user_id" = String, Path)),
    responses((status = 204, description = "Disabled"),
        (status = 403, description = "Needs access.users; or yourself", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "last_administrator", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn disable_person(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let (editor, mut client, person) = match managed(&state, &headers, &user_id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    if person.user_id == editor.actor {
        return forbidden("You cannot disable your own account");
    }
    let outcome = console_auth::disable_local_user(
        &mut client,
        &person.user_id,
        Utc::now(),
        &AuditContext::default(),
        &editor.actor,
        "user",
    )
    .await;
    match outcome {
        // Already disabled is the same as disabled now.
        Ok(DisableOutcome::Disabled | DisableOutcome::NotFound) => {
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(DisableOutcome::LastAdministrator) => last_administrator(),
        Err(_) => unavailable_auth(),
    }
}

/// Lets a disabled person sign in again.
#[utoipa::path(post, path = "/api/v1/users/{user_id}/enable", tag = "access control",
    params(("user_id" = String, Path)),
    responses((status = 204, description = "Enabled"),
        (status = 403, description = "Needs access.users", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn enable_person(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let (editor, mut client, person) = match managed(&state, &headers, &user_id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    match console_people::enable_user(&mut client, &person.user_id, &editor.actor, Utc::now()).await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// Gives a person a one-time password, shown only here: they must set
/// their own at the next sign-in, and their sessions end.
#[utoipa::path(post, path = "/api/v1/users/{user_id}/reset-password", tag = "access control",
    params(("user_id" = String, Path)),
    responses((status = 200, description = "The one-time password", body = OneTimePassword),
        (status = 403, description = "Needs access.users", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "No such person inside your access", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn reset_password(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let (editor, mut client, person) = match managed(&state, &headers, &user_id).await {
        Ok(found) => found,
        Err(response) => return response,
    };
    let (password, phc) = match one_time_credentials(&state).await {
        Ok(credentials) => credentials,
        Err(response) => return response,
    };
    let reset = console_people::reset_password(
        &mut client,
        &person.user_id,
        &phc,
        &editor.actor,
        Utc::now(),
    )
    .await;
    match reset {
        Ok(true) => no_store(
            Json(OneTimePassword {
                one_time_password: password,
            })
            .into_response(),
        ),
        Ok(false) => user_not_found(),
        Err(_) => unavailable_auth(),
    }
}

/// The caller holding `access.users` (CSRF checked), a connection, and the
/// person they manage.
async fn managed(
    state: &AuthHttpState,
    headers: &HeaderMap,
    user_id: &str,
) -> Result<(Editor, platform_store::Client, Person), Response> {
    let editor = caller(state, headers, true).await?;
    if let Some(response) = editor.denied(Permission::AccessUsers) {
        return Err(response);
    }
    let client = state.pool.get().await.map_err(|_| unavailable_auth())?;
    let (person, _) = visible_person(&client, &editor, user_id).await?;
    Ok((editor, client, person))
}
