//! `/v1/saved-views` and `/v1/list-columns/{page}`: a signed-in browser
//! session's own views and hidden columns. Writes check CSRF.

use axum::{
    extract::{
        Json, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use platform_store::saved_views::{self as store, ViewWrite};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::{PAGES, hideable};
use crate::access::guard::{session_user, unavailable_auth};
use crate::http::{
    AuthHttpState,
    problem::{FieldError, ProblemDetails, problem_response},
};

/// One saved view.
#[derive(Serialize, ToSchema)]
pub(crate) struct SavedViewView {
    /// Stable UUID.
    pub id: String,
    /// The list page.
    pub page: String,
    /// 1–60 characters.
    pub name: String,
    /// The URL query string (at most 1000 characters).
    pub query: String,
    /// RFC 3339 creation time.
    pub created_at: String,
}

/// The person's views on a page, by name.
#[derive(Serialize, ToSchema)]
pub(crate) struct SavedViewList {
    /// The views.
    pub items: Vec<SavedViewView>,
}

/// A view to save.
#[derive(Deserialize, ToSchema)]
pub(crate) struct SaveViewRequest {
    /// The list page, such as `hosts`.
    pub page: String,
    /// 1–60 characters, unique per person and page regardless of case.
    pub name: String,
    /// The URL query string, at most 1000 characters.
    pub query: String,
}

/// The page whose views to list.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct PageQuery {
    /// The list page, such as `hosts`.
    page: String,
}

/// The columns a person hid on a page.
#[derive(Serialize, ToSchema)]
pub(crate) struct ListColumnsView {
    /// Hidden column keys.
    pub hidden: Vec<String>,
}

/// The columns to hide on a page.
#[derive(Deserialize, ToSchema)]
pub(crate) struct ListColumnsRequest {
    /// Column keys, at most 32, none twice; never the page's first column.
    pub hidden: Vec<String>,
}

impl From<store::SavedView> for SavedViewView {
    fn from(v: store::SavedView) -> Self {
        Self {
            id: v.id,
            page: v.page,
            name: v.name,
            query: v.query,
            created_at: v.created_at.to_rfc3339(),
        }
    }
}

fn problem(status: StatusCode, code: &'static str, title: &'static str) -> Response {
    problem_response(ProblemDetails::new(status, code, title))
}

fn page_not_found() -> Response {
    problem(
        StatusCode::NOT_FOUND,
        "list_page_not_found",
        "No such list page",
    )
}

fn invalid(code: &'static str, field: &str, message: &'static str) -> Response {
    let mut p = ProblemDetails::new(StatusCode::UNPROCESSABLE_ENTITY, code, message);
    p.field_errors = Some(vec![FieldError {
        field: field.into(),
        code: "invalid".into(),
        message: message.into(),
    }]);
    problem_response(p)
}

fn bad_request() -> Response {
    problem(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The request is invalid",
    )
}

const UNAUTH: &str = "Authentication required";
const PROBLEM: &str = "application/problem+json";

/// The person's saved views on a page.
#[utoipa::path(get, path = "/api/v1/saved-views", tag = "lists", params(PageQuery),
    responses((status = 200, description = "Views by name", body = SavedViewList),
        (status = 401, description = UNAUTH, body = ProblemDetails, content_type = PROBLEM),
        (status = 404, description = "list_page_not_found", body = ProblemDetails, content_type = PROBLEM)))]
pub(crate) async fn list_views(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Query(PageQuery { page })) = query else {
        return bad_request();
    };
    if !PAGES.contains(&page.as_str()) {
        return page_not_found();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::list(&client, &user.user_id, &page).await {
        Ok(items) => Json(SavedViewList {
            items: items.into_iter().map(Into::into).collect(),
        })
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// Saves a view.
#[utoipa::path(post, path = "/api/v1/saved-views", tag = "lists", request_body = SaveViewRequest,
    responses((status = 201, description = "Saved", body = SavedViewView),
        (status = 401, description = UNAUTH, body = ProblemDetails, content_type = PROBLEM),
        (status = 404, description = "list_page_not_found", body = ProblemDetails, content_type = PROBLEM),
        (status = 409, description = "view_name_taken or too_many_views", body = ProblemDetails, content_type = PROBLEM),
        (status = 422, description = "invalid_saved_view", body = ProblemDetails, content_type = PROBLEM)))]
pub(crate) async fn create_view(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<SaveViewRequest>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    if !PAGES.contains(&request.page.as_str()) {
        return page_not_found();
    }
    let name = request.name.trim();
    if !(1..=60).contains(&name.chars().count()) || name.chars().any(char::is_control) {
        return invalid(
            "invalid_saved_view",
            "name",
            "The name must be 1 to 60 characters",
        );
    }
    if request.query.chars().count() > 1000 || request.query.chars().any(char::is_control) {
        return invalid(
            "invalid_saved_view",
            "query",
            "The view is too long to save",
        );
    }
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let now = Utc::now();
    match store::create(
        &mut client,
        &user.user_id,
        &request.page,
        name,
        &request.query,
        now,
    )
    .await
    {
        Ok(ViewWrite::Saved(view)) => {
            (StatusCode::CREATED, Json(SavedViewView::from(view))).into_response()
        }
        Ok(ViewWrite::NameTaken) => problem(
            StatusCode::CONFLICT,
            "view_name_taken",
            "You already have a view with that name",
        ),
        Ok(ViewWrite::TooMany) => problem(
            StatusCode::CONFLICT,
            "too_many_views",
            "You can keep at most 50 views on this page",
        ),
        Err(_) => unavailable_auth(),
    }
}

/// Deletes one of the person's own views.
#[utoipa::path(delete, path = "/api/v1/saved-views/{id}", tag = "lists",
    params(("id" = String, Path)),
    responses((status = 204, description = "Deleted"),
        (status = 401, description = UNAUTH, body = ProblemDetails, content_type = PROBLEM),
        (status = 404, description = "saved_view_not_found", body = ProblemDetails, content_type = PROBLEM)))]
pub(crate) async fn delete_view(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::delete(&client, &user.user_id, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem(
            StatusCode::NOT_FOUND,
            "saved_view_not_found",
            "No such saved view",
        ),
        Err(_) => unavailable_auth(),
    }
}

/// The columns the person hid on a page.
#[utoipa::path(get, path = "/api/v1/list-columns/{page}", tag = "lists",
    params(("page" = String, Path)),
    responses((status = 200, description = "Hidden columns", body = ListColumnsView),
        (status = 401, description = UNAUTH, body = ProblemDetails, content_type = PROBLEM),
        (status = 404, description = "list_page_not_found", body = ProblemDetails, content_type = PROBLEM)))]
pub(crate) async fn get_columns(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if !PAGES.contains(&page.as_str()) {
        return page_not_found();
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::hidden_columns(&client, &user.user_id, &page).await {
        Ok(hidden) => Json(ListColumnsView { hidden }).into_response(),
        Err(_) => unavailable_auth(),
    }
}

/// Sets the columns the person hides on a page.
#[utoipa::path(put, path = "/api/v1/list-columns/{page}", tag = "lists",
    params(("page" = String, Path)), request_body = ListColumnsRequest,
    responses((status = 200, description = "Saved", body = ListColumnsView),
        (status = 401, description = UNAUTH, body = ProblemDetails, content_type = PROBLEM),
        (status = 404, description = "list_page_not_found", body = ProblemDetails, content_type = PROBLEM),
        (status = 422, description = "invalid_columns", body = ProblemDetails, content_type = PROBLEM)))]
pub(crate) async fn put_columns(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(page): Path<String>,
    payload: Result<Json<ListColumnsRequest>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    if !PAGES.contains(&page.as_str()) {
        return page_not_found();
    }
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let allowed = hideable(&page);
    let hidden = request.hidden;
    if hidden
        .iter()
        .any(|c| c == "host" && !allowed.contains(&"host"))
    {
        return invalid(
            "invalid_columns",
            "hidden",
            "The Host column can't be hidden",
        );
    }
    if hidden.len() > 32
        || hidden.iter().any(|c| !allowed.contains(&c.as_str()))
        || hidden
            .iter()
            .enumerate()
            .any(|(i, c)| hidden[..i].contains(c))
    {
        return invalid("invalid_columns", "hidden", "Unknown or repeated column");
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::set_hidden_columns(&client, &user.user_id, &page, &hidden, Utc::now()).await {
        Ok(()) => Json(ListColumnsView { hidden }).into_response(),
        Err(_) => unavailable_auth(),
    }
}
