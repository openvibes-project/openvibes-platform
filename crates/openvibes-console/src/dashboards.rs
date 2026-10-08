//! Dashboards over `/api/v1`: layout validation (here) and the HTTP
//! handlers. A layout is data the UI renders; the server keeps it bounded
//! and well-formed, and forward-compatible through an allow-list of types.

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{SecondsFormat, Utc};
use platform_store::dashboards::{self as store, Dashboard, Refusal};

use serde_json::Value;

use crate::{
    DashboardPage, DashboardView, FieldError, HomeDashboard, Permission, PermissionScope,
    ProblemDetails, SaveDashboardRequest, ShareDashboardRequest,
    problem::problem_response,
    router::{AuthHttpState, parse_if_match_version, session_user, unavailable_auth},
};

pub(crate) const WIDGET_TYPES: [&str; 8] = [
    "number",
    "breakdown",
    "attention",
    "list",
    "trend",
    "top-hosts",
    "note",
    "graph",
];
const MAX_LAYOUT_BYTES: usize = 65_536;
const MAX_WIDGETS: usize = 40;
const MAX_ERRORS: usize = 32;

fn error(field: String, code: &str, message: &str) -> FieldError {
    FieldError {
        field,
        code: code.to_owned(),
        message: message.to_owned(),
    }
}

pub(crate) fn validate_name(raw: &str) -> Result<String, FieldError> {
    let name = raw.trim();
    let count = name.chars().count();
    if count == 0 || count > 80 || name.chars().any(char::is_control) {
        return Err(error(
            "name".into(),
            "invalid_name",
            "Use 1 to 80 characters, without control characters",
        ));
    }
    Ok(name.to_owned())
}

fn int(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

fn valid_config_value(value: &Value) -> bool {
    match value {
        Value::String(text) => text.chars().count() <= 256,
        Value::Bool(_) => true,
        Value::Number(number) => number.is_i64(),
        Value::Array(items) => {
            items.len() <= 16
                && items.iter().all(|item| {
                    item.as_str()
                        .is_some_and(|text| text.chars().count() <= 256)
                })
        }
        _ => false,
    }
}

pub(crate) fn validate_layout(layout: &Value) -> Result<(), Vec<FieldError>> {
    let Some(object) = layout.as_object() else {
        return Err(vec![error(
            "layout".into(),
            "invalid_layout",
            "The layout must be an object",
        )]);
    };
    if serde_json::to_vec(layout).map_or(true, |bytes| bytes.len() > MAX_LAYOUT_BYTES) {
        return Err(vec![error(
            "layout".into(),
            "layout_too_large",
            "The layout exceeds 64 KiB",
        )]);
    }
    let mut errors = Vec::new();
    if object.get("schema").and_then(Value::as_i64) != Some(1) {
        errors.push(error(
            "layout.schema".into(),
            "unsupported_schema",
            "Layout schema must be 1",
        ));
    }
    let Some(widgets) = object.get("widgets").and_then(Value::as_array) else {
        errors.push(error(
            "layout.widgets".into(),
            "invalid_widgets",
            "widgets must be an array",
        ));
        return Err(errors);
    };
    if widgets.len() > MAX_WIDGETS {
        errors.push(error(
            "layout.widgets".into(),
            "too_many_widgets",
            "A dashboard holds at most 40 widgets",
        ));
        return Err(errors);
    }
    let mut seen = std::collections::HashSet::new();
    for (index, widget) in widgets.iter().enumerate() {
        let at = |field: &str| format!("layout.widgets[{index}].{field}");
        let Some(widget) = widget.as_object() else {
            errors.push(error(
                format!("layout.widgets[{index}]"),
                "invalid_widget",
                "A widget must be an object",
            ));
            continue;
        };
        let kind = widget.get("type").and_then(Value::as_str);
        if !kind.is_some_and(|kind| WIDGET_TYPES.contains(&kind)) {
            errors.push(error(
                at("type"),
                "unknown_widget_type",
                "Unknown widget type",
            ));
        }
        let id = widget.get("id").and_then(Value::as_str).unwrap_or_default();
        let id_ok = (1..=32).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !id_ok || !seen.insert(id.to_owned()) {
            errors.push(error(
                at("id"),
                "invalid_widget_id",
                "Widget ids are 1-32 of a-z, 0-9 and -, unique",
            ));
        }
        let (x, y, w, h) = (
            int(widget.get("x")),
            int(widget.get("y")),
            int(widget.get("w")),
            int(widget.get("h")),
        );
        let w_ok = w.is_some_and(|w| (1..=12).contains(&w));
        if !x.is_some_and(|x| (0..=11).contains(&x))
            || (w_ok && x.zip(w).is_some_and(|(x, w)| x + w > 12))
        {
            errors.push(error(
                at("x"),
                "invalid_position",
                "x must be 0-11 and x + w at most 12",
            ));
        }
        if !w_ok {
            errors.push(error(at("w"), "invalid_size", "w must be 1-12"));
        }
        if !y.is_some_and(|y| (0..=199).contains(&y)) {
            errors.push(error(at("y"), "invalid_position", "y must be 0-199"));
        }
        if !h.is_some_and(|h| (1..=12).contains(&h)) {
            errors.push(error(at("h"), "invalid_size", "h must be 1-12"));
        }
        match widget.get("config").and_then(Value::as_object) {
            None => errors.push(error(
                at("config"),
                "invalid_config",
                "config must be an object",
            )),
            Some(config) if config.len() > 16 => errors.push(error(
                at("config"),
                "invalid_config",
                "config holds at most 16 keys",
            )),
            Some(config) => {
                for (key, value) in config {
                    if key.len() > 32 || !valid_config_value(value) {
                        errors.push(error(
                            at(&format!("config.{key}")),
                            "invalid_config",
                            "Config values are short strings, integers, booleans or string lists",
                        ));
                    }
                }
            }
        }
    }
    errors.truncate(MAX_ERRORS);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn view(dashboard: Dashboard, user_id: &str) -> DashboardView {
    DashboardView {
        mine: dashboard.owner_user_id == user_id,
        dashboard_id: dashboard.dashboard_id,
        name: dashboard.name,
        owner_display_name: dashboard.owner_display_name,
        shared_role_id: dashboard.shared_role_id,
        version: dashboard.version.try_into().unwrap_or_default(),
        layout: dashboard.layout,
        created_at: dashboard
            .created_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
        updated_at: dashboard
            .updated_at
            .to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn with_etag(status: StatusCode, dashboard: DashboardView) -> Response {
    let etag = format!("\"{}\"", dashboard.version);
    let mut response = (status, Json(dashboard)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    response
}

fn refused(refusal: Refusal) -> Response {
    problem_response(match refusal {
        Refusal::NotFound => {
            ProblemDetails::not_found("dashboard_not_found", "Dashboard not found")
        }
        Refusal::NotOwner => ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "not_dashboard_owner",
            "Only the owner can change this dashboard; duplicate it instead",
        ),
        Refusal::Stale => ProblemDetails::new(
            StatusCode::PRECONDITION_FAILED,
            "stale_dashboard",
            "The dashboard changed since you loaded it",
        ),
        Refusal::TooMany => ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "too_many_dashboards",
            "You already have 100 dashboards",
        ),
        Refusal::UnknownRole => ProblemDetails::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown_role",
            "No such role",
        ),
    })
}

fn invalid(errors: Vec<crate::FieldError>) -> Response {
    let mut problem = ProblemDetails::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid_dashboard",
        "The dashboard is invalid",
    );
    problem.field_errors = Some(errors);
    problem_response(problem)
}

fn bad_request() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "The request body is invalid",
    ))
}

/// Validates name and layout; the trimmed name, or every field problem.
fn checked(request: &SaveDashboardRequest) -> Result<String, Vec<crate::FieldError>> {
    let name = validate_name(&request.name);
    let layout = validate_layout(&request.layout);
    match (name, layout) {
        (Ok(name), Ok(())) => Ok(name),
        (name, layout) => {
            let mut errors: Vec<_> = name.err().into_iter().collect();
            errors.extend(layout.err().unwrap_or_default());
            errors.truncate(32);
            Err(errors)
        }
    }
}

#[utoipa::path(get, path = "/api/v1/dashboards", tag = "dashboards",
    responses((status = 200, description = "Own and shared dashboards", body = crate::DashboardPage), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn list_dashboards(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::list_visible(&client, &user.user_id).await {
        Ok(items) => Json(DashboardPage {
            items: items.into_iter().map(|d| view(d, &user.user_id)).collect(),
        })
        .into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(post, path = "/api/v1/dashboards", tag = "dashboards", request_body = crate::SaveDashboardRequest,
    responses((status = 201, description = "Created", body = crate::DashboardView), (status = 400, description = "Invalid body", body = ProblemDetails, content_type = "application/problem+json"), (status = 422, description = "Invalid name or layout, or 100 dashboards already", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn create_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<SaveDashboardRequest>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let name = match checked(&request) {
        Ok(name) => name,
        Err(errors) => return invalid(errors),
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::create(
        &mut client,
        &user.user_id,
        &name,
        &request.layout,
        Utc::now(),
    )
    .await
    {
        Ok(Ok(dashboard)) => with_etag(StatusCode::CREATED, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/dashboards/{dashboard_id}", tag = "dashboards", params(("dashboard_id" = String, Path)),
    responses((status = 200, description = "The dashboard", body = crate::DashboardView), (status = 404, description = "Not found or not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::get_visible(&client, &user.user_id, &id).await {
        Ok(Some(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(None) => refused(Refusal::NotFound),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/dashboards/{dashboard_id}", tag = "dashboards", params(("dashboard_id" = String, Path), ("If-Match" = String, Header, description = "Quoted version from ETag")), request_body = crate::SaveDashboardRequest,
    responses((status = 200, description = "Saved", body = crate::DashboardView), (status = 400, description = "Invalid body or If-Match", body = ProblemDetails, content_type = "application/problem+json"), (status = 404, description = "Not found or not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 412, description = "Stale version", body = ProblemDetails, content_type = "application/problem+json"), (status = 422, description = "Invalid name or layout", body = ProblemDetails, content_type = "application/problem+json"), (status = 428, description = "If-Match is required", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn update_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<SaveDashboardRequest>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let expected = match parse_if_match_version(&headers) {
        Ok(Some(version)) => version,
        Ok(None) => {
            return problem_response(ProblemDetails::new(
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "If-Match is required",
            ));
        }
        Err(()) => {
            return problem_response(ProblemDetails::new(
                StatusCode::BAD_REQUEST,
                "invalid_precondition",
                "If-Match must contain one quoted version",
            ));
        }
    };
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let name = match checked(&request) {
        Ok(name) => name,
        Err(errors) => return invalid(errors),
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::update(
        &mut client,
        &user.user_id,
        &id,
        &name,
        &request.layout,
        expected,
        Utc::now(),
    )
    .await
    {
        Ok(Ok(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(delete, path = "/api/v1/dashboards/{dashboard_id}", tag = "dashboards", params(("dashboard_id" = String, Path)),
    responses((status = 204, description = "Deleted"), (status = 404, description = "Not found or not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn delete_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::delete(&mut client, &user.user_id, &id).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/dashboards/{dashboard_id}/sharing", tag = "dashboards", params(("dashboard_id" = String, Path)), request_body = crate::ShareDashboardRequest,
    responses((status = 200, description = "Sharing changed", body = crate::DashboardView), (status = 404, description = "Not found or not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 422, description = "Unknown role", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn share_dashboard(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    payload: Result<Json<ShareDashboardRequest>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let may_share = user
        .capabilities
        .iter()
        .any(|c| c.permission == Permission::DashboardsShare && c.scope == PermissionScope::Global);
    if !may_share {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::set_sharing(
        &mut client,
        &user.user_id,
        &id,
        request.role_id.as_deref(),
        Utc::now(),
    )
    .await
    {
        Ok(Ok(dashboard)) => with_etag(StatusCode::OK, view(dashboard, &user.user_id)),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(get, path = "/api/v1/me/home", tag = "dashboards",
    responses((status = 200, description = "Home dashboard, or null for the built-in", body = crate::HomeDashboard), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn get_home(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    let user = match session_user(&state, &headers, false).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::home(&client, &user.user_id).await {
        Ok(dashboard_id) => Json(HomeDashboard { dashboard_id }).into_response(),
        Err(_) => unavailable_auth(),
    }
}

#[utoipa::path(put, path = "/api/v1/me/home", tag = "dashboards", request_body = crate::HomeDashboard,
    responses((status = 200, description = "Home changed", body = crate::HomeDashboard), (status = 404, description = "Dashboard not visible", body = ProblemDetails, content_type = "application/problem+json"), (status = 401, description = "Authentication required", body = ProblemDetails, content_type = "application/problem+json"), (status = 403, description = "Bearer tokens and missing permissions are refused", body = ProblemDetails, content_type = "application/problem+json"), (status = 503, description = "Unavailable", body = ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn set_home(
    State(state): State<AuthHttpState>,
    headers: HeaderMap,
    payload: Result<Json<HomeDashboard>, JsonRejection>,
) -> Response {
    let user = match session_user(&state, &headers, true).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Json(request)) = payload else {
        return bad_request();
    };
    let Ok(mut client) = state.pool.get().await else {
        return unavailable_auth();
    };
    match store::set_home(&mut client, &user.user_id, request.dashboard_id.as_deref()).await {
        Ok(Ok(())) => Json(request).into_response(),
        Ok(Err(refusal)) => refused(refusal),
        Err(_) => unavailable_auth(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{validate_layout, validate_name};

    fn widget(id: &str, kind: &str, x: i64, w: i64) -> serde_json::Value {
        json!({"id": id, "type": kind, "x": x, "y": 0, "w": w, "h": 2, "config": {"metric": "agents.active"}})
    }

    fn fields(layout: serde_json::Value) -> Vec<String> {
        validate_layout(&layout)
            .unwrap_err()
            .into_iter()
            .map(|error| error.field)
            .collect()
    }

    #[test]
    fn a_small_valid_layout_passes() {
        assert!(validate_layout(&json!({"schema": 1, "widgets": [widget("w1", "number", 0, 3), widget("w2", "note", 3, 9)]})).is_ok());
        assert!(validate_layout(&json!({"schema": 1, "widgets": []})).is_ok());
    }

    #[test]
    fn a_graph_widget_with_several_counts_passes() {
        let layout = json!({"schema": 1, "widgets": [{"id": "g", "type": "graph", "x": 0, "y": 0, "w": 6, "h": 4, "config": {"metrics": ["alarms.active", "vulns.exploited"], "days": 30}}]});
        assert!(validate_layout(&layout).is_ok());
    }

    #[test]
    fn layout_must_be_an_object() {
        assert_eq!(fields(json!([1, 2])), ["layout"]);
        assert_eq!(fields(json!(7)), ["layout"]);
    }

    #[test]
    fn schema_widget_count_and_size_are_bounded() {
        assert_eq!(
            fields(json!({"schema": 2, "widgets": []})),
            ["layout.schema"]
        );
        let many: Vec<_> = (0..41)
            .map(|i| widget(&format!("w{i}"), "number", 0, 1))
            .collect();
        assert_eq!(
            fields(json!({"schema": 1, "widgets": many})),
            ["layout.widgets"]
        );
        let long = "x".repeat(256);
        let heavy: Vec<_> = (0..40)
            .map(|i| {
                json!({"id": format!("w{i}"), "type": "note", "x": 0, "y": 0, "w": 1, "h": 1,
            "config": {"text": vec![long.clone(); 7]}})
            })
            .collect();
        assert_eq!(fields(json!({"schema": 1, "widgets": heavy})), ["layout"]);
    }

    #[test]
    fn each_widget_is_checked_with_a_precise_path() {
        let layout = json!({"schema": 1, "widgets": [
            widget("w1", "pie-chart", 0, 3),
            widget("w1", "number", 10, 3),
            widget("Bad Id", "number", 0, 13),
            {"id": "w4", "type": "number", "x": 0, "y": 200, "w": 1, "h": 13, "config": {}},
            {"id": "w5", "type": "number", "x": 0, "y": 0, "w": 1, "h": 1, "config": {"nested": {"a": 1}}},
        ]});
        assert_eq!(
            fields(layout),
            [
                "layout.widgets[0].type",
                "layout.widgets[1].id",
                "layout.widgets[1].x",
                "layout.widgets[2].id",
                "layout.widgets[2].w",
                "layout.widgets[3].y",
                "layout.widgets[3].h",
                "layout.widgets[4].config.nested",
            ]
        );
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(validate_name("  Morning  ").unwrap(), "Morning");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"n".repeat(81)).is_err());
        assert!(validate_name("tab\there").is_err());
        assert_eq!(validate_name(&"é".repeat(80)).unwrap().chars().count(), 80);
    }
}
