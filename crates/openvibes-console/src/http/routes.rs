//! The route table: merges every area's `routes()`, with the About and auth
//! routes and the API fallbacks.

use axum::{Router, http::StatusCode, response::Response, routing::get};

use super::{
    AuthHttpState,
    problem::{ProblemDetails, problem_response},
};
use crate::access::{
    login::{login, logout, preauth},
    session::session,
};
use crate::{
    about, access, alarms, assistant, audit, cases, compliance, dashboards, hosts, rules,
    vulnerabilities,
};

pub(super) fn api_router() -> Router {
    Router::new()
        .route("/v1/session", get(session))
        .method_not_allowed_fallback(api_method_not_allowed)
        .fallback(api_not_found)
}

/// Every area's routes, plus the About page's two.
pub(super) fn authenticated_api_router() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/about", get(about::about))
        .route("/v1/about/update", get(about::about_update))
        .merge(access::routes())
        .merge(assistant::routes())
        .merge(hosts::routes())
        .merge(compliance::routes())
        .merge(alarms::routes())
        .merge(vulnerabilities::routes())
        .merge(audit::routes())
        .merge(rules::routes())
        .merge(dashboards::routes())
        .merge(cases::routes())
        .method_not_allowed_fallback(api_method_not_allowed)
        .fallback(api_not_found)
}

pub(super) fn authenticated_auth_router() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/preauth", get(preauth))
        .route("/v1/login", axum::routing::post(login))
        .route("/v1/logout", axum::routing::post(logout))
        .fallback(auth_not_found)
}

async fn api_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "api_not_found",
        "API resource not found",
    ))
}

async fn api_method_not_allowed() -> Response {
    problem_response(ProblemDetails::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method not allowed for this API resource",
    ))
}

pub(super) async fn auth_not_found() -> Response {
    problem_response(ProblemDetails::not_found(
        "auth_not_found",
        "Authentication resource not found",
    ))
}
