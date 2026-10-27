//! Saved views and hidden columns of the list pages (roles spec §10).

use axum::{
    Router,
    routing::{delete, get},
};

use crate::http::AuthHttpState;

pub(crate) mod saved_views;

/// The list pages that keep saved views and columns.
pub(crate) const PAGES: &[&str] = &[
    "hosts",
    "alarms",
    "vulnerabilities",
    "compliance",
    "cases",
    "ports",
    "services",
];

/// The column keys a person may hide on a page; the first column of every
/// page (`host`; alarms: `severity`; vulnerabilities: `severity` and
/// `advisory`; compliance: `severity` and `check`; cases: `case` and
/// `title`; ports: `port`; services: `service`) is never in the list.
pub(crate) fn hideable(page: &str) -> &'static [&'static str] {
    match page {
        "hosts" => &["os", "groups", "labels", "problems", "heartbeat", "agent"],
        "alarms" => &[
            "alarm", "host", "count", "seen", "state", "assignee", "case",
        ],
        "vulnerabilities" => &["package", "cvss", "epss", "hosts", "due", "assignee"],
        "compliance" => &["area", "failing", "hosts", "since", "assignee"],
        "cases" => &[
            "severity", "status", "assignee", "hosts", "items", "updated",
        ],
        "ports" => &["hosts", "exposed", "services", "groups", "week", "look"],
        "services" => &["hosts", "runs_as", "ports", "package", "week", "look"],
        _ => &[],
    }
}

/// The saved-view and list-column paths.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route(
            "/v1/saved-views",
            get(saved_views::list_views).post(saved_views::create_view),
        )
        .route("/v1/saved-views/{id}", delete(saved_views::delete_view))
        .route(
            "/v1/list-columns/{page}",
            get(saved_views::get_columns).put(saved_views::put_columns),
        )
}
