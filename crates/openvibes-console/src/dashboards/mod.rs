//! Dashboards and the count history behind their widgets. Browser sessions
//! only: a bearer token is refused.

use axum::{
    Router,
    routing::{get, put},
};

use crate::http::AuthHttpState;

pub(crate) mod dashboard;
pub(crate) mod home;
mod layout;
pub(crate) mod metrics;
mod responses;
mod types;

pub use types::{
    DashboardPage, DashboardRole, DashboardView, HomeDashboard, SaveDashboardRequest,
    ShareDashboardRequest,
};

/// Dashboards, their sharing, the user's home dashboard, and the count
/// history and top hosts behind the widgets.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route(
            "/v1/dashboards",
            get(dashboard::list_dashboards).post(dashboard::create_dashboard),
        )
        .route(
            "/v1/dashboards/{dashboard_id}",
            get(dashboard::get_dashboard)
                .put(dashboard::update_dashboard)
                .delete(dashboard::delete_dashboard),
        )
        .route(
            "/v1/dashboards/{dashboard_id}/sharing",
            put(dashboard::share_dashboard),
        )
        .route("/v1/me/home", get(home::get_home).put(home::set_home))
        .route("/v1/metrics/history", get(metrics::history))
        .route("/v1/metrics/top-hosts", get(metrics::top_hosts))
}
