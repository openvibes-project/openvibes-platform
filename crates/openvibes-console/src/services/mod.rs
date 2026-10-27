//! Services over `/api/v1`: the Services list and a service's page (design
//! in `docs/specs/2026-10-16-roles-permissions-design.md` §10.3, step 5f).
//! Everything needs `hosts.read` and is scoped to the caller's hosts. The
//! older `GET /v1/services` routes stay with `hosts/` for the API and the
//! assistant.

use axum::{Router, routing::get};

use crate::http::AuthHttpState;

pub(crate) mod list_page;
pub(crate) mod list_page_types;
pub(crate) mod page;
pub(crate) mod page_types;

/// The Services list and a service's page.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/service-list", get(list_page::list_service_page))
        .route(
            "/v1/services/{unit}/summary",
            get(page::service_summary_page),
        )
        .route(
            "/v1/services/{unit}/hosts",
            get(page::service_hosts_page_route),
        )
}
