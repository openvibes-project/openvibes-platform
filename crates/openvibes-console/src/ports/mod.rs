//! Ports over `/api/v1`: the Ports list and a port's page (design in
//! `docs/specs/2026-10-16-roles-permissions-design.md` §10.3, step 5e).
//! Everything needs `hosts.read` and is scoped to the caller's hosts. The
//! older `GET /v1/ports` routes stay with `hosts/` for the API and the
//! assistant.

use axum::{Router, routing::get};

use crate::http::AuthHttpState;

pub(crate) mod list_page;
pub(crate) mod list_page_types;
pub(crate) mod page;
pub(crate) mod page_types;

/// The Ports list and a port's page.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/port-list", get(list_page::list_port_page))
        .route(
            "/v1/ports/{protocol}/{port}/summary",
            get(page::port_summary_page),
        )
        .route(
            "/v1/ports/{protocol}/{port}/hosts",
            get(page::port_hosts_page_route),
        )
}
