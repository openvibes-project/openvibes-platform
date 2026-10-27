//! The Software list and a package's page (design in
//! `docs/specs/2026-10-16-roles-permissions-design.md` §10.3, step 5g).
//! Everything needs `hosts.read` and is scoped to the caller's hosts. The
//! older `GET /v1/software` routes stay with `hosts/` for the API and the
//! assistant.

use axum::{Router, routing::get};

use crate::http::AuthHttpState;

pub(crate) mod list_page;
pub(crate) mod list_page_types;
pub(crate) mod page;
pub(crate) mod page_types;

/// The Software list and a package's page.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/software-list", get(list_page::list_software_page))
        .route(
            "/v1/software-pages/{name}/summary",
            get(page::software_summary_page),
        )
        .route(
            "/v1/software-pages/{name}/hosts",
            get(page::software_hosts_page_route),
        )
}
