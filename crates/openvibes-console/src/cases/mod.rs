//! Cases over `/api/v1`: where one investigation happens (design in
//! `docs/specs/2026-10-04-console-cases-design.md`). Reads need
//! `cases.read`, changes `cases.write` (the assignee `cases.assign`); all are
//! scoped to the caller's agents, and a case the caller cannot see reads as absent. Browser
//! sessions only: a bearer token is refused, as for dashboards.

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::http::AuthHttpState;

pub(crate) mod items;
pub(crate) mod list;
pub(crate) mod list_page;
pub(crate) mod list_page_types;
pub(crate) mod lookups;
mod permissions;
mod request;
mod responses;
mod types;
mod views;

pub(crate) use permissions::authorize;

pub use types::{
    ActiveCaseItem, ActiveCaseItemsView, AddCaseNoteRequest, CaseAssigneesView, CaseDetailView,
    CaseEventView, CaseItemRef, CaseItemView, CasePage, CaseSummaryView, CaseUserView,
    CreateCaseRequest, ItemCaseView, ItemCasesView, SetCaseItemOutcomeRequest, UpdateCaseRequest,
};

/// Cases, their notes and items, and the lookups the case views use.
pub(crate) fn routes() -> Router<AuthHttpState> {
    Router::new()
        .route("/v1/cases", get(list::list_cases).post(list::create_case))
        .route("/v1/case-list", get(list_page::list_case_page))
        .route("/v1/cases/for-item", get(items::cases_for_item))
        .route("/v1/cases/assignees", get(lookups::list_assignees))
        .route("/v1/cases/active-items", get(lookups::active_items))
        .route(
            "/v1/cases/{case_id}",
            get(list::get_case).put(list::update_case),
        )
        .route("/v1/cases/{case_id}/notes", post(items::add_note))
        .route("/v1/cases/{case_id}/items", post(items::add_item))
        .route(
            "/v1/cases/{case_id}/items/{item_id}",
            delete(items::remove_item),
        )
        .route(
            "/v1/cases/{case_id}/items/{item_id}/outcome",
            put(items::set_item_outcome),
        )
}
