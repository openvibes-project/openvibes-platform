//! Cases over `/api/v1`: where one investigation happens (design in
//! `docs/specs/2026-10-04-console-cases-design.md`). Reads need
//! `cases.read`, changes `cases.manage`; both are scoped to the caller's
//! agents, and a case the caller cannot see reads as absent. Browser
//! sessions only: a bearer token is refused, as for dashboards.

mod answers;
pub(crate) mod items;
pub(crate) mod list;
pub(crate) mod lookups;
mod permissions;
mod request;
mod types;
mod views;

pub(crate) use permissions::authorize;

pub use types::{
    ActiveCaseItem, ActiveCaseItemsView, AddCaseNoteRequest, CaseAssigneesView, CaseDetailView,
    CaseEventView, CaseItemRef, CaseItemView, CasePage, CaseSummaryView, CaseUserView,
    CreateCaseRequest, ItemCaseView, ItemCasesView, SetCaseItemOutcomeRequest, UpdateCaseRequest,
};
