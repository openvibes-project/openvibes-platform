//! Dashboards and the count history behind their widgets. Browser sessions
//! only: a bearer token is refused.

mod answers;
pub(crate) mod dashboard;
pub(crate) mod home;
mod layout;
pub(crate) mod metrics;
mod types;

pub use types::{
    DashboardPage, DashboardView, HomeDashboard, SaveDashboardRequest, ShareDashboardRequest,
};
