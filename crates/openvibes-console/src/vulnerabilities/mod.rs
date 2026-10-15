//! Vulnerabilities: the summary, the list and advisory detail.

pub(crate) mod advisory;
mod cpe;
pub(crate) mod list;
pub(crate) mod summary;
mod types;

pub use types::{
    CveDetailView, VulnerabilityAdvisoryDetail, VulnerabilityPage, VulnerabilitySeverity,
    VulnerabilitySeverityCount, VulnerabilitySummary, VulnerabilityTopHost, VulnerabilityView,
};
