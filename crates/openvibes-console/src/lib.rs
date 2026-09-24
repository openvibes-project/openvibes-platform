#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Human-facing OpenVIBES console HTTP skeleton.
//!
//! C0 provides strict route separation and loopback-only development and
//! health listeners. Production authentication, TLS, data access, and
//! production data access remain intentionally unavailable until their
//! implementation milestones. Production frontend assets are included only
//! by the `embedded-ui` feature after their Vite output has been validated.

mod api;
#[cfg(feature = "embedded-ui")]
mod assets;
mod auth;
mod config;
mod error;
#[cfg(feature = "embedded-ui")]
mod frontend_contract;
mod openapi;
mod problem;
mod router;
#[cfg(feature = "dev-seed")]
mod seeded;
mod server;

pub use api::{
    AgentDetail, AgentPage, AgentStatus, AgentSummary, AgentView, AuthenticationLevel,
    AuthenticationMethod, CertificatePage, CertificateView, CursorPage, CursorPagination,
    DEFAULT_PAGE_SIZE, EffectiveCapability, FindingHistoryEntry, FindingHistoryPage, FindingOrigin,
    FindingPage, FindingSummary, FindingView, MAX_CURSOR_LENGTH, MAX_PAGE_SIZE, PaginationError,
    Permission, PermissionScope, SessionPrincipal, SessionResponse, Severity,
};
pub use auth::{SessionSecret, browser_origin_allowed, session_cookie};
pub use config::{ConsoleConfig, load_config};
pub use error::ConsoleError;
pub use openapi::{document as console_openapi, json as openapi_json};
pub use problem::{FieldError, ProblemDetails};
pub use router::{Readiness, development_router, health_router, public_router};
pub use server::{run, serve};
