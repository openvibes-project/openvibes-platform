#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Human-facing OpenVIBES console HTTP skeleton.
//!
//! C0 provides strict route separation and loopback-only development and
//! health listeners. Production authentication, TLS, data access, and
//! production data access remain intentionally unavailable until their
//! implementation milestones. Production frontend assets are included only
//! by the `embedded-ui` feature after their Vite output has been validated.

#[cfg(feature = "embedded-ui")]
mod assets;
mod config;
mod error;
mod problem;
#[cfg(feature = "embedded-ui")]
mod public_assets;
mod router;
mod server;

pub use config::{ConsoleConfig, load_config};
pub use error::ConsoleError;
pub use problem::ProblemDetails;
pub use router::{Readiness, health_router, public_router};
pub use server::{run, serve};
