#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The agent-facing ingest service: enrollment, renewal, heartbeats, and
//! finding delivery over TLS 1.3 with per-request mTLS authentication.

mod auth;
mod config;
mod delivery;
mod enroll;
mod error;
mod health;
mod request;
mod server;
mod tls;

pub use config::{IngestConfig, load_config};
pub use error::IngestError;
pub use server::{run, serve};
