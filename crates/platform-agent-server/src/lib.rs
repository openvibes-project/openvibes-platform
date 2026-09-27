#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The agent-facing server shared by ingest and distribution: TLS 1.3 with
//! expiry-tolerant mTLS, agent authentication, load controls, request logs,
//! health, and the accept loop with drain.

mod auth;
mod error;
mod health;
mod limits;
mod request;
mod serve;
mod stall;
mod tls;

pub use auth::AuthenticatedAgent;
pub use error::{ApiError, ServerError};
pub use request::{
    INVENTORY_PATHS, MAX_BODY_BYTES, MAX_INVENTORY_BYTES, body_limit, decoded_body, parse,
    parse_with_limit,
};
pub use serve::{Settings, run};
pub use tls::read_pem;
