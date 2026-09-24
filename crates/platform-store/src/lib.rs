#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The only crate that touches PostgreSQL: connection pool, schema
//! migrations, and every query the platform runs.

/// Agent listing, inspection, and revocation.
pub mod agents;
/// The append-only audit log.
pub mod audit;
/// CA certificates the platform issues under.
pub mod ca;
/// Queries the ingest service runs.
pub mod ingest;
mod maintenance;
mod migrate;
mod status;
/// Enrollment tokens (stored only as hashes).
pub mod tokens;

use std::{fmt, str::FromStr, time::Duration};

use deadpool_postgres::Manager;
use tokio_postgres::NoTls;

/// Pooled connection and pool types, so callers need no pool dependency.
pub use deadpool_postgres::{Client, Pool};
pub use maintenance::{drop_partitions_before, ensure_partitions, partition_days};
pub use migrate::{SCHEMA_VERSION, migrate, schema_version};
pub use status::{OFFLINE_AFTER_MINUTES, Status, status};

/// Fixed failure categories; no SQL, parameters, or connection strings are
/// ever included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// The database could not be reached or the pool is exhausted.
    Unavailable,
    /// The database was migrated by a newer platform; refuse to touch it.
    NewerSchema(i32),
    /// A statement failed.
    Query,
    /// The configured database URL does not parse.
    InvalidUrl,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("database unavailable"),
            Self::NewerSchema(version) => {
                write!(f, "database schema {version} is newer than this platform")
            }
            Self::Query => f.write_str("database query failed"),
            Self::InvalidUrl => f.write_str("invalid database_url"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<tokio_postgres::Error> for StoreError {
    fn from(error: tokio_postgres::Error) -> Self {
        // A server-side error carries an SQLSTATE; anything else is the
        // connection itself.
        if error.code().is_some() {
            Self::Query
        } else {
            Self::Unavailable
        }
    }
}

impl From<deadpool_postgres::PoolError> for StoreError {
    fn from(_: deadpool_postgres::PoolError) -> Self {
        Self::Unavailable
    }
}

/// Default connections per process.
const POOL_SIZE: usize = 16;

/// Longest wait for a pooled connection, a new connection, or a recycle.
const POOL_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest time one statement may run; a stuck query or lock wait fails
/// instead of hanging a request.
const STATEMENT_TIMEOUT_MS: u64 = 10_000;

/// A connection pool of 16 for `url`; see [`connect_sized`].
pub async fn connect(url: &str) -> Result<Pool, StoreError> {
    connect_sized(url, POOL_SIZE).await
}

/// A connection pool of `size` for `url` (libpq key/value or URL form).
/// Connections open lazily. Waiting for a connection, connecting, and
/// recycling are bounded to 5 seconds, and every statement to 10 seconds,
/// so a hung database yields errors, not hangs.
pub async fn connect_sized(url: &str, size: usize) -> Result<Pool, StoreError> {
    let mut config = tokio_postgres::Config::from_str(url).map_err(|_| StoreError::InvalidUrl)?;
    config
        .connect_timeout(POOL_TIMEOUT)
        .options(format!("-c statement_timeout={STATEMENT_TIMEOUT_MS}"));
    Pool::builder(Manager::new(config, NoTls))
        .max_size(size.max(1))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .wait_timeout(Some(POOL_TIMEOUT))
        .create_timeout(Some(POOL_TIMEOUT))
        .recycle_timeout(Some(POOL_TIMEOUT))
        .build()
        .map_err(|_| StoreError::Unavailable)
}
