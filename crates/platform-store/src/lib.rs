#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The only crate that touches PostgreSQL: connection pool, schema
//! migrations, and every query the platform runs.

mod migrate;

use std::{fmt, str::FromStr};

use deadpool_postgres::{Manager, Pool};
use tokio_postgres::NoTls;

pub use migrate::{SCHEMA_VERSION, migrate, schema_version};

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
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("database unavailable"),
            Self::NewerSchema(version) => {
                write!(f, "database schema {version} is newer than this platform")
            }
            Self::Query => f.write_str("database query failed"),
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

/// Maximum connections per process.
const POOL_SIZE: usize = 16;

/// A connection pool for `url` (libpq key/value or URL form). Connections
/// open lazily, so an unreachable server surfaces on first use.
pub async fn connect(url: &str) -> Result<Pool, StoreError> {
    let config = tokio_postgres::Config::from_str(url).map_err(|_| StoreError::Unavailable)?;
    Pool::builder(Manager::new(config, NoTls))
        .max_size(POOL_SIZE)
        .build()
        .map_err(|_| StoreError::Unavailable)
}
