#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The only crate that touches PostgreSQL: connection pool, schema
//! migrations, and every query the platform runs.

/// Agent listing, inspection, and revocation.
pub mod agents;
/// Alarm suppressions (P14) as the console manages them.
pub mod alarm_suppressions;
/// Threat alarms (P14): insert with suppression.
pub mod alarms;
/// Read-only, scoped lookups for the console's assistant.
pub mod assistant;
/// The append-only audit log.
pub mod audit;
/// CA certificates the platform issues under.
pub mod ca;
/// Console reads and triage of threat alarms (P14).
pub mod console_alarms;
/// Local console credentials, throttles, pre-authentication, and sessions.
pub mod console_auth;
/// Cases: investigations with items, notes and a timeline (schema 35).
pub mod console_cases;
/// Console reads of installed software: host packages and fleet software.
pub mod console_inventory;
/// Bounded global read models for the human console.
pub mod console_read;
/// Versioned analyst workflow state and history for current findings.
pub mod console_triage;
/// CPE matching: NVD applicability ranges and lower-confidence findings (schema 39).
pub mod cpe;
/// User dashboards: layouts, sharing by role, home (schema 26).
pub mod dashboards;
/// CVE enrichment: KEV and EPSS (vulnerability management).
pub mod enrichment;
pub mod finding_changes;
/// Host package inventories (vulnerability management).
pub mod health;
/// Open ports and running services per host (P15, Assets v2).
pub mod host_services;
/// Queries the ingest service runs.
pub mod imports;
pub mod ingest;
pub mod inventory;
mod maintenance;
mod migrate;
/// Rule sets, trust keys, and published bundles.
pub mod rules;
pub mod signer;
mod status;
/// Enrollment tokens (stored only as hashes).
pub mod tokens;
/// Advisories, vulnerabilities, and feed state (vulnerability management).
pub mod vulns;
pub mod wire;

use std::{fmt, str::FromStr, time::Duration};

use deadpool_postgres::Manager;
use tokio_postgres::NoTls;

/// Pooled connection and pool types, so callers need no pool dependency.
pub use deadpool_postgres::{Client, Pool};
pub use maintenance::{
    drop_partitions_before, ensure_partitions, partition_days, partition_days_of,
};
pub use migrate::{
    NEEDS_BACKUP, SCHEMA_VERSION, migrate, migrate_additive, needs_backup_after, schema_version,
};
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
    /// A pending migration changes stored data: it runs only through
    /// Update, which backs up first (board #77).
    NeedsBackup(i32),
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
            Self::NeedsBackup(version) => write!(
                f,
                "this upgrade changes stored data (migration {version}): run `openvibes-admin` \
                 → Update (or `sudo openvibes-admin setup --update`), which backs up first"
            ),
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
