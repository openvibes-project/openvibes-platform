#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The only crate that touches PostgreSQL: connection pool, schema
//! migrations, and every query the platform runs.

/// Agent listing, inspection, and revocation.
pub mod agents;
/// The Alarms list: filters, per-value counts, summary and paging in scope.
pub mod alarm_list;
/// The SQL of the Alarms list's one statement.
mod alarm_list_sql;
/// An alarm's page above the fold: siblings, last 24 hours, rule text, related.
pub mod alarm_summary;
mod alarm_suppression_writes;
/// Alarm suppressions (P14) as the console manages them: states, where
/// and duration (roles spec §8).
pub mod alarm_suppressions;
/// Threat alarms (P14): insert with suppression.
pub mod alarms;
/// Threat alarms on a host: on (eBPF or audit) or off, why, and the fix.
pub mod alarms_status;
/// Read-only, scoped lookups for the console's assistant.
pub mod assistant;
/// The opt-in internet lookups setting for the assistant.
pub mod assistant_internet;
/// Read-only, scoped ports, services and software lookups for the assistant.
pub mod assistant_inventory;
/// The append-only audit log.
pub mod audit;
pub mod bulk_triage;
/// CA certificates the platform issues under.
pub mod ca;
/// The Cases list: rows, per-value counts, summary and paging in scope.
pub mod case_list;
mod case_list_sql;
mod case_people;
/// A case's page: tiles, hosts with their problems, who can see it.
pub mod case_summary;
/// What appeared and went away on each host, written at ingest.
pub mod change_log;
/// A compliance check's area and collector, from its rule ID.
pub mod check_area;
/// The Compliance list: one row per check, filters, per-value counts,
/// summary and paging in scope.
pub mod check_list;
/// The SQL of the Compliance list's one statement.
mod check_list_sql;
/// A check's Related card: its port, unit and same-area checks.
pub mod check_related;
/// A check's Hosts table by triage state.
mod check_states;
/// A check's page: header, tiles, text, history and the Hosts table in scope.
pub mod check_summary;
/// The SQL of a check's page.
mod check_summary_sql;
/// Console reads and triage of threat alarms (P14).
pub mod console_alarms;
/// Local console credentials, throttles, pre-authentication, and sessions.
pub mod console_auth;
/// Cases: investigations with items, notes and a timeline (schema 35).
pub mod console_cases;
/// Console reads of installed software: host packages and fleet software.
pub mod console_inventory;
/// People: users with their roles, details, enable, reset and role gifts.
pub mod console_people;
/// Bounded global read models for the human console.
pub mod console_read;
/// Console roles with a host reach, and what a principal holds (schema 52).
pub mod console_roles;
/// General console settings: typed values, audited changes.
pub mod console_settings;
pub mod console_sso;
/// Versioned analyst workflow state and history for current findings.
pub mod console_triage;
/// CPE matching: NVD applicability ranges and lower-confidence findings (schema 39).
pub mod cpe;
/// User dashboards: layouts, sharing by role, home (schema 26).
pub mod dashboards;
/// Alarms from network devices, stored by openvibes-netlog.
pub mod device_alarms;
/// Network devices that send events to openvibes-netlog.
pub mod devices;
/// CVE enrichment: KEV and EPSS (vulnerability management).
pub mod enrichment;
pub mod finding_changes;
pub mod health;
/// Daily per-host problem counts for history graphs.
pub mod history;
/// Automatic host groups made from reported OS facts (schema 53).
pub mod host_group_facts;
/// The preview before a host-group save, re-exported by `host_group_writes`.
mod host_group_preview;
/// Host-group writes (create, update, delete) and the preview before a save.
pub mod host_group_writes;
/// Host groups as the console reads them: list, detail, member hosts, changes.
pub mod host_groups;
/// Host labels: free strings for filtering, never part of access.
pub mod host_labels;
/// The Hosts list: filters, per-value counts, summary and paging in scope.
pub mod host_list;
/// The SQL of the Hosts list's one statement.
mod host_list_sql;
/// Open ports and running services per host (P15, Assets v2).
pub mod host_services;
/// The host page's summary: header, tiles, top-three lists and counts.
pub mod host_summary;
/// Queries the ingest service runs.
pub mod imports;
pub mod ingest;
/// Host package inventories (vulnerability management).
pub mod inventory;
mod maintenance;
mod migrate;
/// The Ports list: one row per port, filters, counts and the summary.
pub mod port_list;
mod port_list_sql;
/// A fixed map of well-known ports: names, classes, related packages.
pub mod port_names;
/// A port's Related card: failing checks, advisories and alarms.
pub mod port_related;
/// A port's page: the summary and the Hosts table.
pub mod port_summary;
/// Rule-set assignment: defaults, group overrides, per-host state.
pub mod rule_assignment;
/// Draft rules for the site's own rule sets.
pub mod rule_drafts;
/// The rule-metadata index of stored bundles (schema 59).
pub mod rule_meta;
/// Rule sets, trust keys, and published bundles.
pub mod rules;
/// Saved views and hidden list columns per person and page (schema 56).
pub mod saved_views;
/// The Services list: one row per unit, filters, counts and the summary.
pub mod service_list;
mod service_list_sql;
/// A fixed map of well-known services: names, classes, related packages.
pub mod service_names;
/// A service's Related card: failing checks, advisories and alarms.
pub mod service_related;
/// A service's page: the summary and the Hosts table.
pub mod service_summary;
pub mod signer;
/// The Software list: one row per package name, filters, counts and the summary.
pub mod software_list;
mod software_list_sql;
/// A package's page: the summary and the Hosts table.
pub mod software_summary;
/// Package versions as the Software pages write and order them.
pub mod software_version;
mod status;
mod summary_parts;
/// Enrollment tokens (stored only as hashes).
pub mod tokens;
pub mod triage_history;
/// Agent version order, the Rust twin of `console_version_older` (schema 57).
pub mod version_order;
/// Its Hosts table.
mod vuln_hosts;
/// The Vulnerabilities list: one row per CVE, filters, per-value counts,
/// summary and paging in scope.
pub mod vuln_list;
/// Its no-fix pairs, through host profiles.
mod vuln_list_profiles;
/// The SQL of the Vulnerabilities list's one statement.
mod vuln_list_sql;
/// Its Related card.
mod vuln_related;
/// A vulnerability's page: its summary and Hosts table, in scope.
pub mod vuln_summary;
/// The SQL of a vulnerability's page.
mod vuln_summary_sql;
pub mod vulnerability_triage;
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
    prune_alarm_hourly,
};
pub use migrate::{
    NEEDS_BACKUP, SCHEMA_VERSION, migrate, migrate_additive, needs_backup_after, schema_version,
};
pub use status::{OFFLINE_AFTER_MINUTES, Status, presence, status};

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
                 → Maintenance → Update OpenVIBES and tick Back up first (or `sudo openvibes-admin \
                 setup --update --backup FILE`)"
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
