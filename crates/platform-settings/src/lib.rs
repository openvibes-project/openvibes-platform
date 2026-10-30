#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! The settings the console changes for the whole platform: each one's key,
//! wording, type, range and default, and the check of a new value. The
//! console checks a change with these; a service that takes its settings
//! from the database applies the same ones over its file, so both sides
//! agree on what is valid. No database code lives here.

mod agent;
mod assistant;
mod definition;
mod general;
mod sso;
mod vulns;

pub use definition::{Applies, Definition, Kind, MAX_CERTIFICATES, Text};

/// Every setting, in display order.
pub fn all() -> impl Iterator<Item = &'static Definition> {
    general::DEFINITIONS
        .iter()
        .chain(sso::DEFINITIONS.iter())
        .chain(agent::ingest::DEFINITIONS.iter())
        .chain(agent::distribution::DEFINITIONS.iter())
        .chain(vulns::DEFINITIONS.iter())
        .chain(assistant::DEFINITIONS.iter())
}

/// The setting with this key.
#[must_use]
pub fn find(key: &str) -> Option<&'static Definition> {
    all().find(|definition| definition.key == key)
}

/// The vulnerability service's keys; the service reads them under this prefix.
pub mod vulns_keys {
    pub use crate::vulns::{
        ARCH, CHECK_INTERVAL_MINUTES, EPSS_URL, EUVD_URL, KEV_URL, MAX_DOWNLOAD_MIB, METALINK_URL,
        NVD_API_KEY, NVD_URL, OSV_MAX_DOWNLOAD_MIB, OSV_URL, PREFIX, PROXY_URL,
    };
}

/// The ingest service's keys; it reads them under this prefix.
pub mod ingest_keys {
    pub use crate::agent::ingest::{
        CLIENT_CERTIFICATE_DAYS, FINDING_RETENTION_DAYS, INVENTORY_REQUEST_TIMEOUT_SECONDS,
        MAX_CONNECTIONS, MAX_IN_FLIGHT, MAX_INVENTORY_IN_FLIGHT, PREFIX, REQUEST_TIMEOUT_SECONDS,
    };
}

/// The rule distribution service's keys; it reads them under this prefix.
pub mod distribution_keys {
    pub use crate::agent::distribution::{
        MAX_CONNECTIONS, MAX_IN_FLIGHT, PREFIX, REQUEST_TIMEOUT_SECONDS,
    };
}

/// The assistant's keys; the console reads them under this prefix when it
/// starts.
pub mod assistant_keys {
    pub use crate::assistant::{
        ALLOW_REMOTE, API_KEY, CONCURRENCY, CONVERSATION_RETENTION_DAYS, DATA_LOCATION,
        DEADLINE_SECONDS, ENABLED, LOOKUP_MODE, MAX_LOOKUPS, MODEL, PREFIX, PROFILE, PROXY_URL,
        PSEUDONYMIZE, QUESTIONS_PER_USER_PER_HOUR, URL,
    };
}

/// The single sign-on keys.
pub mod sso_keys {
    pub use crate::sso::{
        EMAIL_ATTRIBUTE, ENABLED, GROUP_ATTRIBUTE, IDP_CERTIFICATES, IDP_ENTITY_ID, IDP_SSO_URL,
        NAME_ATTRIBUTE, REMOVE_INACTIVE_DAYS,
    };
}
